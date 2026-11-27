//! Which registry key a value write went to. Kernel-Registry's `SetValueKey` names its key by
//! `KeyObject` only (Windows 11 26300: `KeyName` empty on every record of a live capture), so
//! the sensor learns each key object's name from the create or open that returned it and
//! forgets it on close. See `docs/sensors/windows/etw.md#registry-key-paths`.

use std::collections::HashMap;

use schema::{EventMeta, RegistryKey, RegistrySetEvent};

use crate::{
    bounded_lru::BoundedLru,
    normalize,
    payload::{self, KeyOpen, PayloadFields, ValueWrite},
    shed::RegistryKeyShedding,
};

/// The longest key name the table keeps, in bytes. Names are caller-chosen, so a process can
/// build deep chains of long names; a longer one is cut, never refused, since refusing it
/// would hide the write.
pub(crate) const MAX_KEY_NAME_BYTES: usize = 1024;

/// The Kernel-Registry operations the sensor reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegistryOperation {
    /// EID 1 `CreateKey`.
    Create,
    /// EID 2 `OpenKey`.
    Open,
    /// EID 5 `SetValueKey`.
    SetValue,
    /// EID 13 `CloseKey`.
    Close,
}

impl RegistryOperation {
    /// Every id [`Self::from_id`] reads.
    pub(crate) const EVENT_IDS: [u16; 4] = [1, 2, 5, 13];

    pub(crate) fn from_id(event_id: u16) -> Option<Self> {
        match event_id {
            1 => Some(Self::Create),
            2 => Some(Self::Open),
            5 => Some(Self::SetValue),
            13 => Some(Self::Close),
            _ => None,
        }
    }
}

/// A key's name, as far as the table knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeyName {
    /// The key's NT path (`\REGISTRY\...`).
    Absolute(String),
    /// The name below a key the table never saw opened; empty when no part is known.
    BelowUnknownKey(String),
}

impl KeyName {
    fn joined(&self, relative: &str) -> Self {
        match self {
            Self::Absolute(base) => Self::Absolute(join(base, relative)),
            Self::BelowUnknownKey(base) => Self::BelowUnknownKey(join(base, relative)),
        }
    }

    fn text_mut(&mut self) -> &mut String {
        match self {
            Self::Absolute(name) | Self::BelowUnknownKey(name) => name,
        }
    }

    fn into_schema(self) -> RegistryKey {
        match self {
            Self::Absolute(path) => RegistryKey::Resolved {
                path: normalize::normalize_registry_key(&path),
            },
            Self::BelowUnknownKey(relative_name) => RegistryKey::Unresolved { relative_name },
        }
    }
}

/// A value write and the name of the key it went to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyedWrite {
    pub(crate) key: KeyName,
    pub(crate) write: ValueWrite,
}

impl KeyedWrite {
    pub(crate) fn into_event(self, meta: EventMeta) -> RegistrySetEvent {
        self.write.into_event(self.key.into_schema(), meta)
    }
}

struct KeyEntry {
    name: KeyName,
    /// The process that opened the key: its entries count against its share of the table.
    opener: u32,
}

/// Key object → the key's name, for every key opened since the session started and not
/// closed yet, within a cap. Each process holds at most a share of the cap, so one process
/// opening keys cannot evict another's. A write through a key object the table does not
/// hold is still returned, its key unresolved, and counted.
pub(crate) struct RegistryKeys {
    names: BoundedLru<u64, KeyEntry>,
    entries_by_opener: HashMap<u32, usize>,
    share: usize,
    shedding: RegistryKeyShedding,
}

impl RegistryKeys {
    /// # Panics
    ///
    /// Panics when `cap` is 0 — a configuration bug, not a runtime condition.
    #[cfg(test)]
    pub(crate) fn new(cap: usize) -> Self {
        Self::counting(cap, RegistryKeyShedding::default())
    }

    /// A table counting what it sheds into `shedding`, which the health beacon reads. Each
    /// process may hold an eighth of `cap`.
    ///
    /// # Panics
    ///
    /// Panics when `cap` is 0.
    pub(crate) fn counting(cap: usize, shedding: RegistryKeyShedding) -> Self {
        Self {
            names: BoundedLru::counting("registry key objects", cap, shedding.evicted.clone()),
            entries_by_opener: HashMap::new(),
            share: (cap / 8).max(1),
            shedding,
        }
    }

    /// Applies one record of process `pid` to the table and returns the write it carries,
    /// with its key's name. Creates, opens and closes return `None`.
    pub(crate) fn on_record(
        &mut self,
        operation: RegistryOperation,
        pid: u32,
        fields: &impl PayloadFields,
    ) -> Option<KeyedWrite> {
        match operation {
            RegistryOperation::Create | RegistryOperation::Open => {
                if let Some(open) = payload::key_open(fields) {
                    self.opened(&open, pid);
                }
                None
            }
            RegistryOperation::Close => {
                if let Some(key_object) = payload::key_object(fields) {
                    self.forget(key_object);
                }
                None
            }
            RegistryOperation::SetValue => Some(self.keyed(payload::value_write(fields))),
        }
    }

    fn opened(&mut self, open: &KeyOpen, opener: u32) {
        let name = self.name_of(open);
        let name = self.bounded(name);
        self.remember(open.key_object, KeyEntry { name, opener });
    }

    /// The name an open gives its key: its relative name when absolute, else joined to its
    /// base key's name, from the record or from the table; below an unknown key when neither
    /// knows the base.
    fn name_of(&mut self, open: &KeyOpen) -> KeyName {
        if is_absolute(&open.relative_name) {
            return KeyName::Absolute(open.relative_name.clone());
        }
        if is_absolute(&open.base_name) {
            return KeyName::Absolute(join(&open.base_name, &open.relative_name));
        }
        match self.names.get(&open.base_object) {
            Some(base) => base.name.joined(&open.relative_name),
            None => KeyName::BelowUnknownKey(open.relative_name.clone()),
        }
    }

    fn remember(&mut self, key_object: u64, entry: KeyEntry) {
        self.forget(key_object);
        let opener = entry.opener;
        if self.entries_held_by(opener) >= self.share {
            let batch = (self.share / 8).max(1);
            let evicted = self
                .names
                .evict_least_recent(batch, |held| held.opener == opener);
            self.release(&evicted);
        }
        let evicted = self.names.insert(key_object, entry);
        self.release(&evicted);
        *self.entries_by_opener.entry(opener).or_default() += 1;
    }

    fn forget(&mut self, key_object: u64) {
        if let Some(entry) = self.names.remove(&key_object) {
            self.release(&[entry]);
        }
    }

    fn release(&mut self, entries: &[KeyEntry]) {
        for entry in entries {
            if let Some(held) = self.entries_by_opener.get_mut(&entry.opener) {
                *held -= 1;
                if *held == 0 {
                    self.entries_by_opener.remove(&entry.opener);
                }
            }
        }
    }

    fn entries_held_by(&self, opener: u32) -> usize {
        self.entries_by_opener.get(&opener).copied().unwrap_or(0)
    }

    fn keyed(&mut self, write: ValueWrite) -> KeyedWrite {
        let key = match (&write.key_name, write.key_object) {
            (Some(key_name), _) => KeyName::Absolute(key_name.clone()),
            (None, Some(key_object)) => self.names.get(&key_object).map_or_else(
                || KeyName::BelowUnknownKey(String::new()),
                |entry| entry.name.clone(),
            ),
            (None, None) => KeyName::BelowUnknownKey(String::new()),
        };
        let key = self.bounded(key);
        if matches!(key, KeyName::BelowUnknownKey(_)) {
            self.shedding.unresolved_writes.add();
        }
        KeyedWrite { key, write }
    }

    /// `name` cut to [`MAX_KEY_NAME_BYTES`] on a character boundary, the cut counted.
    fn bounded(&self, mut name: KeyName) -> KeyName {
        let text = name.text_mut();
        if text.len() > MAX_KEY_NAME_BYTES {
            text.truncate(text.floor_char_boundary(MAX_KEY_NAME_BYTES));
            self.shedding.names_truncated.add();
        }
        name
    }
}

fn is_absolute(name: &str) -> bool {
    name.starts_with('\\')
}

fn join(base: &str, relative: &str) -> String {
    if relative.is_empty() {
        return base.to_owned();
    }
    if base.is_empty() {
        return relative.to_owned();
    }
    format!("{}\\{relative}", base.trim_end_matches('\\'))
}

#[cfg(test)]
mod tests;
