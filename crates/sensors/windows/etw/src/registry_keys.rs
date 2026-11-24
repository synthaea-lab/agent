//! Which registry key a value write went to. Kernel-Registry's `SetValueKey` names its key by
//! `KeyObject` only (Windows 11 26300: `KeyName` empty on every record of a live capture), so
//! the sensor learns each key object's path from the create or open that returned it and
//! forgets it on close. See `docs/sensors/windows/etw.md#registry-key-paths`.

use schema::{EventMeta, RegistrySetEvent};

use crate::{
    bounded_lru::BoundedLru,
    payload::{self, KeyOpen, PayloadFields, ValueWrite},
};

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

/// A value write and the NT path of the key it went to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyedWrite {
    pub(crate) key_path: String,
    pub(crate) write: ValueWrite,
}

impl KeyedWrite {
    pub(crate) fn into_event(self, meta: EventMeta) -> RegistrySetEvent {
        self.write.into_event(&self.key_path, meta)
    }
}

/// Key object → the key's NT path, for every key opened since the session started and not
/// closed yet, within a cap. A write through a key object opened before the session started,
/// or evicted, has no path: it is counted, not emitted.
pub(crate) struct RegistryKeys {
    paths: BoundedLru<u64, String>,
    unresolved_writes: u64,
}

impl RegistryKeys {
    /// # Panics
    ///
    /// Panics when `cap` is 0 — a configuration bug, not a runtime condition.
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            paths: BoundedLru::new("registry key objects", cap),
            unresolved_writes: 0,
        }
    }

    /// Applies one record to the table and returns the write it carries, with its key's
    /// path. Creates, opens and closes return `None`, and so does a write whose key is
    /// unknown.
    pub(crate) fn on_record(
        &mut self,
        operation: RegistryOperation,
        fields: &impl PayloadFields,
    ) -> Option<KeyedWrite> {
        match operation {
            RegistryOperation::Create | RegistryOperation::Open => {
                if let Some(open) = payload::key_open(fields) {
                    self.opened(&open);
                }
                None
            }
            RegistryOperation::Close => {
                if let Some(key_object) = payload::key_object(fields) {
                    self.paths.remove(&key_object);
                }
                None
            }
            RegistryOperation::SetValue => self.keyed(payload::value_write(fields)),
        }
    }

    /// Writes dropped because their key object had no known path.
    #[cfg_attr(not(test), allow(dead_code))] // read by a future health surface
    pub(crate) fn unresolved_writes(&self) -> u64 {
        self.unresolved_writes
    }

    fn opened(&mut self, open: &KeyOpen) {
        match self.full_path(open) {
            Some(path) => self.paths.insert(open.key_object, path),
            // A path the table no longer holds for the object would be a stale one.
            None => {
                self.paths.remove(&open.key_object);
            }
        }
    }

    /// The NT path an open names: its relative name when absolute, else joined to its base
    /// key's path, from the record or from the table.
    fn full_path(&mut self, open: &KeyOpen) -> Option<String> {
        if is_absolute(&open.relative_name) {
            return Some(open.relative_name.clone());
        }
        let base = if is_absolute(&open.base_name) {
            open.base_name.clone()
        } else {
            self.paths.get(&open.base_object)?.clone()
        };
        Some(join(&base, &open.relative_name))
    }

    fn keyed(&mut self, write: ValueWrite) -> Option<KeyedWrite> {
        let known = write.key_name.clone().or_else(|| {
            write
                .key_object
                .and_then(|key_object| self.paths.get(&key_object).cloned())
        });
        let Some(key_path) = known else {
            self.count_unresolved_write();
            return None;
        };
        Some(KeyedWrite { key_path, write })
    }

    fn count_unresolved_write(&mut self) {
        self.unresolved_writes += 1;
        // Powers of two only: a burst must not flood the log.
        if self.unresolved_writes.is_power_of_two() {
            tracing::warn!(
                unresolved_total = self.unresolved_writes,
                tracked_keys = self.paths.len(),
                "registry value write through a key object with no known path; not emitted"
            );
        }
    }
}

fn is_absolute(name: &str) -> bool {
    name.starts_with('\\')
}

fn join(base: &str, relative: &str) -> String {
    if relative.is_empty() {
        return base.to_owned();
    }
    format!("{}\\{relative}", base.trim_end_matches('\\'))
}

#[cfg(test)]
mod tests;
