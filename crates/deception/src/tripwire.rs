//! Tripwire matching: the events that touch a planted canary.
//!
//! No new sensor hook: canary paths are looked up on the file events the agent already
//! collects. Nothing legitimate touches a canary, so a hit needs no baseline; the caller
//! decides what its own reads (the agent verifying its canaries) and known indexers or
//! backup agents mean for the hit, using the pid and the kind of touch.

use std::collections::HashMap;

use schema::Event;

use crate::lifecycle::{Inventory, InventoryEntry};

/// How an event touched a canary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Touch {
    /// Opened. `flags` are the sensor's platform-native flags: interpreting them as read or
    /// write intent is the caller's, as for any other `FileOpenEvent`.
    Open {
        /// The open flags as the sensor reported them.
        flags: u32,
    },
    /// Deleted.
    Delete,
    /// Renamed away (the canary is the old path).
    RenameFrom {
        /// Where it went.
        to: String,
    },
    /// Something was renamed onto its path.
    RenameTo {
        /// What was renamed.
        from: String,
    },
}

/// A canary touched by an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit<'a> {
    /// The canary, as inventoried.
    pub canary: &'a InventoryEntry,
    /// How it was touched.
    pub touch: Touch,
    /// The process that touched it.
    pub pid: u32,
}

/// The set of planted canary paths, indexed for the event stream.
#[derive(Debug, Clone, Default)]
pub struct Tripwires {
    entries: Vec<InventoryEntry>,
    index: HashMap<String, usize>,
    /// Canaries by file name, for events whose path is relative. `None` when two canaries
    /// share a name: a bare name cannot say which one was meant, so it matches neither.
    by_name: HashMap<String, Option<usize>>,
}

/// The lookup key of a path: separators unified and case folded. Folding is always on, not
/// only on case-insensitive filesystems: a canary's name ends in four random bytes in hex,
/// so an unrelated file that differs from it only by case is not a realistic collision, and
/// one rule for every platform keeps this crate free of platform branches.
fn key(path: &str) -> String {
    path.replace('\\', "/").to_lowercase()
}

/// True for a path that does not say where it is rooted (no leading separator, no drive
/// letter, no UNC prefix).
fn is_relative(path: &str) -> bool {
    let bytes = path.as_bytes();
    !(path.starts_with(['/', '\\']) || (bytes.len() >= 2 && bytes[1] == b':'))
}

/// The last component of a path, in lookup form.
fn name_key(path: &str) -> String {
    let k = key(path);
    k.rsplit('/').next().unwrap_or_default().to_string()
}

impl Tripwires {
    /// Indexes every canary of `inventory`.
    #[must_use]
    pub fn from_inventory(inventory: &Inventory) -> Self {
        let entries = inventory.entries.clone();
        let index = entries
            .iter()
            .enumerate()
            .map(|(i, e)| (key(&e.path.to_string_lossy()), i))
            .collect();
        let mut by_name: HashMap<String, Option<usize>> = HashMap::new();
        for (i, e) in entries.iter().enumerate() {
            by_name
                .entry(name_key(&e.path.to_string_lossy()))
                .and_modify(|slot| *slot = None)
                .or_insert(Some(i));
        }
        Self {
            entries,
            index,
            by_name,
        }
    }

    /// How many canaries are watched.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no canary is watched.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Exact path first. A relative path (the Linux sensor reports `openat` names as the
    /// caller passed them, unresolved against the directory descriptor, so `cd dir && cat
    /// name` and `grep -r` arrive as a bare name) falls back to the file name: a canary's
    /// name ends in four random bytes in hex, so a name match on its own is
    /// nearly collision-free.
    fn entry(&self, path: &str) -> Option<&InventoryEntry> {
        if let Some(&i) = self.index.get(&key(path)) {
            return Some(&self.entries[i]);
        }
        if !is_relative(path) {
            return None;
        }
        let i = (*self.by_name.get(&name_key(path))?)?;
        Some(&self.entries[i])
    }

    /// The canary `event` touches, if any. Only events that carry a path can match: a
    /// `FileWrite` has none (it names a descriptor), so a write to a canary shows up as the
    /// open that preceded it.
    #[must_use]
    pub fn matches(&self, event: &Event) -> Option<Hit<'_>> {
        match event {
            Event::FileOpen(e) => self.entry(&e.path).map(|canary| Hit {
                canary,
                touch: Touch::Open { flags: e.flags },
                pid: e.meta.pid,
            }),
            Event::FileDelete(e) => self.entry(&e.path).map(|canary| Hit {
                canary,
                touch: Touch::Delete,
                pid: e.meta.pid,
            }),
            Event::FileRename(e) => self
                .entry(&e.old_path)
                .map(|canary| Hit {
                    canary,
                    touch: Touch::RenameFrom {
                        to: e.new_path.clone(),
                    },
                    pid: e.meta.pid,
                })
                .or_else(|| {
                    self.entry(&e.new_path).map(|canary| Hit {
                        canary,
                        touch: Touch::RenameTo {
                            from: e.old_path.clone(),
                        },
                        pid: e.meta.pid,
                    })
                }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use schema::{EventMeta, FileDeleteEvent, FileOpenEvent, FileRenameEvent, fixtures};

    use super::*;
    use crate::plan::Kind;

    const CANARY: &str = "/srv/share/passwords_a1b2c3d4.txt";

    fn tripwires() -> Tripwires {
        let mut inventory = Inventory::default();
        inventory.entries.push(InventoryEntry {
            path: PathBuf::from(CANARY),
            kind: Kind::Credentials,
            sha256: "00".into(),
        });
        Tripwires::from_inventory(&inventory)
    }

    fn open(path: &str, pid: u32) -> Event {
        Event::FileOpen(FileOpenEvent {
            meta: EventMeta {
                pid,
                ..fixtures::meta()
            },
            path: path.into(),
            flags: 0o101,
        })
    }

    #[test]
    fn opening_a_canary_is_a_hit_with_the_pid_and_flags() {
        let wires = tripwires();
        let hit = wires.matches(&open(CANARY, 4242)).expect("a hit");
        assert_eq!(hit.pid, 4242);
        assert_eq!(hit.touch, Touch::Open { flags: 0o101 });
        assert_eq!(hit.canary.kind, Kind::Credentials);
    }

    #[test]
    fn other_paths_and_other_events_are_not_hits() {
        let wires = tripwires();
        assert!(
            wires
                .matches(&open("/srv/share/passwords.txt", 1))
                .is_none()
        );
        assert!(wires.matches(&Event::Exec(fixtures::exec())).is_none());
        assert!(
            wires
                .matches(&Event::FileWrite(fixtures::file_write()))
                .is_none()
        );
    }

    #[test]
    fn deleting_and_renaming_a_canary_are_hits() {
        let wires = tripwires();
        let delete = Event::FileDelete(FileDeleteEvent {
            path: CANARY.into(),
            ..fixtures::file_delete()
        });
        assert_eq!(wires.matches(&delete).unwrap().touch, Touch::Delete);

        let away = Event::FileRename(FileRenameEvent {
            old_path: CANARY.into(),
            new_path: format!("{CANARY}.locked"),
            ..fixtures::file_rename()
        });
        assert_eq!(
            wires.matches(&away).unwrap().touch,
            Touch::RenameFrom {
                to: format!("{CANARY}.locked")
            }
        );

        let onto = Event::FileRename(FileRenameEvent {
            old_path: "/tmp/x".into(),
            new_path: CANARY.into(),
            ..fixtures::file_rename()
        });
        assert_eq!(
            wires.matches(&onto).unwrap().touch,
            Touch::RenameTo {
                from: "/tmp/x".into()
            }
        );
    }

    #[test]
    fn separators_and_case_do_not_hide_a_canary() {
        let wires = tripwires();
        assert!(
            wires
                .matches(&open(&CANARY.replace('/', "\\"), 1))
                .is_some()
        );
        assert!(wires.matches(&open(&CANARY.to_uppercase(), 1)).is_some());
    }

    #[test]
    fn a_relative_open_of_a_canary_name_is_a_hit() {
        let wires = tripwires();
        assert!(wires.matches(&open("passwords_a1b2c3d4.txt", 7)).is_some());
        assert!(
            wires
                .matches(&open("./sub/Passwords_A1B2C3D4.txt", 7))
                .is_some()
        );
    }

    #[test]
    fn an_absolute_path_elsewhere_with_a_canary_name_is_not_a_hit() {
        let wires = tripwires();
        assert!(
            wires
                .matches(&open("/home/u/passwords_a1b2c3d4.txt", 7))
                .is_none()
        );
        assert!(
            wires
                .matches(&open(r"C:\\Users\\u\\passwords_a1b2c3d4.txt", 7))
                .is_none()
        );
    }

    #[test]
    fn a_name_shared_by_two_canaries_matches_neither_when_relative() {
        let mut inventory = Inventory::default();
        for dir in ["/srv/a", "/srv/b"] {
            inventory.entries.push(InventoryEntry {
                path: PathBuf::from(format!("{dir}/notes_00112233.txt")),
                kind: Kind::Notes,
                sha256: "00".into(),
            });
        }
        let wires = Tripwires::from_inventory(&inventory);
        assert!(wires.matches(&open("notes_00112233.txt", 1)).is_none());
        assert!(
            wires
                .matches(&open("/srv/b/notes_00112233.txt", 1))
                .is_some()
        );
    }

    #[test]
    fn no_canaries_means_no_hits() {
        let wires = Tripwires::default();
        assert!(wires.is_empty());
        assert!(wires.matches(&open(CANARY, 1)).is_none());
    }
}
