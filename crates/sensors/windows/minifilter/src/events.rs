//! Decoded driver messages to schema events (milestone 2c, #136).
//!
//! The driver reports names in NT device form (`\Device\HarddiskVolume3\Users\…`). Rules match
//! the drive-letter form the ETW sensor produces, so the same file must reach them under the
//! same path whichever sensor saw it: [`VolumeMap`] does the ETW sensor's
//! `normalize_nt_path` over the same `QueryDosDeviceW` table. Sensor crates cannot depend on
//! each other (`tools/check-deps.py`), so the dozen lines are repeated here rather than shared;
//! `a_device_path_gets_its_drive_letter` pins the same behaviour as the ETW tests.
//!
//! Platform-independent, like [`crate::wire`]: tested on every OS.

use schema::{Event, EventMeta, FileDeleteEvent, FileRenameEvent, User};

use crate::wire::{Body, Message};

/// `\Device\HarddiskVolumeN` → `X:`, from the live drive table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VolumeMap {
    /// (device prefix, drive), as `QueryDosDeviceW` gives them.
    entries: Vec<(String, String)>,
}

impl VolumeMap {
    /// A map from explicit pairs: for tests, and for callers that already hold the table.
    #[must_use]
    pub fn from_pairs(pairs: impl IntoIterator<Item = (String, String)>) -> Self {
        Self {
            entries: pairs.into_iter().collect(),
        }
    }

    /// Reads the drive table: `QueryDosDeviceW` for `A:` to `Z:`.
    #[cfg(windows)]
    #[must_use]
    pub fn from_system() -> Self {
        use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;

        let mut entries = Vec::new();
        for letter in b'A'..=b'Z' {
            let drive: [u16; 3] = [u16::from(letter), u16::from(b':'), 0];
            let mut target = [0u16; 512];
            // SAFETY: `drive` is NUL-terminated; `target` holds the 512 wide chars passed.
            let n = unsafe { QueryDosDeviceW(drive.as_ptr(), target.as_mut_ptr(), 512) };
            if n == 0 {
                continue;
            }
            let end = target.iter().position(|&c| c == 0).unwrap_or(0);
            if end == 0 {
                continue;
            }
            entries.push((
                String::from_utf16_lossy(&target[..end]),
                format!("{}:", char::from(letter)),
            ));
        }
        Self { entries }
    }

    /// `path` with its longest matching device prefix replaced by the drive letter; unchanged
    /// when no prefix matches (a network redirector or an unmounted volume: honest, not
    /// guessed). The prefix must end on a component boundary, so `\Device\HarddiskVolume1`
    /// does not swallow the start of `\Device\HarddiskVolume10`.
    #[must_use]
    pub fn normalize(&self, path: &str) -> String {
        let mut best: Option<(&str, &str)> = None;
        for (device, drive) in &self.entries {
            let Some(head) = path.get(..device.len()) else {
                continue;
            };
            let on_boundary = path.len() == device.len() || path[device.len()..].starts_with('\\');
            if head.eq_ignore_ascii_case(device)
                && on_boundary
                && best.is_none_or(|(d, _)| device.len() > d.len())
            {
                best = Some((device.as_str(), drive.as_str()));
            }
        }
        match best {
            Some((device, drive)) => format!("{drive}{}", &path[device.len()..]),
            None => path.to_owned(),
        }
    }

    /// Whether the map holds no drive at all (the table could not be read).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The schema event for one driver message, or `None` for a heartbeat (it proves the driver
/// is alive and carries counters, but describes no file).
///
/// The driver knows the pid and the thread, not the image, the parent or the user: `comm` is
/// left empty, `ppid` 0 and `user` unknown. Nothing in the agent fills them in for these events
/// today (the enrichment queue only handles exec images), so a rule on a minifilter event must
/// key on `pid`, and cannot match on the process name or the account; resolving them from the
/// process table is a follow-up. A pid above `u32::MAX` cannot come from Windows (pids are
/// 32-bit in practice); it is clamped to 0, "unknown", rather than truncated to a real pid.
#[must_use]
pub fn to_event(message: &Message, volumes: &VolumeMap) -> Option<Event> {
    let meta = EventMeta {
        pid: u32::try_from(message.pid).unwrap_or(0),
        ppid: 0,
        user: User::Unknown,
        timestamp_ns: message.timestamp_ns,
        comm: String::new(),
        container: None,
        process_generation: None,
        parent_process_generation: None,
    };
    match &message.body {
        Body::Heartbeat => None,
        Body::Delete { path, .. } => Some(Event::FileDelete(FileDeleteEvent {
            meta,
            path: volumes.normalize(path),
        })),
        Body::Rename {
            old_path, new_path, ..
        } => Some(Event::FileRename(FileRenameEvent {
            meta,
            old_path: volumes.normalize(old_path),
            new_path: volumes.normalize(new_path),
            executable_path: None,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Counters;

    fn volumes() -> VolumeMap {
        VolumeMap::from_pairs([
            (r"\Device\HarddiskVolume1".to_owned(), "C:".to_owned()),
            (r"\Device\HarddiskVolume10".to_owned(), "D:".to_owned()),
        ])
    }

    fn message(body: Body) -> Message {
        Message {
            seq: 7,
            timestamp_ns: 1_700_000_000_000_000_000,
            pid: 4_242,
            tid: 17,
            counters: Counters::default(),
            body,
        }
    }

    #[test]
    fn a_device_path_gets_its_drive_letter() {
        let v = volumes();
        assert_eq!(
            v.normalize(r"\Device\HarddiskVolume1\Users\a.txt"),
            r"C:\Users\a.txt"
        );
        assert_eq!(v.normalize(r"\DEVICE\harddiskvolume1\x"), r"C:\x");
        // Longest prefix on a component boundary: Volume10 is D:, not C: + "0".
        assert_eq!(v.normalize(r"\Device\HarddiskVolume10\x"), r"D:\x");
        assert_eq!(v.normalize(r"\Device\HarddiskVolume1"), "C:");
        // Unknown device: unchanged.
        assert_eq!(
            v.normalize(r"\Device\Mup\server\share\x"),
            r"\Device\Mup\server\share\x"
        );
    }

    #[test]
    fn a_prefix_that_ends_inside_a_multibyte_character_is_not_a_match() {
        // `path.get(..n)` is None when n splits a character: no panic, no match.
        let v = VolumeMap::from_pairs([("ab".to_owned(), "C:".to_owned())]);
        assert_eq!(v.normalize("aé"), "aé");
        assert_eq!(v.normalize("a"), "a");
    }

    #[test]
    fn a_delete_becomes_a_file_delete_with_a_drive_letter_path() {
        let event = to_event(
            &message(Body::Delete {
                path: r"\Device\HarddiskVolume1\Users\x.docx".into(),
                on_close: true,
                truncated: false,
            }),
            &volumes(),
        );
        let Some(Event::FileDelete(delete)) = event else {
            panic!("{event:?}");
        };
        assert_eq!(delete.path, r"C:\Users\x.docx");
        assert_eq!(delete.meta.pid, 4_242);
        assert_eq!(delete.meta.timestamp_ns, 1_700_000_000_000_000_000);
    }

    #[test]
    fn a_rename_keeps_both_paths_normalized() {
        let event = to_event(
            &message(Body::Rename {
                old_path: r"\Device\HarddiskVolume1\d\a.docx".into(),
                new_path: r"\Device\HarddiskVolume1\d\a.docx.locked".into(),
                old_truncated: false,
                new_truncated: false,
            }),
            &volumes(),
        );
        let Some(Event::FileRename(rename)) = event else {
            panic!("{event:?}");
        };
        assert_eq!(rename.old_path, r"C:\d\a.docx");
        assert_eq!(rename.new_path, r"C:\d\a.docx.locked");
    }

    #[test]
    fn a_heartbeat_is_no_event() {
        assert!(to_event(&message(Body::Heartbeat), &volumes()).is_none());
    }

    #[test]
    fn a_pid_beyond_32_bits_is_unknown_not_truncated() {
        let mut m = message(Body::Delete {
            path: "x".into(),
            on_close: false,
            truncated: false,
        });
        m.pid = u64::from(u32::MAX) + 5;
        let Some(Event::FileDelete(delete)) = to_event(&m, &volumes()) else {
            panic!("expected a delete");
        };
        assert_eq!(delete.meta.pid, 0);
    }
}
