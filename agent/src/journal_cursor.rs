//! Persists the journal tail's last-seen cursor across agent restarts (issue #321).
//!
//! Without this, `commands::linux::spawn_journal_tail` (Linux-gated) always started its
//! `journalctl -f` from "now" (`sensor_linux_journal::process::current_cursor`) —
//! the crate's own doc named this an accepted gap, not a decision: a
//! watchdog-triggered restart drops whatever auth/persistence events landed in the
//! restart gap. The journal has stable cursors (`__CURSOR`, `JournalRecord::cursor`)
//! already threaded through every classified record, so persisting the last one seen
//! closes the gap cheaply — no new crate, no `crates/store` integration, just a small
//! file next to the alerts output, same derived-path convention `heartbeat_path_for`
//! uses for #102.

use std::path::{Path, PathBuf};

/// Derives the cursor file's path from the alerts output path — same reasoning as
/// `crate::heartbeat::heartbeat_path_for`: the two paths always travel together, so
/// no separate CLI flag or install-time wiring is needed.
pub(crate) fn cursor_path_for(alerts: &Path) -> PathBuf {
    alerts.with_extension("journal-cursor")
}

/// Reads the last persisted cursor, or `None` if the file is absent, empty, or
/// unreadable — every one of those is the honest "no prior state" case (first start,
/// a fresh install, a deleted state dir), not an error worth failing startup over.
/// The caller falls back to `journalctl`'s own "now" snapshot in that case.
pub(crate) fn read(path: &Path) -> Option<String> {
    let cursor = std::fs::read_to_string(path).ok()?;
    let cursor = cursor.trim();
    if cursor.is_empty() {
        None
    } else {
        Some(cursor.to_string())
    }
}

/// Writes `cursor` to `path` via a same-directory temp file + rename, so a process
/// killed mid-write (the exact moment a restart's resume point matters most) never
/// leaves a torn cursor behind — same pattern `heartbeat::write_once` uses. Silently
/// ignores I/O failures: same posture as the heartbeat writer, a missed persist just
/// means the next restart falls a little further back (or, worst case, to "now"
/// again), never a reason to bring down the journal tail thread over a disk hiccup.
pub(crate) fn write(path: &Path, cursor: &str) {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    if std::fs::write(&tmp, cursor).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(test_name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "journal-cursor-test-{test_name}-{}-{}",
            std::process::id(),
            test_name.len() // cheap uniqueifier alongside the pid, no two tests share a name anyway
        ))
    }

    #[test]
    fn cursor_path_is_derived_from_alerts() {
        assert_eq!(
            cursor_path_for(Path::new("/var/lib/synthaea/alerts.ndjson")),
            PathBuf::from("/var/lib/synthaea/alerts.journal-cursor")
        );
    }

    #[test]
    fn missing_file_reads_as_no_prior_cursor() {
        let path = temp_path("missing");
        std::fs::remove_file(&path).ok();
        assert_eq!(read(&path), None);
    }

    #[test]
    fn a_written_cursor_round_trips_through_read() {
        let path = temp_path("round-trip");
        write(&path, "s=abc123;i=1;b=deadbeef");
        assert_eq!(read(&path), Some("s=abc123;i=1;b=deadbeef".to_string()));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn an_empty_file_reads_as_no_prior_cursor() {
        // A zero-byte file (e.g. truncated by a prior crash mid-write, before this
        // module's temp-file+rename pattern existed) must not be mistaken for a
        // valid empty cursor — `journalctl --after-cursor=""` is not "start now".
        let path = temp_path("empty");
        std::fs::write(&path, "").unwrap();
        assert_eq!(read(&path), None);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn writing_twice_overwrites_not_appends() {
        let path = temp_path("overwrite");
        write(&path, "first-cursor");
        write(&path, "second-cursor");
        assert_eq!(read(&path), Some("second-cursor".to_string()));
        std::fs::remove_file(&path).ok();
    }
}
