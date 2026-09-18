//! Turns a stream of `journalctl -o json` lines into classified events, and (on
//! Linux) produces that stream by actually running `journalctl`.
//!
//! **Why a subprocess and not `libsystemd` FFI:** `journalctl -f -o json` gives
//! cursor-based resume (`--after-cursor`), JSON parsing we already need for
//! `record.rs`, and zero build-time dependency on `libsystemd-dev` being present on
//! every dev/CI machine and target distro — in the same spirit as PR #152 dropping
//! the `vmlinux` bindings crate in favor of reading `/proc` directly. The cost is a
//! child process to supervise; [`process::spawn_follow`] hands back the `Child` and
//! leaves lifecycle management to the caller —
//! `agent::commands::linux::cmd_run` (issue #93), which kills it on Ctrl-C
//! alongside the rest of the agent's threads. Restart-on-unexpected-exit is not
//! built yet (see the crate doc's Status section on cursor persistence).

use std::io::BufRead;

use crate::{JournalError, JournalEvent, JournalRecord, classify, parse_record};

/// Reads classified events out of any line-oriented `journalctl -o json` source.
/// Generic over [`BufRead`] so tests feed canned journal captures without a real
/// journald, and [`process::spawn_follow`]'s child process stdout feeds the same
/// type on Linux.
///
/// Only allowlisted records come out — see [`crate::classify`]. A record that fails
/// to parse in the "expected, recoverable" way (see `record.rs`'s module doc) is
/// skipped rather than ending the stream; a hard I/O error on the underlying reader
/// does end it.
pub struct ClassifiedJournal<R> {
    lines: std::io::Lines<R>,
}

impl<R: BufRead> ClassifiedJournal<R> {
    pub fn new(reader: R) -> Self {
        Self {
            lines: reader.lines(),
        }
    }
}

impl<R: BufRead> Iterator for ClassifiedJournal<R> {
    type Item = Result<(JournalRecord, JournalEvent), JournalError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let line = match self.lines.next()? {
                Ok(line) => line,
                Err(e) => return Some(Err(JournalError::Io(e))),
            };
            if line.trim().is_empty() {
                continue;
            }
            let record = match parse_record(&line) {
                Ok(record) => record,
                // Missing/binary-shaped field on one line — skip it, don't end the
                // stream over it (see record.rs's module doc).
                Err(JournalError::MissingField(_)) => continue,
                Err(e) => return Some(Err(e)),
            };
            if let Some(event) = classify(&record) {
                return Some(Ok((record, event)));
            }
            // Allowlist miss — this iterator only ever yields matches, so keep
            // scanning instead of returning `None` (which would end iteration).
        }
    }
}

#[cfg(target_os = "linux")]
pub mod process {
    //! Drives the real `journalctl` binary. Linux-only: there is nothing to spawn
    //! on a platform without journald.

    use std::process::{Child, Command, Stdio};

    use crate::JournalError;

    /// Runs `journalctl --show-cursor -n0` to get journald's current position
    /// without reading any history. Call once at startup; a real sensor loop would
    /// persist the returned cursor (via `crates/store`, not wired up yet — see the
    /// crate doc) so a restart resumes with [`spawn_follow`] instead of either
    /// replaying the whole journal or silently missing what was written while the
    /// sensor was down.
    ///
    /// # Errors
    ///
    /// [`JournalError::Spawn`] if `journalctl` can't be run or exits non-zero;
    /// [`JournalError::MissingField`] if its output doesn't contain the expected
    /// `-- cursor: ...` line (a `journalctl` version/format this crate doesn't
    /// recognize).
    pub fn current_cursor() -> Result<String, JournalError> {
        let output = Command::new("journalctl")
            .args(["--show-cursor", "-n0", "--no-pager"])
            .output()
            .map_err(JournalError::Spawn)?;
        if !output.status.success() {
            return Err(JournalError::Spawn(std::io::Error::other(format!(
                "journalctl --show-cursor exited with {}",
                output.status
            ))));
        }
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|line| line.strip_prefix("-- cursor: "))
            .map(str::to_string)
            .ok_or(JournalError::MissingField("-- cursor: line"))
    }

    /// Spawns `journalctl -f -o json`, resuming from `after_cursor` when given (a
    /// fresh tail from now otherwise). Returns the still-running [`Child`] with its
    /// stdout piped — feed it to [`crate::ClassifiedJournal::new`] via
    /// `BufReader::new(child.stdout.take().unwrap())`.
    ///
    /// The caller owns the child and must kill it on shutdown; this crate has no
    /// [`schema::sensor::Sensor`] implementation (see the crate doc — its caller,
    /// `agent::commands::linux::cmd_run`, wires it directly instead).
    ///
    /// # Errors
    ///
    /// [`JournalError::Spawn`] if `journalctl` is not on `PATH` or fails to spawn.
    pub fn spawn_follow(after_cursor: Option<&str>) -> Result<Child, JournalError> {
        let mut cmd = Command::new("journalctl");
        cmd.args(["-f", "-o", "json"]);
        if let Some(cursor) = after_cursor {
            cmd.arg(format!("--after-cursor={cursor}"));
        } else {
            cmd.args(["--since", "now"]);
        }
        cmd.stdout(Stdio::piped()).stderr(Stdio::null());
        cmd.spawn().map_err(JournalError::Spawn)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn yields_only_allowlisted_records_in_order() {
        let input = [
            r#"{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1","SYSLOG_IDENTIFIER":"kernel","MESSAGE":"eth0 up"}"#,
            r#"{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"2","SYSLOG_IDENTIFIER":"sudo","MESSAGE":"     lab : TTY=pts/0 ; USER=root ; COMMAND=/bin/true"}"#,
            r#"{"__CURSOR":"c3","__REALTIME_TIMESTAMP":"3","JOB_TYPE":"start","JOB_RESULT":"done","UNIT":"cron.service","MESSAGE":"Started cron.service."}"#,
        ]
        .join("\n");

        let mut it = ClassifiedJournal::new(Cursor::new(input));

        let (record1, event1) = it.next().unwrap().unwrap();
        assert_eq!(record1.cursor, "c2");
        assert!(matches!(event1, JournalEvent::SudoCommand { .. }));

        let (record2, event2) = it.next().unwrap().unwrap();
        assert_eq!(record2.cursor, "c3");
        assert!(matches!(event2, JournalEvent::UnitStarted { .. }));

        assert!(it.next().is_none());
    }

    #[test]
    fn skips_a_binary_message_line_without_ending_the_stream() {
        let input = [
            r#"{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1","MESSAGE":[1,2,3]}"#,
            r#"{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"2","JOB_TYPE":"stop","JOB_RESULT":"done","UNIT":"x.service","MESSAGE":"Stopped x.service."}"#,
        ]
        .join("\n");

        let mut it = ClassifiedJournal::new(Cursor::new(input));
        let (record, event) = it.next().unwrap().unwrap();
        assert_eq!(record.cursor, "c2");
        assert!(matches!(event, JournalEvent::UnitStopped { .. }));
        assert!(it.next().is_none());
    }

    #[test]
    fn empty_input_yields_nothing() {
        let mut it = ClassifiedJournal::new(Cursor::new(""));
        assert!(it.next().is_none());
    }

    #[test]
    fn blank_lines_are_skipped() {
        let input = "\n\n\n";
        let mut it = ClassifiedJournal::new(Cursor::new(input));
        assert!(it.next().is_none());
    }

    // --- process::spawn_follow / current_cursor ---------------------------------
    //
    // Integration-style: exercises the real `journalctl` binary when present, skips
    // itself otherwise (this crate must not require a specific dev/CI environment to
    // build and test — see issue #91's precedent for the same discipline with a
    // kernel-dependent path).

    #[cfg(target_os = "linux")]
    #[test]
    fn spawn_follow_and_current_cursor_against_the_real_journalctl() {
        use std::time::Duration;

        let Ok(cursor) = process::current_cursor() else {
            eprintln!("skipping: journalctl not available or not usable here");
            return;
        };
        assert!(!cursor.is_empty());

        let mut child = match process::spawn_follow(Some(&cursor)) {
            Ok(child) => child,
            Err(e) => {
                eprintln!("skipping: journalctl -f failed to spawn: {e}");
                return;
            }
        };
        assert!(child.stdout.is_some(), "stdout must be piped");

        // `-f` blocks waiting for new entries, so reading its stdout here would hang
        // the test on a quiet journal — the point is just "did it start and stay
        // up", not "did a line arrive in the next instant". Give it a moment to
        // fail fast (bad flag, journalctl missing a feature) before declaring it
        // alive, then tear it down.
        std::thread::sleep(Duration::from_millis(200));
        match child.try_wait() {
            Ok(None) => {} // still running — expected for `-f`
            Ok(Some(status)) => panic!("journalctl -f exited early with {status}"),
            Err(e) => panic!("failed to poll journalctl -f: {e}"),
        }
        child.kill().ok();
        child.wait().ok();
    }
}
