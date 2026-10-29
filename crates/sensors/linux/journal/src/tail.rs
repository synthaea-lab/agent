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

use std::{collections::VecDeque, io::BufRead};

use crate::{
    JournalError, JournalEvent, JournalRecord, classify, classify::pam_sss_reports_user_unknown,
    parse_record,
};

/// Distinct `(pid, module, realtime_us)` entries remembered for
/// [`is_duplicate_pam_failure`]. Small on purpose: only recent, nearby-in-time
/// entries are ever looked up, so nothing is lost by evicting the oldest once a
/// host has enough concurrent `sudo`/`su` invocations in flight to fill this.
const RECENT_PAM_FAILURES_CAP: usize = 64;
/// How close two `PamAuthFailure`s from the same pid but **different** PAM
/// modules have to be to treat the second as the first double-logged by a
/// second stacked module, not a second real attempt (#881 review,
/// `SherlockOmss` 2026-10-22: `pam_unix` and `pam_sss` both authenticating one
/// account would otherwise double-count one wrong password toward `sudo.rs`'s
/// T1548.003 threshold). Module, not just pid, is the signal that matters here:
/// `sudo`'s own password retries reuse the *same* pid and the *same* module for
/// each real attempt (see `agent`'s `sudo_join_tests::five_failed_sudo_passwords_then_a_success_alert_once`,
/// which spaces five genuine same-module failures exactly one second apart on
/// one pid) — pid alone would have wrongly folded those into one. Two PAM
/// modules stacked for the one account instead both log their own failure line
/// from within the *same* libpam stack evaluation, microseconds apart; one
/// second is a reasoned guess at a safe upper bound on that gap, not a
/// measurement from a real stacked host — nothing here has verified it against
/// a real sssd-stacked `sudo`.
const DOUBLE_LOG_DEDUP_WINDOW_US: u64 = 1_000_000;

/// Which PAM module logged a `PamAuthFailure` line — the signal
/// [`ClassifiedJournal::is_duplicate_pam_failure`] keys on, since only a
/// *different* module for the same pid in the same instant indicates one
/// attempt double-logged by two stacked authenticators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PamModule {
    Unix,
    Sss,
}

/// The PAM module that logged `message`, if any — `None` for a record this
/// crate doesn't otherwise treat as PAM-sourced.
fn pam_module(message: &str) -> Option<PamModule> {
    if message.starts_with("pam_unix(") {
        Some(PamModule::Unix)
    } else if message.starts_with("pam_sss(") {
        Some(PamModule::Sss)
    } else {
        None
    }
}

/// Reads classified events out of any line-oriented `journalctl -o json` source.
/// Generic over [`BufRead`] so tests feed canned journal captures without a real
/// journald, and [`process::spawn_follow`]'s child process stdout feeds the same
/// type on Linux.
///
/// Only allowlisted records come out — see [`crate::classify`]. A record that fails
/// to parse in the "expected, recoverable" way (see `record.rs`'s module doc) is
/// skipped rather than ending the stream; a hard I/O error on the underlying reader
/// does end it. A `pam_sss` `PamAuthFailure` is held for one more line before it
/// comes out, in case it turns out to be [`pam_sss_reports_user_unknown`] rather
/// than a real failure (#881); a `PamAuthFailure` that immediately follows another
/// one from the same pid is dropped as the same attempt double-logged by a second
/// stacked PAM module (see [`DOUBLE_LOG_DEDUP_WINDOW_US`]). A held failure still
/// pending when the underlying stream ends is flushed rather than lost — the
/// journal stopping right after it is not a refutation.
pub struct ClassifiedJournal<R> {
    lines: std::io::Lines<R>,
    on_line: Option<Box<dyn FnMut() + Send>>,
    /// A record already read and parsed (while resolving `pending_sss_failure`)
    /// but not yet classified — consumed before reading a fresh line.
    held_record: Option<JournalRecord>,
    /// A `pam_sss` `PamAuthFailure` classified but not yet yielded, waiting to see
    /// whether the next record is its own "received for user ...: 10 (...)" line.
    /// Carries the normalized service (`"sudo"`/`"su"`) the failure matched, to
    /// compare against [`pam_sss_reports_user_unknown`].
    pending_sss_failure: Option<(JournalRecord, JournalEvent, String)>,
    /// `(pid, module, realtime_us)` of recently yielded `PamAuthFailure`s,
    /// oldest first — see [`is_duplicate_pam_failure`].
    recent_pam_failures: VecDeque<(u32, PamModule, u64)>,
}

impl<R: BufRead> ClassifiedJournal<R> {
    pub fn new(reader: R) -> Self {
        Self {
            lines: reader.lines(),
            on_line: None,
            held_record: None,
            pending_sss_failure: None,
            recent_pam_failures: VecDeque::new(),
        }
    }

    /// Calls `hook` once for every non-blank line read from the source, **before**
    /// the line is parsed or classified, so it also fires for the lines the
    /// allowlist drops and for the ones that fail to parse. Those are the vast
    /// majority of a journal and the only proof an idle host gives that
    /// `journalctl` is still delivering; the iterator itself yields allowlisted
    /// records only. The agent hangs its sensor-silence heartbeat here (#71, #83).
    #[must_use]
    pub fn with_line_hook(mut self, hook: impl FnMut() + Send + 'static) -> Self {
        self.on_line = Some(Box::new(hook));
        self
    }

    /// The next parsed record, from `held_record` if one is waiting, otherwise
    /// read fresh from the underlying lines — skipping blanks and the
    /// "expected, recoverable" unparseable lines exactly as plain iteration did
    /// before this struct needed to look one record ahead.
    fn read_record(&mut self) -> Option<Result<JournalRecord, JournalError>> {
        if let Some(record) = self.held_record.take() {
            return Some(Ok(record));
        }
        loop {
            let line = match self.lines.next()? {
                Ok(line) => line,
                Err(e) => return Some(Err(JournalError::Io(e))),
            };
            if line.trim().is_empty() {
                continue;
            }
            if let Some(hook) = self.on_line.as_mut() {
                hook();
            }
            match parse_record(&line) {
                Ok(record) => return Some(Ok(record)),
                // Missing/binary-shaped field on one line — skip it, don't end the
                // stream over it (see record.rs's module doc).
                Err(JournalError::MissingField(_)) => continue,
                Err(e) => return Some(Err(e)),
            }
        }
    }

    /// True when `record` shares a pid with an already-yielded `PamAuthFailure`
    /// from a **different** PAM module, close enough in time to be the same
    /// attempt double-logged by a second stacked module rather than a second
    /// real one — and, if not, remembers this one for the next call. Two
    /// failures from the same pid and the *same* module (e.g. `sudo`'s own
    /// password retries, all `pam_unix`) are never treated as duplicates
    /// regardless of spacing: pid alone doesn't distinguish a double-log from a
    /// second real attempt, only the module does. A record with no parseable
    /// `_PID`, or no recognized PAM module prefix, is never treated as a
    /// duplicate: there is nothing to correlate it against, and silently
    /// dropping an event over a missing optional field is worse than
    /// double-counting it.
    fn is_duplicate_pam_failure(&mut self, record: &JournalRecord) -> bool {
        let Some(pid) = record.pid.as_deref().and_then(|p| p.parse::<u32>().ok()) else {
            return false;
        };
        let Some(module) = pam_module(&record.message) else {
            return false;
        };
        let is_duplicate =
            self.recent_pam_failures
                .iter()
                .any(|&(seen_pid, seen_module, seen_us)| {
                    seen_pid == pid
                        && seen_module != module
                        && record.realtime_us.saturating_sub(seen_us) <= DOUBLE_LOG_DEDUP_WINDOW_US
                });
        if !is_duplicate {
            self.recent_pam_failures
                .push_back((pid, module, record.realtime_us));
            if self.recent_pam_failures.len() > RECENT_PAM_FAILURES_CAP {
                self.recent_pam_failures.pop_front();
            }
        }
        is_duplicate
    }
}

impl<R: BufRead> Iterator for ClassifiedJournal<R> {
    type Item = Result<(JournalRecord, JournalEvent), JournalError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let record = match self.read_record() {
                Some(Ok(record)) => record,
                Some(Err(e)) => return Some(Err(e)),
                // End of stream. A pending pam_sss failure that never got its
                // following line (the stream ended right after it) was never
                // refuted — flush it rather than silently dropping a real
                // failure because the journal happened to stop there.
                None => {
                    let (pend_record, pend_event, _) = self.pending_sss_failure.take()?;
                    if self.is_duplicate_pam_failure(&pend_record) {
                        return None;
                    }
                    return Some(Ok((pend_record, pend_event)));
                }
            };

            if let Some((pend_record, pend_event, pend_service)) = self.pending_sss_failure.take() {
                if pam_sss_reports_user_unknown(&record.message, &pend_service) {
                    // Confirmed PAM_USER_UNKNOWN: the pending failure was never a
                    // real one, and this "received for user" line is not an event
                    // of its own — drop both, keep scanning from a fresh line.
                    continue;
                }
                // Not a confirmation: the pending failure stands. `record` has
                // already been read past it, so hold it for this same call to
                // process right after, instead of re-reading a line.
                self.held_record = Some(record);
                if self.is_duplicate_pam_failure(&pend_record) {
                    continue;
                }
                return Some(Ok((pend_record, pend_event)));
            }

            let Some(event) = classify(&record) else {
                // Allowlist miss — this iterator only ever yields matches, so keep
                // scanning instead of returning `None` (which would end iteration).
                continue;
            };

            if record.message.starts_with("pam_sss(")
                && let JournalEvent::PamAuthFailure { service, .. } = &event
            {
                // Held for one more line — see the struct doc and
                // `pam_sss_reports_user_unknown`.
                let service = service.clone();
                self.pending_sss_failure = Some((record, event, service));
                continue;
            }

            if matches!(event, JournalEvent::PamAuthFailure { .. })
                && self.is_duplicate_pam_failure(&record)
            {
                continue;
            }

            return Some(Ok((record, event)));
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
    /// without reading any history. Call once at startup — as the fallback when no
    /// prior cursor was persisted (fresh install, or `agent::journal_cursor` found
    /// nothing to read, issue #321). When one was persisted, use it instead so a
    /// restart resumes with [`spawn_follow`] rather than either replaying the whole
    /// journal or silently missing what was written while the sensor was down.
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

    #[test]
    fn the_line_hook_fires_for_every_non_blank_line_not_only_allowlisted_ones() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        let input = [
            // allowlist miss
            r#"{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1","SYSLOG_IDENTIFIER":"kernel","MESSAGE":"eth0 up"}"#,
            "",
            // unparseable in the recoverable way (binary MESSAGE)
            r#"{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"2","MESSAGE":[1,2,3]}"#,
            // allowlisted
            r#"{"__CURSOR":"c3","__REALTIME_TIMESTAMP":"3","SYSLOG_IDENTIFIER":"sudo","MESSAGE":"     lab : TTY=pts/0 ; USER=root ; COMMAND=/bin/true"}"#,
            "   ",
            // the agent's own liveness canary
            r#"{"__CURSOR":"c4","__REALTIME_TIMESTAMP":"4","SYSLOG_IDENTIFIER":"synthaea-agent-canary","MESSAGE":"sensor liveness canary"}"#,
        ]
        .join("\n");

        let seen = Arc::new(AtomicUsize::new(0));
        let hook_seen = seen.clone();
        let mut it = ClassifiedJournal::new(Cursor::new(input)).with_line_hook(move || {
            hook_seen.fetch_add(1, Ordering::SeqCst);
        });

        let (record, _) = it.next().unwrap().unwrap();
        assert_eq!(record.cursor, "c3", "only the allowlisted line is yielded");
        assert!(it.next().is_none(), "the canary is not an event");
        assert_eq!(
            seen.load(Ordering::SeqCst),
            4,
            "four non-blank lines, whether classified, skipped or unparseable"
        );
    }

    #[test]
    fn without_a_hook_nothing_changes() {
        let input = r#"{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1","SYSLOG_IDENTIFIER":"kernel","MESSAGE":"eth0 up"}"#;
        let mut it = ClassifiedJournal::new(Cursor::new(input));
        assert!(it.next().is_none());
    }

    // --- pam_sss PAM_USER_UNKNOWN lookahead suppression (#881 review) ----------

    #[test]
    fn pam_sss_auth_failure_is_suppressed_when_confirmed_as_user_unknown() {
        let input = [
            r#"{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1","SYSLOG_IDENTIFIER":"sudo","_PID":"100","MESSAGE":"pam_sss(sudo:auth): authentication failure; logname=omss uid=1000 euid=0 tty=/dev/pts/2 ruser=omss rhost=  user=baduser"}"#,
            r#"{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"2","SYSLOG_IDENTIFIER":"sudo","_PID":"100","MESSAGE":"pam_sss(sudo:auth): received for user baduser: 10 (User not known to the underlying authentication module)"}"#,
        ]
        .join("\n");

        let mut it = ClassifiedJournal::new(Cursor::new(input));
        assert!(
            it.next().is_none(),
            "a failure confirmed as PAM_USER_UNKNOWN by the next line is not a real auth failure"
        );
    }

    #[test]
    fn pam_sss_auth_failure_stands_when_not_confirmed_as_user_unknown() {
        let input = [
            r#"{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1","SYSLOG_IDENTIFIER":"sudo","_PID":"100","MESSAGE":"pam_sss(sudo:auth): authentication failure; logname=omss uid=1000 euid=0 tty=/dev/pts/2 ruser=omss rhost=  user=omss"}"#,
            r#"{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"2","SYSLOG_IDENTIFIER":"sudo","_PID":"100","MESSAGE":"pam_sss(sudo:auth): received for user omss: 7 (Authentication failure)"}"#,
        ]
        .join("\n");

        let mut it = ClassifiedJournal::new(Cursor::new(input));
        let (record, event) = it.next().unwrap().unwrap();
        assert_eq!(record.cursor, "c1");
        assert!(matches!(event, JournalEvent::PamAuthFailure { .. }));
        assert!(
            it.next().is_none(),
            "the status-7 confirmation line is not an event of its own"
        );
    }

    #[test]
    fn pam_sss_auth_failure_stands_when_it_is_the_last_line() {
        let input = r#"{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1","SYSLOG_IDENTIFIER":"sudo","_PID":"100","MESSAGE":"pam_sss(sudo:auth): authentication failure; logname=omss uid=1000 euid=0 tty=/dev/pts/2 ruser=omss rhost=  user=omss"}"#;

        let mut it = ClassifiedJournal::new(Cursor::new(input));
        let (record, event) = it.next().unwrap().unwrap();
        assert_eq!(record.cursor, "c1");
        assert!(matches!(event, JournalEvent::PamAuthFailure { .. }));
        assert!(it.next().is_none());
    }

    // --- double-logged PamAuthFailure dedup (#881 review) -----------------------

    #[test]
    fn a_second_pam_auth_failure_from_the_same_pid_within_the_window_is_dropped() {
        let input = [
            r#"{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1000000","SYSLOG_IDENTIFIER":"sudo","_PID":"100","MESSAGE":"pam_unix(sudo:auth): authentication failure; logname=omss uid=1000 euid=0 tty=/dev/pts/2 ruser=omss rhost=  user=omss"}"#,
            r#"{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"1500000","SYSLOG_IDENTIFIER":"sudo","_PID":"100","MESSAGE":"pam_sss(sudo:auth): authentication failure; logname=omss uid=1000 euid=0 tty=/dev/pts/2 ruser=omss rhost=  user=omss"}"#,
        ]
        .join("\n");

        let mut it = ClassifiedJournal::new(Cursor::new(input));
        let (record, event) = it.next().unwrap().unwrap();
        assert_eq!(record.cursor, "c1");
        assert!(matches!(event, JournalEvent::PamAuthFailure { .. }));
        assert!(
            it.next().is_none(),
            "same pid, 0.5s apart: pam_unix and pam_sss double-logging one attempt"
        );
    }

    #[test]
    fn repeated_same_module_failures_from_the_same_pid_are_never_deduped() {
        // Regression pin (caught by agent's own
        // sudo_join_tests::five_failed_sudo_passwords_then_a_success_alert_once):
        // `sudo` retrying a wrong password reuses the same pid and the same PAM
        // module for every real attempt — pid alone, without the module check,
        // wrongly folded these five distinct failures down to one.
        let input = (1..=5)
            .map(|second| {
                format!(
                    r#"{{"__CURSOR":"c{second}","__REALTIME_TIMESTAMP":"{}","SYSLOG_IDENTIFIER":"sudo","_PID":"100","MESSAGE":"pam_unix(sudo:auth): authentication failure; logname=omss uid=1000 euid=0 tty=/dev/pts/2 ruser=omss rhost=  user=omss"}}"#,
                    second * 1_000_000
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        let mut it = ClassifiedJournal::new(Cursor::new(input));
        for expected_cursor in ["c1", "c2", "c3", "c4", "c5"] {
            let (record, event) = it.next().unwrap().unwrap();
            assert_eq!(record.cursor, expected_cursor);
            assert!(matches!(event, JournalEvent::PamAuthFailure { .. }));
        }
        assert!(it.next().is_none());
    }

    #[test]
    fn a_second_pam_auth_failure_from_the_same_pid_outside_the_window_is_kept() {
        let input = [
            r#"{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1000000","SYSLOG_IDENTIFIER":"sudo","_PID":"100","MESSAGE":"pam_unix(sudo:auth): authentication failure; logname=omss uid=1000 euid=0 tty=/dev/pts/2 ruser=omss rhost=  user=omss"}"#,
            r#"{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"5000001","SYSLOG_IDENTIFIER":"sudo","_PID":"100","MESSAGE":"pam_unix(sudo:auth): authentication failure; logname=omss uid=1000 euid=0 tty=/dev/pts/2 ruser=omss rhost=  user=omss"}"#,
        ]
        .join("\n");

        let mut it = ClassifiedJournal::new(Cursor::new(input));
        let (record1, _) = it.next().unwrap().unwrap();
        assert_eq!(record1.cursor, "c1");
        let (record2, _) = it.next().unwrap().unwrap();
        assert_eq!(
            record2.cursor, "c2",
            "4s apart is a second real attempt, not a double-log"
        );
        assert!(it.next().is_none());
    }

    #[test]
    fn a_second_pam_auth_failure_from_a_different_pid_is_kept() {
        let input = [
            r#"{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1000000","SYSLOG_IDENTIFIER":"sudo","_PID":"100","MESSAGE":"pam_unix(sudo:auth): authentication failure; logname=omss uid=1000 euid=0 tty=/dev/pts/2 ruser=omss rhost=  user=omss"}"#,
            r#"{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"1500000","SYSLOG_IDENTIFIER":"sudo","_PID":"101","MESSAGE":"pam_unix(sudo:auth): authentication failure; logname=lab uid=1001 euid=0 tty=/dev/pts/3 ruser=lab rhost=  user=lab"}"#,
        ]
        .join("\n");

        let mut it = ClassifiedJournal::new(Cursor::new(input));
        let (record1, _) = it.next().unwrap().unwrap();
        assert_eq!(record1.cursor, "c1");
        let (record2, _) = it.next().unwrap().unwrap();
        assert_eq!(
            record2.cursor, "c2",
            "different pid: two different sudo invocations, not a double-log"
        );
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
