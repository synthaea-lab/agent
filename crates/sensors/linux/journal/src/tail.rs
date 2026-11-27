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
    JournalError, JournalEvent, JournalRecord,
    bounded_lines::{BoundedLines, Line, MAX_LINE_BYTES},
    classify,
    pam_filter::PamFailureFilter,
    parse_record,
};

/// Whether the `count`th dropped oversize line is logged: the first, then every
/// [`OVERSIZE_LOG_EVERY`]th, so a flood leaves a trace without becoming a flood of logs.
fn should_report_oversize(count: u64) -> bool {
    count == 1 || count.is_multiple_of(OVERSIZE_LOG_EVERY)
}

/// Spacing of the oversize-line warnings after the first one.
const OVERSIZE_LOG_EVERY: u64 = 1000;

/// Reads classified events out of any line-oriented `journalctl -o json` source.
/// Generic over [`BufRead`] so tests feed canned journal captures without a real
/// journald, and [`process::spawn_follow`]'s child process stdout feeds the same
/// type on Linux.
///
/// Only allowlisted records come out — see [`crate::classify`]. A record that fails
/// to parse in the "expected, recoverable" way (see `record.rs`'s module doc) is
/// skipped rather than ending the stream; a hard I/O error on the underlying reader
/// does end it. Between classification and the caller sits the
/// [`PamFailureFilter`], which holds back a `pam_sss` failure for one more record
/// and drops a failure that a second stacked PAM module logged for the same attempt.
pub struct ClassifiedJournal<R> {
    lines: BoundedLines<R>,
    /// Lines over [`crate::bounded_lines::MAX_LINE_BYTES`], read to their end and dropped.
    oversize_lines: u64,
    on_line: Option<Box<dyn FnMut() + Send>>,
    pam_filter: PamFailureFilter,
    /// What the filter released but the caller has not taken yet: one record can release
    /// two (a held failure and the record that followed it).
    ready: VecDeque<(JournalRecord, JournalEvent)>,
}

impl<R: BufRead> ClassifiedJournal<R> {
    /// Wraps `reader`, one `journalctl -o json` record per line. Lines over the length cap are
    /// dropped and counted rather than ending the stream.
    pub fn new(reader: R) -> Self {
        Self::from_lines(BoundedLines::new(reader))
    }

    fn from_lines(lines: BoundedLines<R>) -> Self {
        Self {
            lines,
            oversize_lines: 0,
            on_line: None,
            pam_filter: PamFailureFilter::default(),
            ready: VecDeque::new(),
        }
    }

    /// How many lines were over the length cap, read to their end and dropped. A host where this
    /// grows has a writer that floods the journal stream; the dropped lines are the
    /// only records the tail lost for this reason.
    #[must_use]
    pub fn oversize_lines_dropped(&self) -> u64 {
        self.oversize_lines
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

    /// The next parsed record, read from the underlying lines, skipping blanks and the
    /// "expected, recoverable" unparseable lines.
    fn read_record(&mut self) -> Option<Result<JournalRecord, JournalError>> {
        loop {
            let line = match self.lines.next()? {
                Ok(Line::Text(line)) => line,
                // Dropped unparsed, but it still proves `journalctl` is delivering.
                Ok(Line::Oversize) => {
                    self.oversize_lines += 1;
                    if should_report_oversize(self.oversize_lines) {
                        tracing::warn!(
                            dropped = self.oversize_lines,
                            max_bytes = MAX_LINE_BYTES,
                            "journal tail: line over the size cap dropped"
                        );
                    }
                    if let Some(hook) = self.on_line.as_mut() {
                        hook();
                    }
                    continue;
                }
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
}

impl<R: BufRead> Iterator for ClassifiedJournal<R> {
    type Item = Result<(JournalRecord, JournalEvent), JournalError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(item) = self.ready.pop_front() {
                return Some(Ok(item));
            }
            match self.read_record() {
                Some(Ok(record)) => {
                    let event = classify(&record);
                    self.ready.extend(self.pam_filter.push(record, event));
                }
                Some(Err(e)) => return Some(Err(e)),
                // End of stream: a failure still held was never refuted.
                None => {
                    self.ready.extend(self.pam_filter.finish());
                    if self.ready.is_empty() {
                        return None;
                    }
                }
            }
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
            r#"{"__CURSOR":"c3","__REALTIME_TIMESTAMP":"3","_PID":"1","JOB_TYPE":"start","JOB_RESULT":"done","UNIT":"cron.service","MESSAGE":"Started cron.service."}"#,
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
            r#"{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"2","_PID":"1","JOB_TYPE":"stop","JOB_RESULT":"done","UNIT":"x.service","MESSAGE":"Stopped x.service."}"#,
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

    // --- line length cap (#189) ------------------------------------------------

    const CAPPED_AT: usize = 256;

    fn oversize_record() -> String {
        format!(
            r#"{{"__CURSOR":"big","__REALTIME_TIMESTAMP":"1","MESSAGE":"{}"}}"#,
            "x".repeat(2 * CAPPED_AT)
        )
    }

    fn capped_journal(input: String) -> ClassifiedJournal<Cursor<String>> {
        ClassifiedJournal::from_lines(BoundedLines::with_cap(Cursor::new(input), CAPPED_AT))
    }

    /// Collects what `tracing` writes, so a test can read the warnings back.
    #[derive(Clone, Default)]
    struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn the_first_oversize_line_logs_a_warning_without_its_content() {
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_ansi(false)
            .finish();
        let secret = "SECRETPAYLOAD";
        let input = format!(
            r#"{{"__CURSOR":"big","MESSAGE":"{secret}{}"}}"#,
            "x".repeat(CAPPED_AT)
        );

        tracing::subscriber::with_default(subscriber, || {
            let mut it = capped_journal(input);
            assert!(it.next().is_none());
        });

        let out = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert!(out.contains("line over the size cap dropped"), "{out}");
        assert!(out.contains("dropped=1"), "{out}");
        assert!(
            !out.contains(secret),
            "the payload must not be logged: {out}"
        );
    }

    #[test]
    fn oversize_warnings_are_rate_limited() {
        assert!(should_report_oversize(1));
        assert!(!should_report_oversize(2));
        assert!(!should_report_oversize(999));
        assert!(should_report_oversize(1000));
        assert!(!should_report_oversize(1001));
        assert!(should_report_oversize(2000));
    }

    #[test]
    fn an_oversize_line_is_dropped_and_counted_and_the_next_record_is_still_read() {
        let input = [
            oversize_record(),
            r#"{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"2","_PID":"1","JOB_TYPE":"stop","JOB_RESULT":"done","UNIT":"x.service","MESSAGE":"Stopped x.service."}"#.to_owned(),
        ]
        .join("\n");

        let mut it = capped_journal(input);
        let (record, event) = it.next().unwrap().unwrap();
        assert_eq!(record.cursor, "c2");
        assert!(matches!(event, JournalEvent::UnitStopped { .. }));
        assert!(it.next().is_none());
        assert_eq!(it.oversize_lines_dropped(), 1);
    }

    #[test]
    fn an_oversize_line_still_fires_the_line_hook() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        let seen = Arc::new(AtomicUsize::new(0));
        let hook_seen = seen.clone();
        let mut it = capped_journal(oversize_record()).with_line_hook(move || {
            hook_seen.fetch_add(1, Ordering::SeqCst);
        });

        assert!(it.next().is_none());
        assert_eq!(
            seen.load(Ordering::SeqCst),
            1,
            "delivery proof, not a record"
        );
    }

    #[test]
    fn a_stream_with_no_oversize_line_counts_none() {
        let mut it = ClassifiedJournal::new(Cursor::new(
            r#"{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1","SYSLOG_IDENTIFIER":"kernel","MESSAGE":"eth0 up"}"#,
        ));
        assert!(it.next().is_none());
        assert_eq!(it.oversize_lines_dropped(), 0);
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

    #[test]
    fn a_held_pam_sss_failure_comes_out_before_the_unrelated_record_that_follows_it() {
        let input = [
            r#"{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1","SYSLOG_IDENTIFIER":"sudo","_PID":"100","MESSAGE":"pam_sss(sudo:auth): authentication failure; logname=omss uid=1000 euid=0 tty=/dev/pts/2 ruser=omss rhost=  user=omss"}"#,
            r#"{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"2","_PID":"1","JOB_TYPE":"stop","JOB_RESULT":"done","UNIT":"x.service","MESSAGE":"Stopped x.service."}"#,
        ]
        .join("\n");

        let mut it = ClassifiedJournal::new(Cursor::new(input));
        let (first, first_event) = it.next().unwrap().unwrap();
        assert_eq!(first.cursor, "c1");
        assert!(matches!(first_event, JournalEvent::PamAuthFailure { .. }));
        let (second, second_event) = it.next().unwrap().unwrap();
        assert_eq!(second.cursor, "c2");
        assert!(matches!(second_event, JournalEvent::UnitStopped { .. }));
        assert!(it.next().is_none());
    }

    #[test]
    fn two_pam_sss_failures_in_a_row_both_stand_and_keep_their_order() {
        let input = [
            r#"{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1","SYSLOG_IDENTIFIER":"sudo","_PID":"100","MESSAGE":"pam_sss(sudo:auth): authentication failure; logname=omss uid=1000 euid=0 tty=/dev/pts/2 ruser=omss rhost=  user=omss"}"#,
            r#"{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"9000000","SYSLOG_IDENTIFIER":"sudo","_PID":"101","MESSAGE":"pam_sss(sudo:auth): authentication failure; logname=lab uid=1001 euid=0 tty=/dev/pts/3 ruser=lab rhost=  user=lab"}"#,
        ]
        .join("\n");

        let mut it = ClassifiedJournal::new(Cursor::new(input));
        let cursors: Vec<_> = it.by_ref().map(|item| item.unwrap().0.cursor).collect();
        assert_eq!(cursors, ["c1", "c2"]);
    }

    #[test]
    fn a_pam_sss_failure_still_pending_at_the_end_is_deduplicated_like_any_other() {
        let input = [
            r#"{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1000000","SYSLOG_IDENTIFIER":"sudo","_PID":"100","MESSAGE":"pam_unix(sudo:auth): authentication failure; logname=omss uid=1000 euid=0 tty=/dev/pts/2 ruser=omss rhost=  user=omss"}"#,
            r#"{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"1500000","SYSLOG_IDENTIFIER":"sudo","_PID":"100","MESSAGE":"pam_sss(sudo:auth): authentication failure; logname=omss uid=1000 euid=0 tty=/dev/pts/2 ruser=omss rhost=  user=omss"}"#,
        ]
        .join("\n");

        let mut it = ClassifiedJournal::new(Cursor::new(input));
        let cursors: Vec<_> = it.by_ref().map(|item| item.unwrap().0.cursor).collect();
        assert_eq!(
            cursors,
            ["c1"],
            "the held pam_sss line is the double-log of c1, flushed at the end of the stream"
        );
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
