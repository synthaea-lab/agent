//! Turns a stream of `log stream --style ndjson` lines into normalized schema
//! events, and (on macOS) produces that stream by actually running
//! `/usr/bin/log`.
//!
//! **Why a subprocess and not `OSLogStore` FFI:** the public `OSLogStore` API
//! only supports positioned snapshots — live streaming goes through private
//! `LoggingSupport.framework` interfaces that Apple neither documents nor
//! keeps stable. `log stream` is the supported surface for exactly this, its
//! NDJSON is line-oriented JSON we already parse for `record.rs`, and the
//! predicate is enforced by the log daemon itself (records outside it are
//! never even serialized into our pipe). Same trade-off and same shape as
//! `sensor-linux-journal` spawning `journalctl`.
//!
//! **Firehose discipline** (issue #95): three gates, in order —
//! 1. the daemon-side predicate ([`PREDICATE`]) allowlists three narrow
//!    sources (sudo outcomes, tccd request decisions, syspolicyd Gatekeeper
//!    verdicts);
//! 2. [`crate::classify`] matches exact message shapes, dropping the
//!    remainder of what the predicate lets through;
//! 3. a sliding-window rate bound ([`MAX_EVENTS_PER_WINDOW`]) sheds — with a
//!    counter, never silently — if a log storm ever defeats both.

use std::{collections::VecDeque, io::BufRead};

use crate::{
    UnifiedLogError, classify, normalize, parse_record, record::LogRecord, tcc::TccJoiner,
};

/// The `log stream` predicate. One string, OR-joined, kept next to the
/// classifier it feeds: a source added here without a [`crate::classify`] arm
/// is dead volume, an arm without a predicate clause never fires.
pub const PREDICATE: &str = "(process == \"sudo\" AND eventMessage CONTAINS \"COMMAND=\") \
     OR (subsystem == \"com.apple.TCC\" AND (eventMessage BEGINSWITH \"AUTHREQ_CTX\" \
     OR eventMessage BEGINSWITH \"AUTHREQ_RESULT\")) \
     OR (process == \"syspolicyd\" AND eventMessage BEGINSWITH \"GK evaluateScanResult\")";

/// Rate bound: normalized events allowed per sliding [`WINDOW`]. Generous —
/// legitimate traffic on these three sources is a few events per minute; a
/// sustained hundreds-per-second stream means a log storm or an adversarial
/// generator, and shedding (counted) beats unbounded memory in the sink path.
const MAX_EVENTS_PER_WINDOW: usize = 512;
/// Sliding window (timestamp deque per the house rule — never reset buckets).
const WINDOW_NS: u64 = 1_000_000_000;

/// Reads normalized schema events out of any line-oriented
/// `log stream --style ndjson` source. Generic over [`BufRead`] so tests feed
/// canned captures; `process::spawn_stream`'s child stdout (macOS) feeds the
/// same
/// type on macOS.
pub struct NormalizedLogStream<R> {
    lines: std::io::Lines<R>,
    joiner: TccJoiner,
    window: VecDeque<u64>,
    /// Events shed by the rate bound, cumulative.
    pub shed_events: u64,
}

impl<R: BufRead> NormalizedLogStream<R> {
    pub fn new(reader: R) -> Self {
        Self {
            lines: reader.lines(),
            joiner: TccJoiner::new(),
            window: VecDeque::new(),
            shed_events: 0,
        }
    }

    /// TCC join counters (shed contexts / unmatched results), for health
    /// reporting.
    #[must_use]
    pub fn tcc_counters(&self) -> (u64, u64) {
        (self.joiner.shed_contexts, self.joiner.unmatched_results)
    }

    /// Sliding-window admission: true when the event at `now_ns` fits.
    fn admit(&mut self, now_ns: u64) -> bool {
        while let Some(&front) = self.window.front() {
            if now_ns.saturating_sub(front) >= WINDOW_NS {
                self.window.pop_front();
            } else {
                break;
            }
        }
        if self.window.len() >= MAX_EVENTS_PER_WINDOW {
            self.shed_events += 1;
            return false;
        }
        self.window.push_back(now_ns);
        true
    }
}

impl<R: BufRead> Iterator for NormalizedLogStream<R> {
    type Item = Result<(LogRecord, schema::Event), UnifiedLogError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let line = match self.lines.next()? {
                Ok(line) => line,
                Err(e) => return Some(Err(UnifiedLogError::Io(e))),
            };
            if line.trim().is_empty() {
                continue;
            }
            let record = match parse_record(&line) {
                Ok(record) => record,
                // Non-message records (timesync, activity transitions) and
                // `log`'s own banner line ("Filtering the log data using...")
                // are expected — skip, never end the stream over them.
                Err(UnifiedLogError::MissingField(_) | UnifiedLogError::Json(_)) => continue,
                Err(e) => return Some(Err(e)),
            };
            let Some(classified) = classify(&record) else {
                continue;
            };
            let Some(event) = normalize(&record, &classified, &mut self.joiner) else {
                continue;
            };
            if !self.admit(record.timestamp_ns) {
                continue;
            }
            return Some(Ok((record, event)));
        }
    }
}

#[cfg(target_os = "macos")]
pub mod process {
    //! Drives the real `/usr/bin/log` binary. macOS-only: there is nothing to
    //! spawn elsewhere.

    use std::process::{Child, Command, Stdio};

    use crate::UnifiedLogError;

    /// Spawns `log stream --style ndjson --predicate` [`super::PREDICATE`],
    /// tailing from now. Returns the still-running [`Child`] with stdout
    /// piped — feed it to [`super::NormalizedLogStream::new`] via
    /// `BufReader::new(child.stdout.take()...)`. The caller owns the child
    /// and must kill it on shutdown (`agent::commands::macos::cmd_run`).
    ///
    /// Reading other users' / system-scope records requires root or admin —
    /// which the agent already runs as for `EndpointSecurity`; unprivileged,
    /// the stream still starts but only carries the caller's own scope.
    ///
    /// # Errors
    ///
    /// [`UnifiedLogError::Spawn`] if `/usr/bin/log` fails to spawn.
    pub fn spawn_stream() -> Result<Child, UnifiedLogError> {
        let mut cmd = Command::new("/usr/bin/log");
        cmd.args([
            "stream",
            "--style",
            "ndjson",
            "--predicate",
            super::PREDICATE,
        ]);
        cmd.stdout(Stdio::piped()).stderr(Stdio::null());
        cmd.spawn().map_err(UnifiedLogError::Spawn)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn sudo_line(timestamp: &str) -> String {
        format!(
            r#"{{"eventType":"logEvent","subsystem":"","processID":28438,"userID":0,"processImagePath":"/usr/bin/sudo","timestamp":"{timestamp}","eventMessage":"lab : TTY=ttys002 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/whoami"}}"#
        )
    }

    #[test]
    fn yields_only_normalized_events_in_order() {
        let input = [
            // `log`'s own non-JSON banner — must be skipped, not fatal.
            "Filtering the log data using a predicate".to_string(),
            // Unclassified tccd chatter that passed the predicate's subsystem gate.
            r#"{"eventType":"logEvent","subsystem":"com.apple.TCC","processID":427,"userID":0,"processImagePath":"/System/Library/PrivateFrameworks/TCC.framework/Support/tccd","timestamp":"2026-09-22 11:12:25.000000+0200","eventMessage":"send_message_with_reply_sync(): 1 attempts"}"#.to_string(),
            sudo_line("2026-09-22 11:12:26.000000+0200"),
            // TCC pair: context (no event) then result (one joined event).
            r#"{"eventType":"logEvent","subsystem":"com.apple.TCC","processID":427,"userID":0,"processImagePath":"/System/Library/PrivateFrameworks/TCC.framework/Support/tccd","timestamp":"2026-09-22 11:12:27.000000+0200","eventMessage":"AUTHREQ_CTX: msgID=427.1, function=TCCAccessRequest, service=kTCCServiceScreenCapture, preflight=no, query=1,"}"#.to_string(),
            r#"{"eventType":"logEvent","subsystem":"com.apple.TCC","processID":427,"userID":0,"processImagePath":"/System/Library/PrivateFrameworks/TCC.framework/Support/tccd","timestamp":"2026-09-22 11:12:28.000000+0200","eventMessage":"AUTHREQ_RESULT: msgID=427.1, authValue=2, authReason=11, authVersion=1,"}"#.to_string(),
        ]
        .join("\n");

        let mut stream = NormalizedLogStream::new(Cursor::new(input));

        let (_, first) = stream.next().unwrap().unwrap();
        assert!(matches!(first, schema::Event::Auth(_)));
        let (_, second) = stream.next().unwrap().unwrap();
        let schema::Event::TccDecision(tcc) = second else {
            panic!("expected the joined TCC decision");
        };
        assert_eq!(tcc.service, "kTCCServiceScreenCapture");
        assert!(stream.next().is_none());
    }

    #[test]
    fn a_log_storm_is_shed_with_a_counter_not_buffered() {
        // 600 identical sudo events within one second: the window admits 512,
        // sheds the rest, and the counter says exactly how many.
        let input = (0..600)
            .map(|_| sudo_line("2026-09-22 11:12:26.000000+0200"))
            .collect::<Vec<_>>()
            .join("\n");
        let mut stream = NormalizedLogStream::new(Cursor::new(input));
        let yielded = stream.by_ref().filter(Result::is_ok).count();
        assert_eq!(yielded, 512);
        assert_eq!(stream.shed_events, 88);
    }

    #[test]
    fn events_spread_across_windows_are_not_shed() {
        let input = [
            sudo_line("2026-09-22 11:12:26.000000+0200"),
            sudo_line("2026-09-22 11:12:27.500000+0200"),
        ]
        .join("\n");
        let mut stream = NormalizedLogStream::new(Cursor::new(input));
        assert_eq!(stream.by_ref().count(), 2);
        assert_eq!(stream.shed_events, 0);
    }

    #[test]
    fn empty_input_yields_nothing() {
        assert!(NormalizedLogStream::new(Cursor::new("")).next().is_none());
    }
}
