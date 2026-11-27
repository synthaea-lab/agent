//! Turns `log stream --style ndjson` lines into schema events and, on macOS,
//! runs `/usr/bin/log` to produce them.
//!
//! A subprocess rather than `OSLogStore`: the public API only reads
//! positioned snapshots, live streaming is private framework territory.
//! Three gates bound the volume, in order: the daemon-side [`PREDICATE`],
//! the exact-shape [`crate::classify`], and a counted sliding-window shed
//! ([`MAX_EVENTS_PER_WINDOW`]).

use std::{
    collections::VecDeque,
    io::BufRead,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use crate::{
    UnifiedLogError,
    bounded_lines::{BoundedLines, Line, MAX_LINE_BYTES},
    classify, normalize, parse_record,
    record::LogRecord,
    tcc::TccJoiner,
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

/// Cumulative loss counters, shared with whoever reports them: the stream moves into its reader
/// thread, so the agent creates the counters, keeps a handle and injects it with
/// [`NormalizedLogStream::with_counters`] (#178). One set belongs to one stream at a time: each
/// stream adds its own losses, so a restarted stream may reuse the handle and the totals go on
/// from where they were.
#[derive(Debug, Default)]
pub struct StreamCounters {
    shed_events: AtomicU64,
    tcc_shed_contexts: AtomicU64,
    tcc_unmatched_results: AtomicU64,
    oversize_lines: AtomicU64,
}

/// A reading of [`StreamCounters`] at one instant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamTotals {
    /// Events shed by the rate bound.
    pub shed_events: u64,
    /// TCC contexts shed by the pending-context cap before their result arrived.
    pub tcc_shed_contexts: u64,
    /// TCC results with no pending context.
    pub tcc_unmatched_results: u64,
    /// Lines over the length cap, read to their end and dropped unparsed.
    pub oversize_lines: u64,
}

impl StreamTotals {
    /// True when nothing was lost.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        *self == Self::default()
    }
}

impl StreamCounters {
    /// The totals now.
    #[must_use]
    pub fn totals(&self) -> StreamTotals {
        StreamTotals {
            shed_events: self.shed_events.load(Ordering::Relaxed),
            tcc_shed_contexts: self.tcc_shed_contexts.load(Ordering::Relaxed),
            tcc_unmatched_results: self.tcc_unmatched_results.load(Ordering::Relaxed),
            oversize_lines: self.oversize_lines.load(Ordering::Relaxed),
        }
    }
}

/// Adds the part of `count` not yet in `total` (`published` is what was already added, and is
/// brought up to `count`). Returns the new total when it reaches a power of two, the moment to
/// warn.
fn add_new_losses(total: &AtomicU64, count: u64, published: &mut u64) -> Option<u64> {
    let new = count.saturating_sub(*published);
    if new == 0 {
        return None;
    }
    *published = count;
    let total = total.fetch_add(new, Ordering::Relaxed) + new;
    total.is_power_of_two().then_some(total)
}

/// Reads normalized schema events out of any line-oriented
/// `log stream --style ndjson` source. Generic over [`BufRead`] so tests feed
/// canned captures; `process::spawn_stream`'s child stdout (macOS) feeds the
/// same
/// type on macOS.
pub struct NormalizedLogStream<R> {
    lines: BoundedLines<R>,
    joiner: TccJoiner,
    /// What of the joiner's `shed_contexts` was already added to `counters`.
    published_shed_contexts: u64,
    /// What of the joiner's `unmatched_results` was already added to `counters`.
    published_unmatched_results: u64,
    window: VecDeque<u64>,
    counters: Arc<StreamCounters>,
}

impl<R: BufRead> NormalizedLogStream<R> {
    /// A stream with counters of its own, for tests: a caller outside them has no way to read the
    /// counters, so it injects a handle with [`Self::with_counters`].
    #[cfg(test)]
    fn new(reader: R) -> Self {
        Self::with_counters(reader, Arc::new(StreamCounters::default()))
    }

    /// A stream that adds to `counters`, which the caller keeps to read the totals.
    pub fn with_counters(reader: R, counters: Arc<StreamCounters>) -> Self {
        Self {
            lines: BoundedLines::new(reader),
            joiner: TccJoiner::new(),
            published_shed_contexts: 0,
            published_unmatched_results: 0,
            window: VecDeque::new(),
            counters,
        }
    }

    /// A handle on the stream's own counters, for tests that built it with [`Self::new`].
    #[cfg(test)]
    #[must_use]
    pub fn counters(&self) -> Arc<StreamCounters> {
        Arc::clone(&self.counters)
    }

    /// Adds what the TCC joiner lost since the last call to the shared counters, warning when a
    /// total reaches a power of two (no health beacon on macOS yet, #34: this is how a loss shows
    /// while running). Adding the difference, not copying the count, keeps the totals whole when
    /// a later stream shares the handle.
    fn publish_tcc(&mut self) {
        if let Some(total) = add_new_losses(
            &self.counters.tcc_shed_contexts,
            self.joiner.shed_contexts,
            &mut self.published_shed_contexts,
        ) {
            tracing::warn!(
                tcc_shed_contexts = total,
                "unified-log tail: TCC context shed before its result arrived"
            );
        }
        if let Some(total) = add_new_losses(
            &self.counters.tcc_unmatched_results,
            self.joiner.unmatched_results,
            &mut self.published_unmatched_results,
        ) {
            tracing::warn!(
                tcc_unmatched_results = total,
                "unified-log tail: TCC result with no pending context"
            );
        }
    }

    /// Counts a line dropped for its length, warning when the total reaches a power of two. The
    /// warning carries the count and the cap, never the line.
    fn count_oversize(&self) {
        let total = self.counters.oversize_lines.fetch_add(1, Ordering::Relaxed) + 1;
        if total.is_power_of_two() {
            tracing::warn!(
                dropped = total,
                max_bytes = MAX_LINE_BYTES,
                "unified-log tail: line over the size cap dropped"
            );
        }
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
            let shed = self.counters.shed_events.fetch_add(1, Ordering::Relaxed) + 1;
            // Powers of two only: a log storm must not flood the log.
            if shed.is_power_of_two() {
                tracing::warn!(
                    shed_total = shed,
                    "unified-log tail: event shed by the rate bound"
                );
            }
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
                Ok(Line::Text(line)) => line,
                Ok(Line::Oversize) => {
                    self.count_oversize();
                    continue;
                }
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
            let normalized = normalize(&record, &classified, &mut self.joiner);
            self.publish_tcc();
            let Some(event) = normalized else {
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
    /// piped — feed it to [`super::NormalizedLogStream::with_counters`] via
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
        assert_eq!(stream.counters().totals().shed_events, 88);
    }

    #[test]
    fn tcc_results_without_a_context_reach_the_shared_counters() {
        let result = r#"{"eventType":"logEvent","subsystem":"com.apple.TCC","processID":427,"userID":0,"processImagePath":"/System/Library/PrivateFrameworks/TCC.framework/Support/tccd","timestamp":"2026-09-22 11:12:28.000000+0200","eventMessage":"AUTHREQ_RESULT: msgID=427.9, authValue=2, authReason=11, authVersion=1,"}"#;
        let mut stream = NormalizedLogStream::new(Cursor::new(result.to_string()));
        let counters = stream.counters();
        assert_eq!(stream.by_ref().count(), 0);
        let totals = counters.totals();
        assert_eq!(totals.tcc_unmatched_results, 1);
        assert_eq!(totals.tcc_shed_contexts, 0);
        assert!(!totals.is_clean());
    }

    #[test]
    fn two_streams_sharing_a_handle_add_their_tcc_losses() {
        let result = |id: u32| {
            format!(
                r#"{{"eventType":"logEvent","subsystem":"com.apple.TCC","processID":427,"userID":0,"processImagePath":"/System/Library/PrivateFrameworks/TCC.framework/Support/tccd","timestamp":"2026-09-22 11:12:28.000000+0200","eventMessage":"AUTHREQ_RESULT: msgID=427.{id}, authValue=2, authReason=11, authVersion=1,"}}"#
            )
        };
        let counters = Arc::new(StreamCounters::default());
        for id in [1, 2] {
            let mut stream =
                NormalizedLogStream::with_counters(Cursor::new(result(id)), Arc::clone(&counters));
            assert_eq!(stream.by_ref().count(), 0);
        }
        assert_eq!(
            counters.totals().tcc_unmatched_results,
            2,
            "the second stream starts its own joiner at 0 and must not overwrite the first's count"
        );
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
        assert!(stream.counters().totals().is_clean());
    }

    #[test]
    fn empty_input_yields_nothing() {
        assert!(NormalizedLogStream::new(Cursor::new("")).next().is_none());
    }

    #[test]
    fn an_oversize_line_is_dropped_and_counted_and_the_next_record_is_still_read() {
        let input = format!(
            "{}\n{}\n",
            "x".repeat(MAX_LINE_BYTES + 1),
            sudo_line("2026-09-22 11:12:26.000000+0200")
        );
        let mut stream = NormalizedLogStream::new(Cursor::new(input));
        let (_, event) = stream.next().unwrap().unwrap();
        assert!(matches!(event, schema::Event::Auth(_)));
        assert!(stream.next().is_none());
        assert_eq!(stream.counters().totals().oversize_lines, 1);
    }

    #[test]
    fn an_oversize_line_with_no_newline_ends_the_stream_without_growing_memory_past_the_cap() {
        let input = "y".repeat(MAX_LINE_BYTES * 3);
        let mut stream = NormalizedLogStream::new(Cursor::new(input));
        assert!(stream.next().is_none());
        assert_eq!(stream.counters().totals().oversize_lines, 1);
    }
}
