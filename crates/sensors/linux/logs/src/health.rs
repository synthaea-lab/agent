//! Detects a log source that is being read but not understood (ADR-0022 §2).
//!
//! A site with a custom `LogFormat`, or a server version that words a line differently,
//! leaves the sensor blind while it looks healthy: every line fails to parse and nothing
//! alerts. A [`MisparseWatch`] counts, per window, the lines that reached a parser and
//! how many were rejected, and reports the window the failures dominate.
//!
//! Only lines that *claimed* to be of the kind count: an ordinary line a parser ignores
//! on purpose (most of an error log) says nothing about the format, and a line cut at
//! the length cap ([`crate::ParseError::Truncated`]) is the cap's doing, not the
//! source's. The caller records neither.

/// Window over which failures are weighed, in seconds.
pub const WINDOW_SECS: u64 = 60;
/// Fewest lines in a window before a verdict is worth giving: three bad lines out of
/// three is a typo in the log, not a format.
pub const MIN_LINES: u32 = 10;

/// A window in which at least half of the lines that reached a parser were rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Misparse {
    pub parsed: u32,
    pub failed: u32,
}

/// Counts parse outcomes for one source and reports each misparsing *episode* once.
#[derive(Debug, Default)]
pub struct MisparseWatch {
    window_start_ns: Option<u64>,
    parsed: u32,
    failed: u32,
    /// The previous window was misparsing and has already been reported.
    reported: bool,
}

impl MisparseWatch {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one line that reached the parser: `ok` is whether it matched.
    pub fn record(&mut self, ok: bool, now_ns: u64) {
        self.window_start_ns.get_or_insert(now_ns);
        if ok {
            self.parsed = self.parsed.saturating_add(1);
        } else {
            self.failed = self.failed.saturating_add(1);
        }
    }

    /// Closes the window once it is [`WINDOW_SECS`] old. Returns the verdict only on
    /// the first misparsing window of an episode; a window that is fine, or too small
    /// to judge, ends the episode so a later one is reported again.
    pub fn tick(&mut self, now_ns: u64) -> Option<Misparse> {
        let start = self.window_start_ns?;
        if now_ns.saturating_sub(start) < WINDOW_SECS * 1_000_000_000 {
            return None;
        }
        let (parsed, failed) = (self.parsed, self.failed);
        self.window_start_ns = None;
        self.parsed = 0;
        self.failed = 0;

        let total = parsed.saturating_add(failed);
        let misparsing = total >= MIN_LINES && failed.saturating_mul(2) >= total;
        if misparsing && !self.reported {
            self.reported = true;
            return Some(Misparse { parsed, failed });
        }
        if !misparsing {
            self.reported = false;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: u64 = 1_000_000_000;

    fn feed(w: &mut MisparseWatch, ok: u32, bad: u32, at: u64) {
        for _ in 0..ok {
            w.record(true, at);
        }
        for _ in 0..bad {
            w.record(false, at);
        }
    }

    #[test]
    fn a_window_dominated_by_failures_is_reported_once_per_episode() {
        let mut w = MisparseWatch::new();
        feed(&mut w, 1, 19, 10 * SEC);
        assert_eq!(w.tick(69 * SEC), None, "window not over");
        assert_eq!(
            w.tick(70 * SEC),
            Some(Misparse {
                parsed: 1,
                failed: 19
            })
        );
        feed(&mut w, 0, 30, 80 * SEC);
        assert_eq!(w.tick(140 * SEC), None, "same episode, not reported again");
    }

    #[test]
    fn a_good_window_ends_the_episode() {
        let mut w = MisparseWatch::new();
        feed(&mut w, 0, 20, 0);
        assert!(w.tick(60 * SEC).is_some());
        feed(&mut w, 20, 0, 70 * SEC);
        assert_eq!(w.tick(130 * SEC), None);
        feed(&mut w, 0, 20, 140 * SEC);
        assert!(w.tick(200 * SEC).is_some(), "a new episode is reported");
    }

    #[test]
    fn a_few_lines_or_a_minority_of_failures_is_not_a_verdict() {
        let mut w = MisparseWatch::new();
        feed(&mut w, 0, 9, 0);
        assert_eq!(w.tick(60 * SEC), None, "under MIN_LINES");
        feed(&mut w, 30, 5, 70 * SEC);
        assert_eq!(w.tick(130 * SEC), None, "failures are a minority");
    }

    #[test]
    fn an_idle_source_yields_nothing() {
        let mut w = MisparseWatch::new();
        assert_eq!(w.tick(1_000 * SEC), None);
    }
}
