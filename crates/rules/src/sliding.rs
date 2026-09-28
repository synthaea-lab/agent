//! The sliding-window counter shared by SELF-SPAWN and BEACON, and the sliding-sum
//! shared by the ransomware write-volume signal (issue #82).

use std::collections::VecDeque;

/// True sliding-window counter shared by SELF-SPAWN and BEACON ("N occurrences in
/// X seconds, one alert per window"). The previous reset-bucket scheme discarded
/// in-window events at the boundary — spawns at t=0s, 29s, 31s never reached a
/// threshold of 3 in 30s, because the reset at 31s dropped the 29s spawn that was
/// still inside the window (review finding).
#[derive(Default)]
pub(crate) struct SlidingCounter {
    timestamps: VecDeque<u64>,
    last_alert_ns: Option<u64>,
}

/// Hard cap on retained timestamps per key — a counter only needs to prove the
/// threshold, not archive the full burst.
const SLIDING_TIMESTAMPS_CAP: usize = 256;

impl SlidingCounter {
    /// Prunes expired timestamps, records the new one, returns the in-window count.
    pub(crate) fn record(&mut self, ts: u64, window_ns: u64) -> u32 {
        while self
            .timestamps
            .front()
            .is_some_and(|&t| ts.saturating_sub(t) > window_ns)
        {
            self.timestamps.pop_front();
        }
        self.timestamps.push_back(ts);
        if self.timestamps.len() > SLIDING_TIMESTAMPS_CAP {
            self.timestamps.pop_front();
        }
        self.timestamps.len() as u32
    }

    /// One alert per window: true (and remembers) unless one already fired within
    /// the window.
    pub(crate) fn try_alert(&mut self, ts: u64, window_ns: u64) -> bool {
        if self
            .last_alert_ns
            .is_some_and(|t| ts.saturating_sub(t) <= window_ns)
        {
            return false;
        }
        self.last_alert_ns = Some(ts);
        true
    }
}

/// Tracks which local ports have already counted toward a BEACON key within the
/// window, for poll-based sources (conntrack) rather than a discrete per-syscall
/// trace: a live flow is re-reported on every poll while it stays open, so without
/// this, one ordinary long-lived connection (SSH, a websocket) that happens to
/// still be open on its 3rd poll would count as 3 "connections" and false-positive
/// BEACON — `local_port` is this host's stable identity for one flow's lifetime,
/// unlike `(daddr, dport)` alone which a real beacon and a single long session
/// share equally.
#[derive(Default)]
pub(crate) struct FlowPortDedup {
    ports: VecDeque<(u16, u64)>,
}

/// Same reasoning as `SLIDING_TIMESTAMPS_CAP`: bounds one key's memory, not a
/// count of legitimate distinct flows expected in practice.
const FLOW_PORT_DEDUP_CAP: usize = 256;

/// Sliding-window sum ("N bytes written in X seconds") — `SlidingCounter` counts
/// occurrences, this sums a value per occurrence. Used by the ransomware
/// write-volume corroboration check (issue #82) to track write volume per pid.
#[derive(Default)]
pub(crate) struct SlidingSum {
    entries: VecDeque<(u64, u64)>,
    total: u64,
}

/// Same reasoning as `SLIDING_TIMESTAMPS_CAP`.
const SLIDING_SUM_CAP: usize = 256;

impl SlidingSum {
    /// Drops entries older than `window_ns` relative to `ts`, keeping `total` in sync.
    fn prune(&mut self, ts: u64, window_ns: u64) {
        while self
            .entries
            .front()
            .is_some_and(|&(t, _)| ts.saturating_sub(t) > window_ns)
        {
            if let Some((_, v)) = self.entries.pop_front() {
                self.total = self.total.saturating_sub(v);
            }
        }
    }

    /// Prunes expired entries, adds `value` at `ts`, returns the new in-window total.
    pub(crate) fn add(&mut self, ts: u64, value: u64, window_ns: u64) -> u64 {
        self.prune(ts, window_ns);
        self.entries.push_back((ts, value));
        self.total = self.total.saturating_add(value);
        if self.entries.len() > SLIDING_SUM_CAP
            && let Some((_, v)) = self.entries.pop_front()
        {
            self.total = self.total.saturating_sub(v);
        }
        self.total
    }

    /// Prunes expired entries and returns the current in-window total, without
    /// adding a new value — for a check that needs to read another event
    /// stream's accumulated volume (the ransomware check reads write volume from
    /// a `FileRenameEvent`).
    pub(crate) fn total(&mut self, ts: u64, window_ns: u64) -> u64 {
        self.prune(ts, window_ns);
        self.total
    }
}

impl FlowPortDedup {
    /// Prunes ports last seen outside the window, then reports whether
    /// `local_port` is new within it (and records it) — `false` means this exact
    /// flow was already counted on an earlier poll in the same window.
    pub(crate) fn is_new(&mut self, local_port: u16, ts: u64, window_ns: u64) -> bool {
        while self
            .ports
            .front()
            .is_some_and(|&(_, t)| ts.saturating_sub(t) > window_ns)
        {
            self.ports.pop_front();
        }
        if self.ports.iter().any(|&(p, _)| p == local_port) {
            return false;
        }
        self.ports.push_back((local_port, ts));
        if self.ports.len() > FLOW_PORT_DEDUP_CAP {
            self.ports.pop_front();
        }
        true
    }
}

/// Sliding-window *distinct*-value counter ("N distinct destinations in X
/// seconds") — SCAN-SPREAD (T1046/T1210, issue #465): the inverse shape from
/// `SlidingCounter`/BEACON's "same destination repeated N times". A value
/// already in the window doesn't add a new entry or extend its own
/// lifetime — same non-refreshing membership check as `FlowPortDedup::is_new`,
/// generalized over the value type instead of hardcoding `u16`.
pub(crate) struct SlidingDistinct<T> {
    entries: VecDeque<(T, u64)>,
    last_alert_ns: Option<u64>,
}

// Not `#[derive(Default)]`: that would require `T: Default` too, which no
// caller needs — nothing here ever constructs a `T`, only stores ones passed
// in by [`SlidingDistinct::record`].
impl<T> Default for SlidingDistinct<T> {
    fn default() -> Self {
        Self {
            entries: VecDeque::new(),
            last_alert_ns: None,
        }
    }
}

/// Same reasoning as `SLIDING_TIMESTAMPS_CAP`.
const SLIDING_DISTINCT_CAP: usize = 256;

impl<T: PartialEq> SlidingDistinct<T> {
    fn prune(&mut self, ts: u64, window_ns: u64) {
        while self
            .entries
            .front()
            .is_some_and(|&(_, t)| ts.saturating_sub(t) > window_ns)
        {
            self.entries.pop_front();
        }
    }

    /// Prunes expired entries, records `value` at `ts` if it isn't already
    /// present in the window, returns the number of distinct values
    /// currently in window (including `value`).
    pub(crate) fn record(&mut self, value: T, ts: u64, window_ns: u64) -> u32 {
        self.prune(ts, window_ns);
        if !self.entries.iter().any(|(v, _)| *v == value) {
            self.entries.push_back((value, ts));
            if self.entries.len() > SLIDING_DISTINCT_CAP {
                self.entries.pop_front();
            }
        }
        self.entries.len() as u32
    }

    /// One alert per window: true (and remembers) unless one already fired within
    /// the window. Same contract as `SlidingCounter::try_alert`.
    pub(crate) fn try_alert(&mut self, ts: u64, window_ns: u64) -> bool {
        if self
            .last_alert_ns
            .is_some_and(|t| ts.saturating_sub(t) <= window_ns)
        {
            return false;
        }
        self.last_alert_ns = Some(ts);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::SlidingDistinct;

    #[test]
    fn counts_distinct_values_only() {
        let mut counter = SlidingDistinct::default();
        assert_eq!(counter.record("a", 0, 10_000_000_000), 1);
        assert_eq!(counter.record("b", 1_000_000_000, 10_000_000_000), 2);
        assert_eq!(
            counter.record("a", 2_000_000_000, 10_000_000_000),
            2,
            "repeating an already-seen value must not grow the count"
        );
        assert_eq!(counter.record("c", 3_000_000_000, 10_000_000_000), 3);
    }

    #[test]
    fn prunes_values_outside_the_window() {
        let mut counter = SlidingDistinct::default();
        counter.record("a", 0, 10_000_000_000);
        counter.record("b", 1_000_000_000, 10_000_000_000);
        // Past the window relative to "a" and "b" — both should be pruned,
        // leaving only the new value.
        assert_eq!(counter.record("c", 20_000_000_000, 10_000_000_000), 1);
    }
}
