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

    /// In-window count at `ts` without recording anything: how many recorded
    /// timestamps are at most `window_ns` old.
    pub(crate) fn count_within(&self, ts: u64, window_ns: u64) -> u32 {
        self.timestamps
            .iter()
            .filter(|&&t| ts.saturating_sub(t) <= window_ns)
            .count() as u32
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
    /// `(slot_start, slot_end, value)`. `slot_start` never changes once a slot
    /// exists — it's what a *new* write compares against to decide whether it
    /// still belongs in this slot (bounds slot width to
    /// [`SLIDING_SUM_SLOT_NS`]). `slot_end` is the timestamp of the most
    /// recent write coalesced into the slot — what [`SlidingSum::prune`]
    /// compares against, so a slot expires based on how long ago it was last
    /// written to, not how long ago it was first opened. Reviewed by Nikolas
    /// on #500: pruning against `slot_start` evicted a slot's bytes up to
    /// [`SLIDING_SUM_SLOT_NS`] before they were actually `window_ns` old,
    /// undercounting a burst right at the window boundary.
    entries: VecDeque<(u64, u64, u64)>,
    total: u64,
}

/// Bounds one key's memory, same reasoning as `SLIDING_TIMESTAMPS_CAP` — with
/// entries coalesced by [`SLIDING_SUM_SLOT_NS`], this is no longer the
/// practical ceiling on the tracked total (issue #496): it only matters if a
/// caller somehow produces more distinct slots than fit in the window, which
/// legitimate writers never do.
const SLIDING_SUM_CAP: usize = 256;

/// Writes within this long of the current slot's first write are coalesced
/// into it rather than starting a new entry (issue #496). Before this
/// existed, `add` pushed one entry per call, so [`SLIDING_SUM_CAP`] capped the
/// tracked total at `256 * (bytes per write call)` — 16-32MB at realistic
/// 64-128KB buffered-write sizes, far under `BURST_WRITE_BYTES_THRESHOLD`
/// (100MB): the threshold was unreachable on real telemetry, confirmed live
/// (120MB written in 64KB chunks produced no alert). Coalescing bounds entry
/// *count* by wall-clock time instead of call count: at most
/// `window_ns / SLIDING_SUM_SLOT_NS` slots ever exist per key (25 for the 5s
/// ransomware window at 200ms), nowhere near `SLIDING_SUM_CAP`, so the total
/// this returns is the real in-window sum regardless of how many small writes
/// produced it. 200ms is short enough that two genuinely distinct write
/// bursts a legitimate multi-writer process interleaves rarely land in the
/// same slot, long enough that a single writer's normal buffered-I/O call
/// rate (sub-millisecond apart) collapses to a handful of slots instead of
/// hundreds.
const SLIDING_SUM_SLOT_NS: u64 = 200_000_000; // 200ms

impl SlidingSum {
    /// Drops entries older than `window_ns` relative to `ts`, keeping `total` in
    /// sync. Compares against each slot's *last* write (`slot_end`), not its
    /// first (`slot_start`) — see the field doc for why that distinction matters.
    fn prune(&mut self, ts: u64, window_ns: u64) {
        while self
            .entries
            .front()
            .is_some_and(|&(_, end, _)| ts.saturating_sub(end) > window_ns)
        {
            if let Some((_, _, v)) = self.entries.pop_front() {
                self.total = self.total.saturating_sub(v);
            }
        }
    }

    /// Prunes expired entries, adds `value` at `ts` (coalesced into the
    /// current slot when `ts` falls within [`SLIDING_SUM_SLOT_NS`] of that
    /// slot's first write — see its doc), returns the new in-window total.
    pub(crate) fn add(&mut self, ts: u64, value: u64, window_ns: u64) -> u64 {
        self.prune(ts, window_ns);
        match self.entries.back_mut() {
            Some((slot_start, slot_end, slot_total))
                if ts.saturating_sub(*slot_start) < SLIDING_SUM_SLOT_NS =>
            {
                *slot_end = ts.max(*slot_end);
                *slot_total = slot_total.saturating_add(value);
            }
            _ => self.entries.push_back((ts, ts, value)),
        }
        self.total = self.total.saturating_add(value);
        if self.entries.len() > SLIDING_SUM_CAP
            && let Some((_, _, v)) = self.entries.pop_front()
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
    use super::{SlidingDistinct, SlidingSum};

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

    const WINDOW_NS: u64 = 5_000_000_000; // matches RANSOMWARE_RENAME_WINDOW_NS

    #[test]
    fn coalesced_slot_expires_from_its_last_write_not_its_first() {
        // Regression for #500 (Nikolas's review of #496's fix): the slot's
        // stored timestamp used to be the *first* write's, so `prune` evicted
        // the whole slot — including bytes from writes coalesced in later,
        // right up to SLIDING_SUM_SLOT_NS after that first write — as soon as
        // that first timestamp alone crossed `window_ns`, up to
        // SLIDING_SUM_SLOT_NS (200ms) before those later bytes were actually
        // `window_ns` old. A large write opens the slot at t=0; a second,
        // tiny write 190ms later coalesces into the same slot (190ms <
        // 200ms), moving its *last* write to t=190ms.
        let mut sum = SlidingSum::default();
        sum.add(0, 100 * 1024 * 1024, WINDOW_NS);
        sum.add(190_000_000, 1, WINDOW_NS);

        // 5.1s after the slot opened, but only 4.91s after it was last
        // written to — still within the window relative to the slot's real
        // recency. The old code pruned on the first write's age (5.1s > 5s)
        // and evicted the whole 100MB+1 here; the fix prunes on the last
        // write's age (4.91s <= 5s) and keeps it.
        let total = sum.total(5_100_000_000, WINDOW_NS);
        assert_eq!(
            total,
            100 * 1024 * 1024 + 1,
            "bytes coalesced into a slot must survive until the slot's last \
             write, not its first, is window_ns old"
        );
    }

    #[test]
    fn slot_still_expires_once_even_its_last_write_is_outside_the_window() {
        // The other half: once the slot's last write really is older than
        // window_ns, it must still expire — this isn't a license to retain
        // forever.
        let mut sum = SlidingSum::default();
        sum.add(0, 100 * 1024 * 1024, WINDOW_NS);
        sum.add(190_000_000, 1, WINDOW_NS);

        let total = sum.total(190_000_000 + WINDOW_NS + 1, WINDOW_NS);
        assert_eq!(total, 0, "a slot outside the window must still be pruned");
    }
}
