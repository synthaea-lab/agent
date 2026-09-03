//! The sliding-window counter shared by SELF-SPAWN and BEACON.

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
