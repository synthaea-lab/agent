//! The ransomware reflex's trigger (issue #82): a process incarnation that both raised the
//! ransomware burst rule (T1486) and touched a planted canary, within one window.
//!
//! Neither signal kills alone. A burst alone is a backup, a video export or an archiver; a
//! canary touch alone is an indexer nobody listed or a curious user. Together, from one
//! process, they are an encryptor walking directories it has no business in. Which signal
//! arrives first does not matter, and time is the events' own timestamps, in a sliding
//! window per process (never a reset bucket).

use store::BoundedMap;

/// A signal is fresh for this long (event time, ns) when the other one arrives.
const WINDOW_NS: u64 = 60 * 1_000_000_000;

/// Most process incarnations tracked at once. Eviction drops the oldest and is counted: at
/// worst a slow encryptor loses its first signal and needs a fresh one.
const MAX_TRACKED: usize = 256;

/// `(pid, incarnation)`: a recycled pid with a different stamp is a different process.
type Process = (u32, Option<u64>);

#[derive(Clone, Copy, Default)]
struct Signals {
    burst_ns: Option<u64>,
    canary_ns: Option<u64>,
}

fn fresh(at: Option<u64>, now_ns: u64) -> bool {
    at.is_some_and(|at| now_ns.saturating_sub(at) < WINDOW_NS)
}

/// Joins the two signals per process.
pub(crate) struct RansomwareJoin {
    seen: BoundedMap<Process, Signals>,
    /// `seen.evicted()` when it was last reported, so each loss is logged once.
    reported_evictions: u64,
}

impl RansomwareJoin {
    pub(crate) fn new() -> Self {
        Self {
            seen: BoundedMap::new(MAX_TRACKED),
            reported_evictions: 0,
        }
    }

    /// The process raised the ransomware burst rule. True when it also touched a canary
    /// inside the window: the corroborated case, reported once.
    pub(crate) fn note_burst(&mut self, process: Process, now_ns: u64) -> bool {
        self.note(process, now_ns, |s| &mut s.burst_ns, |s| s.canary_ns)
    }

    /// The process touched a canary. True when it also raised the burst rule inside the
    /// window.
    pub(crate) fn note_canary(&mut self, process: Process, now_ns: u64) -> bool {
        self.note(process, now_ns, |s| &mut s.canary_ns, |s| s.burst_ns)
    }

    fn note(
        &mut self,
        process: Process,
        now_ns: u64,
        mine: impl FnOnce(&mut Signals) -> &mut Option<u64>,
        other: impl FnOnce(&Signals) -> Option<u64>,
    ) -> bool {
        let mut signals = self.seen.peek(&process).copied().unwrap_or_default();
        *mine(&mut signals) = Some(now_ns);
        if fresh(other(&signals), now_ns) {
            // Reported: a second kill request for the same process would only repeat it.
            self.seen.remove(&process);
            return true;
        }
        self.seen.insert(process, signals);
        self.report_evictions();
        false
    }

    /// Says when tracking shed incarnations: a slow encryptor whose first signal was shed
    /// needs a fresh one, and an operator should be able to see that happened.
    fn report_evictions(&mut self) {
        let evicted = self.seen.evicted();
        if evicted > self.reported_evictions {
            tracing::warn!(
                evicted,
                "ransomware join: tracked processes shed (oldest first)"
            );
            self.reported_evictions = evicted;
        }
    }

    /// Incarnations dropped to stay within the bound.
    #[cfg(test)]
    fn evicted(&self) -> u64 {
        self.seen.evicted()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: Process = (4242, Some(7));
    const T0: u64 = 1_000_000_000_000;

    #[test]
    fn a_burst_alone_does_not_corroborate() {
        let mut join = RansomwareJoin::new();
        assert!(!join.note_burst(P, T0));
        assert!(!join.note_burst(P, T0 + 1));
    }

    #[test]
    fn a_canary_touch_alone_does_not_corroborate() {
        let mut join = RansomwareJoin::new();
        assert!(!join.note_canary(P, T0));
        assert!(!join.note_canary(P, T0 + 1));
    }

    #[test]
    fn both_signals_from_one_process_corroborate_in_either_order() {
        let mut a = RansomwareJoin::new();
        assert!(!a.note_canary(P, T0));
        assert!(a.note_burst(P, T0 + 5_000_000_000));

        let mut b = RansomwareJoin::new();
        assert!(!b.note_burst(P, T0));
        assert!(b.note_canary(P, T0 + 5_000_000_000));
    }

    #[test]
    fn the_signals_of_two_processes_are_not_mixed() {
        let mut join = RansomwareJoin::new();
        assert!(!join.note_canary((1, None), T0));
        assert!(!join.note_burst((2, None), T0 + 1));
    }

    #[test]
    fn a_recycled_pid_with_another_incarnation_is_another_process() {
        let mut join = RansomwareJoin::new();
        assert!(!join.note_canary((9, Some(1)), T0));
        assert!(!join.note_burst((9, Some(2)), T0 + 1));
    }

    #[test]
    fn a_signal_older_than_the_window_does_not_count() {
        let mut join = RansomwareJoin::new();
        assert!(!join.note_canary(P, T0));
        assert!(!join.note_burst(P, T0 + WINDOW_NS));
        // The burst is fresh now, so a canary touch right after does corroborate.
        assert!(join.note_canary(P, T0 + WINDOW_NS + 1));
    }

    #[test]
    fn the_window_slides_with_each_new_signal() {
        let mut join = RansomwareJoin::new();
        assert!(!join.note_canary(P, T0));
        // Another canary touch late in the window refreshes it.
        assert!(!join.note_canary(P, T0 + WINDOW_NS - 1));
        assert!(join.note_burst(P, T0 + 2 * WINDOW_NS - 2));
    }

    #[test]
    fn a_corroborated_process_is_reported_once() {
        let mut join = RansomwareJoin::new();
        assert!(!join.note_canary(P, T0));
        assert!(join.note_burst(P, T0 + 1));
        assert!(!join.note_burst(P, T0 + 2), "needs a fresh canary touch");
        assert!(join.note_canary(P, T0 + 3));
    }

    #[test]
    fn tracking_is_bounded_and_shedding_is_counted() {
        let mut join = RansomwareJoin::new();
        for pid in 0..(MAX_TRACKED as u32 + 10) {
            join.note_canary((pid, None), T0);
        }
        assert!(join.evicted() > 0, "shedding is counted");
        // The oldest was shed: its burst finds no canary touch.
        assert!(!join.note_burst((0, None), T0 + 1));
    }
}
