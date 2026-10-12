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

/// A signal: when (event time, ns) and which incarnation of the pid raised it.
type Stamp = (u64, Option<u64>);

#[derive(Clone, Copy, Default)]
struct Signals {
    burst: Option<Stamp>,
    canary: Option<Stamp>,
}

/// Two stamps are of one process unless both carry an incarnation and the two differ. The
/// sensor stamps an incarnation (`process_generation`) only when it knows the pid, and the
/// schema says a consumer must treat an unstamped event as the same pid, never as a new one:
/// an open stamped and a rename that was not (or the reverse) are still one encryptor.
fn same_process(a: Option<u64>, b: Option<u64>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    }
}

fn fresh(at: u64, now_ns: u64) -> bool {
    now_ns.saturating_sub(at) < WINDOW_NS
}

/// Which of the two signals a call records.
#[derive(Clone, Copy)]
enum Kind {
    Burst,
    Canary,
}

/// Joins the two signals per process.
pub(crate) struct RansomwareJoin {
    seen: BoundedMap<u32, Signals>,
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
    pub(crate) fn note_burst(&mut self, pid: u32, generation: Option<u64>, now_ns: u64) -> bool {
        self.note(Kind::Burst, pid, generation, now_ns)
    }

    /// The process touched a canary. True when it also raised the burst rule inside the
    /// window.
    pub(crate) fn note_canary(&mut self, pid: u32, generation: Option<u64>, now_ns: u64) -> bool {
        self.note(Kind::Canary, pid, generation, now_ns)
    }

    fn note(&mut self, kind: Kind, pid: u32, generation: Option<u64>, now_ns: u64) -> bool {
        let mut signals = self.seen.peek(&pid).copied().unwrap_or_default();
        let stamp = Some((now_ns, generation));
        let other = match kind {
            Kind::Burst => &mut signals.canary,
            Kind::Canary => &mut signals.burst,
        };
        // A signal of another incarnation of this pid is the previous process's: dropped.
        if other.is_some_and(|(_, g)| !same_process(g, generation)) {
            *other = None;
        }
        if other.is_some_and(|(at, _)| fresh(at, now_ns)) {
            // Reported: a second kill request for the same process would only repeat it.
            self.seen.remove(&pid);
            return true;
        }
        match kind {
            Kind::Burst => signals.burst = stamp,
            Kind::Canary => signals.canary = stamp,
        }
        self.seen.insert(pid, signals);
        self.report_evictions();
        false
    }

    /// Says when tracking shed processes: a slow encryptor whose first signal was shed
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

    /// Processes dropped to stay within the bound.
    #[cfg(test)]
    fn evicted(&self) -> u64 {
        self.seen.evicted()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PID: u32 = 4242;
    const GEN: Option<u64> = Some(7);
    const T0: u64 = 1_000_000_000_000;

    #[test]
    fn a_burst_alone_does_not_corroborate() {
        let mut join = RansomwareJoin::new();
        assert!(!join.note_burst(PID, GEN, T0));
        assert!(!join.note_burst(PID, GEN, T0 + 1));
    }

    #[test]
    fn a_canary_touch_alone_does_not_corroborate() {
        let mut join = RansomwareJoin::new();
        assert!(!join.note_canary(PID, GEN, T0));
        assert!(!join.note_canary(PID, GEN, T0 + 1));
    }

    #[test]
    fn both_signals_from_one_process_corroborate_in_either_order() {
        let mut a = RansomwareJoin::new();
        assert!(!a.note_canary(PID, GEN, T0));
        assert!(a.note_burst(PID, GEN, T0 + 5_000_000_000));

        let mut b = RansomwareJoin::new();
        assert!(!b.note_burst(PID, GEN, T0));
        assert!(b.note_canary(PID, GEN, T0 + 5_000_000_000));
    }

    #[test]
    fn the_signals_of_two_processes_are_not_mixed() {
        let mut join = RansomwareJoin::new();
        assert!(!join.note_canary(1, None, T0));
        assert!(!join.note_burst(2, None, T0 + 1));
    }

    #[test]
    fn a_recycled_pid_with_another_incarnation_is_another_process() {
        let mut join = RansomwareJoin::new();
        assert!(!join.note_canary(9, Some(1), T0));
        assert!(!join.note_burst(9, Some(2), T0 + 1));
    }

    #[test]
    fn a_signal_without_an_incarnation_still_joins_a_stamped_one() {
        let mut a = RansomwareJoin::new();
        assert!(!a.note_canary(PID, None, T0));
        assert!(
            a.note_burst(PID, Some(7), T0 + 1),
            "unstamped open, stamped rename"
        );

        let mut b = RansomwareJoin::new();
        assert!(!b.note_burst(PID, Some(7), T0));
        assert!(
            b.note_canary(PID, None, T0 + 1),
            "stamped rename, unstamped open"
        );
    }

    #[test]
    fn a_signal_of_a_previous_incarnation_is_dropped_not_kept() {
        let mut join = RansomwareJoin::new();
        assert!(!join.note_canary(9, Some(1), T0));
        assert!(!join.note_burst(9, Some(2), T0 + 1), "another incarnation");
        // The stale canary signal is gone, so a canary touch by the new incarnation is
        // what joins the burst.
        assert!(join.note_canary(9, Some(2), T0 + 2));
    }

    #[test]
    fn a_signal_older_than_the_window_does_not_count() {
        let mut join = RansomwareJoin::new();
        assert!(!join.note_canary(PID, GEN, T0));
        assert!(!join.note_burst(PID, GEN, T0 + WINDOW_NS));
        // The burst is fresh now, so a canary touch right after does corroborate.
        assert!(join.note_canary(PID, GEN, T0 + WINDOW_NS + 1));
    }

    #[test]
    fn the_window_slides_with_each_new_signal() {
        let mut join = RansomwareJoin::new();
        assert!(!join.note_canary(PID, GEN, T0));
        // Another canary touch late in the window refreshes it.
        assert!(!join.note_canary(PID, GEN, T0 + WINDOW_NS - 1));
        assert!(join.note_burst(PID, GEN, T0 + 2 * WINDOW_NS - 2));
    }

    #[test]
    fn a_corroborated_process_is_reported_once() {
        let mut join = RansomwareJoin::new();
        assert!(!join.note_canary(PID, GEN, T0));
        assert!(join.note_burst(PID, GEN, T0 + 1));
        assert!(
            !join.note_burst(PID, GEN, T0 + 2),
            "needs a fresh canary touch"
        );
        assert!(join.note_canary(PID, GEN, T0 + 3));
    }

    #[test]
    fn tracking_is_bounded_and_shedding_is_counted() {
        let mut join = RansomwareJoin::new();
        for pid in 0..(MAX_TRACKED as u32 + 10) {
            join.note_canary(pid, None, T0);
        }
        assert!(join.evicted() > 0, "shedding is counted");
        // The oldest was shed: its burst finds no canary touch.
        assert!(!join.note_burst(0, None, T0 + 1));
    }
}
