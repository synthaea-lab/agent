//! Per-pid sliding one-second capture budget, shared by the TLS (bytes),
//! readline (commands) and DNS (queries) drains.

use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

const WINDOW: Duration = Duration::from_secs(1);

/// Admissions between sweeps that drop pids whose window has emptied.
const SWEEP_INTERVAL_ADMISSIONS: u32 = 100;

/// Admits an event while the pid's spend over the last [`WINDOW`] plus the
/// event's cost stays within the limit. Denied events spend nothing.
pub(crate) struct SlidingBudget {
    limit_per_window: u64,
    spends_by_pid: HashMap<u32, VecDeque<(Instant, u32)>>,
    admissions_since_sweep: u32,
}

impl SlidingBudget {
    pub(crate) fn per_second(limit: u32) -> Self {
        Self {
            limit_per_window: u64::from(limit),
            spends_by_pid: HashMap::new(),
            admissions_since_sweep: 0,
        }
    }

    /// Spends `cost` from `pid`'s budget and returns `true`, or returns `false`
    /// and spends nothing when the event would exceed it.
    pub(crate) fn try_spend(&mut self, pid: u32, cost: u32) -> bool {
        self.try_spend_at(pid, cost, Instant::now())
    }

    fn try_spend_at(&mut self, pid: u32, cost: u32, now: Instant) -> bool {
        let spends = self.spends_by_pid.entry(pid).or_default();
        while spends
            .front()
            .is_some_and(|&(spent_at, _)| now.duration_since(spent_at) >= WINDOW)
        {
            spends.pop_front();
        }
        let spent_in_window: u64 = spends.iter().map(|&(_, spent)| u64::from(spent)).sum();
        if spent_in_window + u64::from(cost) > self.limit_per_window {
            return false;
        }
        spends.push_back((now, cost));
        self.sweep_emptied_pids_periodically();
        true
    }

    fn sweep_emptied_pids_periodically(&mut self) {
        self.admissions_since_sweep += 1;
        if self.admissions_since_sweep >= SWEEP_INTERVAL_ADMISSIONS {
            self.admissions_since_sweep = 0;
            self.spends_by_pid.retain(|_, spends| !spends.is_empty());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PID: u32 = 42;
    const OTHER_PID: u32 = 7;

    fn after(start: Instant, millis: u64) -> Instant {
        start + Duration::from_millis(millis)
    }

    #[test]
    fn admits_cost_up_to_the_limit_and_denies_the_overflow() {
        let start = Instant::now();
        let mut budget = SlidingBudget::per_second(100);
        assert!(budget.try_spend_at(PID, 60, start));
        assert!(budget.try_spend_at(PID, 40, after(start, 1)));
        assert!(!budget.try_spend_at(PID, 1, after(start, 2)));
    }

    #[test]
    fn denied_event_spends_nothing() {
        let start = Instant::now();
        let mut budget = SlidingBudget::per_second(100);
        assert!(budget.try_spend_at(PID, 60, start));
        assert!(!budget.try_spend_at(PID, 50, after(start, 1)));
        assert!(budget.try_spend_at(PID, 40, after(start, 2)));
    }

    #[test]
    fn event_costing_more_than_the_whole_limit_is_denied() {
        let mut budget = SlidingBudget::per_second(100);
        assert!(!budget.try_spend_at(PID, 101, Instant::now()));
    }

    #[test]
    fn spend_leaves_the_window_exactly_one_second_after_it_was_made() {
        let start = Instant::now();
        let mut budget = SlidingBudget::per_second(100);
        assert!(budget.try_spend_at(PID, 100, start));
        assert!(!budget.try_spend_at(PID, 1, after(start, 999)));
        assert!(budget.try_spend_at(PID, 100, after(start, 1000)));
    }

    #[test]
    fn window_slides_per_spend_instead_of_resetting() {
        let start = Instant::now();
        let mut budget = SlidingBudget::per_second(100);
        assert!(budget.try_spend_at(PID, 50, start));
        assert!(budget.try_spend_at(PID, 50, after(start, 500)));
        assert!(budget.try_spend_at(PID, 50, after(start, 1000)));
        assert!(!budget.try_spend_at(PID, 1, after(start, 1499)));
        assert!(budget.try_spend_at(PID, 50, after(start, 1500)));
    }

    #[test]
    fn budget_is_tracked_per_pid() {
        let start = Instant::now();
        let mut budget = SlidingBudget::per_second(100);
        assert!(budget.try_spend_at(PID, 100, start));
        assert!(budget.try_spend_at(OTHER_PID, 100, start));
        assert!(!budget.try_spend_at(PID, 1, start));
    }

    #[test]
    fn zero_cost_event_is_admitted_even_on_an_exhausted_budget() {
        let start = Instant::now();
        let mut budget = SlidingBudget::per_second(100);
        assert!(budget.try_spend_at(PID, 100, start));
        assert!(budget.try_spend_at(PID, 0, start));
    }

    #[test]
    fn unit_cost_admits_limit_events_per_window_and_denies_the_next() {
        let start = Instant::now();
        let mut budget = SlidingBudget::per_second(3);
        for millis in 0..3 {
            assert!(budget.try_spend_at(PID, 1, after(start, millis)));
        }
        assert!(!budget.try_spend_at(PID, 1, after(start, 3)));
        assert!(budget.try_spend_at(OTHER_PID, 1, after(start, 3)));
    }

    #[test]
    fn zero_limit_denies_every_unit_cost_event() {
        let mut budget = SlidingBudget::per_second(0);
        assert!(!budget.try_spend_at(PID, 1, Instant::now()));
    }

    #[test]
    fn spend_near_u32_max_does_not_overflow_the_window_sum() {
        let start = Instant::now();
        let mut budget = SlidingBudget::per_second(u32::MAX);
        assert!(budget.try_spend_at(PID, u32::MAX, start));
        assert!(!budget.try_spend_at(PID, u32::MAX, start));
    }

    #[test]
    fn sweep_drops_pids_left_with_an_empty_window() {
        let start = Instant::now();
        let mut budget = SlidingBudget::per_second(1);
        assert!(!budget.try_spend_at(PID, 2, start));
        for other_pid in 0..SWEEP_INTERVAL_ADMISSIONS {
            assert!(budget.try_spend_at(PID + 1 + other_pid, 1, start));
        }
        assert!(!budget.spends_by_pid.contains_key(&PID));
    }
}
