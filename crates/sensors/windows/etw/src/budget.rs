//! A per-process event budget for the high-volume, in-process providers (AMSI
//! #282, LDAP-Client #364): one busy process must not flood the sink or slow
//! the real-time consumer (#408). Refusals are counted, never silent.

use std::collections::HashMap;

/// Processes with a live budget window remembered at once.
const PER_PID_CAP: usize = 1_024;

/// `limit` events per process per `window_ns`.
#[derive(Debug)]
pub(crate) struct PidBudget {
    /// Names the provider in the shedding warning.
    label: &'static str,
    limit: u32,
    window_ns: u64,
    /// pid → (window start, events admitted in it).
    windows: HashMap<u32, (u64, u32)>,
    pub(crate) refused: u64,
    /// Live per-process windows forgotten in a pid storm: those processes get
    /// a fresh budget early. Volume, not loss.
    pub(crate) flushed: u64,
}

impl PidBudget {
    pub(crate) fn new(label: &'static str, limit: u32, window_ns: u64) -> Self {
        Self {
            label,
            limit,
            window_ns,
            windows: HashMap::new(),
            refused: 0,
            flushed: 0,
        }
    }

    /// Spends one event of `pid`'s budget; `false` (and counted) once it is
    /// spent for the current window.
    pub(crate) fn spend(&mut self, pid: u32, now_ns: u64) -> bool {
        if self.windows.len() >= PER_PID_CAP && !self.windows.contains_key(&pid) {
            let window_ns = self.window_ns;
            self.windows
                .retain(|_, (start, _)| now_ns.saturating_sub(*start) < window_ns);
            if self.windows.len() >= PER_PID_CAP {
                // A pid storm: start every budget afresh, counted (#744 review).
                let before = self.flushed;
                self.flushed += self.windows.len() as u64;
                self.windows.clear();
                if crossed_power_of_two(before, self.flushed) {
                    tracing::warn!(
                        provider = self.label,
                        flushed = self.flushed,
                        cap = PER_PID_CAP,
                        "per-process budget map full of live windows: budgets reset early"
                    );
                }
            }
        }
        let window = self.windows.entry(pid).or_insert((now_ns, 0));
        if now_ns.saturating_sub(window.0) >= self.window_ns {
            *window = (now_ns, 0);
        }
        if window.1 >= self.limit {
            self.refused += 1;
            // Observable, not silent (#632 review): one warning at the 1st,
            // 2nd, 4th, 8th... refusal bounds the log however long a runaway
            // client keeps going.
            if self.refused.is_power_of_two() {
                tracing::warn!(
                    provider = self.label,
                    pid,
                    refused = self.refused,
                    limit = self.limit,
                    "per-process event budget exhausted: events dropped"
                );
            }
            return false;
        }
        window.1 += 1;
        true
    }

    #[cfg(test)]
    pub(crate) fn tracked(&self) -> usize {
        self.windows.len()
    }
}

/// Whether a counter going from `before` to `after` crossed a power of two:
/// the log cadence for counters that grow in steps larger than one.
fn crossed_power_of_two(before: u64, after: u64) -> bool {
    after > before && (before == 0 || after.ilog2() > before.ilog2())
}

/// Reports one event per key per window (NTLM, #364): the same account
/// re-authenticating to the same target with the same version is one fact.
/// Bounded like [`PidBudget`].
#[derive(Debug)]
pub(crate) struct KeyDedup {
    /// Names the provider in the flush warning.
    label: &'static str,
    window_ns: u64,
    seen: HashMap<String, u64>,
    pub(crate) duplicates: u64,
    /// Live keys forgotten because the map was full of keys still inside their
    /// window. A repeat of one of them is reported again: volume, not loss.
    pub(crate) flushed: u64,
}

/// Keys remembered at once.
const KEY_DEDUP_CAP: usize = 4_096;

impl KeyDedup {
    pub(crate) fn new(label: &'static str, window_ns: u64) -> Self {
        Self {
            label,
            window_ns,
            seen: HashMap::new(),
            duplicates: 0,
            flushed: 0,
        }
    }

    /// `true` the first time `key` is seen within the window.
    pub(crate) fn first(&mut self, key: &str, now_ns: u64) -> bool {
        if self
            .seen
            .get(key)
            .is_some_and(|&t| now_ns.saturating_sub(t) < self.window_ns)
        {
            self.duplicates += 1;
            return false;
        }
        if self.seen.len() >= KEY_DEDUP_CAP {
            let window_ns = self.window_ns;
            self.seen
                .retain(|_, t| now_ns.saturating_sub(*t) < window_ns);
            if self.seen.len() >= KEY_DEDUP_CAP {
                let before = self.flushed;
                self.flushed += self.seen.len() as u64;
                self.seen.clear();
                // Observable, not silent (#744 review): logged when the total
                // crosses a power of two, so a sustained storm logs O(log n) lines.
                if crossed_power_of_two(before, self.flushed) {
                    tracing::warn!(
                        provider = self.label,
                        flushed = self.flushed,
                        cap = KEY_DEDUP_CAP,
                        "dedup map full of live keys: forgotten, repeats will be reported again"
                    );
                }
            }
        }
        self.seen.insert(key.to_string(), now_ns);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_reported_once_per_window() {
        let mut dedup = KeyDedup::new("test", 10);
        assert!(dedup.first("a", 0));
        assert!(!dedup.first("a", 5));
        assert!(dedup.first("b", 5));
        assert!(dedup.first("a", 10));
        assert_eq!(dedup.duplicates, 1);
    }

    #[test]
    fn a_process_is_capped_per_window_then_gets_a_fresh_budget() {
        let mut budget = PidBudget::new("test", 3, 10);
        assert!(budget.spend(7, 0) && budget.spend(7, 1) && budget.spend(7, 2));
        assert!(!budget.spend(7, 3));
        assert!(budget.spend(8, 3), "budget is per process");
        assert!(budget.spend(7, 10), "window over");
        assert_eq!(budget.refused, 1);
    }

    #[test]
    fn a_dedup_map_full_of_live_keys_counts_what_it_forgets() {
        // #744 review: the clear at saturation was silent.
        let mut dedup = KeyDedup::new("test", 1_000);
        for key in 0..KEY_DEDUP_CAP {
            assert!(dedup.first(&key.to_string(), 0));
        }
        assert_eq!(dedup.flushed, 0, "full but not over: nothing forgotten yet");
        assert!(dedup.first("one more", 0));
        assert_eq!(dedup.flushed, KEY_DEDUP_CAP as u64);
        assert!(dedup.first("0", 1), "a forgotten key is reported again");
    }

    #[test]
    fn expired_keys_are_dropped_before_live_ones_and_not_counted() {
        let mut dedup = KeyDedup::new("test", 10);
        for key in 0..KEY_DEDUP_CAP {
            dedup.first(&key.to_string(), 0);
        }
        assert!(dedup.first("late", 10), "every earlier key has expired");
        assert_eq!(dedup.flushed, 0, "expiry is not a loss");
        assert!(!dedup.first("late", 11));
    }

    #[test]
    fn a_pid_storm_counts_the_budgets_it_resets() {
        let mut budget = PidBudget::new("test", 1, 1_000);
        for pid in 0..PER_PID_CAP as u32 {
            budget.spend(pid, 0);
        }
        assert_eq!(budget.flushed, 0);
        budget.spend(u32::MAX, 0);
        assert_eq!(budget.flushed, PER_PID_CAP as u64);
        assert!(budget.spend(0, 1), "pid 0 got a fresh budget early");
    }

    #[test]
    fn the_flush_log_fires_once_per_power_of_two_crossed() {
        assert!(crossed_power_of_two(0, 4_096));
        assert!(crossed_power_of_two(4_096, 8_192));
        assert!(!crossed_power_of_two(4_096, 6_000));
        assert!(!crossed_power_of_two(5, 5));
        assert!(
            !crossed_power_of_two(0, 0),
            "nothing flushed, nothing to log"
        );
        assert!(crossed_power_of_two(7, 8));
    }

    #[test]
    fn memory_stays_bounded() {
        let mut budget = PidBudget::new("test", 1, 1_000_000);
        for pid in 0..(PER_PID_CAP as u32 * 2) {
            budget.spend(pid, 0);
        }
        assert!(budget.tracked() <= PER_PID_CAP);
    }
}
