//! A per-process event budget for the high-volume, in-process providers (AMSI
//! #282, LDAP-Client #364): one busy process must not flood the sink or slow
//! the real-time consumer (#408). Refusals are counted, never silent.

use std::collections::HashMap;

/// Processes with a live budget window remembered at once.
const PER_PID_CAP: usize = 1_024;

/// `limit` events per process per `window_ns`.
#[derive(Debug)]
pub(crate) struct PidBudget {
    limit: u32,
    window_ns: u64,
    /// pid → (window start, events admitted in it).
    windows: HashMap<u32, (u64, u32)>,
    pub(crate) refused: u64,
}

impl PidBudget {
    pub(crate) fn new(limit: u32, window_ns: u64) -> Self {
        Self {
            limit,
            window_ns,
            windows: HashMap::new(),
            refused: 0,
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
                self.windows.clear(); // a pid storm: start every budget afresh
            }
        }
        let window = self.windows.entry(pid).or_insert((now_ns, 0));
        if now_ns.saturating_sub(window.0) >= self.window_ns {
            *window = (now_ns, 0);
        }
        if window.1 >= self.limit {
            self.refused += 1;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_process_is_capped_per_window_then_gets_a_fresh_budget() {
        let mut budget = PidBudget::new(3, 10);
        assert!(budget.spend(7, 0) && budget.spend(7, 1) && budget.spend(7, 2));
        assert!(!budget.spend(7, 3));
        assert!(budget.spend(8, 3), "budget is per process");
        assert!(budget.spend(7, 10), "window over");
        assert_eq!(budget.refused, 1);
    }

    #[test]
    fn memory_stays_bounded() {
        let mut budget = PidBudget::new(1, 1_000_000);
        for pid in 0..(PER_PID_CAP as u32 * 2) {
            budget.spend(pid, 0);
        }
        assert!(budget.tracked() <= PER_PID_CAP);
    }
}
