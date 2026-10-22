//! The shared half of "N authentication failures, then a success" rules (#880): the bounded,
//! event-time join [`crate::rdp`] and [`crate::sudo`] both build on.
//!
//! What is shared is the delicate part, so that a fix lands once: a sorted failure history and a
//! sorted success history per key, both capped; the join of a success to the failures in the
//! window that ends at it; one alert per success and one per fixed window; and the bound on the
//! windows remembered. What stays in each rule: the key (an address, an invoker uid, a target
//! name), what a success carries (`D`: the RDP user, nothing for `sudo`), the thresholds and
//! windows (their own constants in `exclusions`), and the alert itself (technique, severity,
//! message), which the caller builds in the closure it passes to [`History::join`].
//!
//! The join is on event time, not on arrival order: a success is remembered, a failure that
//! arrives later is checked against the successes it falls before, and either arrival can complete
//! the join. A failure timestamped after the success never counts. History is bounded by the caps
//! and the least-recently-seen key (the caller's `BoundedMap`), never by time: pruning against the
//! newest timestamp seen would let one event far in the future erase what a late event still
//! needs, and the alert count would depend on delivery order again.

use std::collections::VecDeque;

use crate::Alert;

/// Alerted windows remembered per key. Far more than the successes kept.
pub(crate) const ALERTED_WINDOWS_CAP: usize = 16;

/// What bounds and triggers one rule's join.
#[derive(Clone, Copy)]
pub(crate) struct JoinParams {
    /// Failures at or after `success - window_ns` and at or before the success count.
    pub(crate) window_ns: u64,
    /// Failures in the window that make an alert.
    pub(crate) threshold: usize,
    /// Failure timestamps kept per key: enough to prove the threshold, not to archive a spray.
    pub(crate) failures_cap: usize,
    /// Successes kept per key until a failure can still complete their join.
    pub(crate) successes_cap: usize,
}

/// A remembered success, with whatever the rule wants in its alert (`D`).
pub(crate) struct Success<D> {
    pub(crate) timestamp_ns: u64,
    pub(crate) detail: D,
    pub(crate) alerted: bool,
}

/// One key's history. The field names are the ones the rules' own tests read.
pub(crate) struct History<D> {
    /// Failure timestamps, oldest first.
    pub(crate) failures: VecDeque<u64>,
    /// Successes, oldest first.
    pub(crate) successes: VecDeque<Success<D>>,
    /// The fixed windows (`timestamp / window`) an alert already fired for: one alert per window
    /// per key. Fixed slots, not "within a window of the last alert": the latter moves with the
    /// order alerts are emitted in, so the number of alerts would depend on delivery order again
    /// (a success at 0, 400 and 700 s gave 2 or 3).
    pub(crate) alerted_windows: VecDeque<u64>,
}

// Not `#[derive(Default)]`: that would require `D: Default`, which nothing here needs.
impl<D> Default for History<D> {
    fn default() -> Self {
        Self {
            failures: VecDeque::new(),
            successes: VecDeque::new(),
            alerted_windows: VecDeque::new(),
        }
    }
}

/// Inserts `value` keeping `deque` sorted, dropping the oldest past `cap`.
pub(crate) fn insert_sorted(deque: &mut VecDeque<u64>, value: u64, cap: usize) {
    let at = deque.partition_point(|&t| t <= value);
    deque.insert(at, value);
    if deque.len() > cap {
        deque.pop_front();
    }
}

impl<D> History<D> {
    /// Records a failure at `timestamp_ns`, oldest first, dropping the oldest past the cap.
    pub(crate) fn record_failure(&mut self, timestamp_ns: u64, params: &JoinParams) {
        insert_sorted(&mut self.failures, timestamp_ns, params.failures_cap);
    }

    /// Records a not-yet-alerted success at `timestamp_ns`, oldest first, dropping the oldest
    /// past the cap.
    pub(crate) fn record_success(&mut self, timestamp_ns: u64, detail: D, params: &JoinParams) {
        let at = self
            .successes
            .partition_point(|s| s.timestamp_ns <= timestamp_ns);
        self.successes.insert(
            at,
            Success {
                timestamp_ns,
                detail,
                alerted: false,
            },
        );
        if self.successes.len() > params.successes_cap {
            self.successes.pop_front();
        }
    }

    /// Every remembered success that now has enough failures in the window ending at it, once per
    /// window. One arrival can complete several successes (a single late failure that falls in
    /// the windows of two of them), so this returns all of them, not the first. `alert` builds
    /// the rule's alert from the success and the number of failures counted.
    pub(crate) fn join(
        &mut self,
        params: &JoinParams,
        mut alert: impl FnMut(&Success<D>, usize) -> Alert,
    ) -> Vec<Alert> {
        let mut alerts = Vec::new();
        for success in &mut self.successes {
            if success.alerted {
                continue;
            }
            let from = success.timestamp_ns.saturating_sub(params.window_ns);
            let count = self
                .failures
                .iter()
                .filter(|&&t| t >= from && t <= success.timestamp_ns)
                .count();
            let window = success.timestamp_ns / params.window_ns;
            let recent = self.alerted_windows.contains(&window);
            if count >= params.threshold && !recent {
                success.alerted = true;
                self.alerted_windows.push_back(window);
                if self.alerted_windows.len() > ALERTED_WINDOWS_CAP {
                    self.alerted_windows.pop_front();
                }
                alerts.push(alert(success, count));
            }
        }
        alerts
    }
}

#[cfg(test)]
mod tests {
    use schema::detection::Severity;

    use super::*;

    const SECOND: u64 = 1_000_000_000;

    /// Not the 5 failures in 300 s both rules use today: the join must follow the parameters it
    /// is given, so a third consumer with other numbers gets them.
    const PARAMS: JoinParams = JoinParams {
        window_ns: 10 * SECOND,
        threshold: 2,
        failures_cap: 3,
        successes_cap: 2,
    };

    /// The detail doubles as the technique, so the alert shows which success it is for (and no
    /// technique-shaped literal sits in this file: `tools/attack-coverage.py` lists those).
    fn alert(success: &Success<&'static str>, count: usize) -> Alert {
        Alert {
            technique: success.detail,
            severity: Severity::Low,
            message: format!("after {count}"),
        }
    }

    #[test]
    fn the_threshold_and_the_window_are_the_callers() {
        let mut history = History::<&'static str>::default();
        history.record_failure(SECOND, &PARAMS);
        history.record_success(5 * SECOND, "alice", &PARAMS);
        assert!(
            history.join(&PARAMS, alert).is_empty(),
            "one failure of two"
        );
        history.record_failure(2 * SECOND, &PARAMS);
        let alerts = history.join(&PARAMS, alert);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].technique, "alice", "the detail reaches the alert");
        assert_eq!(alerts[0].message, "after 2", "and so does the count");

        // A failure 11 s before the success is outside a 10 s window, 10 s before is inside.
        let mut history = History::<&'static str>::default();
        history.record_failure(4 * SECOND, &PARAMS);
        history.record_failure(5 * SECOND, &PARAMS);
        history.record_success(15 * SECOND, "bob", &PARAMS);
        let alerts = history.join(&PARAMS, alert);
        assert!(
            alerts.is_empty(),
            "the 4 s failure is 11 s before the success: outside the window"
        );
        history.record_failure(5 * SECOND + 1, &PARAMS);
        let alerts = history.join(&PARAMS, alert);
        assert_eq!(
            (alerts[0].technique, alerts[0].message.as_str()),
            ("bob", "after 2")
        );
    }

    #[test]
    fn the_caps_are_the_callers() {
        let mut history = History::<()>::default();
        for second in 0..10 {
            history.record_failure(second * SECOND, &PARAMS);
            history.record_success(second * SECOND, (), &PARAMS);
        }
        assert_eq!(
            history.failures.len(),
            3,
            "the failure cap of the parameters"
        );
        assert_eq!(
            history.successes.len(),
            2,
            "the success cap of the parameters"
        );
        assert_eq!(
            history.failures.front(),
            Some(&(7 * SECOND)),
            "oldest dropped first"
        );
    }

    #[test]
    fn inserting_out_of_order_keeps_both_histories_sorted() {
        let mut history = History::<()>::default();
        for second in [5, 1, 3, 2, 4] {
            history.record_failure(
                second * SECOND,
                &JoinParams {
                    failures_cap: 10,
                    ..PARAMS
                },
            );
        }
        assert!(history.failures.iter().is_sorted());
        for second in [5, 1, 3] {
            history.record_success(
                second * SECOND,
                (),
                &JoinParams {
                    successes_cap: 10,
                    ..PARAMS
                },
            );
        }
        assert!(history.successes.iter().map(|s| s.timestamp_ns).is_sorted());
    }

    #[test]
    fn of_two_successes_at_one_instant_the_first_to_arrive_is_the_one_alerted() {
        // Equal timestamps keep arrival order, so which success (which RDP user) an alert names
        // does not depend on a tie-break nobody chose; the second is the same window, no alert.
        let mut history = History::<&'static str>::default();
        history.record_failure(SECOND, &PARAMS);
        history.record_failure(2 * SECOND, &PARAMS);
        history.record_success(5 * SECOND, "first", &PARAMS);
        history.record_success(5 * SECOND, "second", &PARAMS);
        let alerts = history.join(&PARAMS, alert);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].technique, "first");
    }
}
