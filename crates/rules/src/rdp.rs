//! An RDP authentication that succeeds after authentication failures from the
//! same address, T1021.001 (Remote Services: Remote Desktop Protocol, #285).
//!
//! The failures (`Event::Auth`, 4625) and the success (`SessionState::Connect`,
//! 1149) come from two different Windows event channels, read on independent
//! poll threads, so the success can reach the rules *before* the last failures
//! that precede it. Counting only what has already arrived would make the
//! alert depend on the phase of two timers. This joins on the events' own
//! timestamps instead: a success is remembered, a failure that arrives later is
//! checked against the successes it falls before, and either arrival can
//! complete the join. A failure timestamped after the success never counts.
//!
//! History is bounded by the caps below and the least-recently-seen address, never
//! by time: pruning against the newest timestamp seen would let one event far in the
//! future (a clock step, a stalled channel catching up) erase what a late event still
//! needs, and the alert count would depend on delivery order again.
//!
//! The failures are the Windows Security-log failures that carry a source address
//! (the caller, `RuleState::on_auth`, only passes events with a Windows identity:
//! application-log failures are stamped when the line is read, not with event time),
//! from any logon type, not only RDP ones.

use std::{collections::VecDeque, net::IpAddr};

use schema::detection::Severity;
use store::BoundedMap;

use crate::{
    Alert,
    exclusions::{RDP_SUCCESS_AFTER_FAILURES_THRESHOLD, RDP_SUCCESS_AFTER_FAILURES_WINDOW_NS},
};

/// Distinct source addresses tracked; the least recently seen goes first, so a
/// flood of fabricated addresses cannot grow memory without limit.
const SOURCES_CAP: usize = 4_096;
/// Failure timestamps kept per address: enough to prove the threshold, not to
/// archive a spray (same reasoning as the sliding counters' cap).
const FAILURES_PER_SOURCE_CAP: usize = 256;
/// Successes kept per address until a failure can still complete their join.
const SUCCESSES_PER_SOURCE_CAP: usize = 8;

struct Success {
    timestamp_ns: u64,
    user: String,
    alerted: bool,
}

#[derive(Default)]
struct Source {
    /// Failure timestamps, oldest first.
    failures: VecDeque<u64>,
    /// Successes, oldest first.
    successes: VecDeque<Success>,
    /// The fixed windows (`timestamp / window`) an alert already fired for: one alert
    /// per window per address. Fixed slots, not "within a window of the last alert":
    /// the latter moves with the order alerts are emitted in, so the number of alerts
    /// would depend on delivery order again (a success at 0, 400 and 700 s gave 2 or 3).
    alerted_windows: VecDeque<u64>,
}

/// Alerted windows remembered per address. Far more than the successes kept.
const ALERTED_WINDOWS_CAP: usize = 16;

/// Per-address history that joins an RDP success to the failures before it.
pub(crate) struct RdpSuccessAfterFailures {
    sources: BoundedMap<IpAddr, Source>,
}

impl RdpSuccessAfterFailures {
    pub(crate) fn new() -> Self {
        Self {
            sources: BoundedMap::new(SOURCES_CAP),
        }
    }

    /// An authentication failure from `address` at `timestamp_ns`. May complete
    /// the join of a success that was already seen.
    pub(crate) fn on_failure(&mut self, address: IpAddr, timestamp_ns: u64) -> Option<Alert> {
        let address = address.to_canonical();
        let source = self.sources.get_or_insert_with(address, Source::default);
        insert_sorted(&mut source.failures, timestamp_ns, FAILURES_PER_SOURCE_CAP);
        source.join(address)
    }

    /// An RDP authentication from `address` succeeded at `timestamp_ns`.
    pub(crate) fn on_success(
        &mut self,
        address: IpAddr,
        timestamp_ns: u64,
        user: &str,
    ) -> Option<Alert> {
        let address = address.to_canonical();
        let source = self.sources.get_or_insert_with(address, Source::default);
        let at = source
            .successes
            .partition_point(|s| s.timestamp_ns <= timestamp_ns);
        source.successes.insert(
            at,
            Success {
                timestamp_ns,
                user: user.to_string(),
                alerted: false,
            },
        );
        if source.successes.len() > SUCCESSES_PER_SOURCE_CAP {
            source.successes.pop_front();
        }
        source.join(address)
    }
}

/// Inserts `value` keeping `deque` sorted, dropping the oldest past `cap`.
fn insert_sorted(deque: &mut VecDeque<u64>, value: u64, cap: usize) {
    let at = deque.partition_point(|&t| t <= value);
    deque.insert(at, value);
    if deque.len() > cap {
        deque.pop_front();
    }
}

impl Source {
    /// The first remembered success that now has enough failures in the window
    /// ending at it, once per window.
    fn join(&mut self, address: IpAddr) -> Option<Alert> {
        for success in &mut self.successes {
            if success.alerted {
                continue;
            }
            let from = success
                .timestamp_ns
                .saturating_sub(RDP_SUCCESS_AFTER_FAILURES_WINDOW_NS);
            let count = self
                .failures
                .iter()
                .filter(|&&t| t >= from && t <= success.timestamp_ns)
                .count();
            let window = success.timestamp_ns / RDP_SUCCESS_AFTER_FAILURES_WINDOW_NS;
            let recent = self.alerted_windows.contains(&window);
            if count >= RDP_SUCCESS_AFTER_FAILURES_THRESHOLD as usize && !recent {
                success.alerted = true;
                self.alerted_windows.push_back(window);
                if self.alerted_windows.len() > ALERTED_WINDOWS_CAP {
                    self.alerted_windows.pop_front();
                }
                return Some(Alert {
                    technique: "T1021.001",
                    severity: Severity::Medium,
                    message: format!(
                        "user={} source={address}: RDP authentication succeeded after {count} \
                         failed authentications from that address in {}s: guessed or sprayed \
                         credentials worked, or a shared address (NAT, RD Gateway)",
                        success.user,
                        RDP_SUCCESS_AFTER_FAILURES_WINDOW_NS / 1_000_000_000,
                    ),
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const SECOND: u64 = 1_000_000_000;
    const EXPECTED_THRESHOLD: usize = 5;
    const EXPECTED_WINDOW_NS: u64 = 300_000_000_000;
    const EXPECTED_SOURCES_CAP: usize = 4_096;
    const EXPECTED_FAILURES_CAP: usize = 256;
    const EXPECTED_SUCCESSES_CAP: usize = 8;
    const ADDRESS: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 7));

    fn fixed_game(order: [usize; 6]) -> usize {
        let events = [
            (false, SECOND),
            (false, 2 * SECOND),
            (false, 3 * SECOND),
            (false, 4 * SECOND),
            (false, 5 * SECOND),
            (true, 10 * SECOND),
        ];
        let mut state = RdpSuccessAfterFailures::new();
        order
            .into_iter()
            .filter_map(|index| {
                let (success, timestamp) = events[index];
                if success {
                    state.on_success(ADDRESS, timestamp, "alice")
                } else {
                    state.on_failure(ADDRESS, timestamp)
                }
            })
            .count()
    }

    proptest! {
        #[test]
        fn every_permutation_of_one_game_has_the_same_alert_count(keys in any::<[u32; 6]>()) {
            let mut order = [0, 1, 2, 3, 4, 5];
            order.sort_by_key(|&index| (keys[index], index));
            prop_assert_eq!(fixed_game(order), 1);
        }

        #[test]
        fn several_successes_alert_once_per_window_in_any_delivery_order(
            successes in prop::collection::vec(301_u64..5_000, 1..=6),
            keys in prop::collection::vec(any::<u32>(), 36),
        ) {
            // Each success has five failures in the seconds before it; the
            // reference is independent of the code under test: one alert per
            // distinct fixed window that holds a success.
            let mut events: Vec<(bool, u64)> = Vec::new();
            for &second in &successes {
                for before in 1..=5 {
                    events.push((false, (second - before) * SECOND));
                }
                events.push((true, second * SECOND));
            }
            let mut order: Vec<usize> = (0..events.len()).collect();
            order.sort_by_key(|&index| (keys[index], index));

            let mut state = RdpSuccessAfterFailures::new();
            let alerts = order
                .into_iter()
                .filter_map(|index| {
                    let (success, timestamp) = events[index];
                    if success {
                        state.on_success(ADDRESS, timestamp, "alice")
                    } else {
                        state.on_failure(ADDRESS, timestamp)
                    }
                })
                .count();

            let mut windows: Vec<u64> = successes
                .iter()
                .map(|second| second * SECOND / EXPECTED_WINDOW_NS)
                .collect();
            windows.sort_unstable();
            windows.dedup();
            prop_assert_eq!(alerts, windows.len());
        }

        #[test]
        fn fewer_than_five_failures_never_alert(
            timestamps in prop::collection::vec(any::<u64>(), 0..5),
            success_at in any::<u64>(),
        ) {
            let mut state = RdpSuccessAfterFailures::new();
            for timestamp in timestamps {
                prop_assert!(state.on_failure(ADDRESS, timestamp).is_none());
            }
            prop_assert!(state.on_success(ADDRESS, success_at, "alice").is_none());
        }
    }

    #[test]
    fn ipv4_and_its_ipv4_mapped_ipv6_form_share_one_source() {
        let mut state = RdpSuccessAfterFailures::new();
        for second in 0..EXPECTED_THRESHOLD as u64 {
            state.on_failure("::ffff:192.0.2.7".parse().unwrap(), second * SECOND);
        }
        assert!(state.on_success(ADDRESS, 10 * SECOND, "alice").is_some());
        assert_eq!(state.sources.len(), 1);
    }

    #[test]
    fn exact_window_boundaries_are_inclusive_at_both_ends() {
        let success = 500 * SECOND;
        let window = EXPECTED_WINDOW_NS;
        let before = [
            success - 4 * SECOND,
            success - 3 * SECOND,
            success - 2 * SECOND,
            success - SECOND,
        ];

        for (boundary, expected) in [
            (success - window, true),
            (success - window - 1, false),
            (success, true),
            (success + 1, false),
        ] {
            let mut state = RdpSuccessAfterFailures::new();
            for timestamp in before {
                state.on_failure(ADDRESS, timestamp);
            }
            state.on_failure(ADDRESS, boundary);
            assert_eq!(
                state.on_success(ADDRESS, success, "alice").is_some(),
                expected,
                "boundary timestamp {boundary}"
            );
        }
    }

    #[test]
    fn failure_cap_evicts_oldest_and_keeps_a_valid_alert() {
        let mut state = RdpSuccessAfterFailures::new();
        for second in 0..=EXPECTED_FAILURES_CAP as u64 {
            state.on_failure(ADDRESS, second * SECOND);
        }
        let source = state.sources.iter().next().unwrap().1;
        assert_eq!(source.failures.len(), EXPECTED_FAILURES_CAP);
        assert_eq!(source.failures.front(), Some(&SECOND));
        assert!(state.on_success(ADDRESS, 300 * SECOND, "alice").is_some());
    }

    #[test]
    fn ninth_success_evicts_oldest_but_newer_success_can_still_alert() {
        let mut state = RdpSuccessAfterFailures::new();
        for second in 100..109 {
            state.on_success(ADDRESS, second * SECOND, "alice");
        }
        let source = state.sources.iter().next().unwrap().1;
        assert_eq!(source.successes.len(), EXPECTED_SUCCESSES_CAP);
        assert_eq!(source.successes.front().unwrap().timestamp_ns, 101 * SECOND);
        for second in 100..105 {
            state.on_failure(ADDRESS, second * SECOND);
        }
        assert!(
            state
                .sources
                .iter()
                .next()
                .unwrap()
                .1
                .successes
                .iter()
                .any(|success| success.alerted)
        );
    }

    #[test]
    fn alert_count_for_successes_at_0_400_and_700_seconds_does_not_depend_on_order() {
        // The review example: the second success handled first used to give 3
        // alerts instead of 2 (the last-alert timestamp moved backwards).
        let successes = [(5_u64, 0_u64), (405, 400), (705, 700)];
        for order in [
            [0, 1, 2],
            [1, 0, 2],
            [2, 1, 0],
            [1, 2, 0],
            [0, 2, 1],
            [2, 0, 1],
        ] {
            let mut state = RdpSuccessAfterFailures::new();
            let mut alerts = 0;
            for index in order {
                let (_, second) = successes[index];
                for before in 1..=5 {
                    let at = (second + 10).saturating_sub(before) * SECOND;
                    alerts += usize::from(state.on_failure(ADDRESS, at).is_some());
                }
                alerts += usize::from(
                    state
                        .on_success(ADDRESS, (second + 10) * SECOND, "alice")
                        .is_some(),
                );
            }
            assert_eq!(alerts, 3, "order {order:?}");
        }
    }

    #[test]
    fn out_of_order_timestamps_join_by_event_time() {
        let mut state = RdpSuccessAfterFailures::new();
        state.on_success(ADDRESS, 10 * SECOND, "alice");
        for second in [9, 2, 8, 1, 7] {
            let alert = state.on_failure(ADDRESS, second * SECOND);
            if second != 7 {
                assert!(alert.is_none());
            } else {
                assert!(alert.is_some());
            }
        }
    }

    #[test]
    fn arbitrary_large_timestamp_reordering_keeps_the_alert_count() {
        let mut chronological = RdpSuccessAfterFailures::new();
        let mut reordered = RdpSuccessAfterFailures::new();
        let mut chronological_alerts = 0;
        let mut reordered_alerts = 0;
        for second in 1..=5 {
            chronological_alerts +=
                usize::from(chronological.on_failure(ADDRESS, second * SECOND).is_some());
        }
        chronological_alerts += usize::from(
            chronological
                .on_success(ADDRESS, 10 * SECOND, "alice")
                .is_some(),
        );
        chronological_alerts +=
            usize::from(chronological.on_failure(ADDRESS, 1_000 * SECOND).is_some());

        reordered_alerts += usize::from(reordered.on_failure(ADDRESS, 1_000 * SECOND).is_some());
        for second in 1..=5 {
            reordered_alerts +=
                usize::from(reordered.on_failure(ADDRESS, second * SECOND).is_some());
        }
        reordered_alerts += usize::from(
            reordered
                .on_success(ADDRESS, 10 * SECOND, "alice")
                .is_some(),
        );

        assert_eq!(reordered_alerts, chronological_alerts);
    }

    #[test]
    fn zero_and_u64_max_timestamps_do_not_overflow() {
        let mut at_zero = RdpSuccessAfterFailures::new();
        for _ in 0..EXPECTED_THRESHOLD {
            at_zero.on_failure(ADDRESS, 0);
        }
        assert!(at_zero.on_success(ADDRESS, 0, "alice").is_some());

        let mut at_max = RdpSuccessAfterFailures::new();
        for _ in 0..EXPECTED_THRESHOLD {
            at_max.on_failure(ADDRESS, u64::MAX);
        }
        assert!(at_max.on_success(ADDRESS, u64::MAX, "alice").is_some());
    }

    #[test]
    fn one_hundred_thousand_pseudorandom_events_respect_every_capacity() {
        let mut state = RdpSuccessAfterFailures::new();
        let mut random = 0x4d59_5df4_d0f3_3173_u64;
        for index in 0..100_000 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let address = IpAddr::V4(std::net::Ipv4Addr::from((random >> 16) as u32));
            let timestamp = random.rotate_left(23);
            if random & 1 == 0 {
                state.on_failure(address, timestamp);
            } else {
                state.on_success(address, timestamp, "user");
            }
            if index % 256 == 255 || index == 99_999 {
                assert!(state.sources.len() <= EXPECTED_SOURCES_CAP);
                assert!(state.sources.iter().all(|(_, source)| {
                    source.failures.len() <= EXPECTED_FAILURES_CAP
                        && source.successes.len() <= EXPECTED_SUCCESSES_CAP
                }));
            }
        }
    }
}
