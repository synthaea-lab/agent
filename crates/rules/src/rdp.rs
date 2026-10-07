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
//! The failures are every authentication failure with a source address, from
//! any source (`Event::Auth` also carries application-log failures), not only
//! RDP ones.

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
    /// When the last alert for this address fired: one alert per window.
    last_alert_ns: Option<u64>,
    /// The newest timestamp seen, which the history is pruned against.
    newest_ns: u64,
}

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
        source.touch(timestamp_ns);
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
        source.touch(timestamp_ns);
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
    /// Records the newest timestamp and drops what no later arrival can use:
    /// events older than two windows before it. Two windows, not one, because
    /// the other channel's events can trail by a poll interval or more.
    fn touch(&mut self, timestamp_ns: u64) {
        self.newest_ns = self.newest_ns.max(timestamp_ns);
        let keep_from = self
            .newest_ns
            .saturating_sub(2 * RDP_SUCCESS_AFTER_FAILURES_WINDOW_NS);
        while self.failures.front().is_some_and(|&t| t < keep_from) {
            self.failures.pop_front();
        }
        while self
            .successes
            .front()
            .is_some_and(|s| s.timestamp_ns < keep_from)
        {
            self.successes.pop_front();
        }
    }

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
            let recent = self.last_alert_ns.is_some_and(|last| {
                last.abs_diff(success.timestamp_ns) <= RDP_SUCCESS_AFTER_FAILURES_WINDOW_NS
            });
            if count >= RDP_SUCCESS_AFTER_FAILURES_THRESHOLD as usize && !recent {
                success.alerted = true;
                self.last_alert_ns = Some(success.timestamp_ns);
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
