//! A local privilege-escalation success (`sudo`/`su`) that follows authentication
//! failures for the same account (#381): reported as T1548.003 (Sudo and Sudo
//! Caching) for `sudo`, T1110.001 (Brute Force: Password Guessing) for `su` —
//! `su` is a plain login prompt with no caching to abuse, so the sudo-specific
//! technique never fit it (review of #838, Sollykhan 2026-10-19, non-blocking).
//!
//! Both sides come from the same `AuthEvent` stream (`RuleState::on_auth`, one
//! journal tail, unlike T1021.001's two independent Windows event channels), so
//! out-of-order delivery is less likely here than for [`crate::rdp`] — but nothing
//! in `schema::AuthEvent` promises journal records arrive in timestamp order
//! (a restart replaying a backlog, a buffered writer), so this joins on event
//! time the same way, for the same reason: counting only what already arrived
//! would make the alert depend on delivery order.
//!
//! **`sudo` and `su` key on different things, and keep separate bounded
//! histories** (review of #838, Sollykhan 2026-10-19, point 1 — rewriting what
//! was here before):
//! - **`sudo` is keyed on [`RuleState::on_auth`]'s trusted `AuthEvent::meta.user`
//!   uid** — the `_UID` journald stamps on the reporting process, from the
//!   kernel's own view of the sender's socket credentials, never from anything
//!   the process writes into the message or names itself (`_COMM`, by contrast,
//!   is the kernel's view of `/proc/<pid>/comm`, which a local user controls
//!   just by naming the file they execute — `cp /usr/bin/logger /tmp/sudo;
//!   /tmp/sudo -t sudo 'pam_unix(sudo:auth): authentication failure; ...
//!   user=victim'` produces `_COMM=sudo` with an attacker-chosen `user=`, and
//!   used to be enough to add forged history to any victim's name). `sudo`
//!   only ever authenticates the *invoker's* own password — never learning the
//!   `-u` target on a failed attempt — so the invoker's uid is already the
//!   right join key semantically, not merely the forgery-proof one: confirmed
//!   live (Fedora 43, sudo 1.9.17p2) that one genuine wrong-then-right sudo
//!   stamps the same `_UID` on the `pam_unix(sudo:auth)` failure line and the
//!   `COMMAND=` success line.
//! - **`su` stays keyed on the real target name** `AuthEvent::target_user`
//!   names (`root`, or whoever `su` is asked for) — deliberately not changed by
//!   the point above. `su <name>` logs a failure for whatever name a local user
//!   types, with no uid of a "real" target to key on until a session actually
//!   opens, and keying on the target name is what lets several *different*
//!   invoker accounts' failed attempts against the same privileged target join
//!   into one alert (credential spraying from more than one already-compromised
//!   low-privilege account) — switching to invoker-uid keying would lose exactly
//!   that. `su`'s forgery exposure is narrower than the one above: its alert
//!   never names an invoker, so a forged line cannot frame a specific victim,
//!   only pollute or manufacture a `su target=<name>` alert — the same residual
//!   gap the throwaway-name spray below already accepts.
//!
//! History is bounded by the caps below and the least-recently-seen account,
//! never by time, for the same future-timestamp-pruning reason as [`crate::rdp`].
//! `su`'s spray of throwaway names can only displace other `su` history, never
//! `sudo`'s — they're separate maps for exactly that reason, not just because
//! they key on different things.

use schema::detection::Severity;
use store::BoundedMap;

// The tests of this module read the cap the shared join enforces.
#[cfg(test)]
use crate::failure_join::ALERTED_WINDOWS_CAP;
use crate::{
    Alert,
    exclusions::{SUDO_SUCCESS_AFTER_FAILURES_THRESHOLD, SUDO_SUCCESS_AFTER_FAILURES_WINDOW_NS},
    failure_join::{History, JoinParams},
};

/// Distinct accounts tracked per map; the least recently seen goes first.
const TARGETS_CAP: usize = 4_096;
/// Failure timestamps kept per account.
const FAILURES_PER_TARGET_CAP: usize = 256;
/// Successes kept per account until a failure can still complete their join.
const SUCCESSES_PER_TARGET_CAP: usize = 8;

/// What the shared join ([`crate::failure_join`]) is given for `sudo` and `su`: the same for
/// both, which differ only in their key and their technique.
const PARAMS: JoinParams = JoinParams {
    window_ns: SUDO_SUCCESS_AFTER_FAILURES_WINDOW_NS,
    threshold: SUDO_SUCCESS_AFTER_FAILURES_THRESHOLD as usize,
    failures_cap: FAILURES_PER_TARGET_CAP,
    successes_cap: SUCCESSES_PER_TARGET_CAP,
};

/// One account's history; a success carries nothing the alert needs.
type Target = History<()>;

/// Per-account history that joins a privilege-escalation success to the
/// authentication failures before it. See the module doc for why `sudo` and
/// `su` key on different things and keep separate maps.
pub(crate) struct SudoSuccessAfterFailures {
    /// `sudo` history, one entry per invoker uid.
    targets: BoundedMap<u32, Target>,
    /// `su` history, one entry per target name.
    su_targets: BoundedMap<String, Target>,
}

impl SudoSuccessAfterFailures {
    pub(crate) fn new() -> Self {
        Self {
            targets: BoundedMap::new(TARGETS_CAP),
            su_targets: BoundedMap::new(TARGETS_CAP),
        }
    }

    /// A `sudo` authentication failure by `invoker_uid` at `timestamp_ns`. May
    /// complete the join of successes already seen, one per window.
    pub(crate) fn on_sudo_failure(&mut self, invoker_uid: u32, timestamp_ns: u64) -> Vec<Alert> {
        let target = self
            .targets
            .get_or_insert_with(invoker_uid, Target::default);
        target.record_failure(timestamp_ns, &PARAMS);
        join(
            target,
            &format!("sudo invoker_uid={invoker_uid}"),
            SUDO_TECHNIQUE,
        )
    }

    /// A `sudo` privilege-escalation success by `invoker_uid` at `timestamp_ns`.
    pub(crate) fn on_sudo_success(&mut self, invoker_uid: u32, timestamp_ns: u64) -> Vec<Alert> {
        let target = self
            .targets
            .get_or_insert_with(invoker_uid, Target::default);
        target.record_success(timestamp_ns, (), &PARAMS);
        join(
            target,
            &format!("sudo invoker_uid={invoker_uid}"),
            SUDO_TECHNIQUE,
        )
    }

    /// An `su` authentication failure against `target_name` at `timestamp_ns`.
    /// May complete the join of successes already seen, one per window.
    pub(crate) fn on_su_failure(&mut self, target_name: &str, timestamp_ns: u64) -> Vec<Alert> {
        let target = self
            .su_targets
            .get_or_insert_with(target_name.to_string(), Target::default);
        target.record_failure(timestamp_ns, &PARAMS);
        join(target, &format!("su target={target_name}"), SU_TECHNIQUE)
    }

    /// An `su` privilege-escalation success into `target_name` at `timestamp_ns`.
    pub(crate) fn on_su_success(&mut self, target_name: &str, timestamp_ns: u64) -> Vec<Alert> {
        let target = self
            .su_targets
            .get_or_insert_with(target_name.to_string(), Target::default);
        target.record_success(timestamp_ns, (), &PARAMS);
        join(target, &format!("su target={target_name}"), SU_TECHNIQUE)
    }
}

/// ATT&CK technique reported for a `sudo` join — see the module doc for why
/// `su` reports a different one.
const SUDO_TECHNIQUE: &str = "T1548.003";
/// ATT&CK technique reported for an `su` join (review of #838, Sollykhan
/// 2026-10-19, non-blocking): `su` has no cache to abuse, so a success after
/// repeated failures is password guessing, not sudo caching.
const SU_TECHNIQUE: &str = "T1110.001";

/// The alert of every success the shared join completes. `account` is the precomputed,
/// analyst-facing label (e.g. `"sudo invoker_uid=1001"` or `"su target=root"`); `technique` is
/// [`SUDO_TECHNIQUE`] or [`SU_TECHNIQUE`] depending on which called. The join has no opinion on
/// what either means.
fn join(target: &mut Target, account: &str, technique: &'static str) -> Vec<Alert> {
    target.join(&PARAMS, |_, count| Alert {
        technique,
        severity: Severity::Medium,
        message: format!(
            "{account}: a local privilege escalation succeeded after {count} \
             failed authentications for that account in {}s: guessed or \
             sprayed credentials worked, or a shared account under sustained \
             attempts",
            SUDO_SUCCESS_AFTER_FAILURES_WINDOW_NS / 1_000_000_000,
        ),
    })
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const SECOND: u64 = 1_000_000_000;
    const EXPECTED_THRESHOLD: usize = 5;
    const EXPECTED_WINDOW_NS: u64 = 300_000_000_000;
    const EXPECTED_TARGETS_CAP: usize = 4_096;
    const EXPECTED_FAILURES_CAP: usize = 256;
    const EXPECTED_SUCCESSES_CAP: usize = 8;
    /// A fixed invoker uid for tests that only exercise the shared join
    /// mechanics (window math, ordering, cap eviction) — these behave
    /// identically regardless of whether the account is a `sudo` uid or an
    /// `su` target name, so they go through the `sudo` side arbitrarily.
    const UID: u32 = 1000;

    fn fixed_game(order: [usize; 6]) -> usize {
        let events = [
            (false, SECOND),
            (false, 2 * SECOND),
            (false, 3 * SECOND),
            (false, 4 * SECOND),
            (false, 5 * SECOND),
            (true, 10 * SECOND),
        ];
        let mut state = SudoSuccessAfterFailures::new();
        order
            .into_iter()
            .flat_map(|index| {
                let (success, timestamp) = events[index];
                if success {
                    state.on_sudo_success(UID, timestamp)
                } else {
                    state.on_sudo_failure(UID, timestamp)
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
            let mut events: Vec<(bool, u64)> = Vec::new();
            for &second in &successes {
                for before in 1..=5 {
                    events.push((false, (second - before) * SECOND));
                }
                events.push((true, second * SECOND));
            }
            let mut order: Vec<usize> = (0..events.len()).collect();
            order.sort_by_key(|&index| (keys[index], index));

            let mut state = SudoSuccessAfterFailures::new();
            let alerts = order
                .into_iter()
                .flat_map(|index| {
                    let (success, timestamp) = events[index];
                    if success {
                        state.on_sudo_success(UID, timestamp)
                    } else {
                        state.on_sudo_failure(UID, timestamp)
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
            let mut state = SudoSuccessAfterFailures::new();
            for timestamp in timestamps {
                prop_assert!(state.on_sudo_failure(UID, timestamp).is_empty());
            }
            prop_assert!(state.on_sudo_success(UID, success_at).is_empty());
        }
    }

    #[test]
    fn distinct_sudo_invokers_do_not_share_history() {
        let mut state = SudoSuccessAfterFailures::new();
        for second in 0..EXPECTED_THRESHOLD as u64 {
            state.on_sudo_failure(1000, second * SECOND);
        }
        // uid 1001 never had a failure: its success must not borrow uid 1000's.
        assert!(state.on_sudo_success(1001, 10 * SECOND).is_empty());
        assert!(!state.on_sudo_success(1000, 10 * SECOND).is_empty());
    }

    #[test]
    fn distinct_su_targets_do_not_share_history() {
        let mut state = SudoSuccessAfterFailures::new();
        for second in 0..EXPECTED_THRESHOLD as u64 {
            state.on_su_failure("root", second * SECOND);
        }
        assert!(state.on_su_success("alice", 10 * SECOND).is_empty());
        assert!(!state.on_su_success("root", 10 * SECOND).is_empty());
    }

    #[test]
    fn su_target_root_and_sudo_invoker_do_not_share_history() {
        // An `su` failure against target "root" and a `sudo` success by
        // invoker uid 0 are unrelated: the two maps are keyed on different
        // things entirely (a name vs. a uid) and never shared.
        let mut state = SudoSuccessAfterFailures::new();
        for second in 0..EXPECTED_THRESHOLD as u64 {
            state.on_su_failure("root", second * SECOND);
        }
        assert!(
            state.on_sudo_success(0, 10 * SECOND).is_empty(),
            "sudo's own uid-0 success must not borrow su's root-target failures"
        );
        assert!(!state.on_su_success("root", 10 * SECOND).is_empty());
    }

    #[test]
    fn a_su_spray_of_throwaway_names_cannot_evict_sudo_history() {
        // `su <name>` logs a failure for any name a local user types (#838
        // review): more throwaway names than the map holds must not push a real
        // `sudo` invoker's failures out before the matching success arrives.
        let mut state = SudoSuccessAfterFailures::new();
        for second in 0..EXPECTED_THRESHOLD as u64 {
            state.on_sudo_failure(0, second * SECOND);
        }
        for index in 0..(EXPECTED_TARGETS_CAP as u64 * 2) {
            state.on_su_failure(&format!("spray{index}"), 5 * SECOND + index);
        }
        assert!(
            !state.on_sudo_success(0, 10 * SECOND).is_empty(),
            "the su spray displaced sudo's history"
        );
        assert!(state.su_targets.len() <= EXPECTED_TARGETS_CAP);
    }

    #[test]
    fn the_alert_says_what_the_account_is_for_each_service() {
        let mut state = SudoSuccessAfterFailures::new();
        for second in 0..EXPECTED_THRESHOLD as u64 {
            state.on_sudo_failure(1234, second * SECOND);
            state.on_su_failure("root", second * SECOND);
        }
        let sudo_alert = state.on_sudo_success(1234, 10 * SECOND);
        let su_alert = state.on_su_success("root", 10 * SECOND);
        assert!(sudo_alert[0].message.starts_with("sudo invoker_uid=1234:"));
        assert!(su_alert[0].message.starts_with("su target=root:"));
    }

    #[test]
    fn sudo_and_su_report_different_techniques() {
        // su is a plain login prompt, not sudo caching (review of #838,
        // Sollykhan 2026-10-19, non-blocking).
        let mut state = SudoSuccessAfterFailures::new();
        for second in 0..EXPECTED_THRESHOLD as u64 {
            state.on_sudo_failure(1234, second * SECOND);
            state.on_su_failure("root", second * SECOND);
        }
        let sudo_alert = state.on_sudo_success(1234, 10 * SECOND);
        let su_alert = state.on_su_success("root", 10 * SECOND);
        assert_eq!(sudo_alert[0].technique, "T1548.003");
        assert_eq!(su_alert[0].technique, "T1110.001");
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
            let mut state = SudoSuccessAfterFailures::new();
            for timestamp in before {
                state.on_sudo_failure(UID, timestamp);
            }
            state.on_sudo_failure(UID, boundary);
            assert_eq!(
                !state.on_sudo_success(UID, success).is_empty(),
                expected,
                "boundary timestamp {boundary}"
            );
        }
    }

    #[test]
    fn failure_cap_evicts_oldest_and_keeps_a_valid_alert() {
        let mut state = SudoSuccessAfterFailures::new();
        for second in 0..=EXPECTED_FAILURES_CAP as u64 {
            state.on_sudo_failure(UID, second * SECOND);
        }
        let target = state.targets.iter().next().unwrap().1;
        assert_eq!(target.failures.len(), EXPECTED_FAILURES_CAP);
        assert_eq!(target.failures.front(), Some(&SECOND));
        assert!(!state.on_sudo_success(UID, 300 * SECOND).is_empty());
    }

    #[test]
    fn ninth_success_evicts_oldest_but_newer_success_can_still_alert() {
        let mut state = SudoSuccessAfterFailures::new();
        for second in 100..109 {
            state.on_sudo_success(UID, second * SECOND);
        }
        let target = state.targets.iter().next().unwrap().1;
        assert_eq!(target.successes.len(), EXPECTED_SUCCESSES_CAP);
        assert_eq!(target.successes.front().unwrap().timestamp_ns, 101 * SECOND);
        for second in 100..105 {
            state.on_sudo_failure(UID, second * SECOND);
        }
        assert!(
            state
                .targets
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
    fn out_of_order_timestamps_join_by_event_time() {
        let mut state = SudoSuccessAfterFailures::new();
        state.on_sudo_success(UID, 10 * SECOND);
        for second in [9, 2, 8, 1, 7] {
            let alert = state.on_sudo_failure(UID, second * SECOND);
            if second != 7 {
                assert!(alert.is_empty());
            } else {
                assert!(!alert.is_empty());
            }
        }
    }

    #[test]
    fn alerted_windows_evict_the_oldest_at_the_fixed_cap() {
        let mut state = SudoSuccessAfterFailures::new();
        let mut alerts = 0;
        for window in 0..=ALERTED_WINDOWS_CAP as u64 {
            let start = window * SUDO_SUCCESS_AFTER_FAILURES_WINDOW_NS;
            for offset in 0..SUDO_SUCCESS_AFTER_FAILURES_THRESHOLD as u64 {
                assert!(state.on_sudo_failure(UID, start + offset).is_empty());
            }
            alerts += state.on_sudo_success(UID, start + 10).len();
        }

        let target = state.targets.iter().next().unwrap().1;
        assert_eq!(alerts, ALERTED_WINDOWS_CAP + 1);
        assert_eq!(target.alerted_windows.len(), ALERTED_WINDOWS_CAP);
        assert_eq!(target.alerted_windows.front(), Some(&1));
        assert_eq!(
            target.alerted_windows.back(),
            Some(&(ALERTED_WINDOWS_CAP as u64))
        );
    }

    #[test]
    fn zero_and_u64_max_timestamps_do_not_overflow() {
        let mut at_zero = SudoSuccessAfterFailures::new();
        for _ in 0..EXPECTED_THRESHOLD {
            at_zero.on_sudo_failure(UID, 0);
        }
        assert!(!at_zero.on_sudo_success(UID, 0).is_empty());

        let mut at_max = SudoSuccessAfterFailures::new();
        for _ in 0..EXPECTED_THRESHOLD {
            at_max.on_sudo_failure(UID, u64::MAX);
        }
        assert!(!at_max.on_sudo_success(UID, u64::MAX).is_empty());
    }

    #[test]
    fn one_hundred_thousand_pseudorandom_events_respect_every_capacity() {
        let mut state = SudoSuccessAfterFailures::new();
        let mut random = 0x4d59_5df4_d0f3_3173_u64;
        for index in 0..100_000 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let uid = (random >> 16) as u32 % (EXPECTED_TARGETS_CAP as u32 * 2);
            let timestamp = random.rotate_left(23);
            if random & 1 == 0 {
                state.on_sudo_failure(uid, timestamp);
            } else {
                state.on_sudo_success(uid, timestamp);
            }
            if index % 256 == 255 || index == 99_999 {
                assert!(state.targets.len() <= EXPECTED_TARGETS_CAP);
                assert!(state.targets.iter().all(|(_, target)| {
                    target.failures.len() <= EXPECTED_FAILURES_CAP
                        && target.successes.len() <= EXPECTED_SUCCESSES_CAP
                }));
            }
        }
    }
}
