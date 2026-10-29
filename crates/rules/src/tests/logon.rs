//! FIRST-SEEN-LOGON (T1078, #376): the first successful logon of an account after the
//! learning window.

use schema::{AuthEvent, AuthKind, AuthOutcome, User, detection::Severity};

use super::*;
use crate::exclusions::LOGON_LEARNING_NS;

const HOUR: u64 = 3_600_000_000_000;

fn logon(user: &str, ts: u64) -> AuthEvent {
    AuthEvent {
        target_user: user.to_string(),
        meta: EventMeta {
            timestamp_ns: ts,
            ..schema::fixtures::meta()
        },
        ..schema::fixtures::auth()
    }
}

fn first_seen(state: &mut RuleState, user: &str, ts: u64) -> Vec<crate::Alert> {
    state
        .on_auth(&logon(user, ts))
        .into_iter()
        .filter(|a| a.technique == "T1078")
        .collect()
}

/// A state whose learning window is over: `alice` logged on at t = 0 and it is 25 h later.
fn after_the_window() -> (RuleState, u64) {
    let mut state = RuleState::new();
    assert!(first_seen(&mut state, "alice", 0).is_empty());
    (state, 25 * HOUR)
}

#[test]
fn an_account_first_seen_after_the_window_alerts_once() {
    let (mut state, now) = after_the_window();
    let mut event = logon("mallory", now);
    event.source_address = Some("203.0.113.9".parse().unwrap());
    let alerts: Vec<_> = state
        .on_auth(&event)
        .into_iter()
        .filter(|a| a.technique == "T1078")
        .collect();
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(alerts[0].severity, Severity::Low);
    assert!(
        alerts[0].message.contains("mallory"),
        "{}",
        alerts[0].message
    );
    assert!(
        alerts[0].message.contains("203.0.113.9"),
        "{}",
        alerts[0].message
    );
    // It is in the baseline now.
    assert!(first_seen(&mut state, "mallory", now + HOUR).is_empty());
}

#[test]
fn accounts_seen_inside_the_window_are_learned_without_an_alert() {
    let mut state = RuleState::new();
    assert!(first_seen(&mut state, "alice", 0).is_empty());
    assert!(first_seen(&mut state, "bob", HOUR).is_empty());
    assert!(first_seen(&mut state, "carol", LOGON_LEARNING_NS - 1).is_empty());
    // After the window those three are known.
    for user in ["alice", "bob", "carol"] {
        assert!(first_seen(&mut state, user, 30 * HOUR).is_empty(), "{user}");
    }
    assert_eq!(first_seen(&mut state, "dave", 30 * HOUR).len(), 1);
}

#[test]
fn the_window_is_measured_from_the_first_logon_of_any_account_generic_included() {
    let mut state = RuleState::new();
    // Only `root` logs on for a day; the clock started with it.
    assert!(first_seen(&mut state, "root", 0).is_empty());
    assert!(first_seen(&mut state, "root", 12 * HOUR).is_empty());
    assert_eq!(
        first_seen(&mut state, "mallory", LOGON_LEARNING_NS).len(),
        1
    );
}

#[test]
fn generic_accounts_never_alert() {
    let (mut state, now) = after_the_window();
    for user in [
        "root",
        "SYSTEM",
        "NT AUTHORITY\\SYSTEM",
        "CORP\\Administrator",
        "WS01$",
        "DWM-2",
        "ANONYMOUS LOGON",
        "ubuntu",
        "ec2-user",
        "admin",
    ] {
        assert!(first_seen(&mut state, user, now).is_empty(), "{user}");
    }
}

#[test]
fn vagrant_is_not_generic() {
    let (mut state, now) = after_the_window();
    assert_eq!(first_seen(&mut state, "vagrant", now).len(), 1);
}

#[test]
fn a_failed_logon_never_counts_however_new_the_name() {
    let (mut state, now) = after_the_window();
    let mut event = logon("mallory", now);
    event.outcome = AuthOutcome::Failure;
    event.kind = AuthKind::LogonFailure;
    assert!(state.on_auth(&event).iter().all(|a| a.technique != "T1078"));
    // The failed name did not enter the baseline either: the first success still alerts.
    assert_eq!(first_seen(&mut state, "mallory", now + HOUR).len(), 1);
}

#[test]
fn sudo_su_and_privileged_sessions_are_not_logons() {
    let (mut state, now) = after_the_window();
    for kind in [AuthKind::ExplicitCredentials, AuthKind::PrivilegedSession] {
        let mut event = logon("mallory", now);
        event.kind = kind;
        event.meta.comm = "su".to_string();
        assert!(state.on_auth(&event).iter().all(|a| a.technique != "T1078"));
    }
    assert_eq!(first_seen(&mut state, "mallory", now + HOUR).len(), 1);
}

#[test]
fn the_account_is_compared_without_regard_to_case() {
    let (mut state, now) = after_the_window();
    assert!(first_seen(&mut state, "ALICE", now).is_empty());
    assert_eq!(first_seen(&mut state, "Mallory", now).len(), 1);
    assert!(first_seen(&mut state, "mallory", now + HOUR).is_empty());
}

#[test]
fn a_windows_logon_is_covered_too() {
    let mut state = RuleState::new();
    let windows = |user: &str, ts: u64| {
        let mut event = logon(user, ts);
        event.meta.user = User::Windows {
            sid: "S-1-5-21-1-2-3-1001".to_string(),
            integrity_level: None,
        };
        event
    };
    assert!(state.on_auth(&windows("CORP\\alice", 0)).is_empty());
    let alerts = state.on_auth(&windows("CORP\\bob", 25 * HOUR));
    assert_eq!(
        alerts.iter().filter(|a| a.technique == "T1078").count(),
        1,
        "{alerts:?}"
    );
}

#[test]
fn an_empty_account_name_is_ignored() {
    let (mut state, now) = after_the_window();
    assert!(first_seen(&mut state, "", now).is_empty());
}

#[test]
fn an_event_older_than_the_baseline_start_is_inside_the_window() {
    let mut state = RuleState::new();
    assert!(first_seen(&mut state, "alice", 100 * HOUR).is_empty());
    assert!(first_seen(&mut state, "bob", 0).is_empty());
}

#[test]
fn the_baseline_is_bounded_and_an_evicted_account_is_first_seen_again() {
    let (mut state, now) = after_the_window();
    for i in 0..(COUNTER_CAP + 10) {
        first_seen(&mut state, &format!("user{i}"), now);
    }
    // `alice` was the oldest entry and is gone; the newest are still known.
    assert_eq!(first_seen(&mut state, "alice", now + HOUR).len(), 1);
    assert!(first_seen(&mut state, &format!("user{}", COUNTER_CAP + 9), now + HOUR).is_empty());
}

#[test]
fn the_failure_burst_and_the_first_seen_alert_are_independent() {
    let (mut state, now) = after_the_window();
    let mut techniques = Vec::new();
    for i in 0..u64::from(AUTH_FAILURE_THRESHOLD) {
        let mut event = logon("mallory", now + i);
        event.outcome = AuthOutcome::Failure;
        event.kind = AuthKind::LogonFailure;
        techniques.extend(state.on_auth(&event).iter().map(|a| a.technique));
    }
    techniques.extend(
        state
            .on_auth(&logon("mallory", now + HOUR))
            .iter()
            .map(|a| a.technique),
    );
    assert_eq!(techniques, ["T1110", "T1078"]);
}

#[test]
fn the_outcome_gates_the_rule_on_its_own() {
    // No sensor pairs a failed outcome with `AuthKind::Logon`; the rule still must not trust
    // the kind alone: a failure's user name is chosen by whoever tries it.
    let (mut state, now) = after_the_window();
    let mut event = logon("mallory", now);
    event.outcome = AuthOutcome::Failure;
    assert!(state.on_auth(&event).iter().all(|a| a.technique != "T1078"));
}
