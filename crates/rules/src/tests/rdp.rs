//! RDP success-after-failures rule (T1021.001).

use schema::{AuthEvent, AuthKind, AuthOutcome, SessionEvent, SessionState};

use super::*;
use crate::exclusions::{
    RDP_SUCCESS_AFTER_FAILURES_THRESHOLD, RDP_SUCCESS_AFTER_FAILURES_WINDOW_NS,
};

const SEC: u64 = 1_000_000_000;

fn failure(source: &str, user: &str, ts: u64) -> AuthEvent {
    AuthEvent {
        meta: EventMeta {
            timestamp_ns: ts,
            ..meta()
        },
        outcome: AuthOutcome::Failure,
        kind: AuthKind::LogonFailure,
        target_user: user.to_string(),
        target_user_sid: None,
        source_address: Some(source.parse().unwrap()),
        status_code: None,
    }
}

fn connect(source: Option<&str>, user: &str, ts: u64) -> SessionEvent {
    SessionEvent {
        meta: EventMeta {
            timestamp_ns: ts,
            ..meta()
        },
        state: SessionState::Connect,
        session_id: None,
        target_user: user.to_string(),
        source_address: source.map(|address| address.parse().unwrap()),
        console: false,
    }
}

#[test]
fn connect_after_five_failures_across_accounts_alerts_once_per_window() {
    let mut state = RuleState::new();
    for i in 0..u64::from(RDP_SUCCESS_AFTER_FAILURES_THRESHOLD) {
        let user = if i % 2 == 0 { "alice" } else { "bob" };
        state.on_auth(&failure("192.0.2.50", user, i * SEC));
    }

    let success = connect(Some("192.0.2.50"), "LAB\\alice", 10 * SEC);
    let alerts = state.on_session(&success);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1021.001");
    assert_eq!(alerts[0].severity, schema::detection::Severity::High);
    assert!(alerts[0].message.contains("LAB\\alice"));
    assert!(alerts[0].message.contains("192.0.2.50"));
    assert!(alerts[0].message.contains("5 failed authentications"));
    assert!(state.on_session(&success).is_empty());
}

#[test]
fn connect_below_threshold_does_not_alert() {
    let mut state = RuleState::new();
    for i in 0..u64::from(RDP_SUCCESS_AFTER_FAILURES_THRESHOLD - 1) {
        state.on_auth(&failure("192.0.2.50", "alice", i * SEC));
    }
    assert!(
        state
            .on_session(&connect(Some("192.0.2.50"), "alice", 10 * SEC))
            .is_empty()
    );
}

#[test]
fn failures_from_another_source_do_not_count() {
    let mut state = RuleState::new();
    for i in 0..u64::from(RDP_SUCCESS_AFTER_FAILURES_THRESHOLD) {
        state.on_auth(&failure("192.0.2.50", "alice", i * SEC));
    }
    assert!(
        state
            .on_session(&connect(Some("192.0.2.51"), "alice", 10 * SEC))
            .is_empty()
    );
}

#[test]
fn failures_outside_the_window_do_not_count() {
    let mut state = RuleState::new();
    for i in 0..u64::from(RDP_SUCCESS_AFTER_FAILURES_THRESHOLD) {
        state.on_auth(&failure("192.0.2.50", "alice", i * SEC));
    }
    let success_ts = RDP_SUCCESS_AFTER_FAILURES_WINDOW_NS + 5 * SEC;
    assert!(
        state
            .on_session(&connect(Some("192.0.2.50"), "alice", success_ts))
            .is_empty()
    );
}

#[test]
fn console_or_addressless_connect_never_alerts() {
    let mut state = RuleState::new();
    for i in 0..u64::from(RDP_SUCCESS_AFTER_FAILURES_THRESHOLD) {
        state.on_auth(&failure("192.0.2.50", "alice", i * SEC));
    }

    let mut console = connect(Some("192.0.2.50"), "alice", 10 * SEC);
    console.console = true;
    assert!(state.on_session(&console).is_empty());
    assert!(
        state
            .on_session(&connect(None, "alice", 10 * SEC))
            .is_empty()
    );
}
