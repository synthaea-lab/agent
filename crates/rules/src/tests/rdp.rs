//! RDP success-after-failures rule (T1021.001).

use schema::{AuthEvent, AuthOutcome, SessionEvent, SessionState, User, fixtures};

use super::*;
use crate::exclusions::{
    RDP_SUCCESS_AFTER_FAILURES_THRESHOLD, RDP_SUCCESS_AFTER_FAILURES_WINDOW_NS,
};

const SEC: u64 = 1_000_000_000;
const THRESHOLD: u64 = RDP_SUCCESS_AFTER_FAILURES_THRESHOLD as u64;

fn failure(source: &str, user: &str, ts: u64) -> AuthEvent {
    AuthEvent {
        meta: EventMeta {
            timestamp_ns: ts,
            user: User::Windows {
                sid: "S-1-5-18".into(),
                integrity_level: None,
            },
            ..meta()
        },
        outcome: AuthOutcome::Failure,
        target_user: user.to_string(),
        source_address: Some(source.parse().unwrap()),
        ..fixtures::auth()
    }
}

fn connect(source: Option<&str>, user: &str, ts: u64) -> SessionEvent {
    let mut event = fixtures::session();
    event.meta = EventMeta {
        timestamp_ns: ts,
        ..meta()
    };
    event.state = SessionState::Connect;
    event.session_id = None;
    event.target_user = user.to_string();
    event.source_address = source.map(|address| address.parse().unwrap());
    event.console = false;
    event
}

#[test]
fn connect_after_five_failures_across_accounts_alerts_once_per_window() {
    let mut state = RuleState::new();
    for i in 0..THRESHOLD {
        let user = if i % 2 == 0 { "alice" } else { "bob" };
        state.on_auth(&failure("192.0.2.50", user, i * SEC));
    }

    let success = connect(Some("192.0.2.50"), "LAB\\alice", 10 * SEC);
    let alerts = state.on_session(&success);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1021.001");
    assert_eq!(alerts[0].severity, schema::detection::Severity::Medium);
    assert!(alerts[0].message.contains("LAB\\alice"));
    assert!(alerts[0].message.contains("192.0.2.50"));
    assert!(alerts[0].message.contains("5 failed authentications"));
    assert!(state.on_session(&success).is_empty());
}

#[test]
fn application_log_failures_do_not_feed_the_join() {
    // A `[logs]` source stamps its failures when the line is read, not with the event's
    // own time: they must not complete a join that runs on event time.
    let mut state = RuleState::new();
    for i in 0..THRESHOLD {
        let mut failure = failure("192.0.2.50", "alice", i * SEC);
        failure.meta.user = User::Unknown;
        state.on_auth(&failure);
    }
    assert!(
        state
            .on_session(&connect(Some("192.0.2.50"), "alice", 10 * SEC))
            .is_empty()
    );
}

#[test]
fn connect_below_threshold_does_not_alert() {
    let mut state = RuleState::new();
    for i in 0..THRESHOLD - 1 {
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
    for i in 0..THRESHOLD {
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
    for i in 0..THRESHOLD {
        state.on_auth(&failure("192.0.2.50", "alice", i * SEC));
    }
    let late = RDP_SUCCESS_AFTER_FAILURES_WINDOW_NS + 10 * SEC;
    assert!(
        state
            .on_session(&connect(Some("192.0.2.50"), "alice", late))
            .is_empty()
    );
}

#[test]
fn connect_without_a_source_address_is_ignored() {
    let mut state = RuleState::new();
    for i in 0..THRESHOLD {
        state.on_auth(&failure("192.0.2.50", "alice", i * SEC));
    }
    assert!(
        state
            .on_session(&connect(None, "alice", 10 * SEC))
            .is_empty()
    );
}

#[test]
fn success_delivered_before_the_last_failure_still_alerts() {
    // The two channels are polled by independent threads: the 1149 can reach
    // the rules before the fifth 4625 that precedes it in time.
    let mut state = RuleState::new();
    for i in 0..THRESHOLD - 1 {
        state.on_auth(&failure("192.0.2.50", "alice", i * SEC));
    }
    assert!(
        state
            .on_session(&connect(Some("192.0.2.50"), "alice", 10 * SEC))
            .is_empty(),
        "four failures are not enough yet"
    );

    let alerts = state.on_auth(&failure("192.0.2.50", "alice", 6 * SEC));
    let rdp: Vec<_> = alerts
        .iter()
        .filter(|a| a.technique == "T1021.001")
        .collect();
    assert_eq!(rdp.len(), 1, "the late failure completes the join");
    assert!(rdp[0].message.contains("alice"));

    assert!(
        state
            .on_auth(&failure("192.0.2.50", "alice", 7 * SEC))
            .iter()
            .all(|a| a.technique != "T1021.001"),
        "once per window"
    );
}

#[test]
fn failure_timestamped_after_the_success_does_not_count() {
    let mut state = RuleState::new();
    for i in 0..THRESHOLD - 1 {
        state.on_auth(&failure("192.0.2.50", "alice", i * SEC));
    }
    state.on_session(&connect(Some("192.0.2.50"), "alice", 10 * SEC));

    let alerts = state.on_auth(&failure("192.0.2.50", "alice", 11 * SEC));
    assert!(
        alerts.iter().all(|a| a.technique != "T1021.001"),
        "a failure after the success is not a failure before it"
    );
}

#[test]
fn ipv4_mapped_ipv6_address_is_the_same_source() {
    let mut state = RuleState::new();
    for i in 0..THRESHOLD {
        state.on_auth(&failure("::ffff:192.0.2.50", "alice", i * SEC));
    }
    let alerts = state.on_session(&connect(Some("192.0.2.50"), "alice", 10 * SEC));
    assert_eq!(alerts.len(), 1);
}

#[test]
fn a_second_success_in_the_same_window_does_not_alert_again() {
    let mut state = RuleState::new();
    for i in 0..THRESHOLD {
        state.on_auth(&failure("192.0.2.50", "alice", i * SEC));
    }
    assert_eq!(
        state
            .on_session(&connect(Some("192.0.2.50"), "alice", 10 * SEC))
            .len(),
        1
    );
    assert!(
        state
            .on_session(&connect(Some("192.0.2.50"), "alice", 20 * SEC))
            .is_empty()
    );
}
