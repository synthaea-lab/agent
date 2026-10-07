//! T1563.002 — a disconnected session reconnected from another client (#285).

use std::net::IpAddr;

use schema::{SessionEvent, SessionState, detection::Severity};

use crate::RuleState;

const OWNER: &str = "198.51.100.40";
const ATTACKER: &str = "203.0.113.9";

fn step(state: SessionState, session_id: u32, client: Option<&str>, at_s: u64) -> SessionEvent {
    let mut event = schema::fixtures::session();
    event.meta.timestamp_ns = at_s * 1_000_000_000;
    event.state = state;
    event.session_id = Some(session_id);
    event.target_user = r"LAB\alice".into();
    event.source_address = client.map(|c| c.parse::<IpAddr>().unwrap());
    event.console = false;
    event
}

fn at_console(state: SessionState, session_id: u32, at_s: u64) -> SessionEvent {
    SessionEvent {
        console: true,
        ..step(state, session_id, None, at_s)
    }
}

#[test]
fn reconnect_from_another_address_alerts() {
    let mut state = RuleState::new();
    assert!(
        state
            .on_session(&step(SessionState::Disconnect, 2, Some(OWNER), 100))
            .is_empty()
    );
    let alerts = state.on_session(&step(SessionState::Reconnect, 2, Some(ATTACKER), 400));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1563.002");
    assert_eq!(alerts[0].severity, Severity::Medium);
    let message = &alerts[0].message;
    assert!(message.contains("session 2"), "{message}");
    assert!(message.contains(r"user=LAB\alice"), "{message}");
    assert!(
        message.contains(&format!(
            "from {OWNER} and reconnected from {ATTACKER} 300s later"
        )),
        "{message}"
    );
}

#[test]
fn reconnect_from_the_same_address_does_not_alert() {
    let mut state = RuleState::new();
    state.on_session(&step(SessionState::Disconnect, 2, Some(OWNER), 100));
    assert!(
        state
            .on_session(&step(SessionState::Reconnect, 2, Some(OWNER), 400))
            .is_empty()
    );
}

#[test]
fn console_session_taken_over_remotely_alerts() {
    // `tscon` hijacks of a console session, or the console user's session
    // picked up over RDP from elsewhere.
    let mut state = RuleState::new();
    state.on_session(&at_console(SessionState::Disconnect, 1, 100));
    let alerts = state.on_session(&step(SessionState::Reconnect, 1, Some(ATTACKER), 160));
    assert_eq!(alerts.len(), 1);
    assert!(
        alerts[0]
            .message
            .contains(&format!("from the console and reconnected from {ATTACKER}")),
        "{}",
        alerts[0].message
    );
}

#[test]
fn fast_user_switching_at_the_console_does_not_alert() {
    // Windows 11 Home's only disconnect/reconnect: console to console.
    let mut state = RuleState::new();
    state.on_session(&at_console(SessionState::Disconnect, 1, 100));
    assert!(
        state
            .on_session(&at_console(SessionState::Reconnect, 1, 200))
            .is_empty()
    );
}

#[test]
fn a_session_alerts_once_per_disconnect() {
    let mut state = RuleState::new();
    state.on_session(&step(SessionState::Disconnect, 2, Some(OWNER), 100));
    assert_eq!(
        state
            .on_session(&step(SessionState::Reconnect, 2, Some(ATTACKER), 200))
            .len(),
        1
    );
    // A second reconnect with no disconnect in between has nothing to compare.
    assert!(
        state
            .on_session(&step(SessionState::Reconnect, 2, Some(OWNER), 300))
            .is_empty()
    );
}

#[test]
fn a_reused_session_id_does_not_inherit_the_old_disconnect() {
    for reset in [SessionState::Logoff, SessionState::Logon] {
        let mut state = RuleState::new();
        state.on_session(&step(SessionState::Disconnect, 2, Some(OWNER), 100));
        state.on_session(&step(reset, 2, None, 200));
        assert!(
            state
                .on_session(&step(SessionState::Reconnect, 2, Some(ATTACKER), 300))
                .is_empty(),
            "{reset:?} must forget session 2's disconnect"
        );
    }
}

#[test]
fn sessions_are_tracked_independently() {
    let mut state = RuleState::new();
    state.on_session(&step(SessionState::Disconnect, 2, Some(OWNER), 100));
    state.on_session(&step(SessionState::Disconnect, 3, Some(ATTACKER), 110));
    assert!(
        state
            .on_session(&step(SessionState::Reconnect, 3, Some(ATTACKER), 120))
            .is_empty()
    );
    assert_eq!(
        state
            .on_session(&step(SessionState::Reconnect, 2, Some(ATTACKER), 130))
            .len(),
        1
    );
}

#[test]
fn a_reconnect_naming_no_client_does_not_alert() {
    // `Address` missing or not an IP address: no evidence of a change.
    let mut state = RuleState::new();
    state.on_session(&step(SessionState::Disconnect, 2, Some(OWNER), 100));
    assert!(
        state
            .on_session(&step(SessionState::Reconnect, 2, None, 200))
            .is_empty()
    );
}

#[test]
fn an_rdp_authentication_alone_does_not_alert() {
    let mut state = RuleState::new();
    let connect = SessionEvent {
        session_id: None,
        ..step(SessionState::Connect, 0, Some(ATTACKER), 100)
    };
    assert!(state.on_session(&connect).is_empty());
}
