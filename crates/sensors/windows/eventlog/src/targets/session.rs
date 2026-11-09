//! Terminal Services session lifecycle (#285).
//!
//! What 4624 cannot say: new session or reconnect, disconnected (left alive)
//! or logged off, and which client each step came from. Both channels are on by
//! default on every SKU, RDP host or not: the console session logs 21/23 too
//! (`Address` `LOCAL`), and a host without an RDP listener simply never writes
//! a 1149. No audit toggle.

use std::net::IpAddr;

use schema::{Event, EventMeta, SessionEvent, SessionState, User, time::now_ns};

use super::BlockOutcome;
use crate::xml;

const SESSION_LOGON: u32 = 21;
const SESSION_LOGOFF: u32 = 23;
const SESSION_DISCONNECT: u32 = 24;
const SESSION_RECONNECT: u32 = 25;
const RDP_AUTHENTICATED: u32 = 1149;

/// `(source_address, console)` from the event's client field. `LOCAL` is the
/// console; anything else that is not an IP address (a gateway name, a shape
/// not seen yet) is reported as no address rather than guessed at.
fn session_origin(address: Option<&str>) -> (Option<IpAddr>, bool) {
    match address {
        Some(a) if a.eq_ignore_ascii_case("LOCAL") => (None, true),
        Some(a) => (a.parse().ok(), false),
        None => (None, false),
    }
}

fn session_event(ev: xml::TerminalSessionEvent, state: SessionState) -> Event {
    let (source_address, console) = session_origin(ev.address.as_deref());
    Event::Session(SessionEvent {
        meta: EventMeta {
            pid: ev.pid,
            ppid: 0,
            user: User::Unknown,
            timestamp_ns: ev.time_created_ns.unwrap_or_else(now_ns),
            comm: String::new(),
            container: None, // attributed by the ETW sensor only (https://github.com/synthaea-lab/agent/issues/39)
            process_generation: None,
            parent_process_generation: None,
        },
        state,
        session_id: ev.session_id,
        target_user: ev.user.unwrap_or_default(),
        source_address,
        console,
    })
}

/// Normalizes a `LocalSessionManager` 21/23/24/25 into a [`SessionEvent`].
///
/// Skipped (cursor still advances): a block without a `SessionID` (every
/// consumer keys on it), and any event id the `XPath` filter let through
/// that this function has no state for. 22 (shell start) is not subscribed:
/// it repeats the 21 it follows.
pub(crate) fn normalize_session_lifecycle_block(block: &str) -> BlockOutcome {
    let Some(ev) = xml::parse_local_session_event(block) else {
        return BlockOutcome::Unparseable;
    };
    let record_id = ev.record_id;
    let state = match ev.event_id {
        SESSION_LOGON => SessionState::Logon,
        SESSION_LOGOFF => SessionState::Logoff,
        SESSION_DISCONNECT => SessionState::Disconnect,
        SESSION_RECONNECT => SessionState::Reconnect,
        _ => return BlockOutcome::Filtered { record_id },
    };
    if ev.session_id.is_none() {
        return BlockOutcome::Filtered { record_id };
    }
    BlockOutcome::Event {
        record_id,
        event: session_event(ev, state),
    }
}

/// Normalizes a `RemoteConnectionManager` 1149 (a client authenticated to the
/// RDP listener) into a [`SessionEvent`] with [`SessionState::Connect`]. With
/// Network Level Authentication on (the default) that means the credentials
/// were good; without it, only that a client connected. 4625 is where failed
/// attempts land, and it carries the source address too.
///
/// Skipped: a block naming neither a user nor a client, and any other id.
pub(crate) fn normalize_rdp_connection_block(block: &str) -> BlockOutcome {
    let Some(ev) = xml::parse_remote_connection_event(block) else {
        return BlockOutcome::Unparseable;
    };
    let record_id = ev.record_id;
    if ev.event_id != RDP_AUTHENTICATED || (ev.user.is_none() && ev.address.is_none()) {
        return BlockOutcome::Filtered { record_id };
    }
    BlockOutcome::Event {
        record_id,
        event: session_event(ev, SessionState::Connect),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lsm_block(event_id: u32, user_data: &str) -> String {
        format!(
            "<Event><System><EventID>{event_id}</EventID><EventRecordID>40</EventRecordID><Execution ProcessID='2312' ThreadID='1'/></System><UserData><EventXML xmlns='Event_NS'>{user_data}</EventXML></UserData></Event>"
        )
    }

    fn session(parsed: BlockOutcome) -> SessionEvent {
        match parsed {
            BlockOutcome::Event {
                record_id: 40,
                event: Event::Session(e),
            } => e,
            other => panic!("expected a SessionEvent, got {other:?}"),
        }
    }

    #[test]
    fn a_remote_reconnect_carries_session_and_client_address() {
        let e = session(normalize_session_lifecycle_block(&lsm_block(
            25,
            r"<User>LAB\alice</User><SessionID>2</SessionID><Address>198.51.100.40</Address>",
        )));
        assert_eq!(e.state, SessionState::Reconnect);
        assert_eq!(e.session_id, Some(2));
        assert_eq!(e.target_user, r"LAB\alice");
        assert_eq!(e.source_address, Some("198.51.100.40".parse().unwrap()));
        assert!(!e.console);
        assert_eq!(e.meta.pid, 2312);
    }

    #[test]
    fn local_is_the_console_not_an_address() {
        let e = session(normalize_session_lifecycle_block(&lsm_block(
            24,
            r"<User>LAB\alice</User><SessionID>1</SessionID><Address>LOCAL</Address>",
        )));
        assert_eq!(e.state, SessionState::Disconnect);
        assert!(e.console);
        assert_eq!(e.source_address, None);
    }

    #[test]
    fn an_ipv6_client_address_is_kept() {
        let e = session(normalize_session_lifecycle_block(&lsm_block(
            21,
            r"<User>LAB\alice</User><SessionID>3</SessionID><Address>2001:db8::7</Address>",
        )));
        assert_eq!(e.source_address, Some("2001:db8::7".parse().unwrap()));
    }

    #[test]
    fn an_unparseable_client_is_no_address_and_not_the_console() {
        let e = session(normalize_session_lifecycle_block(&lsm_block(
            25,
            r"<User>LAB\alice</User><SessionID>2</SessionID><Address>gw.lab.example</Address>",
        )));
        assert_eq!(e.source_address, None);
        assert!(!e.console);
    }

    #[test]
    fn a_logoff_names_no_client() {
        let e = session(normalize_session_lifecycle_block(&lsm_block(
            23,
            r"<User>LAB\alice</User><SessionID>2</SessionID>",
        )));
        assert_eq!(e.state, SessionState::Logoff);
        assert_eq!((e.source_address, e.console), (None, false));
    }

    #[test]
    fn a_lifecycle_event_without_session_id_is_skipped() {
        let block = lsm_block(25, r"<User>LAB\alice</User><Address>LOCAL</Address>");
        assert!(matches!(
            normalize_session_lifecycle_block(&block),
            BlockOutcome::Filtered { record_id: 40 }
        ));
    }

    #[test]
    fn other_session_manager_ids_are_skipped() {
        // 59 is the RPC trace that makes up most of the channel.
        let block = lsm_block(59, "<SessionId>0</SessionId>");
        assert!(matches!(
            normalize_session_lifecycle_block(&block),
            BlockOutcome::Filtered { record_id: 40 }
        ));
    }

    #[test]
    fn an_rdp_authentication_is_a_connect_with_no_session() {
        let block = lsm_block(
            1149,
            "<Param1>alice</Param1><Param2>LAB</Param2><Param3>198.51.100.40</Param3>",
        );
        let e = session(normalize_rdp_connection_block(&block));
        assert_eq!(e.state, SessionState::Connect);
        assert_eq!(e.session_id, None);
        assert_eq!(e.target_user, r"LAB\alice");
        assert_eq!(e.source_address, Some("198.51.100.40".parse().unwrap()));
    }

    #[test]
    fn an_rdp_authentication_naming_nothing_is_skipped() {
        let block = lsm_block(1149, "<Param1></Param1><Param2></Param2><Param3></Param3>");
        assert!(matches!(
            normalize_rdp_connection_block(&block),
            BlockOutcome::Filtered { record_id: 40 }
        ));
    }
}
