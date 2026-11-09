//! Terminal Services session events (`LocalSessionManager` and `RemoteConnectionManager`).

use crate::xml::{
    scan::{system_header, user_data_field},
    time::time_created_ns,
};

/// Fields of one Terminal Services session event (#285), from either channel:
///
/// - `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`
///   21 (logon), 23 (logoff), 24 (disconnect), 25 (reconnect):
///   `<UserData><EventXML>` with `User`, `SessionID` and, except on 23,
///   `Address`.
/// - `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational`
///   1149 (a client authenticated to the listener): `Param1` user, `Param2`
///   domain, `Param3` client address; no session yet.
///
/// Neither channel uses `<Data Name=...>` elements, and neither is localized
/// in these fields. The 21/23 shapes were checked on a Windows 11 26200 host
/// (2026-10-05): the console session logs them too, with `Address` `LOCAL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalSessionEvent {
    pub record_id: u64,
    pub event_id: u32,
    /// `<Execution ProcessID>`: the Terminal Services svchost, not an actor.
    pub pid: u32,
    /// `DOMAIN\user` as the event writes it (1149: `Param2\Param1`, or
    /// `Param1` alone when the domain is empty).
    pub user: Option<String>,
    pub session_id: Option<u32>,
    /// The client as written: an IP address, `LOCAL` for the console, or
    /// whatever else Windows put there. Interpreted by `sensor.rs`.
    pub address: Option<String>,
    /// When the event happened (`<TimeCreated SystemTime>`), not when it was read.
    pub time_created_ns: Option<u64>,
}

/// Parses one `LocalSessionManager` 21/23/24/25 `<Event>` block. `None`
/// without an `EventRecordID`, same convention as the other parsers here.
#[must_use]
pub fn parse_local_session_event(block: &str) -> Option<TerminalSessionEvent> {
    let (record_id, event_id, pid) = system_header(block)?;
    Some(TerminalSessionEvent {
        record_id,
        event_id,
        pid,
        user: user_data_field(block, "User"),
        session_id: user_data_field(block, "SessionID").and_then(|s| s.parse().ok()),
        address: user_data_field(block, "Address"),
        time_created_ns: time_created_ns(block),
    })
}

/// Parses one `RemoteConnectionManager` 1149 `<Event>` block. `None` without
/// an `EventRecordID`.
#[must_use]
pub fn parse_remote_connection_event(block: &str) -> Option<TerminalSessionEvent> {
    let (record_id, event_id, pid) = system_header(block)?;
    let user =
        user_data_field(block, "Param1").map(|name| match user_data_field(block, "Param2") {
            Some(domain) => format!("{domain}\\{name}"),
            None => name,
        });
    Some(TerminalSessionEvent {
        record_id,
        event_id,
        pid,
        user,
        session_id: None,
        address: user_data_field(block, "Param3"),
        time_created_ns: time_created_ns(block),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::{fixtures::LOGON_FAILURE_XML, records::logon::parse_logon_block};

    /// A real console logon (21) from a Windows 11 26200 host, 2026-10-05,
    /// with the computer and account renamed.
    const LSM_21_CONSOLE: &str = r"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TerminalServices-LocalSessionManager' Guid='{5d896912-022d-40aa-a3a8-4fa5515c76d7}'/><EventID>21</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x1000000000000000</Keywords><TimeCreated SystemTime='2026-10-05T11:46:09.8088735Z'/><EventRecordID>16693</EventRecordID><Correlation ActivityID='{f48050f4-5382-4583-b7f5-6c0251ba0000}'/><Execution ProcessID='2312' ThreadID='2324'/><Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel><Computer>SANDBOX</Computer><Security UserID='S-1-5-18'/></System><UserData><EventXML xmlns='Event_NS'><User>SANDBOX\alice</User><SessionID>1</SessionID><Address>LOCAL</Address></EventXML></UserData></Event>";

    /// A real logoff (23) from the same host: no `Address` element.
    const LSM_23_LOGOFF: &str = r"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TerminalServices-LocalSessionManager' Guid='{5d896912-022d-40aa-a3a8-4fa5515c76d7}'/><EventID>23</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x1000000000000000</Keywords><TimeCreated SystemTime='2026-10-05T00:04:15.7851490Z'/><EventRecordID>16688</EventRecordID><Correlation ActivityID='{f48064b9-4c41-4efa-85e2-92176a980000}'/><Execution ProcessID='2292' ThreadID='39104'/><Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel><Computer>SANDBOX</Computer><Security UserID='S-1-5-18'/></System><UserData><EventXML xmlns='Event_NS'><User>SANDBOX\alice</User><SessionID>1</SessionID></EventXML></UserData></Event>";

    /// 1149 in its documented shape (no lab capture yet: the host the 21/23
    /// came from runs no RDP listener).
    const RCM_1149: &str = r"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TerminalServices-RemoteConnectionManager' Guid='{c76baa63-ae81-421c-b425-340b4b24157f}'/><EventID>1149</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x1000000000000000</Keywords><TimeCreated SystemTime='2026-10-05T12:00:00.0000000Z'/><EventRecordID>77</EventRecordID><Correlation ActivityID='{f420c0f4-1e2f-4b29-8a3c-4f6d0e3a0000}'/><Execution ProcessID='1180' ThreadID='2044'/><Channel>Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational</Channel><Computer>SANDBOX</Computer><Security UserID='S-1-5-20'/></System><UserData><EventXML xmlns='Event_NS'><Param1>alice</Param1><Param2>LAB</Param2><Param3>198.51.100.40</Param3></EventXML></UserData></Event>";

    #[test]
    fn console_logon_reads_user_session_and_local_address() {
        let ev = parse_local_session_event(LSM_21_CONSOLE).expect("parses");
        assert_eq!(
            ev,
            TerminalSessionEvent {
                record_id: 16693,
                event_id: 21,
                pid: 2312,
                user: Some(r"SANDBOX\alice".into()),
                session_id: Some(1),
                address: Some("LOCAL".into()),
                time_created_ns: Some(1791200769808873500),
            }
        );
    }

    #[test]
    fn logon_and_session_events_carry_the_time_they_happened() {
        assert_eq!(
            parse_logon_block(LOGON_FAILURE_XML).and_then(|e| e.time_created_ns),
            Some(1789997363236729800)
        );
        assert_eq!(
            parse_local_session_event(LSM_21_CONSOLE).and_then(|e| e.time_created_ns),
            Some(1791200769808873500)
        );
        assert_eq!(
            parse_remote_connection_event(RCM_1149).and_then(|e| e.time_created_ns),
            Some(1791201600000000000)
        );
    }

    #[test]
    fn logoff_has_no_address() {
        let ev = parse_local_session_event(LSM_23_LOGOFF).expect("parses");
        assert_eq!(ev.event_id, 23);
        assert_eq!(ev.session_id, Some(1));
        assert_eq!(ev.address, None);
    }

    #[test]
    fn rdp_authentication_joins_domain_and_user_and_has_no_session() {
        let ev = parse_remote_connection_event(RCM_1149).expect("parses");
        assert_eq!(ev.event_id, 1149);
        assert_eq!(ev.pid, 1180);
        assert_eq!(ev.user.as_deref(), Some(r"LAB\alice"));
        assert_eq!(ev.address.as_deref(), Some("198.51.100.40"));
        assert_eq!(ev.session_id, None);
    }

    #[test]
    fn rdp_authentication_without_domain_keeps_the_bare_user() {
        let block = RCM_1149.replace("<Param2>LAB</Param2>", "<Param2></Param2>");
        let ev = parse_remote_connection_event(&block).expect("parses");
        assert_eq!(ev.user.as_deref(), Some("alice"));
    }

    #[test]
    fn session_fields_outside_user_data_are_not_read() {
        // A `<User>` in some other part of the block (here the provider name
        // slot) must not stand in for the session's account.
        let block = LSM_23_LOGOFF
            .replace("<User>SANDBOX\\alice</User>", "")
            .replace("<Correlation", "<User>mallory</User><Correlation");
        let ev = parse_local_session_event(&block).expect("parses");
        assert_eq!(ev.user, None);
    }

    #[test]
    fn non_numeric_session_id_reads_as_none() {
        let block = LSM_21_CONSOLE.replace("<SessionID>1</SessionID>", "<SessionID>x</SessionID>");
        assert_eq!(
            parse_local_session_event(&block)
                .expect("parses")
                .session_id,
            None
        );
    }
}
