//! Security 4624/4625/4648/4672: logons, failed logons, explicit credentials, special
//! privileges.

use crate::xml::{
    scan::{extract_between, opt_data},
    time::time_created_ns,
};

/// Fields extracted from a Security-log logon/session `<Event>` block — events
/// **4624** (successful logon), **4625** (failed logon), **4648** (explicit-
/// credential logon — RunAs/lateral movement), and **4672** (special privileges
/// assigned to a new logon). One struct for all four: they share almost every
/// field name, and `sensor.rs`'s `to_auth_event` is the single place that turns
/// `event_id` into the right `schema::AuthKind`/`schema::AuthOutcome` and picks
/// Subject vs. Target (see below).
///
/// `Subject*` is the security context Windows itself associates with the event —
/// for 4624/4625 that is normally SYSTEM (`S-1-5-18`, the LSA subsystem creating
/// the logon on the account's behalf), not the account logging in (that is
/// `Target*`). For 4648/4672 `Subject*` is the already-authenticated caller.
/// **4648 never carries a `TargetUserSid`** (the target account is named but not
/// yet SID-resolved at explicit-logon time) and **4672 carries no `Target*` field
/// at all** — the Subject *is* the account that just received the privileges, so
/// `to_auth_event` reuses Subject as the reported target for that one kind.
///
/// Field names are the standard, publicly documented Microsoft Security-auditing
/// schema for these four event IDs. Reconciled against a real
/// `wevtutil qe Security /f:xml` capture on 2026-09-21 (Windows 11 lab VM
/// `Sandbox`); the fixtures in this
/// module's tests are trimmed but otherwise faithful to that capture.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LogonEvent {
    pub record_id: u64,
    /// 4624, 4625, 4648, or 4672 — parsed from the block's own `<EventID>`
    /// rather than passed in, so one poller can query all four IDs at once.
    pub event_id: u32,
    /// PID of the reporting process (`<Execution ProcessID='...'>`) — the
    /// "Microsoft-Windows-Security-Auditing" provider runs inside LSASS for
    /// every event this module parses, not the account's own process.
    pub pid: u32,
    pub subject_user_sid: Option<String>,
    pub subject_user_name: Option<String>,
    pub target_user_sid: Option<String>,
    pub target_user_name: Option<String>,
    /// `None` for a local console/service logon, where Windows reports the
    /// literal sentinel `"-"` rather than omitting the field — filtered out
    /// here so callers don't have to know about the sentinel.
    pub ip_address: Option<String>,
    /// Hex status code (4625 only). Combined with `sub_status` by `sensor.rs`
    /// into `schema::AuthEvent::status_code`.
    pub status: Option<String>,
    pub sub_status: Option<String>,
    /// When the event happened (`<TimeCreated SystemTime>`), not when it was read.
    pub time_created_ns: Option<u64>,
}

/// Parses one 4624/4625/4648/4672 `<Event>` block. `None` if the block is
/// missing `EventRecordID` or `EventID` (a genuinely different event matched the
/// `XPath` filter, or a `wevtutil` output shape change — skip rather than guess,
/// same convention as [`parse_service_install_block`](crate::xml::parse_service_install_block)).
#[must_use]
pub fn parse_logon_block(block: &str) -> Option<LogonEvent> {
    let record_id = extract_between(block, "<EventRecordID>", "</EventRecordID>")?
        .parse()
        .ok()?;
    let event_id = extract_between(block, "<EventID>", "</EventID>")?
        .parse()
        .ok()?;
    let pid = extract_between(block, "ProcessID='", "'")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Some(LogonEvent {
        record_id,
        event_id,
        pid,
        subject_user_sid: opt_data(block, "SubjectUserSid"),
        subject_user_name: opt_data(block, "SubjectUserName"),
        target_user_sid: opt_data(block, "TargetUserSid"),
        target_user_name: opt_data(block, "TargetUserName"),
        ip_address: opt_data(block, "IpAddress"),
        status: opt_data(block, "Status"),
        sub_status: opt_data(block, "SubStatus"),
        time_created_ns: time_created_ns(block),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::{fixtures::LOGON_FAILURE_XML, scan::split_event_blocks};

    // Fixtures reconciled 2026-09-21 against a real
    // `wevtutil qe Security /f:xml` capture on Windows 11 lab VM `Sandbox`.
    // UTF-16-LE from wevtutil normalised to UTF-8
    // via iconv (a stray `Système`-mojibake artefact from that pipeline was
    // corrected back to `Système` here; the parser reads neither the field nor
    // the surrounding text, so the round-trip is safe).

    /// Three concatenated 4624 events as one `wevtutil` query returns them:
    /// two service-account logons (`LogonType` 5, Target SYSTEM `S-1-5-18`,
    /// `IpAddress='-'`) followed by the interactive `runas`-triggered logon
    /// (`LogonType` 2, Target `testuser224`, `IpAddress='::1'`). Exercises both
    /// the multi-event splitter and the `"-"`-sentinel filter on `IpAddress`.
    const LOGON_SUCCESS_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4624</EventID><Version>3</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-09-21T13:31:23.4077711Z'/><EventRecordID>76351</EventRecordID><Correlation ActivityID='{9f6e2246-49c9-0001-c923-6e9fc949dd01}'/><Execution ProcessID='836' ThreadID='932'/><Channel>Security</Channel><Computer>Sandbox</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>SANDBOX$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-5-18</Data><Data Name='TargetUserName'>Système</Data><Data Name='TargetDomainName'>AUTORITE NT</Data><Data Name='TargetLogonId'>0x3e7</Data><Data Name='LogonType'>5</Data><Data Name='LogonProcessName'>Advapi  </Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>-</Data><Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x330</Data><Data Name='ProcessName'>C:\Windows\System32\services.exe</Data><Data Name='IpAddress'>-</Data><Data Name='IpPort'>-</Data><Data Name='ImpersonationLevel'>%%1833</Data><Data Name='RestrictedAdminMode'>-</Data><Data Name='RemoteCredentialGuard'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1843</Data><Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='ElevatedToken'>%%1842</Data></EventData></Event><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4624</EventID><Version>3</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-09-21T13:29:39.7628569Z'/><EventRecordID>76342</EventRecordID><Correlation ActivityID='{9f6e2246-49c9-0001-c923-6e9fc949dd01}'/><Execution ProcessID='836' ThreadID='876'/><Channel>Security</Channel><Computer>Sandbox</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>SANDBOX$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-5-18</Data><Data Name='TargetUserName'>Système</Data><Data Name='TargetDomainName'>AUTORITE NT</Data><Data Name='TargetLogonId'>0x3e7</Data><Data Name='LogonType'>5</Data><Data Name='LogonProcessName'>Advapi  </Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>-</Data><Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x330</Data><Data Name='ProcessName'>C:\Windows\System32\services.exe</Data><Data Name='IpAddress'>-</Data><Data Name='IpPort'>-</Data><Data Name='ImpersonationLevel'>%%1833</Data><Data Name='RestrictedAdminMode'>-</Data><Data Name='RemoteCredentialGuard'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1843</Data><Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='ElevatedToken'>%%1842</Data></EventData></Event><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4624</EventID><Version>3</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-09-21T13:29:36.7187492Z'/><EventRecordID>76340</EventRecordID><Correlation ActivityID='{9f6e2246-49c9-0001-c923-6e9fc949dd01}'/><Execution ProcessID='836' ThreadID='876'/><Channel>Security</Channel><Computer>Sandbox</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1663667890-2519037288-962558911-1001</Data><Data Name='SubjectUserName'>solka</Data><Data Name='SubjectDomainName'>SANDBOX</Data><Data Name='SubjectLogonId'>0x12abb7</Data><Data Name='TargetUserSid'>S-1-5-21-1663667890-2519037288-962558911-1002</Data><Data Name='TargetUserName'>testuser224</Data><Data Name='TargetDomainName'>Sandbox</Data><Data Name='TargetLogonId'>0xd15e6e</Data><Data Name='LogonType'>2</Data><Data Name='LogonProcessName'>seclogo</Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>SANDBOX</Data><Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0xb90</Data><Data Name='ProcessName'>C:\Windows\System32\svchost.exe</Data><Data Name='IpAddress'>::1</Data><Data Name='IpPort'>0</Data><Data Name='ImpersonationLevel'>%%1833</Data><Data Name='RestrictedAdminMode'>-</Data><Data Name='RemoteCredentialGuard'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1843</Data><Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='ElevatedToken'>%%1843</Data></EventData></Event>"#;

    /// An explicit-credential logon (`Start-Process -Credential` targeting a
    /// local account on `localhost`) — no `TargetUserSid` (never resolved for
    /// this event type), Subject is the already-authenticated caller (`solka`).
    const EXPLICIT_CREDENTIALS_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4648</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-09-21T13:29:36.7187097Z'/><EventRecordID>76339</EventRecordID><Correlation ActivityID='{9f6e2246-49c9-0001-c923-6e9fc949dd01}'/><Execution ProcessID='836' ThreadID='876'/><Channel>Security</Channel><Computer>Sandbox</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1663667890-2519037288-962558911-1001</Data><Data Name='SubjectUserName'>solka</Data><Data Name='SubjectDomainName'>SANDBOX</Data><Data Name='SubjectLogonId'>0x12abb7</Data><Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TargetUserName'>testuser224</Data><Data Name='TargetDomainName'>Sandbox</Data><Data Name='TargetLogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TargetServerName'>localhost</Data><Data Name='TargetInfo'>localhost</Data><Data Name='ProcessId'>0xb90</Data><Data Name='ProcessName'>C:\Windows\System32\svchost.exe</Data><Data Name='IpAddress'>::1</Data><Data Name='IpPort'>0</Data></EventData></Event>"#;

    /// Special privileges assigned to a new logon — no `Target*` fields at all;
    /// Subject is the account that just received the privileges.
    const SPECIAL_PRIVILEGES_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4672</EventID><Version>0</Version><Level>0</Level><Task>12548</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-09-07T09:00:00.500000000Z'/><EventRecordID>9004</EventRecordID><Correlation/><Execution ProcessID='604' ThreadID='703'/><Channel>Security</Channel><Computer>LAB-VM</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1004336348-1177238915-682003330-1001</Data><Data Name='SubjectUserName'>victim</Data><Data Name='SubjectDomainName'>LAB-VM</Data><Data Name='SubjectLogonId'>0x3a2f1</Data><Data Name='PrivilegeList'>SeDebugPrivilege SeBackupPrivilege SeRestorePrivilege</Data></EventData></Event>"#;

    #[test]
    fn parses_a_real_shaped_logon_success_block() {
        // Real wevtutil output for `EventID=4624` returns concatenated events;
        // exercise both the multi-event splitter and the two logon shapes the
        // capture contains (service-account SYSTEM logon vs. real interactive
        // logon) rather than picking only one.
        let blocks = split_event_blocks(LOGON_SUCCESS_XML);
        assert_eq!(blocks.len(), 3);

        // First block: LogonType 5, Target SYSTEM, `IpAddress='-'` — proves the
        // `"-"`-sentinel filter still trims the field on real captures.
        let sys_logon = parse_logon_block(blocks[0]).expect("should parse");
        assert_eq!(sys_logon.record_id, 76351);
        assert_eq!(sys_logon.event_id, 4624);
        assert_eq!(sys_logon.pid, 836);
        assert_eq!(sys_logon.target_user_sid.as_deref(), Some("S-1-5-18"));
        // "-" sentinel (no network address for a local/service logon) filtered out.
        assert_eq!(sys_logon.ip_address, None);

        // Third block: LogonType 2, interactive logon of `testuser224` from
        // `solka` via `runas`, `IpAddress='::1'` (IPv6 loopback, kept as-is).
        let user_logon = parse_logon_block(blocks[2]).expect("should parse");
        assert_eq!(user_logon.record_id, 76340);
        assert_eq!(user_logon.event_id, 4624);
        assert_eq!(user_logon.pid, 836);
        assert_eq!(
            user_logon.subject_user_sid.as_deref(),
            Some("S-1-5-21-1663667890-2519037288-962558911-1001")
        );
        assert_eq!(user_logon.subject_user_name.as_deref(), Some("solka"));
        assert_eq!(
            user_logon.target_user_sid.as_deref(),
            Some("S-1-5-21-1663667890-2519037288-962558911-1002")
        );
        assert_eq!(user_logon.target_user_name.as_deref(), Some("testuser224"));
        assert_eq!(user_logon.ip_address.as_deref(), Some("::1"));
    }

    #[test]
    fn parses_a_real_shaped_logon_failure_block() {
        let block = split_event_blocks(LOGON_FAILURE_XML)[0];
        let parsed = parse_logon_block(block).expect("should parse");
        assert_eq!(parsed.record_id, 76333);
        assert_eq!(parsed.event_id, 4625);
        assert_eq!(parsed.status.as_deref(), Some("0xc000006d"));
        assert_eq!(parsed.sub_status.as_deref(), Some("0xc000006a"));
        // `::1` (IPv6 loopback) is a real value, not a sentinel — keep as-is.
        assert_eq!(parsed.ip_address.as_deref(), Some("::1"));
        assert_eq!(parsed.target_user_sid.as_deref(), Some("S-1-0-0"));
        assert_eq!(parsed.target_user_name.as_deref(), Some("testuser224"));
        // 4625 for a not-yet-resolved caller: `SubjectUserName='-'` filtered
        // out by the sentinel guard.
        assert_eq!(parsed.subject_user_name, None);
    }

    #[test]
    fn parses_a_real_shaped_explicit_credentials_block() {
        let block = split_event_blocks(EXPLICIT_CREDENTIALS_XML)[0];
        let parsed = parse_logon_block(block).expect("should parse");
        assert_eq!(parsed.record_id, 76339);
        assert_eq!(parsed.event_id, 4648);
        assert_eq!(parsed.subject_user_name.as_deref(), Some("solka"));
        assert_eq!(parsed.target_user_name.as_deref(), Some("testuser224"));
        // 4648 never resolves a TargetUserSid.
        assert_eq!(parsed.target_user_sid, None);
        assert_eq!(parsed.ip_address.as_deref(), Some("::1"));
    }

    #[test]
    fn parses_a_real_shaped_special_privileges_block() {
        let block = split_event_blocks(SPECIAL_PRIVILEGES_XML)[0];
        let parsed = parse_logon_block(block).expect("should parse");
        assert_eq!(parsed.event_id, 4672);
        assert_eq!(parsed.subject_user_name.as_deref(), Some("victim"));
        // 4672 has no Target* fields at all.
        assert_eq!(parsed.target_user_name, None);
        assert_eq!(parsed.target_user_sid, None);
    }

    #[test]
    fn logon_block_missing_record_id_does_not_parse() {
        let block = "<Event><EventData><Data Name='TargetUserName'>x</Data></EventData></Event>";
        assert!(parse_logon_block(block).is_none());
    }

    #[test]
    fn logon_block_missing_event_id_does_not_parse() {
        let block = "<Event><EventRecordID>1</EventRecordID></Event>";
        assert!(parse_logon_block(block).is_none());
    }
}
