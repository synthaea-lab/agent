//! Security 1102 / System 104: an event log was cleared.

use crate::xml::{
    scan::{security_user_id, system_header, user_data_field},
    time::time_created_ns,
};

/// Fields of a "log cleared" record the Event Log service writes into a log it
/// has just emptied (#799): Security **1102** or System **104**, both from the
/// `Microsoft-Windows-Eventlog` provider, both carrying a `<UserData>`
/// `<LogFileCleared>` element. Raw as written; `sensor.rs` decides what a
/// missing field means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogClearedRecord {
    pub record_id: u64,
    pub event_id: u32,
    /// `<Execution ProcessID>`: the Event Log service, not the clearer.
    pub pid: u32,
    /// `ClientProcessId`: the process that asked for the clear. Present in
    /// both events on Windows 11 26200 (lab, 2026-10-15); older builds may
    /// not write it.
    pub client_pid: Option<u32>,
    /// 104: the channel that was cleared (`UserData`'s `<Channel>`, not the
    /// header's, which is always `System`). 1102 does not carry one: it is
    /// always about the Security log it is written into.
    pub cleared_channel: Option<String>,
    /// 1102: `SubjectUserSid`. 104 has no such field; its header's
    /// `<Security UserID>` names the same account and is read instead.
    pub subject_sid: Option<String>,
    pub subject_user_name: Option<String>,
    pub subject_domain_name: Option<String>,
    /// 1102 only.
    pub subject_logon_id: Option<String>,
    /// 104 only, and empty unless the clear asked for a backup.
    pub backup_path: Option<String>,
    /// When the log was cleared (`<TimeCreated SystemTime>`).
    pub time_created_ns: Option<u64>,
}

/// Parses one Security 1102 or System 104 `<Event>` block. `None` without an
/// `EventRecordID`, same convention as the other parsers here.
#[must_use]
pub fn parse_log_cleared_event(block: &str) -> Option<LogClearedRecord> {
    let (record_id, event_id, pid) = system_header(block)?;
    Some(LogClearedRecord {
        record_id,
        event_id,
        pid,
        client_pid: user_data_field(block, "ClientProcessId").and_then(|s| s.parse().ok()),
        cleared_channel: user_data_field(block, "Channel"),
        subject_sid: user_data_field(block, "SubjectUserSid").or_else(|| security_user_id(block)),
        subject_user_name: user_data_field(block, "SubjectUserName"),
        subject_domain_name: user_data_field(block, "SubjectDomainName"),
        subject_logon_id: user_data_field(block, "SubjectLogonId"),
        backup_path: user_data_field(block, "BackupPath"),
        time_created_ns: time_created_ns(block),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::scan::split_event_blocks;

    /// A real System 104, captured on Windows 11 26200 (2026-10-15, #799):
    /// `OpenSSH/Operational` cleared through .NET's
    /// `EventLogSession.GlobalSession.ClearLog(channel, backupPath)`, not
    /// `wevtutil`. Verbatim `wevtutil qe` output, computer and account renamed.
    const LOG_FILE_CLEARED_104: &str = r"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog' Guid='{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}'/><EventID>104</EventID><Version>1</Version><Level>4</Level><Task>104</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-10-15T12:50:01.7166040Z'/><EventRecordID>78381</EventRecordID><Correlation/><Execution ProcessID='3792' ThreadID='44592'/><Channel>System</Channel><Computer>LAB-W11</Computer><Security UserID='S-1-5-21-61980266-902198588-2058873832-1001'/></System><UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserName>analyst</SubjectUserName><SubjectDomainName>LAB-W11</SubjectDomainName><Channel>OpenSSH/Operational</Channel><BackupPath>C:\Users\analyst\Documents\OpenSSH-backup-799.evtx</BackupPath><ClientProcessId>41684</ClientProcessId><ClientProcessStartKey>84161018036490963</ClientProcessStartKey></LogFileCleared></UserData></Event>";

    /// The real Security 1102 from the same `ClearLog` run, 17 ms later.
    const SECURITY_LOG_CLEARED_1102: &str = r"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog' Guid='{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}'/><EventID>1102</EventID><Version>1</Version><Level>4</Level><Task>104</Task><Opcode>0</Opcode><Keywords>0x4020000000000000</Keywords><TimeCreated SystemTime='2026-10-15T12:50:01.7339239Z'/><EventRecordID>1399119</EventRecordID><Correlation/><Execution ProcessID='3792' ThreadID='47044'/><Channel>Security</Channel><Computer>LAB-W11</Computer><Security/></System><UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserSid>S-1-5-21-61980266-902198588-2058873832-1001</SubjectUserSid><SubjectUserName>analyst</SubjectUserName><SubjectDomainName>LAB-W11</SubjectDomainName><SubjectLogonId>0x37b4d</SubjectLogonId><ClientProcessId>41684</ClientProcessId><ClientProcessStartKey>84161018036490963</ClientProcessStartKey></LogFileCleared></UserData></Event>";

    #[test]
    fn a_real_104_names_the_cleared_channel_not_the_system_log() {
        let block = split_event_blocks(LOG_FILE_CLEARED_104)[0];
        let parsed = parse_log_cleared_event(block).expect("should parse");
        assert_eq!(parsed.record_id, 78381);
        assert_eq!(parsed.event_id, 104);
        assert_eq!(parsed.pid, 3792);
        assert_eq!(parsed.client_pid, Some(41684));
        assert_eq!(
            parsed.cleared_channel.as_deref(),
            Some("OpenSSH/Operational")
        );
        // 104 has no SubjectUserSid: the header's Security UserID stands in.
        assert_eq!(
            parsed.subject_sid.as_deref(),
            Some("S-1-5-21-61980266-902198588-2058873832-1001")
        );
        assert_eq!(parsed.subject_user_name.as_deref(), Some("analyst"));
        assert_eq!(parsed.subject_domain_name.as_deref(), Some("LAB-W11"));
        assert_eq!(parsed.subject_logon_id, None);
        assert_eq!(
            parsed.backup_path.as_deref(),
            Some(r"C:\Users\analyst\Documents\OpenSSH-backup-799.evtx")
        );
        assert!(parsed.time_created_ns.is_some());
    }

    #[test]
    fn a_real_1102_carries_the_clearing_sid_and_logon_session() {
        let block = split_event_blocks(SECURITY_LOG_CLEARED_1102)[0];
        let parsed = parse_log_cleared_event(block).expect("should parse");
        assert_eq!(parsed.record_id, 1_399_119);
        assert_eq!(parsed.event_id, 1102);
        assert_eq!(parsed.client_pid, Some(41684));
        assert_eq!(parsed.cleared_channel, None);
        assert_eq!(
            parsed.subject_sid.as_deref(),
            Some("S-1-5-21-61980266-902198588-2058873832-1001")
        );
        assert_eq!(parsed.subject_logon_id.as_deref(), Some("0x37b4d"));
        assert_eq!(parsed.backup_path, None);
    }
}
