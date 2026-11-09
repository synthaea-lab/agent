//! Security 1102 / System 104 — an event log cleared (T1070.001, #799).
//!
//! The Event Log service writes these itself as the first record of the log it
//! has just emptied, whatever asked for the clear (`wevtutil`, `EvtClearLog`,
//! .NET, a renamed copy of a tool), and no audit subcategory gates them: the
//! command-line rule cannot see the API paths, these can.

use schema::{Event, EventMeta, LogClearedEvent, User, time::now_ns};

use super::BlockOutcome;
use crate::xml;

const SECURITY_LOG_CLEARED: u32 = 1102;
const LOG_FILE_CLEARED: u32 = 104;

/// Normalizes a 1102 or a 104 into a [`LogClearedEvent`].
///
/// Skipped (cursor still advances): any other id the filter let through, and
/// a 104 that does not name the channel it cleared — an alert that cannot say
/// which log is gone is not worth guessing at.
pub(crate) fn normalize_log_cleared_block(block: &str) -> BlockOutcome {
    let Some(record) = xml::parse_log_cleared_event(block) else {
        return BlockOutcome::Unparseable;
    };
    let record_id = record.record_id;
    let channel = match record.event_id {
        SECURITY_LOG_CLEARED => "Security".to_string(),
        LOG_FILE_CLEARED => match record.cleared_channel {
            Some(channel) => channel,
            None => return BlockOutcome::Filtered { record_id },
        },
        _ => return BlockOutcome::Filtered { record_id },
    };
    let subject_user = match (record.subject_domain_name, record.subject_user_name) {
        (Some(domain), Some(name)) => format!("{domain}\\{name}"),
        (None, Some(name)) => name,
        (_, None) => String::new(),
    };
    let user = record
        .subject_sid
        .map_or(User::Unknown, |sid| User::Windows {
            sid,
            integrity_level: None,
        });
    let event = Event::LogCleared(LogClearedEvent {
        meta: EventMeta {
            pid: record.client_pid.unwrap_or(record.pid),
            ppid: 0,
            user,
            timestamp_ns: record.time_created_ns.unwrap_or_else(now_ns),
            comm: String::new(),
            container: None, // Windows: no container support
            process_generation: None,
            parent_process_generation: None,
        },
        channel,
        subject_user,
        subject_logon_id: record.subject_logon_id,
        backup_path: record.backup_path,
    });
    BlockOutcome::Event { record_id, event }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Trimmed from the real 104 and 1102 captured in the lab (#799, see xml/records/log_cleared.rs).
    const BLOCK_104: &str = "<Event><System><EventID>104</EventID>\
        <TimeCreated SystemTime='2026-10-15T12:50:01.7166040Z'/><EventRecordID>78381</EventRecordID>\
        <Execution ProcessID='3792' ThreadID='44592'/><Channel>System</Channel>\
        <Security UserID='S-1-5-21-1-2-3-1001'/></System><UserData><LogFileCleared>\
        <SubjectUserName>analyst</SubjectUserName><SubjectDomainName>LAB-W11</SubjectDomainName>\
        <Channel>OpenSSH/Operational</Channel><BackupPath>C:\\Users\\analyst\\ssh.evtx</BackupPath>\
        <ClientProcessId>41684</ClientProcessId></LogFileCleared></UserData></Event>";
    const BLOCK_1102: &str = "<Event><System><EventID>1102</EventID>\
        <EventRecordID>1399119</EventRecordID><Execution ProcessID='3792' ThreadID='47044'/>\
        <Channel>Security</Channel><Security/></System><UserData><LogFileCleared>\
        <SubjectUserSid>S-1-5-21-1-2-3-1001</SubjectUserSid><SubjectUserName>analyst</SubjectUserName>\
        <SubjectDomainName>LAB-W11</SubjectDomainName><SubjectLogonId>0x37b4d</SubjectLogonId>\
        <ClientProcessId>41684</ClientProcessId></LogFileCleared></UserData></Event>";

    fn log_cleared(block: &str) -> LogClearedEvent {
        match normalize_log_cleared_block(block) {
            BlockOutcome::Event {
                event: Event::LogCleared(e),
                ..
            } => e,
            other => panic!("expected a LogCleared event, got {other:?}"),
        }
    }

    fn windows_user(sid: &str) -> User {
        User::Windows {
            sid: sid.into(),
            integrity_level: None,
        }
    }

    #[test]
    fn a_104_reports_the_cleared_channel_and_the_clearing_process() {
        let event = log_cleared(BLOCK_104);
        assert_eq!(event.channel, "OpenSSH/Operational");
        assert_eq!(event.subject_user, r"LAB-W11\analyst");
        assert_eq!(event.meta.user, windows_user("S-1-5-21-1-2-3-1001"));
        // The clearing process, not the Event Log service (3792).
        assert_eq!(event.meta.pid, 41684);
        assert_eq!(event.meta.timestamp_ns, 1_792_068_601_716_604_000);
        assert_eq!(event.subject_logon_id, None);
        assert_eq!(
            event.backup_path.as_deref(),
            Some(r"C:\Users\analyst\ssh.evtx")
        );
    }

    #[test]
    fn a_1102_is_the_security_log_with_its_logon_session() {
        let event = log_cleared(BLOCK_1102);
        assert_eq!(event.channel, "Security");
        assert_eq!(event.subject_user, r"LAB-W11\analyst");
        assert_eq!(event.meta.user, windows_user("S-1-5-21-1-2-3-1001"));
        assert_eq!(event.meta.pid, 41684);
        assert_eq!(event.subject_logon_id.as_deref(), Some("0x37b4d"));
        assert_eq!(event.backup_path, None);
    }

    #[test]
    fn without_a_client_pid_the_event_log_service_stands_in() {
        let block = BLOCK_1102.replace("<ClientProcessId>41684</ClientProcessId>", "");
        assert_eq!(log_cleared(&block).meta.pid, 3792);
    }

    #[test]
    fn without_a_subject_the_account_is_unknown_not_guessed() {
        let block = BLOCK_1102
            .replace("<SubjectUserSid>S-1-5-21-1-2-3-1001</SubjectUserSid>", "")
            .replace("<SubjectUserName>analyst</SubjectUserName>", "");
        let event = log_cleared(&block);
        assert_eq!(event.meta.user, User::Unknown);
        assert_eq!(event.subject_user, "");
    }

    #[test]
    fn a_104_without_a_channel_and_other_ids_are_skipped_but_advance_the_cursor() {
        let no_channel = BLOCK_104.replace("<Channel>OpenSSH/Operational</Channel>", "");
        assert!(matches!(
            normalize_log_cleared_block(&no_channel),
            BlockOutcome::Filtered { record_id: 78381 }
        ));
        let other_id = BLOCK_1102.replace("<EventID>1102</EventID>", "<EventID>1100</EventID>");
        assert!(matches!(
            normalize_log_cleared_block(&other_id),
            BlockOutcome::Filtered {
                record_id: 1_399_119
            }
        ));
    }
}
