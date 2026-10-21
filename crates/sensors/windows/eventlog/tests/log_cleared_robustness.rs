//! Parser robustness for the log-cleared records (#799):
//! `parse_log_cleared_event` reads `wevtutil` XML whose channel, account and
//! backup path are whatever the clearing process supplied (`ClearLog` takes
//! any backup path, an account can be named anything). A panic on the polling
//! loop stops the sensor, so the parser must never panic on anything; `None` or
//! odd field values are fine.

use sensor_windows_eventlog::xml::{parse_log_cleared_event, split_event_blocks};

/// The real System 104 from `src/xml.rs`'s unit tests (Windows 11 26200,
/// 2026-10-15, computer and account renamed), with a multi-byte account name
/// so the truncation sweep crosses char boundaries.
const CAPTURE_104: &str = r"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog' Guid='{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}'/><EventID>104</EventID><Version>1</Version><Level>4</Level><Task>104</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-10-15T12:50:01.7166040Z'/><EventRecordID>78381</EventRecordID><Correlation/><Execution ProcessID='3792' ThreadID='44592'/><Channel>System</Channel><Computer>LAB-W11</Computer><Security UserID='S-1-5-21-61980266-902198588-2058873832-1001'/></System><UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserName>élodie</SubjectUserName><SubjectDomainName>LAB-W11</SubjectDomainName><Channel>OpenSSH/Operational</Channel><BackupPath>C:\Users\élodie\Documents\OpenSSH-backup-799.evtx</BackupPath><ClientProcessId>41684</ClientProcessId><ClientProcessStartKey>84161018036490963</ClientProcessStartKey></LogFileCleared></UserData></Event>";

/// The real Security 1102 from the same run.
const CAPTURE_1102: &str = r"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog' Guid='{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}'/><EventID>1102</EventID><Version>1</Version><Level>4</Level><Task>104</Task><Opcode>0</Opcode><Keywords>0x4020000000000000</Keywords><TimeCreated SystemTime='2026-10-15T12:50:01.7339239Z'/><EventRecordID>1399119</EventRecordID><Correlation/><Execution ProcessID='3792' ThreadID='47044'/><Channel>Security</Channel><Computer>LAB-W11</Computer><Security/></System><UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserSid>S-1-5-21-61980266-902198588-2058873832-1001</SubjectUserSid><SubjectUserName>élodie</SubjectUserName><SubjectDomainName>LAB-W11</SubjectDomainName><SubjectLogonId>0x37b4d</SubjectLogonId><ClientProcessId>41684</ClientProcessId><ClientProcessStartKey>84161018036490963</ClientProcessStartKey></LogFileCleared></UserData></Event>";

fn assert_every_truncation_is_handled(capture: &str, event_id: u32) {
    let mut cuts = 0;
    for end in 0..capture.len() {
        if !capture.is_char_boundary(end) {
            continue;
        }
        let prefix = &capture[..end];
        cuts += 1;
        assert!(split_event_blocks(prefix).is_empty(), "cut at {end}");
        let _ = parse_log_cleared_event(prefix);
    }
    assert!(cuts > 800, "the sweep must actually cover the capture");
    let full = split_event_blocks(capture);
    assert_eq!(full.len(), 1);
    assert_eq!(
        parse_log_cleared_event(full[0])
            .expect("complete capture")
            .event_id,
        event_id
    );
}

#[test]
fn every_truncation_of_a_real_104_is_handled_without_panicking() {
    assert_every_truncation_is_handled(CAPTURE_104, 104);
}

#[test]
fn every_truncation_of_a_real_1102_is_handled_without_panicking() {
    assert_every_truncation_is_handled(CAPTURE_1102, 1102);
}

/// `capture` with one element's text replaced.
fn with_field(capture: &str, tag: &str, value: &str) -> String {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = capture.find(&open).expect("tag in capture") + open.len();
    let end = start + capture[start..].find(&close).expect("closing tag");
    format!("{}{value}{}", &capture[..start], &capture[end..])
}

#[test]
fn malformed_fields_never_panic() {
    let mut cases = Vec::new();
    for capture in [CAPTURE_104, CAPTURE_1102] {
        cases.extend([
            with_field(capture, "EventID", "99999999999999999999"),
            with_field(capture, "EventRecordID", "18446744073709551616"),
            with_field(capture, "EventRecordID", "\u{663}\u{664}"),
            with_field(capture, "ClientProcessId", "-1"),
            with_field(capture, "ClientProcessId", "4294967296"),
            with_field(capture, "SubjectUserName", "&amp;lt;&#xFFFFFFFF;&#;&amp;"),
            with_field(capture, "SubjectUserName", "\u{202E}nimda"),
            with_field(capture, "SubjectDomainName", &"A".repeat(100_000)),
            capture.replace("</UserData>", ""),
            capture.replace("<UserData>", ""),
            capture.replacen("<UserData>", "</UserData><UserData>", 1),
            capture.replace("</EventRecordID>", ""),
            capture.replace("ProcessID='", "ProcessID='-"),
            capture.replace("</System>", ""),
        ]);
    }
    cases.extend([
        with_field(CAPTURE_104, "Channel", ""),
        with_field(CAPTURE_104, "Channel", "</Channel><BackupPath>C:\\x"),
        with_field(CAPTURE_104, "BackupPath", &"\\".repeat(100_000)),
        CAPTURE_104.replace("UserID='", "UserID='</System>"),
        CAPTURE_104.replace("UserID='", "UserID=\""),
        with_field(CAPTURE_1102, "SubjectUserSid", ""),
        with_field(CAPTURE_1102, "SubjectLogonId", "0x"),
        String::new(),
        "<Event></Event>".to_string(),
        "<Event><UserData></UserData></Event>".to_string(),
        "<Event><System><Security UserID='".to_string(),
        "<Event>".repeat(1_000),
    ]);
    for case in &cases {
        for block in split_event_blocks(case) {
            let _ = parse_log_cleared_event(block);
        }
        let _ = parse_log_cleared_event(case);
    }
}

#[test]
fn a_missing_record_id_is_skipped_not_guessed() {
    let without = CAPTURE_104.replace("<EventRecordID>78381</EventRecordID>", "");
    assert!(parse_log_cleared_event(&without).is_none());
    let without = CAPTURE_1102.replace("<EventRecordID>1399119</EventRecordID>", "");
    assert!(parse_log_cleared_event(&without).is_none());
}

#[test]
fn an_unparseable_client_pid_is_absent_not_zero() {
    let block = with_field(CAPTURE_1102, "ClientProcessId", "4294967296");
    let parsed = parse_log_cleared_event(&block).expect("parses");
    assert_eq!(parsed.client_pid, None);
}
