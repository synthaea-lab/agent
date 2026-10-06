//! Parser robustness for the Terminal Services session events (#285):
//! `parse_local_session_event` and `parse_remote_connection_event` read
//! `wevtutil` XML whose user name, for a 1149, is whatever the remote client
//! authenticated as. A panic on the polling loop stops the sensor, so the
//! parsers must never panic on anything; `None` or odd field values are fine.

use sensor_windows_eventlog::xml::{
    parse_local_session_event, parse_remote_connection_event, split_event_blocks,
};

/// The real console logon (21) from `src/xml.rs`'s unit tests (Windows 11
/// 26200, 2026-10-05, computer and account renamed), with a multi-byte user
/// name so the truncation sweep crosses char boundaries.
const CAPTURE_21: &str = r"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TerminalServices-LocalSessionManager' Guid='{5d896912-022d-40aa-a3a8-4fa5515c76d7}'/><EventID>21</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x1000000000000000</Keywords><TimeCreated SystemTime='2026-10-05T11:46:09.8088735Z'/><EventRecordID>16693</EventRecordID><Correlation ActivityID='{f48050f4-5382-4583-b7f5-6c0251ba0000}'/><Execution ProcessID='2312' ThreadID='2324'/><Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel><Computer>SANDBOX</Computer><Security UserID='S-1-5-18'/></System><UserData><EventXML xmlns='Event_NS'><User>SANDBOX\élodie</User><SessionID>1</SessionID><Address>LOCAL</Address></EventXML></UserData></Event>";

/// 1149 in its documented shape, from `src/xml.rs`'s unit tests.
const SHAPE_1149: &str = r"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TerminalServices-RemoteConnectionManager' Guid='{c76baa63-ae81-421c-b425-340b4b24157f}'/><EventID>1149</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x1000000000000000</Keywords><TimeCreated SystemTime='2026-10-05T12:00:00.0000000Z'/><EventRecordID>77</EventRecordID><Correlation ActivityID='{f420c0f4-1e2f-4b29-8a3c-4f6d0e3a0000}'/><Execution ProcessID='1180' ThreadID='2044'/><Channel>Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational</Channel><Computer>SANDBOX</Computer><Security UserID='S-1-5-20'/></System><UserData><EventXML xmlns='Event_NS'><Param1>ünïcödé</Param1><Param2>LAB</Param2><Param3>198.51.100.40</Param3></EventXML></UserData></Event>";

fn assert_every_truncation_is_handled(
    capture: &str,
    parse: fn(&str) -> Option<sensor_windows_eventlog::xml::TerminalSessionEvent>,
    event_id: u32,
) {
    let mut cuts = 0;
    for end in 0..capture.len() {
        if !capture.is_char_boundary(end) {
            continue;
        }
        let prefix = &capture[..end];
        cuts += 1;
        assert!(split_event_blocks(prefix).is_empty(), "cut at {end}");
        let _ = parse(prefix);
    }
    assert!(cuts > 800, "the sweep must actually cover the capture");
    let full = split_event_blocks(capture);
    assert_eq!(full.len(), 1);
    assert_eq!(parse(full[0]).expect("complete capture").event_id, event_id);
}

#[test]
fn every_truncation_of_a_real_21_is_handled_without_panicking() {
    assert_every_truncation_is_handled(CAPTURE_21, parse_local_session_event, 21);
}

#[test]
fn every_truncation_of_a_1149_is_handled_without_panicking() {
    assert_every_truncation_is_handled(SHAPE_1149, parse_remote_connection_event, 1149);
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
    for capture in [CAPTURE_21, SHAPE_1149] {
        cases.extend([
            with_field(capture, "EventID", "99999999999999999999"),
            with_field(capture, "EventRecordID", "18446744073709551616"),
            with_field(capture, "EventRecordID", "\u{663}\u{664}"),
            capture.replace("</UserData>", ""),
            capture.replace("<UserData>", ""),
            capture.replacen("<UserData>", "</UserData><UserData>", 1),
            capture.replace("</EventRecordID>", ""),
            capture.replace("ProcessID='", "ProcessID='-"),
        ]);
    }
    cases.extend([
        with_field(CAPTURE_21, "SessionID", "-1"),
        with_field(CAPTURE_21, "SessionID", "4294967296"),
        with_field(CAPTURE_21, "Address", "999.999.999.999"),
        with_field(CAPTURE_21, "Address", "[::1]:3389"),
        with_field(CAPTURE_21, "User", "&amp;lt;&#xFFFFFFFF;&#;&amp;"),
        with_field(SHAPE_1149, "Param1", "\u{202E}nimda"),
        with_field(SHAPE_1149, "Param1", &"A".repeat(100_000)),
        with_field(SHAPE_1149, "Param2", "</Param2><Param3>10.0.0.1"),
        with_field(SHAPE_1149, "Param3", ""),
        String::new(),
        "<Event></Event>".to_string(),
        "<Event><UserData></UserData></Event>".to_string(),
        "<Event>".repeat(1_000),
    ]);
    for case in &cases {
        for block in split_event_blocks(case) {
            let _ = parse_local_session_event(block);
            let _ = parse_remote_connection_event(block);
        }
        let _ = parse_local_session_event(case);
        let _ = parse_remote_connection_event(case);
    }
}

#[test]
fn a_missing_record_id_is_skipped_not_guessed() {
    let without = CAPTURE_21.replace("<EventRecordID>16693</EventRecordID>", "");
    assert!(parse_local_session_event(&without).is_none());
    let without = SHAPE_1149.replace("<EventRecordID>77</EventRecordID>", "");
    assert!(parse_remote_connection_event(&without).is_none());
}
