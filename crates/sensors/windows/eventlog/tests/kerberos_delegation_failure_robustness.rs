//! Parser robustness for the Kerberos delegation-failure records (#364):
//! `parse_kerberos_delegation_failure_block` reads `TargetName`/`ProcessName` and the other
//! EID 201/202 fields, which an attacker's own process controls (it is the one making the
//! denied request). A panic on the polling loop stops the sensor, so the parser must never
//! panic on anything; `None` or odd field values are fine.

use sensor_windows_eventlog::xml::{parse_kerberos_delegation_failure_block, split_event_blocks};

/// EID 201 fixture, field names and order from the provider's own manifest
/// (`Microsoft-Windows-Security-Kerberos`, `wevtutil gp ... /ge:true /gm:true`, #364), with a
/// multi-byte process name so the truncation sweep crosses char boundaries. `<Event ` (with
/// the trailing space `split_event_blocks` looks for) matches real `wevtutil /f:xml` output.
const BLOCK_201: &str = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>\
    <System><EventID>201</EventID>\
    <TimeCreated SystemTime='2026-10-23T09:15:30.0000000Z'/><EventRecordID>5201</EventRecordID>\
    <Channel>Microsoft-Windows-Kerberos/Operational</Channel></System><EventData>\
    <Data Name='TargetName'>cifs/dc01.lab.internal</Data><Data Name='UserName'>analyst</Data>\
    <Data Name='DomainName'>LAB</Data><Data Name='CallerPID'>4120</Data>\
    <Data Name='ProcessName'>C:\\Windows\\System32\\f\u{00e9}lix.exe</Data>\
    <Data Name='ClientLUID'>0x3e7</Data><Data Name='ClientUserName'>svc_fileserver</Data>\
    <Data Name='ClientDomainName'>LAB</Data><Data Name='MechanismOID'>1.2.840.113554.1.2.2</Data>\
    </EventData></Event>";

fn assert_every_truncation_is_handled(capture: &str, event_id: u32) {
    let mut cuts = 0;
    for end in 0..capture.len() {
        if !capture.is_char_boundary(end) {
            continue;
        }
        let prefix = &capture[..end];
        cuts += 1;
        assert!(split_event_blocks(prefix).is_empty(), "cut at {end}");
        let _ = parse_kerberos_delegation_failure_block(prefix);
    }
    assert!(cuts > 500, "the sweep must actually cover the capture");
    let full = split_event_blocks(capture);
    assert_eq!(full.len(), 1);
    assert_eq!(
        parse_kerberos_delegation_failure_block(full[0])
            .expect("complete capture")
            .event_id,
        event_id
    );
}

#[test]
fn every_truncation_of_a_real_201_is_handled_without_panicking() {
    assert_every_truncation_is_handled(BLOCK_201, 201);
}

/// `capture` with one plain element's text replaced (`<tag>...</tag>`, no attributes).
fn with_field(capture: &str, tag: &str, value: &str) -> String {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = capture.find(&open).expect("tag in capture") + open.len();
    let end = start + capture[start..].find(&close).expect("closing tag");
    format!("{}{value}{}", &capture[..start], &capture[end..])
}

/// `capture` with one `<Data Name='name'>...</Data>` element's text replaced.
fn with_data_field(capture: &str, name: &str, value: &str) -> String {
    let open = format!("<Data Name='{name}'>");
    let start = capture.find(&open).expect("Data field in capture") + open.len();
    let end = start + capture[start..].find("</Data>").expect("closing tag");
    format!("{}{value}{}", &capture[..start], &capture[end..])
}

#[test]
fn malformed_fields_never_panic() {
    let cases = [
        with_field(BLOCK_201, "EventID", "99999999999999999999"),
        with_field(BLOCK_201, "EventRecordID", "18446744073709551616"),
        with_field(BLOCK_201, "EventRecordID", "\u{663}\u{664}"),
        with_data_field(BLOCK_201, "CallerPID", "-1"),
        with_data_field(BLOCK_201, "CallerPID", "4294967296"),
        with_data_field(BLOCK_201, "TargetName", "&amp;lt;&#xFFFFFFFF;&#;&amp;"),
        with_data_field(BLOCK_201, "TargetName", "\u{202E}nimda"),
        with_data_field(BLOCK_201, "ProcessName", &"A".repeat(100_000)),
        BLOCK_201.replace("</EventData>", ""),
        BLOCK_201.replace("<EventData>", ""),
        BLOCK_201.replacen("<EventData>", "</EventData><EventData>", 1),
        BLOCK_201.replace("</EventRecordID>", ""),
        BLOCK_201.replace("</System>", ""),
        BLOCK_201.replace("Name='TargetName'", "Name=\"TargetName\""),
        BLOCK_201.replace(
            "<TimeCreated SystemTime='2026-10-23T09:15:30.0000000Z'/>",
            "",
        ),
        BLOCK_201.replace("SystemTime='", "SystemTime='not-a-time"),
        String::new(),
        "<Event ></Event>".to_string(),
        "<Event ><EventData></EventData></Event>".to_string(),
        "<Event ><System><EventID>".to_string(),
        "<Event >".repeat(1_000),
    ];
    for case in &cases {
        for block in split_event_blocks(case) {
            let _ = parse_kerberos_delegation_failure_block(block);
        }
        let _ = parse_kerberos_delegation_failure_block(case);
    }
}

#[test]
fn a_missing_record_id_is_skipped_not_guessed() {
    let without = BLOCK_201.replace("<EventRecordID>5201</EventRecordID>", "");
    assert!(parse_kerberos_delegation_failure_block(&without).is_none());
}

#[test]
fn a_missing_event_id_is_skipped_not_guessed() {
    let without = BLOCK_201.replace("<EventID>201</EventID>", "");
    assert!(parse_kerberos_delegation_failure_block(&without).is_none());
}

#[test]
fn an_unparseable_caller_pid_is_absent_not_zero() {
    let block = with_data_field(BLOCK_201, "CallerPID", "4294967296");
    let parsed = parse_kerberos_delegation_failure_block(&block).expect("parses");
    assert_eq!(parsed.caller_pid, None);
}
