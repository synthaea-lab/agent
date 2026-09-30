//! Parser robustness for the `AppLocker` 8003/8004 path (#427, #529 review):
//! `parse_applocker_event` and `split_event_blocks` read `wevtutil` XML whose
//! `FilePath`/`FullFilePath` carry the blocked file's name, which whoever dropped
//! the file chose. A panic on the polling loop stops the sensor, so the parsers
//! must never panic on anything; returning `None` or odd field values is fine.

use sensor_windows_eventlog::xml::{
    expand_applocker_path, parse_applocker_event, split_event_blocks,
};

/// The real 8003 (audit mode) captured on Windows 11 26100, copied from the
/// unit-test fixture in `src/xml.rs`. It contains a multi-byte `®` in `Fqbn`,
/// which makes the truncation sweep cross char boundaries.
const CAPTURE_8003: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-AppLocker' Guid='{cbda4dbf-8d5d-4f69-9578-be14aa540d22}'/><EventID>8003</EventID><Version>0</Version><Level>3</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-09-29T08:12:31.6189560Z'/><EventRecordID>24</EventRecordID><Correlation/><Execution ProcessID='6868' ThreadID='564'/><Channel>Microsoft-Windows-AppLocker/EXE and DLL</Channel><Computer>Sandbox</Computer><Security UserID='S-1-5-21-1663667890-2519037288-962558911-1001'/></System><UserData><RuleAndFileData xmlns='http://schemas.microsoft.com/schemas/event/Microsoft.Windows/1.0.0.0'><PolicyNameLength>3</PolicyNameLength><PolicyName>EXE</PolicyName><RuleId>{00000000-0000-0000-0000-000000000000}</RuleId><RuleNameLength>1</RuleNameLength><RuleName>-</RuleName><RuleSddlLength>1</RuleSddlLength><RuleSddl>-</RuleSddl><TargetUser>S-1-5-21-1663667890-2519037288-962558911-1001</TargetUser><TargetProcessId>7092</TargetProcessId><FilePathLength>35</FilePathLength><FilePath>%OSDRIVE%\USERS\PUBLIC\TEST8003.EXE</FilePath><FileHashLength>32</FileHashLength><FileHash>8C972B0E2047FC0E84BBDC66A662D1E52FDE28E5D2D040BDCDA21CC7D6BB2810</FileHash><FqbnLength>118</FqbnLength><Fqbn>O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US\MICROSOFT® WINDOWS® OPERATING SYSTEM\WHOAMI.EXE\10.0.26100.1882</Fqbn><TargetLogonId>0x72d47</TargetLogonId><FullFilePathLength>28</FullFilePathLength><FullFilePath>C:\Users\Public\test8003.exe</FullFilePath></RuleAndFileData></UserData></Event>"#;

/// The real 8004 (enforced block) captured on the same VM, copied from
/// `src/xml.rs`. Its `FileHash` element is empty (`FileHashLength` 0).
const CAPTURE_8004: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-AppLocker' Guid='{cbda4dbf-8d5d-4f69-9578-be14aa540d22}'/><EventID>8004</EventID><Version>0</Version><Level>2</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-09-30T08:21:58.8915403Z'/><EventRecordID>29</EventRecordID><Correlation/><Execution ProcessID='7764' ThreadID='8072'/><Channel>Microsoft-Windows-AppLocker/EXE and DLL</Channel><Computer>SYN-DRV-W11</Computer><Security UserID='S-1-5-21-1663667890-2519037288-962558911-1001'/></System><UserData><RuleAndFileData xmlns='http://schemas.microsoft.com/schemas/event/Microsoft.Windows/1.0.0.0'><PolicyNameLength>3</PolicyNameLength><PolicyName>EXE</PolicyName><RuleId>{00000000-0000-0000-0000-000000000000}</RuleId><RuleNameLength>1</RuleNameLength><RuleName>-</RuleName><RuleSddlLength>1</RuleSddlLength><RuleSddl>-</RuleSddl><TargetUser>S-1-5-21-1663667890-2519037288-962558911-1001</TargetUser><TargetProcessId>9184</TargetProcessId><FilePathLength>35</FilePathLength><FilePath>%OSDRIVE%\USERS\PUBLIC\TEST8004.EXE</FilePath><FileHashLength>0</FileHashLength><FileHash></FileHash><FqbnLength>1</FqbnLength><Fqbn>-</Fqbn><TargetLogonId>0x92d46</TargetLogonId><FullFilePathLength>28</FullFilePathLength><FullFilePath>C:\Users\Public\test8004.exe</FullFilePath></RuleAndFileData></UserData></Event>"#;

fn assert_every_truncation_is_handled(capture: &str, event_id: u32) {
    let mut cuts = 0;
    for end in 0..capture.len() {
        if !capture.is_char_boundary(end) {
            continue;
        }
        let prefix = &capture[..end];
        cuts += 1;
        // A truncated document never yields an `<Event>` block to parse.
        assert!(split_event_blocks(prefix).is_empty(), "cut at {end}");
        // Fed directly, a prefix may parse partially or not at all, but never panics.
        let _ = parse_applocker_event(prefix);
    }
    assert!(cuts > 1_000, "the sweep must actually cover the capture");
    let full = split_event_blocks(capture);
    assert_eq!(full.len(), 1);
    let parsed = parse_applocker_event(full[0]).expect("the complete capture parses");
    assert_eq!(parsed.event_id, event_id);
}

#[test]
fn every_truncation_of_a_real_8003_is_handled_without_panicking() {
    assert_every_truncation_is_handled(CAPTURE_8003, 8003);
}

#[test]
fn every_truncation_of_a_real_8004_is_handled_without_panicking() {
    assert_every_truncation_is_handled(CAPTURE_8004, 8004);
}

/// The capture with one element's text replaced, for the malformed-field cases.
fn with_field(tag: &str, value: &str) -> String {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = CAPTURE_8003.find(&open).expect("tag in capture") + open.len();
    let end = start + CAPTURE_8003[start..].find(&close).expect("closing tag");
    format!("{}{value}{}", &CAPTURE_8003[..start], &CAPTURE_8003[end..])
}

#[test]
fn malformed_fields_never_panic() {
    let cases = [
        with_field("EventID", "99999999999999999999"),
        with_field("EventID", "-1"),
        with_field("EventRecordID", "18446744073709551616"),
        with_field("EventRecordID", "\u{663}\u{664}"),
        with_field("TargetProcessId", "-5"),
        with_field("TargetProcessId", "0x1F"),
        with_field("FullFilePath", ""),
        with_field("FullFilePath", "&amp;lt;&#xFFFFFFFF;&#99999999999;&#;&amp;"),
        with_field("FullFilePath", "C:\\Users\\Public\\\u{202E}exe.8003tset"),
        with_field("FilePath", "%OSDRIVE%%OSDRIVE%\\\u{202E}X.EXE"),
        CAPTURE_8003.replace("</FullFilePath>", ""),
        CAPTURE_8003.replace("<FullFilePath>", ""),
        CAPTURE_8003.replacen("<FullFilePath>", "</FullFilePath><FullFilePath>", 1),
        CAPTURE_8003.replace("</EventRecordID>", ""),
        CAPTURE_8003
            .replace("<UserData>", "")
            .replace("</UserData>", ""),
        String::new(),
        "<Event></Event>".to_string(),
        "</Event><Event>".to_string(),
        "<Event>".repeat(1_000),
    ];
    for case in &cases {
        for block in split_event_blocks(case) {
            let _ = parse_applocker_event(block);
        }
        let _ = parse_applocker_event(case);
    }
}

#[test]
fn a_missing_record_id_is_skipped_not_guessed() {
    let without = CAPTURE_8003.replace("<EventRecordID>24</EventRecordID>", "");
    assert!(parse_applocker_event(&without).is_none());
}

#[test]
fn path_expansion_never_panics_on_odd_variables() {
    let env = |name: &str| match name {
        "SystemDrive" => Some("C:".to_string()),
        "SystemRoot" => Some("C:\\Windows".to_string()),
        _ => None,
    };
    for raw in [
        "",
        "%",
        "%%",
        "%OSDRIVE%",
        "%OSDRIVE%%OSDRIVE%\\X.EXE",
        "%osdrive%\\x.exe",
        "%UNKNOWN%\\X.EXE",
        "%REMOVABLE%\\X.EXE",
        "%SYSTEM32%\u{202E}\\X.EXE",
        "\u{202E}%WINDIR%",
    ] {
        let _ = expand_applocker_path(raw, env);
        let _ = expand_applocker_path(raw, |_| None);
    }
}
