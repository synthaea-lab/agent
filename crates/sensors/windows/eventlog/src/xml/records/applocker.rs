//! `AppLocker` policy decisions and the path variables their `FilePath` carries.

use crate::xml::scan::{attribute_value, element_text, event_field, unescape_xml_entities};

/// One `AppLocker` policy-decision event. EXE/DLL and MSI/Script use `FilePath`;
/// packaged-app channels use `Package` instead. `AppLocker` emits these as
/// `<UserData>` / `<RuleAndFileData>` rather than the
/// `<EventData><Data Name=...>` shape the Security channel uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppLockerEvent {
    pub record_id: u64,
    /// `System/EventID`, one of the channel's audited or enforced decision ids.
    pub event_id: u32,
    /// Collection or policy name from `RuleAndFileData/PolicyName` (for
    /// example `EXE`, `DLL`, `MSI`, `SCRIPT`, or a packaged-app identity).
    /// Empty if missing.
    pub policy_name: String,
    /// SID of the user whose execution was refused
    /// (`RuleAndFileData/TargetUser`). Deliberately not
    /// `System/Security/@UserID`, which names the account the event was
    /// *logged* under; the two matched in the only real capture so far (#427).
    pub target_user: Option<String>,
    /// PID from `<Execution ProcessID='...'>`. 0 if missing. Checked in the
    /// lab (#529) for 8003 and 8004; the other channels have not been lab-tested.
    pub pid: u32,
    /// PID of the process being *created* for the image
    /// (`RuleAndFileData/TargetProcessId`), not its launcher. Checked in the
    /// lab (#529): on an 8003 it is the audited binary's own live process
    /// (`Start-Process -PassThru` reported the same id); on an 8004 the pid
    /// was allocated but the process never ran. 0 if missing.
    pub target_process_id: u32,
    /// Affected object from `RuleAndFileData/FilePath`, or the `Package`
    /// identity used by packaged-app events. File paths retain variables and
    /// case — see [`expand_applocker_path`]. Empty if no identity is present.
    pub file_path: String,
    /// `RuleAndFileData/FullFilePath`: the image's real path, original case,
    /// no path variable (e.g. `C:\Users\Public\test8003.exe`). Present in
    /// the real 8003 captured on Windows 11 26100 (#427); `None` when the
    /// build doesn't emit it, in which case callers fall back to
    /// [`expand_applocker_path`] on [`Self::file_path`].
    pub full_file_path: Option<String>,
}

/// Parses one `AppLocker` policy-decision `<Event>` block. `None` if the block
/// is missing `EventRecordID` (a genuinely different event matched the `XPath`
/// filter, or a `wevtutil` output shape change — skip rather than guess, same
/// convention as the other parsers in this module).
#[must_use]
pub fn parse_applocker_event(block: &str) -> Option<AppLockerEvent> {
    let record_id = element_text(block, "EventRecordID")?.parse().ok()?;
    let event_id = element_text(block, "EventID")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let policy_name = event_field(block, "PolicyName")
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    let target_user = event_field(block, "TargetUser")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    // `AppLocker`'s payload lives in <UserData><RuleAndFileData>: children are
    // *plain* elements (`<FilePath>...</FilePath>`), not `<Data Name='...'>`
    // like on the Security channel.
    let pid = attribute_value(block, "ProcessID")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let target_process_id = event_field(block, "TargetProcessId")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    // Unescaped like `FullFilePath`: the fallback path would otherwise keep
    // `&amp;` for a directory containing `&`.
    let file_path = event_field(block, "FilePath")
        // Packaged app events carry the package identity in place of a file
        // path. It is still the policy's affected object and fits the existing
        // PolicyDenial object_path field without a schema change.
        .or_else(|| event_field(block, "Package"))
        .map(str::trim)
        .map(unescape_xml_entities)
        .unwrap_or_default();
    // `<FullFilePath>` cannot be mistaken for `<FilePath>`: the marker
    // includes the opening `<`, so the two never overlap.
    let full_file_path = event_field(block, "FullFilePath")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(unescape_xml_entities);
    Some(AppLockerEvent {
        record_id,
        event_id,
        policy_name,
        target_user,
        pid,
        target_process_id,
        file_path,
        full_file_path,
    })
}

/// Expands the path variable `AppLocker` prefixes its `FilePath` with, so the
/// path can be matched by rules written against real paths (#427).
/// `AppLocker` path variables are *not* environment variables; each maps to
/// one (Microsoft Learn, "Understanding the path rule condition in AppLocker"):
///
/// | Variable | Expanded from |
/// |---|---|
/// | `%OSDRIVE%` | `SystemDrive` |
/// | `%WINDIR%` | `SystemRoot` |
/// | `%SYSTEM32%` | `SystemRoot` + `\System32` |
/// | `%PROGRAMFILES%` | `ProgramFiles` |
///
/// Two variables are lossy by design: `%SYSTEM32%` covers both `System32` and
/// `SysWOW64`, and `%PROGRAMFILES%` both `Program Files` and
/// `Program Files (x86)`; the event does not say which, so the 64-bit
/// directory is assumed. `%REMOVABLE%` and `%HOT%` (removable media) have no
/// fixed drive letter and are left as-is, as is any variable `env` cannot
/// resolve. Case is preserved (`AppLocker` upper-cases paths; rules compare
/// case-insensitively). `env` looks up an environment variable — injected so
/// the mapping is testable off-Windows.
#[must_use]
pub fn expand_applocker_path(raw: &str, env: impl Fn(&str) -> Option<String>) -> String {
    const VARIABLES: &[(&str, &str, &str)] = &[
        ("%OSDRIVE%", "SystemDrive", ""),
        ("%WINDIR%", "SystemRoot", ""),
        ("%SYSTEM32%", "SystemRoot", "\\System32"),
        ("%PROGRAMFILES%", "ProgramFiles", ""),
    ];
    for (variable, env_name, suffix) in VARIABLES {
        let Some(prefix) = raw.get(..variable.len()) else {
            continue;
        };
        if !prefix.eq_ignore_ascii_case(variable) {
            continue;
        }
        return match env(env_name) {
            Some(value) => format!("{value}{suffix}{}", &raw[variable.len()..]),
            None => raw.to_string(),
        };
    }
    raw.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::scan::split_event_blocks;

    /// A `powershell.exe` invocation from a low-privilege lab account that
    /// `AppLocker` refused to run because its file path (`C:\Users\...\Downloads`)
    /// matched a deny rule. Shape mirrors the `<UserData>`/`<RuleAndFileData>`
    /// `AppLocker` actually emits, not the `<EventData>` shape of Security events.
    const APPLOCKER_BLOCK_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-AppLocker' Guid='{cbda4dbf-8d5d-4f69-9578-be14aa540d22}'/><EventID>8004</EventID><Version>0</Version><Level>2</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-09-22T08:19:44.1273512Z'/><EventRecordID>512</EventRecordID><Correlation/><Execution ProcessID='732' ThreadID='4104'/><Channel>Microsoft-Windows-AppLocker/EXE and DLL</Channel><Computer>Sandbox</Computer><Security UserID='S-1-5-21-1663667890-2519037288-962558911-1001'/></System><UserData><RuleAndFileData xmlns='http://schemas.microsoft.com/schemas/event/Microsoft.Windows/1.0.0.0'><PolicyName>EXE</PolicyName><RuleId>{00000000-0000-0000-0000-000000000000}</RuleId><RuleName>Deny Everyone from Downloads</RuleName><RuleSddl>D:(XA;;FX;;;WD;(Exists Path))</RuleSddl><TargetUser>S-1-5-21-1663667890-2519037288-962558911-1001</TargetUser><TargetProcessId>5312</TargetProcessId><FilePath>%OSDRIVE%\USERS\SOLKA\DOWNLOADS\POWERSHELL.EXE</FilePath><FileHash>0000000000000000000000000000000000000000000000000000000000000000</FileHash><FqbnLength>1</FqbnLength><Fqbn>O:\O:\O:0.0.0.0</Fqbn></RuleAndFileData></UserData></Event>"#;

    #[test]
    fn parses_a_real_shaped_applocker_block() {
        let block = split_event_blocks(APPLOCKER_BLOCK_XML)[0];
        let parsed = parse_applocker_event(block).expect("should parse");
        assert_eq!(parsed.record_id, 512);
        assert_eq!(parsed.event_id, 8004);
        assert_eq!(parsed.policy_name, "EXE");
        assert_eq!(
            parsed.target_user.as_deref(),
            Some("S-1-5-21-1663667890-2519037288-962558911-1001")
        );
        assert_eq!(parsed.target_process_id, 5312);
        assert_eq!(
            parsed.file_path,
            "%OSDRIVE%\\USERS\\SOLKA\\DOWNLOADS\\POWERSHELL.EXE"
        );
    }

    /// A real 8003, captured on the Windows 11 26100 lab VM (2026-09-29,
    /// #427): `AuditOnly` EXE collection allowing only `%WINDIR%` and
    /// `%PROGRAMFILES%`, then `whoami.exe` copied to `C:\Users\Public` and
    /// run. Verbatim `wevtutil qe ... /f:xml` output.
    const APPLOCKER_AUDIT_8003_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-AppLocker' Guid='{cbda4dbf-8d5d-4f69-9578-be14aa540d22}'/><EventID>8003</EventID><Version>0</Version><Level>3</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-09-29T08:12:31.6189560Z'/><EventRecordID>24</EventRecordID><Correlation/><Execution ProcessID='6868' ThreadID='564'/><Channel>Microsoft-Windows-AppLocker/EXE and DLL</Channel><Computer>Sandbox</Computer><Security UserID='S-1-5-21-1663667890-2519037288-962558911-1001'/></System><UserData><RuleAndFileData xmlns='http://schemas.microsoft.com/schemas/event/Microsoft.Windows/1.0.0.0'><PolicyNameLength>3</PolicyNameLength><PolicyName>EXE</PolicyName><RuleId>{00000000-0000-0000-0000-000000000000}</RuleId><RuleNameLength>1</RuleNameLength><RuleName>-</RuleName><RuleSddlLength>1</RuleSddlLength><RuleSddl>-</RuleSddl><TargetUser>S-1-5-21-1663667890-2519037288-962558911-1001</TargetUser><TargetProcessId>7092</TargetProcessId><FilePathLength>35</FilePathLength><FilePath>%OSDRIVE%\USERS\PUBLIC\TEST8003.EXE</FilePath><FileHashLength>32</FileHashLength><FileHash>8C972B0E2047FC0E84BBDC66A662D1E52FDE28E5D2D040BDCDA21CC7D6BB2810</FileHash><FqbnLength>118</FqbnLength><Fqbn>O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US\MICROSOFT® WINDOWS® OPERATING SYSTEM\WHOAMI.EXE\10.0.26100.1882</Fqbn><TargetLogonId>0x72d47</TargetLogonId><FullFilePathLength>28</FullFilePathLength><FullFilePath>C:\Users\Public\test8003.exe</FullFilePath></RuleAndFileData></UserData></Event>"#;

    #[test]
    fn parses_a_real_8003_capture() {
        let block = split_event_blocks(APPLOCKER_AUDIT_8003_XML)[0];
        let parsed = parse_applocker_event(block).expect("should parse");
        assert_eq!(parsed.record_id, 24);
        assert_eq!(parsed.event_id, 8003);
        assert_eq!(parsed.policy_name, "EXE");
        assert_eq!(
            parsed.target_user.as_deref(),
            Some("S-1-5-21-1663667890-2519037288-962558911-1001")
        );
        assert_eq!(parsed.pid, 6868);
        assert_eq!(parsed.target_process_id, 7092);
        assert_eq!(parsed.file_path, "%OSDRIVE%\\USERS\\PUBLIC\\TEST8003.EXE");
        assert_eq!(
            parsed.full_file_path.as_deref(),
            Some("C:\\Users\\Public\\test8003.exe")
        );
    }

    /// A real 8004, captured on the same lab VM (renamed `SYN-DRV-W11`,
    /// Windows 11 Pro 26200, 2026-09-30, #529): same rules as the 8003 above
    /// but the EXE collection `Enabled` (enforced), then `whoami.exe` copied
    /// to `C:\Users\Public\test8004.exe` and run — refused. Unlike the 8003,
    /// the block carries no `FileHash` (length 0, empty element) and `Fqbn`
    /// is `-`. Verbatim `wevtutil qe ... /f:xml` output.
    const APPLOCKER_BLOCK_8004_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-AppLocker' Guid='{cbda4dbf-8d5d-4f69-9578-be14aa540d22}'/><EventID>8004</EventID><Version>0</Version><Level>2</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-09-30T08:21:58.8915403Z'/><EventRecordID>29</EventRecordID><Correlation/><Execution ProcessID='7764' ThreadID='8072'/><Channel>Microsoft-Windows-AppLocker/EXE and DLL</Channel><Computer>SYN-DRV-W11</Computer><Security UserID='S-1-5-21-1663667890-2519037288-962558911-1001'/></System><UserData><RuleAndFileData xmlns='http://schemas.microsoft.com/schemas/event/Microsoft.Windows/1.0.0.0'><PolicyNameLength>3</PolicyNameLength><PolicyName>EXE</PolicyName><RuleId>{00000000-0000-0000-0000-000000000000}</RuleId><RuleNameLength>1</RuleNameLength><RuleName>-</RuleName><RuleSddlLength>1</RuleSddlLength><RuleSddl>-</RuleSddl><TargetUser>S-1-5-21-1663667890-2519037288-962558911-1001</TargetUser><TargetProcessId>9184</TargetProcessId><FilePathLength>35</FilePathLength><FilePath>%OSDRIVE%\USERS\PUBLIC\TEST8004.EXE</FilePath><FileHashLength>0</FileHashLength><FileHash></FileHash><FqbnLength>1</FqbnLength><Fqbn>-</Fqbn><TargetLogonId>0x92d46</TargetLogonId><FullFilePathLength>28</FullFilePathLength><FullFilePath>C:\Users\Public\test8004.exe</FullFilePath></RuleAndFileData></UserData></Event>"#;

    #[test]
    fn parses_a_real_8004_capture() {
        let block = split_event_blocks(APPLOCKER_BLOCK_8004_XML)[0];
        let parsed = parse_applocker_event(block).expect("should parse");
        assert_eq!(parsed.record_id, 29);
        assert_eq!(parsed.event_id, 8004);
        assert_eq!(parsed.policy_name, "EXE");
        assert_eq!(
            parsed.target_user.as_deref(),
            Some("S-1-5-21-1663667890-2519037288-962558911-1001")
        );
        assert_eq!(parsed.pid, 7764);
        assert_eq!(parsed.target_process_id, 9184);
        assert_eq!(parsed.file_path, "%OSDRIVE%\\USERS\\PUBLIC\\TEST8004.EXE");
        assert_eq!(
            parsed.full_file_path.as_deref(),
            Some("C:\\Users\\Public\\test8004.exe")
        );
    }

    #[test]
    fn applocker_file_path_is_unescaped_like_full_file_path() {
        let xml = APPLOCKER_BLOCK_8004_XML
            .replace(
                "TEST8004.EXE</FilePath>",
                "R&amp;D\\TEST8004.EXE</FilePath>",
            )
            .replace(
                "test8004.exe</FullFilePath>",
                "R&amp;D\\test8004.exe</FullFilePath>",
            );
        let parsed = parse_applocker_event(split_event_blocks(&xml)[0]).expect("should parse");
        assert_eq!(
            parsed.file_path,
            "%OSDRIVE%\\USERS\\PUBLIC\\R&D\\TEST8004.EXE"
        );
        assert_eq!(
            parsed.full_file_path.as_deref(),
            Some("C:\\Users\\Public\\R&D\\test8004.exe")
        );
    }

    #[test]
    fn applocker_event_without_full_file_path_has_none() {
        let parsed = parse_applocker_event(split_event_blocks(APPLOCKER_BLOCK_XML)[0])
            .expect("should parse");
        assert_eq!(parsed.full_file_path, None);
    }

    #[test]
    fn parses_an_audit_mode_8003_dll_event() {
        // Same channel and payload shape as 8004; only the ID and, for a
        // library, the rule collection differ.
        let xml = APPLOCKER_BLOCK_XML
            .replace("<EventID>8004</EventID>", "<EventID>8003</EventID>")
            .replace(
                "<PolicyName>EXE</PolicyName>",
                "<PolicyName>DLL</PolicyName>",
            );
        let parsed = parse_applocker_event(split_event_blocks(&xml)[0]).expect("should parse");
        assert_eq!(parsed.event_id, 8003);
        assert_eq!(parsed.policy_name, "DLL");
    }

    #[test]
    fn applocker_event_without_target_user_has_none() {
        let xml = APPLOCKER_BLOCK_XML.replace(
            "<TargetUser>S-1-5-21-1663667890-2519037288-962558911-1001</TargetUser>",
            "",
        );
        let parsed = parse_applocker_event(split_event_blocks(&xml)[0]).expect("should parse");
        assert_eq!(parsed.target_user, None);
    }

    #[test]
    fn applocker_block_missing_record_id_does_not_parse() {
        let block = "<Event><UserData><RuleAndFileData><FilePath>x</FilePath></RuleAndFileData></UserData></Event>";
        assert!(parse_applocker_event(block).is_none());
    }

    fn lab_env(name: &str) -> Option<String> {
        match name {
            "SystemDrive" => Some("C:".into()),
            "SystemRoot" => Some("C:\\Windows".into()),
            "ProgramFiles" => Some("C:\\Program Files".into()),
            _ => None,
        }
    }

    #[test]
    fn expands_every_fixed_applocker_path_variable() {
        let cases = [
            (
                "%OSDRIVE%\\USERS\\SOLKA\\DOWNLOADS\\POWERSHELL.EXE",
                "C:\\USERS\\SOLKA\\DOWNLOADS\\POWERSHELL.EXE",
            ),
            ("%WINDIR%\\TEMP\\X.EXE", "C:\\Windows\\TEMP\\X.EXE"),
            ("%SYSTEM32%\\CMD.EXE", "C:\\Windows\\System32\\CMD.EXE"),
            (
                "%PROGRAMFILES%\\APP\\APP.EXE",
                "C:\\Program Files\\APP\\APP.EXE",
            ),
        ];
        for (raw, expected) in cases {
            assert_eq!(expand_applocker_path(raw, lab_env), expected, "{raw}");
        }
    }

    #[test]
    fn applocker_variable_match_is_case_insensitive() {
        assert_eq!(
            expand_applocker_path("%osdrive%\\x.exe", lab_env),
            "C:\\x.exe"
        );
    }

    #[test]
    fn removable_media_and_unresolvable_variables_are_left_as_is() {
        for raw in ["%HOT%\\X.EXE", "%REMOVABLE%\\X.EXE"] {
            assert_eq!(expand_applocker_path(raw, lab_env), raw);
        }
        assert_eq!(
            expand_applocker_path("%OSDRIVE%\\X.EXE", |_| None),
            "%OSDRIVE%\\X.EXE"
        );
    }

    #[test]
    fn only_a_leading_variable_is_expanded() {
        for raw in ["C:\\TOOLS\\%OSDRIVE%\\X.EXE", "C:\\X.EXE", ""] {
            assert_eq!(expand_applocker_path(raw, lab_env), raw);
        }
    }
}
