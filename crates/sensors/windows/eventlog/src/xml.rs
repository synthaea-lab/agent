//! Pure parsing helpers for `wevtutil qe ... /f:xml` output — platform-independent
//! and unit-tested on every CI leg, same split as `sensor-windows::normalize`: the
//! Windows-only part of this crate is the `wevtutil`/`auditpol` process invocation
//! (`sensor.rs`), not this logic.
//!
//! `wevtutil /f:xml` concatenates one `<Event xmlns="...">...</Event>` block per
//! matched record, with no enclosing root element — not itself valid XML, and not
//! worth a real XML parser dependency for the handful of fields this crate needs.
//! Substring extraction is fragile in general, but the shape of `wevtutil`'s output
//! has been stable across the Windows versions tested; if that ever changes, these
//! functions are the one place to fix it (and to add a regression fixture to).

/// Splits a `wevtutil /f:xml` output into individual `<Event>...</Event>` blocks.
#[must_use]
pub fn split_event_blocks(xml: &str) -> Vec<&str> {
    let mut blocks = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<Event ") {
        let after_start = &rest[start..];
        match after_start.find("</Event>") {
            Some(end) => {
                let end_full = end + "</Event>".len();
                blocks.push(&after_start[..end_full]);
                rest = &after_start[end_full..];
            }
            None => break,
        }
    }
    blocks
}

/// Extracts the text strictly between the first occurrence of `start` and the next
/// occurrence of `end` after it.
#[must_use]
pub fn extract_between<'a>(block: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let from = block.find(start)? + start.len();
    let rest = &block[from..];
    let to = rest.find(end)?;
    Some(&rest[..to])
}

/// Unescapes the 5 standard XML entities. Needed for `TaskContent` (event 4698),
/// which is itself XML nested inside the enclosing `wevtutil` XML document, hence
/// escaped (`&lt;`/`&gt;`) there. Order is deliberate: `&amp;` last, so as not to
/// wrongly re-interpret a double-escaped `&amp;lt;` as `<` (not observed in
/// practice, but more correct to guard against).
#[must_use]
pub fn unescape_xml_entities(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Fields extracted from a 7045 ("A service was installed in the system") `<Event>`
/// block — System log, no audit prerequisite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceInstallEvent {
    pub record_id: u64,
    pub service_name: String,
    /// As passed to `CreateService()`/`sc create` — already a normal Windows path
    /// (possibly with trailing arguments), not an NT kernel device path. Do NOT run
    /// this through an NT-path normalizer (`sensor-windows::normalize_nt_path`):
    /// that function looks for the 3rd backslash to splice in a drive letter, which
    /// truncates an already-normal path like `C:\Users\...\payload.exe` into
    /// `C:\...\payload.exe` (bug found and fixed during the original investigation).
    pub image_path: String,
    /// PID that requested the service creation (e.g. `services.exe`, `sc.exe`).
    pub pid: u32,
}

/// Parses one 7045 `<Event>` block. `None` if the block is missing a required field
/// (a genuinely different event matched the `XPath` filter, or a `wevtutil` output
/// shape change — treated the same way: skip rather than guess).
#[must_use]
pub fn parse_service_install_block(block: &str) -> Option<ServiceInstallEvent> {
    let record_id = extract_between(block, "<EventRecordID>", "</EventRecordID>")?
        .parse()
        .ok()?;
    let service_name = extract_between(block, "<Data Name='ServiceName'>", "</Data>")
        .unwrap_or_default()
        .to_string();
    let image_path = extract_between(block, "<Data Name='ImagePath'>", "</Data>")
        .unwrap_or_default()
        .trim()
        .to_string();
    let pid = extract_between(block, "ProcessID='", "'")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Some(ServiceInstallEvent {
        record_id,
        service_name,
        image_path,
        pid,
    })
}

/// Fields extracted from a 4698 ("A scheduled task was created") `<Event>` block —
/// Security log, requires the "Other Object Access Events" audit subcategory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledTaskEvent {
    pub record_id: u64,
    /// e.g. `\TestTask` — the Task Scheduler path, not just the leaf name.
    pub task_name: String,
    /// The full task definition XML, already unescaped (`unescape_xml_entities`
    /// applied by `parse_scheduled_task_block`) — pass to
    /// [`task_action_path`] to pull out the actual command.
    pub task_content: String,
    /// PID of the process that created the task (e.g. `schtasks.exe`) — not a
    /// future execution of the task itself, which is only registered here, not run.
    pub pid: u32,
}

/// Parses one 4698 `<Event>` block.
#[must_use]
pub fn parse_scheduled_task_block(block: &str) -> Option<ScheduledTaskEvent> {
    let record_id = extract_between(block, "<EventRecordID>", "</EventRecordID>")?
        .parse()
        .ok()?;
    let task_name = extract_between(block, "<Data Name='TaskName'>", "</Data>")
        .unwrap_or_default()
        .to_string();
    let task_content_escaped =
        extract_between(block, "<Data Name='TaskContent'>", "</Data>").unwrap_or_default();
    let task_content = unescape_xml_entities(task_content_escaped);
    let pid = extract_between(block, "<Data Name='ClientProcessId'>", "</Data>")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Some(ScheduledTaskEvent {
        record_id,
        task_name,
        task_content,
        pid,
    })
}

/// Extracts the effective action path from an unescaped `TaskContent` XML fragment:
/// `<Command>` (required) plus `<Arguments>` (optional), joined the same way
/// `ImagePath` naturally reads on the service side — `check_scheduled_task_persistence`
/// (`rules`) applies the same suspicious-directory filter to both. `None` when
/// `<Command>` is absent or empty (a task type this crate does not need to alert on,
/// e.g. a COM-handler action with no command line).
#[must_use]
pub fn task_action_path(task_content: &str) -> Option<String> {
    let command = extract_between(task_content, "<Command>", "</Command>")?
        .trim()
        .to_string();
    if command.is_empty() {
        return None;
    }
    let arguments = extract_between(task_content, "<Arguments>", "</Arguments>")
        .unwrap_or_default()
        .trim();
    if arguments.is_empty() {
        Some(command)
    } else {
        Some(format!("{command} {arguments}"))
    }
}

/// Task Scheduler paths are tree paths (`\Microsoft\Windows\...\MyTask`); rules and
/// alert messages want just the leaf name, consistent with how `comm` reads
/// elsewhere in the codebase (a short name, not a full path).
#[must_use]
pub fn task_leaf_name(task_name: &str) -> String {
    task_name
        .rsplit('\\')
        .next()
        .unwrap_or(task_name)
        .to_string()
}

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
/// schema for these four event IDs. Unlike 7045/4698 (each empirically confirmed
/// against a real lab-VM capture during the original #94 investigation — see
/// `docs/adr/0004-...`), these have **not** yet been reconciled against a real
/// `wevtutil qe Security /f:xml` capture. Whoever validates this on the lab VM
/// should diff a real capture against the constants in this module's tests and
/// fix any mismatch here before relying on this in production.
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
}

/// Text of a `<Data Name='{name}'>...</Data>` element, or `None` if the field is
/// absent, empty, or the literal `"-"` sentinel Windows uses for "not
/// applicable" (observed on `IpAddress` for local logons; guarded against here
/// so a missing field never round-trips as the literal string `"-"`).
fn opt_data(block: &str, name: &str) -> Option<String> {
    extract_between(block, &format!("<Data Name='{name}'>"), "</Data>")
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "-")
        .map(str::to_string)
}

/// Parses one 4624/4625/4648/4672 `<Event>` block. `None` if the block is
/// missing `EventRecordID` or `EventID` (a genuinely different event matched the
/// `XPath` filter, or a `wevtutil` output shape change — skip rather than guess,
/// same convention as [`parse_service_install_block`]).
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
    })
}

/// Fields extracted from a 4720 ("A user account was created") `<Event>` block —
/// Security log, requires the "User Account Management" audit subcategory (usually
/// enabled by default on both Client and Server SKUs, but the sensor enables it
/// itself belt-and-suspenders, like it does for 4698's subcategory).
///
/// Scope of the 4720 signal for a userland EDR on a member/standalone machine:
/// **local SAM only** (T1136.001 — Local Account). Domain account creation writes
/// 4720 on the domain controller, not on the machine where the attacker actually ran
/// `net user /add`, so we never observe it — that is T1136.002 (Domain Account) and
/// out of scope regardless. The sensor does not try to distinguish local vs. domain
/// on the reporting host (both look identical here); the SAM/domain distinction is
/// upstream, in whether Windows wrote the 4720 on THIS machine at all.
///
/// `TargetUserSid`/`TargetUserName` — the newly created account.
/// `SubjectUserSid`/`SubjectUserName` — the caller that created it (usually a local
/// administrator, or SYSTEM for programmatic paths like the Local Users MMC applet).
/// `SamAccountName` exists on this event too but is redundant with `TargetUserName`
/// on local SAM (differs from `TargetUserName` only for downlevel domain accounts,
/// which are out of scope) — kept out of the struct to avoid duplication.
///
/// Not yet reconciled against a real `wevtutil qe Security /f:xml` capture — same
/// caveat as [`LogonEvent`] above; whoever validates this on the lab VM should diff
/// against the fixture in this module's tests.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AccountCreatedEvent {
    pub record_id: u64,
    /// PID of the reporting process (`<Execution ProcessID='...'>`) — LSASS, same
    /// as [`LogonEvent`]. Not the caller's PID; that is not carried on this event.
    pub pid: u32,
    /// SID of the newly created account (`S-1-5-21-...`). None if the field was
    /// missing (should not happen on a well-formed 4720).
    pub target_user_sid: Option<String>,
    /// SAM name of the newly created account.
    pub target_user_name: Option<String>,
    /// SID of the caller that created the account.
    pub subject_user_sid: Option<String>,
    /// SAM name of the caller.
    pub subject_user_name: Option<String>,
}

/// Parses one 4720 `<Event>` block. `None` if the block is missing `EventRecordID`
/// (a genuinely different event matched the `XPath` filter — skip rather than
/// guess, same convention as the other parsers in this module).
#[must_use]
pub fn parse_account_created_block(block: &str) -> Option<AccountCreatedEvent> {
    let record_id = extract_between(block, "<EventRecordID>", "</EventRecordID>")?
        .parse()
        .ok()?;
    let pid = extract_between(block, "ProcessID='", "'")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Some(AccountCreatedEvent {
        record_id,
        pid,
        // 4720 uses `TargetSid`, NOT `TargetUserSid` (that spelling is only on
        // 4624/4625/4648 in `LogonEvent`). Documented in the Microsoft
        // Security-auditing schema for 4720; caught while writing this module's
        // 4720 fixture.
        target_user_sid: opt_data(block, "TargetSid"),
        target_user_name: opt_data(block, "TargetUserName"),
        subject_user_sid: opt_data(block, "SubjectUserSid"),
        subject_user_name: opt_data(block, "SubjectUserName"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Field names and general shape observed on `wevtutil qe System /f:xml` for a
    /// real 7045 event (lab, 2026-09-03) — trimmed to the fields this module reads.
    const SERVICE_INSTALL_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager' Guid='{555908d1-a6d7-4695-8e1e-26931d2012f4}' EventSourceName='Service Control Manager'/><EventID Qualifiers='16384'>7045</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8080000000000000</Keywords><TimeCreated SystemTime='2026-09-03T10:15:00.000000000Z'/><EventRecordID>42</EventRecordID><Correlation/><Execution ProcessID='956' ThreadID='1000'/><Channel>System</Channel><Computer>LAB-VM</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='ServiceName'>evilsvc</Data><Data Name='ImagePath'>C:\Users\victim\AppData\Roaming\payload.exe </Data><Data Name='ServiceType'>user mode service</Data><Data Name='StartType'>demand start</Data><Data Name='AccountName'>LocalSystem</Data></EventData></Event>"#;

    /// Same shape for a real 4698 event (`wevtutil qe Security /f:xml`, 2026-09-03),
    /// `TaskContent` escaped as `wevtutil` renders it (nested XML inside XML).
    const SCHEDULED_TASK_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4698</EventID><Version>1</Version><Level>0</Level><Task>12804</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-09-03T10:20:00.000000000Z'/><EventRecordID>777</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='8'/><Channel>Security</Channel><Computer>LAB-VM</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1-2-3-1001</Data><Data Name='SubjectUserName'>victim</Data><Data Name='TaskName'>\EvilTask</Data><Data Name='TaskContent'>&lt;?xml version="1.0" encoding="UTF-16"?&gt;&lt;Task&gt;&lt;Actions&gt;&lt;Exec&gt;&lt;Command&gt;C:\Users\victim\AppData\Roaming\payload.exe&lt;/Command&gt;&lt;Arguments&gt;-silent&lt;/Arguments&gt;&lt;/Exec&gt;&lt;/Actions&gt;&lt;/Task&gt;</Data><Data Name='ClientProcessId'>2468</Data></EventData></Event>"#;

    #[test]
    fn splits_a_single_event_block() {
        let blocks = split_event_blocks(SERVICE_INSTALL_XML);
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].starts_with("<Event "));
        assert!(blocks[0].ends_with("</Event>"));
    }

    #[test]
    fn splits_multiple_concatenated_event_blocks() {
        let doc = format!("{SERVICE_INSTALL_XML}{SCHEDULED_TASK_XML}");
        let blocks = split_event_blocks(&doc);
        assert_eq!(blocks.len(), 2);
    }

    #[test]
    fn no_event_blocks_in_empty_or_unrelated_input() {
        assert!(split_event_blocks("").is_empty());
        assert!(split_event_blocks("<NoEventsHere/>").is_empty());
    }

    #[test]
    fn extracts_between_markers() {
        assert_eq!(
            extract_between("<a>value</a>", "<a>", "</a>"),
            Some("value")
        );
        assert_eq!(extract_between("<a>value</a>", "<b>", "</b>"), None);
    }

    #[test]
    fn unescapes_the_five_standard_entities() {
        assert_eq!(unescape_xml_entities("a &lt;b&gt; c"), "a <b> c");
        assert_eq!(
            unescape_xml_entities("&quot;q&quot; &apos;a&apos;"),
            "\"q\" 'a'"
        );
        assert_eq!(unescape_xml_entities("R&amp;D"), "R&D");
        // &amp; last: a literal "&amp;lt;" in the source must not become "<".
        assert_eq!(unescape_xml_entities("&amp;lt;"), "&lt;");
    }

    #[test]
    fn parses_a_real_shaped_service_install_block() {
        let block = split_event_blocks(SERVICE_INSTALL_XML)[0];
        let parsed = parse_service_install_block(block).expect("should parse");
        assert_eq!(parsed.record_id, 42);
        assert_eq!(parsed.service_name, "evilsvc");
        // trim() must strip the trailing space wevtutil sometimes emits.
        assert_eq!(
            parsed.image_path,
            r"C:\Users\victim\AppData\Roaming\payload.exe"
        );
        assert_eq!(parsed.pid, 956);
    }

    #[test]
    fn service_install_block_missing_record_id_does_not_parse() {
        let block = "<Event><EventData><Data Name='ServiceName'>x</Data></EventData></Event>";
        assert!(parse_service_install_block(block).is_none());
    }

    #[test]
    fn parses_a_real_shaped_scheduled_task_block() {
        let block = split_event_blocks(SCHEDULED_TASK_XML)[0];
        let parsed = parse_scheduled_task_block(block).expect("should parse");
        assert_eq!(parsed.record_id, 777);
        assert_eq!(parsed.task_name, r"\EvilTask");
        assert_eq!(parsed.pid, 2468);
        // Unescaped: the nested XML should show real angle brackets now.
        assert!(parsed.task_content.contains("<Command>"));
        assert!(!parsed.task_content.contains("&lt;"));
    }

    #[test]
    fn extracts_command_and_arguments_from_task_content() {
        let block = split_event_blocks(SCHEDULED_TASK_XML)[0];
        let parsed = parse_scheduled_task_block(block).unwrap();
        let path = task_action_path(&parsed.task_content).expect("should have a command");
        assert_eq!(path, r"C:\Users\victim\AppData\Roaming\payload.exe -silent");
    }

    #[test]
    fn task_action_path_without_arguments_is_just_the_command() {
        let content =
            "<Task><Actions><Exec><Command>C:\\legit\\backup.exe</Command></Exec></Actions></Task>";
        assert_eq!(
            task_action_path(content).as_deref(),
            Some(r"C:\legit\backup.exe")
        );
    }

    #[test]
    fn task_action_path_with_no_command_is_none() {
        let content = "<Task><Actions><ComHandler/></Actions></Task>";
        assert!(task_action_path(content).is_none());
    }

    #[test]
    fn task_leaf_name_strips_the_scheduler_tree_path() {
        assert_eq!(task_leaf_name(r"\Microsoft\Windows\Backup\Daily"), "Daily");
        assert_eq!(task_leaf_name(r"\EvilTask"), "EvilTask");
        assert_eq!(task_leaf_name("NoLeadingSlash"), "NoLeadingSlash");
    }

    // ── Logon events (4624/4625/4648/4672) ───────────────────────────────────
    //
    // Shape built from the documented Microsoft Security-auditing schema, NOT
    // yet reconciled against a real lab-VM capture (see `LogonEvent`'s doc) —
    // unlike SERVICE_INSTALL_XML/SCHEDULED_TASK_XML above, which were.

    /// A successful interactive logon (`LogonType` 10 = RemoteInteractive/RDP).
    /// Subject is SYSTEM (LSASS acting on the machine's behalf); Target is the
    /// account actually logging in.
    const LOGON_SUCCESS_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4624</EventID><Version>2</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-09-07T09:00:00.000000000Z'/><EventRecordID>9001</EventRecordID><Correlation/><Execution ProcessID='604' ThreadID='700'/><Channel>Security</Channel><Computer>LAB-VM</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>LAB-VM$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-5-21-1004336348-1177238915-682003330-1001</Data><Data Name='TargetUserName'>victim</Data><Data Name='TargetDomainName'>LAB-VM</Data><Data Name='TargetLogonId'>0x3a2f1</Data><Data Name='LogonType'>10</Data><Data Name='LogonProcessName'>User32 </Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>LAB-VM</Data><Data Name='IpAddress'>-</Data><Data Name='IpPort'>0</Data></EventData></Event>"#;

    /// A failed network logon (`LogonType` 3), wrong-password substatus.
    const LOGON_FAILURE_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2026-09-07T09:01:00.000000000Z'/><EventRecordID>9002</EventRecordID><Correlation/><Execution ProcessID='604' ThreadID='701'/><Channel>Security</Channel><Computer>LAB-VM</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='SubjectUserName'>-</Data><Data Name='SubjectDomainName'>-</Data><Data Name='SubjectLogonId'>0x0</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>admin</Data><Data Name='TargetDomainName'>LAB-VM</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc000006a</Data><Data Name='LogonType'>3</Data><Data Name='WorkstationName'>ATTACKER-BOX</Data><Data Name='ProcessId'>0x0</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>198.51.100.23</Data><Data Name='IpPort'>51514</Data></EventData></Event>"#;

    /// An explicit-credential logon (`runas /user:Administrator`) — no
    /// `TargetUserSid` (never resolved for this event type).
    const EXPLICIT_CREDENTIALS_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4648</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-09-07T09:02:00.000000000Z'/><EventRecordID>9003</EventRecordID><Correlation/><Execution ProcessID='604' ThreadID='702'/><Channel>Security</Channel><Computer>LAB-VM</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1004336348-1177238915-682003330-1001</Data><Data Name='SubjectUserName'>victim</Data><Data Name='SubjectDomainName'>LAB-VM</Data><Data Name='SubjectLogonId'>0x3a2f1</Data><Data Name='TargetUserName'>Administrator</Data><Data Name='TargetDomainName'>LAB-VM</Data><Data Name='TargetServerName'>localhost</Data><Data Name='TargetInfo'>localhost</Data><Data Name='ProcessId'>0x1a4</Data><Data Name='ProcessName'>C:\Windows\System32\cmd.exe</Data><Data Name='IpAddress'>127.0.0.1</Data><Data Name='IpPort'>0</Data></EventData></Event>"#;

    /// Special privileges assigned to a new logon — no `Target*` fields at all;
    /// Subject is the account that just received the privileges.
    const SPECIAL_PRIVILEGES_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4672</EventID><Version>0</Version><Level>0</Level><Task>12548</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-09-07T09:00:00.500000000Z'/><EventRecordID>9004</EventRecordID><Correlation/><Execution ProcessID='604' ThreadID='703'/><Channel>Security</Channel><Computer>LAB-VM</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1004336348-1177238915-682003330-1001</Data><Data Name='SubjectUserName'>victim</Data><Data Name='SubjectDomainName'>LAB-VM</Data><Data Name='SubjectLogonId'>0x3a2f1</Data><Data Name='PrivilegeList'>SeDebugPrivilege SeBackupPrivilege SeRestorePrivilege</Data></EventData></Event>"#;

    #[test]
    fn parses_a_real_shaped_logon_success_block() {
        let block = split_event_blocks(LOGON_SUCCESS_XML)[0];
        let parsed = parse_logon_block(block).expect("should parse");
        assert_eq!(parsed.record_id, 9001);
        assert_eq!(parsed.event_id, 4624);
        assert_eq!(parsed.pid, 604);
        assert_eq!(parsed.subject_user_sid.as_deref(), Some("S-1-5-18"));
        assert_eq!(parsed.target_user_name.as_deref(), Some("victim"));
        assert_eq!(
            parsed.target_user_sid.as_deref(),
            Some("S-1-5-21-1004336348-1177238915-682003330-1001")
        );
        // "-" sentinel (no network address for a local/console logon) filtered out.
        assert_eq!(parsed.ip_address, None);
    }

    #[test]
    fn parses_a_real_shaped_logon_failure_block() {
        let block = split_event_blocks(LOGON_FAILURE_XML)[0];
        let parsed = parse_logon_block(block).expect("should parse");
        assert_eq!(parsed.event_id, 4625);
        assert_eq!(parsed.status.as_deref(), Some("0xc000006d"));
        assert_eq!(parsed.sub_status.as_deref(), Some("0xc000006a"));
        assert_eq!(parsed.ip_address.as_deref(), Some("198.51.100.23"));
        assert_eq!(parsed.target_user_sid.as_deref(), Some("S-1-0-0"));
    }

    #[test]
    fn parses_a_real_shaped_explicit_credentials_block() {
        let block = split_event_blocks(EXPLICIT_CREDENTIALS_XML)[0];
        let parsed = parse_logon_block(block).expect("should parse");
        assert_eq!(parsed.event_id, 4648);
        assert_eq!(parsed.subject_user_name.as_deref(), Some("victim"));
        assert_eq!(parsed.target_user_name.as_deref(), Some("Administrator"));
        // 4648 never resolves a TargetUserSid.
        assert_eq!(parsed.target_user_sid, None);
        assert_eq!(parsed.ip_address.as_deref(), Some("127.0.0.1"));
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

    // ── Account creation (4720) ──────────────────────────────────────────────
    //
    // Shape built from the documented Microsoft Security-auditing schema for
    // 4720 (`User Account Management`). Not yet reconciled against a real
    // `wevtutil qe Security /f:xml` capture — same caveat as `LogonEvent`;
    // whoever validates this on the lab VM should diff a real capture against
    // this fixture and fix any mismatch.

    /// A local SAM account creation via `net user attacker P@ssw0rd /add`.
    /// Subject is the caller (a local administrator), Target is the newly
    /// created account (`S-1-5-21-...-1005`, next RID after `victim`'s 1001).
    const ACCOUNT_CREATED_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4720</EventID><Version>0</Version><Level>0</Level><Task>13824</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-09-07T09:10:00.000000000Z'/><EventRecordID>9010</EventRecordID><Correlation/><Execution ProcessID='604' ThreadID='710'/><Channel>Security</Channel><Computer>LAB-VM</Computer><Security/></System><EventData><Data Name='TargetUserName'>attacker</Data><Data Name='TargetDomainName'>LAB-VM</Data><Data Name='TargetSid'>S-1-5-21-1004336348-1177238915-682003330-1005</Data><Data Name='SubjectUserSid'>S-1-5-21-1004336348-1177238915-682003330-500</Data><Data Name='SubjectUserName'>Administrator</Data><Data Name='SubjectDomainName'>LAB-VM</Data><Data Name='SubjectLogonId'>0x1a4c9</Data><Data Name='PrivilegeList'>-</Data><Data Name='SamAccountName'>attacker</Data><Data Name='DisplayName'>%%1793</Data><Data Name='UserPrincipalName'>-</Data><Data Name='HomeDirectory'>%%1793</Data><Data Name='HomePath'>%%1793</Data><Data Name='ScriptPath'>%%1793</Data><Data Name='ProfilePath'>%%1793</Data><Data Name='UserWorkstations'>%%1793</Data><Data Name='PasswordLastSet'>%%1794</Data><Data Name='AccountExpires'>%%1794</Data><Data Name='PrimaryGroupId'>513</Data><Data Name='AllowedToDelegateTo'>-</Data><Data Name='OldUacValue'>0x0</Data><Data Name='NewUacValue'>0x15</Data><Data Name='UserAccountControl'>%%2080 %%2082 %%2084</Data><Data Name='UserParameters'>%%1793</Data><Data Name='SidHistory'>-</Data><Data Name='LogonHours'>%%1797</Data></EventData></Event>"#;

    #[test]
    fn parses_a_real_shaped_account_created_block() {
        let block = split_event_blocks(ACCOUNT_CREATED_XML)[0];
        let parsed = parse_account_created_block(block).expect("should parse");
        assert_eq!(parsed.record_id, 9010);
        assert_eq!(parsed.pid, 604);
        assert_eq!(parsed.target_user_name.as_deref(), Some("attacker"));
        // 4720 uses `TargetSid`, not `TargetUserSid` — the parser knows this
        // (see comment on `parse_account_created_block`).
        assert_eq!(
            parsed.target_user_sid.as_deref(),
            Some("S-1-5-21-1004336348-1177238915-682003330-1005")
        );
        assert_eq!(
            parsed.subject_user_sid.as_deref(),
            Some("S-1-5-21-1004336348-1177238915-682003330-500")
        );
        assert_eq!(parsed.subject_user_name.as_deref(), Some("Administrator"));
    }

    #[test]
    fn account_created_block_missing_record_id_does_not_parse() {
        let block = "<Event><EventData><Data Name='TargetUserName'>x</Data></EventData></Event>";
        assert!(parse_account_created_block(block).is_none());
    }
}
