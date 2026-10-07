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
    /// [`task_actions`] to pull out every action it runs.
    pub task_content: String,
    /// PID of the process that created the task (e.g. `schtasks.exe`) — not a
    /// future execution of the task itself, which is only registered here, not run.
    pub pid: u32,
}

/// Parses one 4698 `<Event>` block.
#[must_use]
pub fn parse_scheduled_task_block(block: &str) -> Option<ScheduledTaskEvent> {
    parse_task_block_with_content_field(block, "TaskContent")
}

/// Parses one 4702 ("A scheduled task was updated") `<Event>` block — same shape
/// as 4698 and reuses [`ScheduledTaskEvent`] (with `task_content` holding the
/// task's *new* definition), but the content field is named `TaskContentNew`, not
/// `TaskContent`. Confirmed against a real 4702 emitted by `schtasks /change`
/// (lab, 2026-09-22): every other field keeps its 4698 name.
#[must_use]
pub fn parse_scheduled_task_update_block(block: &str) -> Option<ScheduledTaskEvent> {
    parse_task_block_with_content_field(block, "TaskContentNew")
}

fn parse_task_block_with_content_field(
    block: &str,
    content_field: &str,
) -> Option<ScheduledTaskEvent> {
    let record_id = extract_between(block, "<EventRecordID>", "</EventRecordID>")?
        .parse()
        .ok()?;
    let task_name = extract_between(block, "<Data Name='TaskName'>", "</Data>")
        .unwrap_or_default()
        .to_string();
    let content_marker = format!("<Data Name='{content_field}'>");
    let task_content_escaped =
        extract_between(block, &content_marker, "</Data>").unwrap_or_default();
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

/// Upper bound on the actions read from one task definition. Task Scheduler
/// rejects a task with more than 32 actions, so anything past that is malformed or
/// hostile input.
pub const MAX_TASK_ACTIONS: usize = 32;

/// Separator between actions in the rendered action list. Display only: a command
/// line may itself contain ` | `, so the joined string is not meant to be parsed.
pub const TASK_ACTION_SEPARATOR: &str = " | ";

/// Rendered in place of the action list when a task definition has no action this
/// crate can read (`FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN` is set alongside).
pub const TASK_ACTION_UNKNOWN: &str = "<action unknown>";

/// One action of a scheduled task definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskAction {
    /// `<Exec>`: `Command`, plus `Arguments` when present.
    Exec(String),
    /// `<ComHandler>`: the COM class Task Scheduler instantiates (`ClassId`).
    ComHandler(String),
}

impl TaskAction {
    /// Alert-facing form: the command line as-is, `com:{ClassId}` for a COM handler.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Exec(command_line) => command_line.clone(),
            Self::ComHandler(class_id) => format!("com:{class_id}"),
        }
    }
}

/// Every `Exec` and `ComHandler` action of an unescaped `TaskContent` fragment, in
/// document order, capped at [`MAX_TASK_ACTIONS`].
///
/// Each action is read from its own element, not from the first `<Command>` of the
/// document: a task may carry several actions, and a benign first action must not
/// hide the next one (#422). Start tags with attributes (`<Exec id="Action1">`,
/// valid per the Task Scheduler schema) and self-closing tags (`<ComHandler/>`)
/// are matched. An action with nothing readable (no `Command`, no `ClassId`) is
/// skipped; other action types (deprecated `SendEmail`/`ShowMessage`) are ignored.
#[must_use]
pub fn task_actions(task_content: &str) -> Vec<TaskAction> {
    let mut actions = Vec::new();
    let mut rest = task_content;
    while actions.len() < MAX_TASK_ACTIONS {
        let Some((kind, body, after)) = next_action_element(rest) else {
            break;
        };
        rest = after;
        let action = match kind {
            ActionKind::Exec => exec_command_line(body).map(TaskAction::Exec),
            ActionKind::ComHandler => extract_between(body, "<ClassId>", "</ClassId>")
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .map(|id| TaskAction::ComHandler(id.to_string())),
        };
        actions.extend(action);
    }
    actions
}

/// A task's actions rendered for `FileOpenEvent::path`, joined with
/// [`TASK_ACTION_SEPARATOR`]. `None` when the task has no readable action.
#[must_use]
pub fn task_actions_display(task_content: &str) -> Option<String> {
    let actions = task_actions(task_content);
    if actions.is_empty() {
        return None;
    }
    Some(
        actions
            .iter()
            .map(TaskAction::render)
            .collect::<Vec<_>>()
            .join(TASK_ACTION_SEPARATOR),
    )
}

#[derive(Clone, Copy)]
enum ActionKind {
    Exec,
    ComHandler,
}

/// Next `<Exec …>` or `<ComHandler …>` element in `s`: its kind, its body (empty
/// for a self-closing tag) and the text after it. `None` when there is no further
/// element or the next one is not closed.
fn next_action_element(s: &str) -> Option<(ActionKind, &str, &str)> {
    let mut search_from = 0;
    loop {
        let tag_start = search_from + s[search_from..].find('<')?;
        let after_lt = &s[tag_start + 1..];
        let (kind, name) = if starts_with_tag(after_lt, "Exec") {
            (ActionKind::Exec, "Exec")
        } else if starts_with_tag(after_lt, "ComHandler") {
            (ActionKind::ComHandler, "ComHandler")
        } else {
            search_from = tag_start + 1;
            continue;
        };
        let tag_end = tag_start + s[tag_start..].find('>')?;
        let after_tag = &s[tag_end + 1..];
        if s[..tag_end].ends_with('/') {
            return Some((kind, "", after_tag));
        }
        let close = format!("</{name}>");
        let body_len = after_tag.find(&close)?;
        return Some((
            kind,
            &after_tag[..body_len],
            &after_tag[body_len + close.len()..],
        ));
    }
}

/// `true` when `s` starts with the element name `name` followed by a tag
/// delimiter: `Exec` matches `<Exec>`, `<Exec id="A">` and `<Exec/>`, not
/// `<ExecutionTimeLimit>`.
fn starts_with_tag(s: &str, name: &str) -> bool {
    s.strip_prefix(name)
        .and_then(|rest| rest.chars().next())
        .is_some_and(|c| c == '>' || c == '/' || c.is_whitespace())
}

/// `Command` plus optional `Arguments` of one `<Exec>` body. `None` when `Command`
/// is absent or empty.
fn exec_command_line(body: &str) -> Option<String> {
    let command = extract_between(body, "<Command>", "</Command>")?.trim();
    if command.is_empty() {
        return None;
    }
    let arguments = extract_between(body, "<Arguments>", "</Arguments>")
        .unwrap_or_default()
        .trim();
    if arguments.is_empty() {
        Some(command.to_string())
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
/// schema for these four event IDs. Reconciled against a real
/// `wevtutil qe Security /f:xml` capture on 2026-09-21 (Windows 11 lab VM
/// `Sandbox`, issue #224 — see `lab/eventlog-captures/2026-09-21-sandbox/*.xml`); the fixtures in this
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
        time_created_ns: time_created_ns(block),
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
/// Reconciled against a real `wevtutil qe Security /f:xml` capture on 2026-09-21
/// (Windows 11 lab VM `Sandbox`, issue #224 — see `lab/eventlog-captures/2026-09-21-sandbox/4720.xml`);
/// the fixture in this module's tests is faithful to that capture.
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

/// One `Microsoft-Windows-AppLocker/EXE and DLL` event: **8004** (an image
/// was refused — deny rule matched, or no allow rule in an allowlist policy)
/// or **8003** (audit-only mode: it *would* have been refused, #427).
/// `AppLocker`'s channel emits these as `<UserData>` / `<RuleAndFileData>`
/// rather than the `<EventData><Data Name=...>` shape the Security channel
/// uses, so this parser reads the raw child elements directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppLockerEvent {
    pub record_id: u64,
    /// `System/EventID`: 8004 (blocked) or 8003 (audit mode). 0 if missing.
    pub event_id: u32,
    /// Which rule collection matched (`RuleAndFileData/PolicyName`): `EXE`
    /// for executables, `DLL` for libraries — the channel carries both.
    /// Empty if missing.
    pub policy_name: String,
    /// SID of the user whose execution was refused
    /// (`RuleAndFileData/TargetUser`). Deliberately not
    /// `System/Security/@UserID`, which names the account the event was
    /// *logged* under; the two matched in the only real capture so far (#427).
    pub target_user: Option<String>,
    /// PID of the process that tried to launch the image
    /// (`<Execution ProcessID='...'>`). 0 if missing. Checked in the lab
    /// (#529): for both 8003 and 8004 it equals the launching shell's `$PID`.
    pub pid: u32,
    /// PID of the process being *created* for the image
    /// (`RuleAndFileData/TargetProcessId`), not its launcher. Checked in the
    /// lab (#529): on an 8003 it is the audited binary's own live process
    /// (`Start-Process -PassThru` reported the same id); on an 8004 the pid
    /// was allocated but the process never ran. 0 if missing.
    pub target_process_id: u32,
    /// Path of the image as `AppLocker` reports it (`RuleAndFileData/FilePath`),
    /// path variables and upper case included — see [`expand_applocker_path`].
    /// Empty if missing.
    pub file_path: String,
    /// `RuleAndFileData/FullFilePath`: the image's real path, original case,
    /// no path variable (e.g. `C:\Users\Public\test8003.exe`). Present in
    /// the real 8003 captured on Windows 11 26100 (#427); `None` when the
    /// build doesn't emit it, in which case callers fall back to
    /// [`expand_applocker_path`] on [`Self::file_path`].
    pub full_file_path: Option<String>,
}

/// Parses one 8003/8004 `<Event>` block. `None` if the block is missing
/// `EventRecordID` (a genuinely different event matched the `XPath` filter, or
/// a `wevtutil` output shape change — skip rather than guess, same convention
/// as the other parsers in this module).
#[must_use]
pub fn parse_applocker_event(block: &str) -> Option<AppLockerEvent> {
    let record_id = extract_between(block, "<EventRecordID>", "</EventRecordID>")?
        .parse()
        .ok()?;
    let event_id = extract_between(block, "<EventID>", "</EventID>")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let policy_name = extract_between(block, "<PolicyName>", "</PolicyName>")
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    let target_user = extract_between(block, "<TargetUser>", "</TargetUser>")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    // `AppLocker`'s payload lives in <UserData><RuleAndFileData>: children are
    // *plain* elements (`<FilePath>...</FilePath>`), not `<Data Name='...'>`
    // like on the Security channel.
    let pid = extract_between(block, "ProcessID='", "'")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let target_process_id = extract_between(block, "<TargetProcessId>", "</TargetProcessId>")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    // Unescaped like `FullFilePath`: the fallback path would otherwise keep
    // `&amp;` for a directory containing `&`.
    let file_path = extract_between(block, "<FilePath>", "</FilePath>")
        .map(str::trim)
        .map(unescape_xml_entities)
        .unwrap_or_default();
    // `<FullFilePath>` cannot be mistaken for `<FilePath>`: the marker
    // includes the opening `<`, so the two never overlap.
    let full_file_path = extract_between(block, "<FullFilePath>", "</FullFilePath>")
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

/// `<Data Name='name'>value</Data>` of an `<EventData>` block: trimmed, XML
/// entities unescaped, `None` when absent or empty. The Defender and
/// `CodeIntegrity` field names contain spaces (`Threat Name`, `File Name`).
fn data_field(block: &str, name: &str) -> Option<String> {
    let marker = format!("<Data Name='{name}'>");
    extract_between(block, &marker, "</Data>")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(unescape_xml_entities)
}

fn data_u32(block: &str, name: &str) -> Option<u32> {
    data_field(block, name)?.parse().ok()
}

/// Fields of one Microsoft Defender Antivirus Operational event (#283):
/// 1116/1117 (detection, action taken), 5001/5010/5012 (protection turned
/// off), 5007 (a setting changed). Which fields are present depends on the
/// event id; the others stay `None`.
///
/// The channel is **localized** (a French host writes `Severity Name` as
/// "Élevée", `Action Name` as "Supprimer"): only the numeric ids and the
/// untranslated `Threat Name` / `Path` are read, never the `* Name` texts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefenderLogEvent {
    pub record_id: u64,
    pub event_id: u32,
    /// `Detection ID`: the GUID a 1116 and its 1117 share.
    pub detection_id: Option<String>,
    pub threat_name: Option<String>,
    pub severity_id: Option<u32>,
    pub category_id: Option<u32>,
    pub action_id: Option<u32>,
    /// `Path`: the resource as Defender writes it (`file:_C:\x.exe`,
    /// `CmdLine:_...`). Not cut here.
    pub path: Option<String>,
    /// `Process Name`, without Defender's literal `Unknown` placeholder.
    pub process_name: Option<String>,
    pub detection_user: Option<String>,
    /// 5007 only: `<registry value path> = <data>` before and after.
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

/// Parses one Defender Operational `<Event>` block. `None` without an
/// `EventRecordID`, same convention as the other parsers here.
#[must_use]
pub fn parse_defender_event(block: &str) -> Option<DefenderLogEvent> {
    let record_id = extract_between(block, "<EventRecordID>", "</EventRecordID>")?
        .parse()
        .ok()?;
    let event_id = extract_between(block, "<EventID>", "</EventID>")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    Some(DefenderLogEvent {
        record_id,
        event_id,
        detection_id: data_field(block, "Detection ID"),
        threat_name: data_field(block, "Threat Name"),
        severity_id: data_u32(block, "Severity ID"),
        category_id: data_u32(block, "Category ID"),
        action_id: data_u32(block, "Action ID"),
        path: data_field(block, "Path"),
        process_name: data_field(block, "Process Name").filter(|p| p != "Unknown"),
        detection_user: data_field(block, "Detection User"),
        old_value: data_field(block, "Old Value"),
        new_value: data_field(block, "New Value"),
    })
}

/// Fields of one `Microsoft-Windows-CodeIntegrity/Operational` 3076/3077 event
/// (WDAC audit / enforced verdict, #283).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeIntegrityEvent {
    pub record_id: u64,
    pub event_id: u32,
    /// `File Name`: the image that failed the policy, as an **NT device path**
    /// (`\Device\HarddiskVolume3\...`), not a drive-letter path.
    pub file_name: Option<String>,
    /// `Process Name`: the process that tried to load it, also an NT path.
    pub process_name: Option<String>,
    /// `SI Signing Scenario`: 0 kernel mode, 1 user mode.
    pub signing_scenario: Option<u32>,
}

/// Parses one 3076/3077 `<Event>` block. `None` without an `EventRecordID`.
#[must_use]
pub fn parse_code_integrity_event(block: &str) -> Option<CodeIntegrityEvent> {
    let record_id = extract_between(block, "<EventRecordID>", "</EventRecordID>")?
        .parse()
        .ok()?;
    let event_id = extract_between(block, "<EventID>", "</EventID>")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    Some(CodeIntegrityEvent {
        record_id,
        event_id,
        file_name: data_field(block, "File Name"),
        process_name: data_field(block, "Process Name"),
        signing_scenario: data_u32(block, "SI Signing Scenario"),
    })
}

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

/// `<tag>value</tag>` inside the event's `<UserData>`: trimmed, entities
/// unescaped, `None` when absent or empty.
fn user_data_field(block: &str, tag: &str) -> Option<String> {
    let user_data = extract_between(block, "<UserData>", "</UserData>")?;
    extract_between(user_data, &format!("<{tag}>"), &format!("</{tag}>"))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(unescape_xml_entities)
}

/// `EventRecordID`, `EventID` and `<Execution ProcessID>` of a block. `None`
/// without a record id; a missing event id or pid reads as 0.
fn system_header(block: &str) -> Option<(u64, u32, u32)> {
    let record_id = extract_between(block, "<EventRecordID>", "</EventRecordID>")?
        .parse()
        .ok()?;
    let event_id = extract_between(block, "<EventID>", "</EventID>")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let pid = extract_between(block, "ProcessID='", "'")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Some((record_id, event_id, pid))
}

/// The event's own time, `<TimeCreated SystemTime='2026-09-21T13:29:23.0286360Z'/>`,
/// as nanoseconds since the Unix epoch (the unit of `EventMeta::timestamp_ns`).
/// `None` when the attribute is absent or not exactly `YYYY-MM-DDTHH:MM:SS[.f]Z`
/// with a fraction of one to nine digits and a real calendar date from 1970 on.
///
/// The pollers read each channel on its own thread, so an event is *processed*
/// some seconds after it happened, and two channels do not agree on that delay.
/// A rule that joins events from two channels needs when they happened, not when
/// they arrived (the RDP success-after-failures join, #285).
#[must_use]
pub fn time_created_ns(block: &str) -> Option<u64> {
    let text = extract_between(block, "<TimeCreated SystemTime='", "'")
        .or_else(|| extract_between(block, "<TimeCreated SystemTime=\"", "\""))?;
    system_time_ns(text.trim())
}

fn digits(text: &str, from: usize, to: usize) -> Option<u32> {
    let part = text.get(from..to)?;
    if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    part.parse().ok()
}

fn is_leap(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if is_leap(year) => 29,
        _ => 28,
    }
}

/// Days from 1970-01-01 to the given civil date (proleptic Gregorian; the
/// standard "days from civil" computation, valid for every date from 1970).
fn days_from_civil(year: u32, month: u32, day: u32) -> u64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_from_march = i64::from((month + 9) % 12);
    let day_of_year = (153 * month_from_march + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    u64::try_from(era * 146_097 + day_of_era - 719_468).unwrap_or(0)
}

fn system_time_ns(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || *bytes.last()? != b'Z'
    {
        return None;
    }
    let year = digits(text, 0, 4)?;
    let month = digits(text, 5, 7)?;
    let day = digits(text, 8, 10)?;
    let hour = digits(text, 11, 13)?;
    let minute = digits(text, 14, 16)?;
    let second = digits(text, 17, 19)?;
    if year < 1970
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let fraction_ns = if bytes.len() == 20 {
        0
    } else {
        // `.` then one to nine digits, then `Z`.
        let fraction_len = bytes.len() - 21;
        if bytes[19] != b'.' || !(1..=9).contains(&fraction_len) {
            return None;
        }
        let value = u64::from(digits(text, 20, bytes.len() - 1)?);
        value * 10_u64.pow(u32::try_from(9 - fraction_len).ok()?)
    };
    let seconds = days_from_civil(year, month, day) * 86_400
        + u64::from(hour) * 3_600
        + u64::from(minute) * 60
        + u64::from(second);
    seconds.checked_mul(1_000_000_000)?.checked_add(fraction_ns)
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

/// One `Microsoft-Windows-TaskScheduler/Operational` event 106 — a scheduled
/// task was registered on this host. Distinct from the Security-channel event
/// 4698 (`ScheduledTaskEvent`) because the Operational channel fires *always*
/// (no audit-subcategory required) but carries less structure: only the task
/// name and the user context that registered it — no serialized XML task
/// content, so no action path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskSchedulerOpRegisteredEvent {
    pub record_id: u64,
    /// PID of the reporting process (`<Execution ProcessID='...'>`) — the
    /// Task Scheduler service host. 0 if missing.
    pub pid: u32,
    /// The registered task's full name (`\...\MyTask`). Empty if missing.
    pub task_name: String,
    /// SAM or UPN of the account that registered the task
    /// (`<Data Name='UserContext'>`). Empty if missing.
    pub user_context: String,
}

/// Largest task definition file [`decode_task_definition`] is fed: a real one is
/// a few KiB, and the file is attacker-writable content, so the read is capped.
pub const MAX_TASK_DEFINITION_BYTES: u64 = 256 * 1024;

/// Path of task `task_name`'s definition file, relative to
/// `%SystemRoot%\System32\Tasks` (Task Scheduler stores one file per task,
/// mirroring the task tree: `\Folder\Name` → `Folder\Name`). An event 106
/// carries no action, so the sensor reads the actions back from this file.
///
/// `None` unless `task_name` is rooted (`\…`) and every component is a plain
/// file name: the name comes from the event log, and must not be able to walk
/// the read out of the Tasks directory (`..`, a drive or stream `:`, an empty
/// component from `\\`), nor rely on Win32 stripping trailing dots and spaces.
#[must_use]
pub fn task_definition_relative_path(task_name: &str) -> Option<String> {
    let components: Vec<&str> = task_name.strip_prefix('\\')?.split('\\').collect();
    let plain = |c: &&str| {
        !c.is_empty()
            && !c.ends_with(['.', ' '])
            && !c.chars().any(|ch| {
                ch.is_control() || matches!(ch, '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
            })
    };
    components.iter().all(plain).then(|| components.join("\\"))
}

/// Text of a task definition file: UTF-16LE with a BOM as Task Scheduler writes
/// them, UTF-8 (BOM optional) otherwise. Lossy — the result only feeds
/// [`task_actions_display`], which tolerates any input.
#[must_use]
pub fn decode_task_definition(bytes: &[u8]) -> String {
    if let Some(utf16) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = utf16
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    let utf8 = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    String::from_utf8_lossy(utf8).into_owned()
}

/// Parses one 106 `<Event>` block. `None` if the block is missing
/// `EventRecordID` (same convention as the other parsers).
#[must_use]
pub fn parse_task_scheduler_op_registered_block(
    block: &str,
) -> Option<TaskSchedulerOpRegisteredEvent> {
    let record_id = extract_between(block, "<EventRecordID>", "</EventRecordID>")?
        .parse()
        .ok()?;
    let pid = extract_between(block, "ProcessID='", "'")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let task_name = opt_data(block, "TaskName").unwrap_or_default();
    let user_context = opt_data(block, "UserContext").unwrap_or_default();
    Some(TaskSchedulerOpRegisteredEvent {
        record_id,
        pid,
        task_name,
        user_context,
    })
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Field names and general shape observed on `wevtutil qe System /f:xml` for a
    /// real 7045 event (lab, 2026-09-03) — trimmed to the fields this module reads.
    const SERVICE_INSTALL_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager' Guid='{555908d1-a6d7-4695-8e1e-26931d2012f4}' EventSourceName='Service Control Manager'/><EventID Qualifiers='16384'>7045</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8080000000000000</Keywords><TimeCreated SystemTime='2026-09-03T10:15:00.000000000Z'/><EventRecordID>42</EventRecordID><Correlation/><Execution ProcessID='956' ThreadID='1000'/><Channel>System</Channel><Computer>LAB-VM</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='ServiceName'>evilsvc</Data><Data Name='ImagePath'>C:\Users\victim\AppData\Roaming\payload.exe </Data><Data Name='ServiceType'>user mode service</Data><Data Name='StartType'>demand start</Data><Data Name='AccountName'>LocalSystem</Data></EventData></Event>"#;

    /// Same shape for a real 4698 event (`wevtutil qe Security /f:xml`, 2026-09-03),
    /// `TaskContent` escaped as `wevtutil` renders it (nested XML inside XML).
    const SCHEDULED_TASK_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4698</EventID><Version>1</Version><Level>0</Level><Task>12804</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-09-03T10:20:00.000000000Z'/><EventRecordID>777</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='8'/><Channel>Security</Channel><Computer>LAB-VM</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1-2-3-1001</Data><Data Name='SubjectUserName'>victim</Data><Data Name='TaskName'>\EvilTask</Data><Data Name='TaskContent'>&lt;?xml version="1.0" encoding="UTF-16"?&gt;&lt;Task&gt;&lt;Actions&gt;&lt;Exec&gt;&lt;Command&gt;C:\Users\victim\AppData\Roaming\payload.exe&lt;/Command&gt;&lt;Arguments&gt;-silent&lt;/Arguments&gt;&lt;/Exec&gt;&lt;/Actions&gt;&lt;/Task&gt;</Data><Data Name='ClientProcessId'>2468</Data></EventData></Event>"#;

    /// Real 4702 event (`wevtutil qe Security /f:xml`, lab, 2026-09-22, captured
    /// via `schtasks /change`) — trimmed to the fields this module reads. The one
    /// real difference from 4698: the content field is `TaskContentNew`.
    const SCHEDULED_TASK_UPDATE_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4702</EventID><Version>1</Version><Level>0</Level><Task>12804</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-09-22T08:57:54.8691097Z'/><EventRecordID>1293003</EventRecordID><Correlation ActivityID='{0d9dacec-4a69-0002-40ae-9d0d694add01}'/><Execution ProcessID='1552' ThreadID='1736'/><Channel>Security</Channel><Computer>SOFREXS</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-773117704-2304876226-3118202801-1001</Data><Data Name='SubjectUserName'>chouc</Data><Data Name='SubjectDomainName'>SOFREXS</Data><Data Name='SubjectLogonId'>0xd8c6d</Data><Data Name='TaskName'>\ClaudeTest</Data><Data Name='TaskContentNew'>&lt;?xml version="1.0" encoding="UTF-16"?&gt;&lt;Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"&gt;&lt;Actions Context="Author"&gt;&lt;Exec&gt;&lt;Command&gt;cmd.exe&lt;/Command&gt;&lt;Arguments&gt;/c echo hi&lt;/Arguments&gt;&lt;/Exec&gt;&lt;/Actions&gt;&lt;/Task&gt;</Data><Data Name='ClientProcessId'>25132</Data><Data Name='ParentProcessId'>25440</Data></EventData></Event>"#;

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
        let path = task_actions_display(&parsed.task_content).expect("should have an action");
        assert_eq!(path, r"C:\Users\victim\AppData\Roaming\payload.exe -silent");
    }

    #[test]
    fn parses_a_real_scheduled_task_update_block() {
        let block = split_event_blocks(SCHEDULED_TASK_UPDATE_XML)[0];
        let parsed = parse_scheduled_task_update_block(block).expect("should parse");
        assert_eq!(parsed.record_id, 1_293_003);
        assert_eq!(parsed.task_name, r"\ClaudeTest");
        assert_eq!(parsed.pid, 25132);
        assert!(parsed.task_content.contains("<Command>cmd.exe</Command>"));
        assert!(!parsed.task_content.contains("&lt;"));
    }

    #[test]
    fn task_update_actions_read_task_content_new() {
        let block = split_event_blocks(SCHEDULED_TASK_UPDATE_XML)[0];
        let parsed = parse_scheduled_task_update_block(block).expect("should parse");
        let path = task_actions_display(&parsed.task_content).expect("should have an action");
        assert_eq!(path, "cmd.exe /c echo hi");
    }

    #[test]
    fn creation_parser_does_not_pick_up_the_update_content_field() {
        // The marker includes the closing quote, so `TaskContent` never matches
        // `TaskContentNew`: a 4702 fed to the 4698 parser yields empty content.
        let block = split_event_blocks(SCHEDULED_TASK_UPDATE_XML)[0];
        let parsed = parse_scheduled_task_block(block).expect("record id still parses");
        assert!(parsed.task_content.is_empty());
    }

    #[test]
    fn task_actions_reads_every_exec_not_only_the_first() {
        let content = r"<Task><Actions><Exec><Command>C:\legit\backup.exe</Command></Exec><Exec><Command>C:\Users\Public\evil.exe</Command><Arguments>-q</Arguments></Exec></Actions></Task>";
        assert_eq!(
            task_actions(content),
            vec![
                TaskAction::Exec(r"C:\legit\backup.exe".into()),
                TaskAction::Exec(r"C:\Users\Public\evil.exe -q".into()),
            ]
        );
    }

    #[test]
    fn task_actions_takes_arguments_from_the_same_exec() {
        // The old single-action parser paired the first Command with the first
        // Arguments of the whole document, producing "a.exe --x" here.
        let content = "<Actions><Exec><Command>a.exe</Command></Exec><Exec><Command>b.exe</Command><Arguments>--x</Arguments></Exec></Actions>";
        assert_eq!(
            task_actions(content),
            vec![
                TaskAction::Exec("a.exe".into()),
                TaskAction::Exec("b.exe --x".into()),
            ]
        );
    }

    #[test]
    fn task_actions_matches_exec_with_attributes() {
        let content = r#"<Actions Context="Author"><Exec id="Action1"><Command>calc.exe</Command></Exec></Actions>"#;
        assert_eq!(
            task_actions(content),
            vec![TaskAction::Exec("calc.exe".into())]
        );
    }

    #[test]
    fn task_actions_ignores_elements_that_only_start_like_exec() {
        let content = "<Settings><ExecutionTimeLimit>PT72H</ExecutionTimeLimit></Settings><Actions><Exec><Command>a.exe</Command></Exec></Actions>";
        assert_eq!(
            task_actions(content),
            vec![TaskAction::Exec("a.exe".into())]
        );
    }

    #[test]
    fn task_actions_reads_com_handler_class_id() {
        let content = "<Actions><ComHandler><ClassId>{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}</ClassId><Data>x</Data></ComHandler></Actions>";
        let actions = task_actions(content);
        assert_eq!(
            actions,
            vec![TaskAction::ComHandler(
                "{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}".into()
            )]
        );
        assert_eq!(
            actions[0].render(),
            "com:{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}"
        );
    }

    #[test]
    fn task_actions_skips_com_handler_without_class_id() {
        let content = "<Task><Actions><ComHandler/></Actions></Task>";
        assert!(task_actions(content).is_empty());
        assert!(task_actions_display(content).is_none());
    }

    #[test]
    fn task_actions_display_keeps_document_order() {
        let content = "<Actions><ComHandler><ClassId>{X}</ClassId></ComHandler><Exec><Command>b.exe</Command></Exec></Actions>";
        assert_eq!(
            task_actions_display(content).as_deref(),
            Some("com:{X} | b.exe")
        );
    }

    #[test]
    fn task_actions_is_capped() {
        let content: String = (0..40)
            .map(|i| format!("<Exec><Command>a{i}.exe</Command></Exec>"))
            .collect();
        let actions = task_actions(&content);
        assert_eq!(actions.len(), MAX_TASK_ACTIONS);
        assert_eq!(actions[31], TaskAction::Exec("a31.exe".into()));
    }

    #[test]
    fn task_actions_stops_at_an_unclosed_element() {
        let content =
            "<Actions><Exec><Command>a.exe</Command></Exec><Exec><Command>b.exe</Command>";
        assert_eq!(
            task_actions(content),
            vec![TaskAction::Exec("a.exe".into())]
        );
    }

    #[test]
    fn task_leaf_name_strips_the_scheduler_tree_path() {
        assert_eq!(task_leaf_name(r"\Microsoft\Windows\Backup\Daily"), "Daily");
        assert_eq!(task_leaf_name(r"\EvilTask"), "EvilTask");
        assert_eq!(task_leaf_name("NoLeadingSlash"), "NoLeadingSlash");
    }

    // ── Logon events (4624/4625/4648/4672) ───────────────────────────────────
    //
    // Fixtures reconciled 2026-09-21 (issue #224) against a real
    // `wevtutil qe Security /f:xml` capture on Windows 11 lab VM `Sandbox` —
    // see `lab/eventlog-captures/2026-09-21-sandbox/*.xml`. UTF-16-LE from wevtutil normalised to UTF-8
    // via iconv (a stray `Système`-mojibake artefact from that pipeline was
    // corrected back to `Système` here; the parser reads neither the field nor
    // the surrounding text, so the round-trip is safe).

    /// Three concatenated 4624 events as one `wevtutil` query returns them:
    /// two service-account logons (`LogonType` 5, Target SYSTEM `S-1-5-18`,
    /// `IpAddress='-'`) followed by the interactive `runas`-triggered logon
    /// (`LogonType` 2, Target `testuser224`, `IpAddress='::1'`). Exercises both
    /// the multi-event splitter and the `"-"`-sentinel filter on `IpAddress`.
    const LOGON_SUCCESS_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4624</EventID><Version>3</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-09-21T13:31:23.4077711Z'/><EventRecordID>76351</EventRecordID><Correlation ActivityID='{9f6e2246-49c9-0001-c923-6e9fc949dd01}'/><Execution ProcessID='836' ThreadID='932'/><Channel>Security</Channel><Computer>Sandbox</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>SANDBOX$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-5-18</Data><Data Name='TargetUserName'>Système</Data><Data Name='TargetDomainName'>AUTORITE NT</Data><Data Name='TargetLogonId'>0x3e7</Data><Data Name='LogonType'>5</Data><Data Name='LogonProcessName'>Advapi  </Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>-</Data><Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x330</Data><Data Name='ProcessName'>C:\Windows\System32\services.exe</Data><Data Name='IpAddress'>-</Data><Data Name='IpPort'>-</Data><Data Name='ImpersonationLevel'>%%1833</Data><Data Name='RestrictedAdminMode'>-</Data><Data Name='RemoteCredentialGuard'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1843</Data><Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='ElevatedToken'>%%1842</Data></EventData></Event><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4624</EventID><Version>3</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-09-21T13:29:39.7628569Z'/><EventRecordID>76342</EventRecordID><Correlation ActivityID='{9f6e2246-49c9-0001-c923-6e9fc949dd01}'/><Execution ProcessID='836' ThreadID='876'/><Channel>Security</Channel><Computer>Sandbox</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>SANDBOX$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-5-18</Data><Data Name='TargetUserName'>Système</Data><Data Name='TargetDomainName'>AUTORITE NT</Data><Data Name='TargetLogonId'>0x3e7</Data><Data Name='LogonType'>5</Data><Data Name='LogonProcessName'>Advapi  </Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>-</Data><Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x330</Data><Data Name='ProcessName'>C:\Windows\System32\services.exe</Data><Data Name='IpAddress'>-</Data><Data Name='IpPort'>-</Data><Data Name='ImpersonationLevel'>%%1833</Data><Data Name='RestrictedAdminMode'>-</Data><Data Name='RemoteCredentialGuard'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1843</Data><Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='ElevatedToken'>%%1842</Data></EventData></Event><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4624</EventID><Version>3</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-09-21T13:29:36.7187492Z'/><EventRecordID>76340</EventRecordID><Correlation ActivityID='{9f6e2246-49c9-0001-c923-6e9fc949dd01}'/><Execution ProcessID='836' ThreadID='876'/><Channel>Security</Channel><Computer>Sandbox</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1663667890-2519037288-962558911-1001</Data><Data Name='SubjectUserName'>solka</Data><Data Name='SubjectDomainName'>SANDBOX</Data><Data Name='SubjectLogonId'>0x12abb7</Data><Data Name='TargetUserSid'>S-1-5-21-1663667890-2519037288-962558911-1002</Data><Data Name='TargetUserName'>testuser224</Data><Data Name='TargetDomainName'>Sandbox</Data><Data Name='TargetLogonId'>0xd15e6e</Data><Data Name='LogonType'>2</Data><Data Name='LogonProcessName'>seclogo</Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>SANDBOX</Data><Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0xb90</Data><Data Name='ProcessName'>C:\Windows\System32\svchost.exe</Data><Data Name='IpAddress'>::1</Data><Data Name='IpPort'>0</Data><Data Name='ImpersonationLevel'>%%1833</Data><Data Name='RestrictedAdminMode'>-</Data><Data Name='RemoteCredentialGuard'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1843</Data><Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='ElevatedToken'>%%1843</Data></EventData></Event>"#;

    /// A failed network logon (`LogonType` 3, `NtLmSsp`), wrong-password
    /// substatus, from a `net use \\localhost\C$` attempt by an account that is
    /// not a local administrator — `IpAddress='::1'` because Windows resolves
    /// `localhost` to the IPv6 loopback first.
    const LOGON_FAILURE_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2026-09-21T13:29:23.2367298Z'/><EventRecordID>76333</EventRecordID><Correlation ActivityID='{9f6e2246-49c9-0001-c923-6e9fc949dd01}'/><Execution ProcessID='836' ThreadID='4836'/><Channel>Security</Channel><Computer>Sandbox</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='SubjectUserName'>-</Data><Data Name='SubjectDomainName'>-</Data><Data Name='SubjectLogonId'>0x0</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>testuser224</Data><Data Name='TargetDomainName'>-</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc000006a</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>NtLmSsp </Data><Data Name='AuthenticationPackageName'>NTLM</Data><Data Name='WorkstationName'>SANDBOX</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x0</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>::1</Data><Data Name='IpPort'>54937</Data></EventData></Event>"#;

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

    // ── Account creation (4720) ──────────────────────────────────────────────
    //
    // Fixture reconciled 2026-09-21 (issue #224) against a real
    // `wevtutil qe Security /f:xml` capture on Windows 11 lab VM `Sandbox` —
    // see `lab/eventlog-captures/2026-09-21-sandbox/4720.xml`. Note that `UserAccountControl` is
    // multi-line (indented `%%2080/%%2082/%%2084`, one per line); the parser
    // ignores this field, so the whitespace shape does not affect correctness
    // but is preserved here to stay faithful to what wevtutil rendered.

    /// A local SAM account creation via `net user testuser224 <pwd> /add`
    /// executed by `solka` (a local administrator). Target is the newly
    /// created `testuser224` account (RID 1002).
    const ACCOUNT_CREATED_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4720</EventID><Version>0</Version><Level>0</Level><Task>13824</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-09-21T13:29:23.0286360Z'/><EventRecordID>76327</EventRecordID><Correlation ActivityID='{9f6e2246-49c9-0001-c923-6e9fc949dd01}'/><Execution ProcessID='836' ThreadID='4836'/><Channel>Security</Channel><Computer>Sandbox</Computer><Security/></System><EventData><Data Name='TargetUserName'>testuser224</Data><Data Name='TargetDomainName'>Sandbox</Data><Data Name='TargetSid'>S-1-5-21-1663667890-2519037288-962558911-1002</Data><Data Name='SubjectUserSid'>S-1-5-21-1663667890-2519037288-962558911-1001</Data><Data Name='SubjectUserName'>solka</Data><Data Name='SubjectDomainName'>SANDBOX</Data><Data Name='SubjectLogonId'>0x12abb7</Data><Data Name='PrivilegeList'>-</Data><Data Name='SamAccountName'>testuser224</Data><Data Name='DisplayName'>%%1793</Data><Data Name='UserPrincipalName'>-</Data><Data Name='HomeDirectory'>%%1793</Data><Data Name='HomePath'>%%1793</Data><Data Name='ScriptPath'>%%1793</Data><Data Name='ProfilePath'>%%1793</Data><Data Name='UserWorkstations'>%%1793</Data><Data Name='PasswordLastSet'>%%1794</Data><Data Name='AccountExpires'>%%1794</Data><Data Name='PrimaryGroupId'>513</Data><Data Name='AllowedToDelegateTo'>-</Data><Data Name='OldUacValue'>0x0</Data><Data Name='NewUacValue'>0x15</Data><Data Name='UserAccountControl'>
		%%2080
		%%2082
		%%2084</Data><Data Name='UserParameters'>%%1793</Data><Data Name='SidHistory'>-</Data><Data Name='LogonHours'>%%1797</Data></EventData></Event>"#;

    #[test]
    fn parses_a_real_shaped_account_created_block() {
        let block = split_event_blocks(ACCOUNT_CREATED_XML)[0];
        let parsed = parse_account_created_block(block).expect("should parse");
        assert_eq!(parsed.record_id, 76327);
        assert_eq!(parsed.pid, 836);
        assert_eq!(parsed.target_user_name.as_deref(), Some("testuser224"));
        // 4720 uses `TargetSid`, not `TargetUserSid` — the parser knows this
        // (see comment on `parse_account_created_block`).
        assert_eq!(
            parsed.target_user_sid.as_deref(),
            Some("S-1-5-21-1663667890-2519037288-962558911-1002")
        );
        assert_eq!(
            parsed.subject_user_sid.as_deref(),
            Some("S-1-5-21-1663667890-2519037288-962558911-1001")
        );
        assert_eq!(parsed.subject_user_name.as_deref(), Some("solka"));
    }

    #[test]
    fn account_created_block_missing_record_id_does_not_parse() {
        let block = "<Event><EventData><Data Name='TargetUserName'>x</Data></EventData></Event>";
        assert!(parse_account_created_block(block).is_none());
    }

    // ── `AppLocker` EID 8004 ───────────────────────────────────────────────

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

    // ── `AppLocker` path variables (#427) ───────────────────────────────

    fn lab_env(name: &str) -> Option<String> {
        match name {
            "SystemDrive" => Some("C:".into()),
            "SystemRoot" => Some("C:\\Windows".into()),
            "ProgramFiles" => Some("C:\\Program Files".into()),
            _ => None,
        }
    }

    // ── Defender Operational (#283) ──────────────────────────────────────────

    /// Shape of a real 1117 captured on a French Windows 11 host (names kept
    /// localized on purpose; account and path replaced): the numeric ids and
    /// `Threat Name` are what the parser may rely on.
    const DEFENDER_1117_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Windows Defender' Guid='{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}'/><EventID>1117</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-10-01T14:38:47.6936386Z'/><EventRecordID>7272</EventRecordID><Correlation/><Execution ProcessID='6164' ThreadID='3192'/><Channel>Microsoft-Windows-Windows Defender/Operational</Channel><Computer>LabPC</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='Product Name'>Antivirus Microsoft Defender</Data><Data Name='Product Version'>4.18.26080.4</Data><Data Name='Detection ID'>{3F813A68-3FA3-456D-8818-54AB191C87B3}</Data><Data Name='Detection Time'>2026-10-01T14:37:46.365Z</Data><Data Name='Unused'></Data><Data Name='Unused2'></Data><Data Name='Threat ID'>2147741009</Data><Data Name='Threat Name'>HackTool:Win32/Mimikatz.I</Data><Data Name='Severity ID'>4</Data><Data Name='Severity Name'>Élevée</Data><Data Name='Category ID'>34</Data><Data Name='Category Name'>Outil</Data><Data Name='FWLink'>https://go.microsoft.com/fwlink/?linkid=37020&amp;name=HackTool:Win32/Mimikatz.I&amp;threatid=2147741009&amp;enterprise=0</Data><Data Name='Status Code'>4</Data><Data Name='Status Description'></Data><Data Name='State'>2</Data><Data Name='Source ID'>2</Data><Data Name='Source Name'>Système</Data><Data Name='Process Name'>Unknown</Data><Data Name='Detection User'>LAB\alice</Data><Data Name='Unused3'></Data><Data Name='Path'>file:_C:\Users\Public\a&amp;b.exe</Data><Data Name='Origin ID'>0</Data><Data Name='Origin Name'>Inconnu</Data><Data Name='Execution ID'>0</Data><Data Name='Execution Name'>Inconnu</Data><Data Name='Type ID'>0</Data><Data Name='Type Name'>Concret</Data><Data Name='Pre Execution Status'>0</Data><Data Name='Action ID'>3</Data><Data Name='Action Name'>Supprimer</Data><Data Name='Unused4'></Data><Data Name='Error Code'>0x00000000</Data><Data Name='Error Description'>L’opération a réussi. </Data></EventData></Event>"#;

    #[test]
    fn parses_a_real_shaped_localized_defender_1117() {
        let parsed = parse_defender_event(split_event_blocks(DEFENDER_1117_XML)[0]).unwrap();
        assert_eq!(parsed.record_id, 7272);
        assert_eq!(parsed.event_id, 1117);
        assert_eq!(
            parsed.detection_id.as_deref(),
            Some("{3F813A68-3FA3-456D-8818-54AB191C87B3}")
        );
        assert_eq!(
            parsed.threat_name.as_deref(),
            Some("HackTool:Win32/Mimikatz.I")
        );
        assert_eq!(
            (parsed.severity_id, parsed.category_id, parsed.action_id),
            (Some(4), Some(34), Some(3))
        );
        assert_eq!(
            parsed.path.as_deref(),
            Some(r"file:_C:\Users\Public\a&b.exe")
        );
        assert_eq!(parsed.detection_user.as_deref(), Some(r"LAB\alice"));
        assert_eq!(
            parsed.process_name, None,
            "Defender's `Unknown` is no process"
        );
        assert_eq!((parsed.old_value, parsed.new_value), (None, None));
    }

    #[test]
    fn parses_defender_5007_values_and_skips_empty_ones() {
        let xml = "<Event xmlns='x'><System><EventID>5007</EventID><EventRecordID>9001</EventRecordID></System><EventData><Data Name='Product Name'>Antivirus Microsoft Defender</Data><Data Name='Old Value'></Data><Data Name='New Value'>HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\Users\\Public = 0x0</Data></EventData></Event>";
        let parsed = parse_defender_event(split_event_blocks(xml)[0]).unwrap();
        assert_eq!(parsed.event_id, 5007);
        assert_eq!(parsed.old_value, None);
        assert_eq!(
            parsed.new_value.as_deref(),
            Some(
                r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\Public = 0x0"
            )
        );
    }

    #[test]
    fn defender_block_missing_record_id_does_not_parse() {
        assert!(parse_defender_event("<Event><EventData></EventData></Event>").is_none());
    }

    // ── CodeIntegrity (WDAC) 3076/3077 (#283) ────────────────────────────────

    #[test]
    fn parses_a_wdac_enforced_block() {
        let xml = "<Event xmlns='x'><System><EventID>3077</EventID><EventRecordID>77</EventRecordID></System><EventData><Data Name='FileNameLength'>66</Data><Data Name='File Name'>\\Device\\HarddiskVolume3\\Users\\Public\\x.dll</Data><Data Name='ProcessNameLength'>74</Data><Data Name='Process Name'>\\Device\\HarddiskVolume3\\Windows\\System32\\rundll32.exe</Data><Data Name='Requested Signing Level'>8</Data><Data Name='Validated Signing Level'>1</Data><Data Name='Status'>0xC0E90002</Data><Data Name='SI Signing Scenario'>1</Data></EventData></Event>";
        let parsed = parse_code_integrity_event(split_event_blocks(xml)[0]).unwrap();
        assert_eq!((parsed.record_id, parsed.event_id), (77, 3077));
        assert_eq!(
            parsed.file_name.as_deref(),
            Some(r"\Device\HarddiskVolume3\Users\Public\x.dll")
        );
        assert_eq!(
            parsed.process_name.as_deref(),
            Some(r"\Device\HarddiskVolume3\Windows\System32\rundll32.exe")
        );
        assert_eq!(parsed.signing_scenario, Some(1));
    }

    #[test]
    fn wdac_block_without_fields_still_parses_with_nones() {
        let xml = "<Event xmlns='x'><System><EventID>3076</EventID><EventRecordID>5</EventRecordID></System><EventData></EventData></Event>";
        let parsed = parse_code_integrity_event(split_event_blocks(xml)[0]).unwrap();
        assert_eq!(parsed.file_name, None);
        assert_eq!(parsed.signing_scenario, None);
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

    // ── TaskScheduler Operational EID 106 ───────────────────────────────

    /// A user (`SANDBOX\solka`) registering a scheduled task named `\atomic-r`
    /// via `schtasks.exe /Create ...`. Emitted by the Task Scheduler service on
    /// the always-on `Microsoft-Windows-TaskScheduler/Operational` channel, no
    /// audit subcategory required — the complement to Security 4698 whose audit
    /// enablement may fail on a hardened host.
    const TASK_SCHEDULER_OP_106_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TaskScheduler' Guid='{de7b24ea-73c8-4a09-985d-5bdadcfa9017}'/><EventID>106</EventID><Version>0</Version><Level>4</Level><Task>106</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-09-22T08:21:11.7752210Z'/><EventRecordID>18432</EventRecordID><Correlation/><Execution ProcessID='2124' ThreadID='2892'/><Channel>Microsoft-Windows-TaskScheduler/Operational</Channel><Computer>Sandbox</Computer><Security UserID='S-1-5-21-1663667890-2519037288-962558911-1001'/></System><EventData><Data Name='TaskName'>\atomic-r</Data><Data Name='UserContext'>SANDBOX\solka</Data></EventData></Event>"#;

    #[test]
    fn parses_a_real_shaped_task_scheduler_op_106_block() {
        let block = split_event_blocks(TASK_SCHEDULER_OP_106_XML)[0];
        let parsed = parse_task_scheduler_op_registered_block(block).expect("should parse");
        assert_eq!(parsed.record_id, 18432);
        assert_eq!(parsed.pid, 2124);
        assert_eq!(parsed.task_name, "\\atomic-r");
        assert_eq!(parsed.user_context, "SANDBOX\\solka");
    }

    #[test]
    fn task_scheduler_op_106_missing_record_id_does_not_parse() {
        let block = "<Event><EventData><Data Name='TaskName'>x</Data></EventData></Event>";
        assert!(parse_task_scheduler_op_registered_block(block).is_none());
    }

    // ── Task definition read-back for event 106 (#422) ───────────────────

    #[test]
    fn task_definition_path_mirrors_the_task_tree() {
        assert_eq!(
            task_definition_relative_path(r"\atomic-r").as_deref(),
            Some("atomic-r")
        );
        assert_eq!(
            task_definition_relative_path(r"\Microsoft\Windows\Backup\Daily task").as_deref(),
            Some(r"Microsoft\Windows\Backup\Daily task")
        );
    }

    #[test]
    fn task_definition_path_refuses_to_leave_the_tasks_directory() {
        for name in [
            r"\..\..\Windows\win.ini",
            r"\Folder\..",
            r"\.",
            r"\x...",
            r"\trailing ",
            r"\\server\share",
            r"\C:\x",
            r"\x:stream",
            r"\a/b",
            "relative",
            "",
            r"\",
            "\\bad\u{0}name",
        ] {
            assert_eq!(task_definition_relative_path(name), None, "{name:?}");
        }
    }

    #[test]
    fn task_definition_decodes_utf16le_with_bom() {
        let text = "<Task><Actions><Exec><Command>C:\\x.exe</Command></Exec></Actions></Task>";
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(decode_task_definition(&bytes), text);
        assert_eq!(
            task_actions_display(&decode_task_definition(&bytes)).as_deref(),
            Some(r"C:\x.exe")
        );
    }

    #[test]
    fn task_definition_decodes_utf8_with_or_without_bom() {
        assert_eq!(decode_task_definition(b"\xEF\xBB\xBF<Task/>"), "<Task/>");
        assert_eq!(decode_task_definition(b"<Task/>"), "<Task/>");
    }

    #[test]
    fn task_definition_decoding_never_panics_on_odd_input() {
        for bytes in [&[][..], &[0xFF, 0xFE, 0x41][..], &[0xFF][..], &[0xC3][..]] {
            let _ = decode_task_definition(bytes);
        }
    }

    // ── Terminal Services session events (#285) ──────────────────────────

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
    fn time_created_reads_wevtutil_timestamps_exactly() {
        let at = |t: &str| time_created_ns(&format!("<TimeCreated SystemTime='{t}'/>"));
        assert_eq!(at("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            at("2026-09-21T13:29:23.0286360Z"),
            Some(1789997363028636000)
        );
        assert_eq!(
            at("2024-02-29T23:59:59.999999999Z"),
            Some(1709251199999999999)
        );
        assert_eq!(
            at("2000-03-01T00:00:00.000000000Z"),
            Some(951868800000000000)
        );
    }

    #[test]
    fn time_created_rejects_what_is_not_a_real_timestamp() {
        let at = |t: &str| time_created_ns(&format!("<TimeCreated SystemTime='{t}'/>"));
        assert_eq!(time_created_ns("<Event/>"), None, "no attribute");
        for bad in [
            "",
            "2026-09-21",
            "2026-09-21T13:29:23",
            "2026-09-21 13:29:23Z",
            "2026-13-01T00:00:00Z",
            "2026-00-10T00:00:00Z",
            "2026-02-30T00:00:00Z",
            "2023-02-29T00:00:00Z",
            "2026-09-21T24:00:00Z",
            "2026-09-21T13:60:00Z",
            "2026-09-21T13:29:60Z",
            "1969-12-31T23:59:59Z",
            "2026-09-21T13:29:23.Z",
            "2026-09-21T13:29:23.1234567891Z",
            "2026-09-21T13:29:23,5Z",
            "2026-09-21T13:29:23+01:00",
            "20x6-09-21T13:29:23Z",
        ] {
            assert_eq!(at(bad), None, "{bad:?}");
        }
    }

    proptest! {
        #[test]
        fn time_created_round_trips_against_time_crate(
            // `time_created_ns` returns u64 nanoseconds, so cap the reference
            // generator below u64::MAX / 1e9; a separate boundary case covers
            // the overflow edge.
            seconds in 0_u64..18_446_744_073,
            nanos in 0_u32..1_000_000_000,
        ) {
            let reference = time::OffsetDateTime::from_unix_timestamp(seconds as i64)
                .unwrap()
                .replace_nanosecond(nanos)
                .unwrap();
            let date = reference.date();
            let clock = reference.time();
            let timestamp = format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
                date.year(),
                u8::from(date.month()),
                date.day(),
                clock.hour(),
                clock.minute(),
                clock.second(),
                clock.nanosecond(),
            );
            let event = format!("<TimeCreated SystemTime='{timestamp}'/>");
            prop_assert_eq!(
                time_created_ns(&event),
                Some(reference.unix_timestamp_nanos() as u64),
            );
        }
    }

    #[test]
    fn time_created_handles_gregorian_century_leap_years() {
        let at = |text: &str| time_created_ns(&format!("<TimeCreated SystemTime='{text}'/>"));
        assert_eq!(at("2000-02-29T00:00:00Z"), Some(951_782_400_000_000_000));
        assert_eq!(at("1900-02-29T00:00:00Z"), None);
        assert_eq!(at("2100-02-29T00:00:00Z"), None);
        assert_eq!(at("2100-03-01T00:00:00Z"), Some(4_107_542_400_000_000_000));
    }

    #[test]
    fn time_created_rejects_nanoseconds_beyond_u64() {
        assert_eq!(
            time_created_ns("<TimeCreated SystemTime='2554-07-21T23:34:33.709551616Z'/>"),
            None,
        );
    }

    #[test]
    fn time_created_accepts_both_attribute_quote_styles_and_rejects_hostile_text() {
        assert_eq!(
            time_created_ns("<TimeCreated SystemTime=\"2026-01-02T03:04:05.000000006Z\"/>"),
            Some(1_767_323_045_000_000_006),
        );
        assert_eq!(
            time_created_ns("<TimeCreated SystemTime='2026-01-02T03:04:05.000000006Z'/>"),
            Some(1_767_323_045_000_000_006),
        );
        for hostile in [
            "2026-0é-02T03:04:05Z",
            "2026-01-02T03:04:é5Z",
            "2026-01-02T03:04:05\"Z",
            "2026-01-02T03:04:05'Z",
        ] {
            let event = format!("<TimeCreated SystemTime='{hostile}'/>");
            assert_eq!(time_created_ns(&event), None, "{hostile:?}");
        }
        let million_digits = format!(
            "<TimeCreated SystemTime='2026-01-02T03:04:05.{}Z'/>",
            "7".repeat(1_000_000),
        );
        assert_eq!(time_created_ns(&million_digits), None);
    }

    #[test]
    fn time_created_rejects_each_required_delimiter_when_only_it_is_wrong() {
        for malformed in [
            "2026/01-02T03:04:05Z",
            "2026-01/02T03:04:05Z",
            "2026-01-02t03:04:05Z",
            "2026-01-02T03.04:05Z",
            "2026-01-02T03:04.05Z",
            "2026-01-02T03:04:05X",
        ] {
            let event = format!("<TimeCreated SystemTime='{malformed}'/>");
            assert_eq!(time_created_ns(&event), None, "{malformed}");
        }
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
