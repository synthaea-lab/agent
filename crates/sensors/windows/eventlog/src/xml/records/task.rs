//! Scheduled-task registrations: Security 4698/4702 and Task Scheduler Operational 106.

use crate::xml::scan::{extract_between, opt_data, unescape_xml_entities};

/// Fields extracted from a 4698 ("A scheduled task was created") `<Event>` block —
/// Security log, requires the "Other Object Access Events" audit subcategory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledTaskEvent {
    pub record_id: u64,
    /// e.g. `\TestTask` — the Task Scheduler path, not just the leaf name.
    pub task_name: String,
    /// The full task definition XML, already unescaped (`unescape_xml_entities`
    /// applied by `parse_scheduled_task_block`) — pass to
    /// [`task_actions`](crate::xml::task_actions) to pull out every action it runs.
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
    use super::*;
    use crate::xml::{
        fixtures::SCHEDULED_TASK_XML, records::task_definition::task_actions_display,
        scan::split_event_blocks,
    };

    /// Real 4702 event (`wevtutil qe Security /f:xml`, lab, 2026-09-22, captured
    /// via `schtasks /change`) — trimmed to the fields this module reads. The one
    /// real difference from 4698: the content field is `TaskContentNew`.
    const SCHEDULED_TASK_UPDATE_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4702</EventID><Version>1</Version><Level>0</Level><Task>12804</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-09-22T08:57:54.8691097Z'/><EventRecordID>1293003</EventRecordID><Correlation ActivityID='{0d9dacec-4a69-0002-40ae-9d0d694add01}'/><Execution ProcessID='1552' ThreadID='1736'/><Channel>Security</Channel><Computer>SOFREXS</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-773117704-2304876226-3118202801-1001</Data><Data Name='SubjectUserName'>chouc</Data><Data Name='SubjectDomainName'>SOFREXS</Data><Data Name='SubjectLogonId'>0xd8c6d</Data><Data Name='TaskName'>\ClaudeTest</Data><Data Name='TaskContentNew'>&lt;?xml version="1.0" encoding="UTF-16"?&gt;&lt;Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"&gt;&lt;Actions Context="Author"&gt;&lt;Exec&gt;&lt;Command&gt;cmd.exe&lt;/Command&gt;&lt;Arguments&gt;/c echo hi&lt;/Arguments&gt;&lt;/Exec&gt;&lt;/Actions&gt;&lt;/Task&gt;</Data><Data Name='ClientProcessId'>25132</Data><Data Name='ParentProcessId'>25440</Data></EventData></Event>"#;

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

    /// A user (`SANDBOX\solka`) registering a scheduled task named `\atomic-r`
    /// via `schtasks.exe /Create ...`. Emitted by the Task Scheduler service on
    /// the `Microsoft-Windows-TaskScheduler/Operational` channel, no audit
    /// subcategory required — the complement to Security 4698 whose audit
    /// enablement may fail on a hardened host. The channel is Task Scheduler
    /// history, off by default on client SKUs: only hosts where an operator
    /// enabled it produce this event (#786).
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
}
