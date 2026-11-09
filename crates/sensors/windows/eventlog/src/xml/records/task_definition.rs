//! A scheduled task's definition XML: its actions, its leaf name, and the on-disk file
//! an event 106 is read back from.

use crate::xml::scan::extract_between;

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
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    let utf8 = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    String::from_utf8_lossy(utf8).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
