//! Persistence artifacts reported as file opens: service installs, scheduled tasks, account creation.

use std::{fs::File, io::Read, path::Path};

use schema::{
    Event, EventMeta, FLAG_PERSISTENCE_ACCOUNT_ARTIFACT, FLAG_PERSISTENCE_ARTIFACT,
    FLAG_PERSISTENCE_TASK_ARTIFACT, FLAG_PERSISTENCE_TASK_UPDATE_ARTIFACT, FileOpenEvent, User,
    time::now_ns,
};

use super::BlockOutcome;
use crate::xml::{self};

/// The meta shape shared by the three persistence-artifact targets, which all
/// reuse [`FileOpenEvent`] (see ADR-0004) rather than defining event types of
/// their own.
pub(crate) fn persistence_file_open(pid: u32, comm: String, path: String, flags: u32) -> Event {
    Event::FileOpen(FileOpenEvent {
        meta: EventMeta {
            pid,
            ppid: 0,
            user: User::Unknown,
            timestamp_ns: now_ns(),
            comm,
            container: None, // attributed by the ETW sensor only (https://github.com/synthaea-lab/agent/issues/39)
            process_generation: None,
            parent_process_generation: None,
        },
        path,
        flags,
    })
}

// ── Event 7045 — service install (T1543.003) ─────────────────────────────────

/// A 7045 without a service name or image path is unusable — the alert quotes
/// them as `comm`/`path`. Skip, advancing the cursor.
pub(crate) fn normalize_service_install(block: &str) -> BlockOutcome {
    let Some(install) = xml::parse_service_install_block(block) else {
        return BlockOutcome::Unparseable;
    };
    let record_id = install.record_id;
    if install.service_name.is_empty() || install.image_path.is_empty() {
        return BlockOutcome::Filtered { record_id };
    }
    let event = persistence_file_open(
        install.pid,
        install.service_name,
        install.image_path,
        FLAG_PERSISTENCE_ARTIFACT,
    );
    BlockOutcome::Event { record_id, event }
}

/// Same tolerance rule as [`normalize_service_install`].
pub(crate) fn normalize_scheduled_task(block: &str) -> BlockOutcome {
    let Some(task) = xml::parse_scheduled_task_block(block) else {
        return BlockOutcome::Unparseable;
    };
    normalize_task(task, FLAG_PERSISTENCE_TASK_ARTIFACT)
}

/// Shared by 4698 (creation) and 4702 (update): only the parser and the flag
/// differ between the two. A task with no name is filtered; an unreadable action
/// is reported, not skipped.
pub(crate) fn normalize_task(task: xml::ScheduledTaskEvent, flag: u32) -> BlockOutcome {
    let record_id = task.record_id;
    if task.task_name.is_empty() {
        return BlockOutcome::Filtered { record_id };
    }
    // A task whose action we cannot read is still a persistence artifact: report
    // it with a placeholder path instead of dropping it (#422). Every action is
    // read, not only the first (#443): a benign first action must not hide a
    // malicious second one — on creation or on update alike.
    let (path, flags) = match xml::task_actions_display(&task.task_content) {
        Some(actions) => (actions, flag),
        None => (
            xml::TASK_ACTION_UNKNOWN.to_string(),
            flag | schema::FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN,
        ),
    };
    let event = persistence_file_open(task.pid, xml::task_leaf_name(&task.task_name), path, flags);
    BlockOutcome::Event { record_id, event }
}

// ── Event 4702 — scheduled task update (T1053.005 task-hijack) ───────────────

pub(crate) fn normalize_scheduled_task_update(block: &str) -> BlockOutcome {
    let Some(task) = xml::parse_scheduled_task_update_block(block) else {
        return BlockOutcome::Unparseable;
    };
    normalize_task(task, FLAG_PERSISTENCE_TASK_UPDATE_ARTIFACT)
}

/// A 4720 without a target user name is not usable — the alert message quotes
/// it as `comm`. Skip, advancing the cursor.
pub(crate) fn normalize_account_created(block: &str) -> BlockOutcome {
    let Some(account) = xml::parse_account_created_block(block) else {
        return BlockOutcome::Unparseable;
    };
    let record_id = account.record_id;
    let Some(target_name) = account.target_user_name else {
        return BlockOutcome::Filtered { record_id };
    };
    // TargetSid is preferred as `path` (the persistence artifact's canonical
    // identifier — survives an account rename). Falling back to the leaf name
    // reproduced as a placeholder path keeps the alert well-formed if the SID
    // is missing on some future Windows shape rather than dropping the event
    // outright.
    let sid = account
        .target_user_sid
        .unwrap_or_else(|| format!("(unknown-sid:{target_name})"));
    let event = persistence_file_open(
        account.pid,
        target_name,
        sid,
        FLAG_PERSISTENCE_ACCOUNT_ARTIFACT,
    );
    BlockOutcome::Event { record_id, event }
}

// ── Event 106 — TaskScheduler Operational "task registered" ─────────────────
//
// The `Microsoft-Windows-TaskScheduler/Operational` channel is Task Scheduler's
// "history" switch, and it is **off by default**: disabled, with no log file, on a
// Windows 11 25H2 client (lab, 2026-10-12, #786; Server not checked). Where an
// operator turned it on, it needs no `auditpol` interaction and complements the
// Security 4698 path whose `enable_scheduled_task_audit` may fail on a hardened
// host. Where it is off, this target sees nothing and the start-up channel check
// says so (`warn_about_disabled_channels`). When both channels
// are up, one registration yields a 4698 and a 106 carrying the same task and
// actions: both raw events are kept, and the rules layer reports the pair once
// (`RuleState`'s scheduled-task registration dedup, #422).

/// Same shape as a 4698 once the actions are known: a 106 carries no task XML,
/// so the definition is read back from the task's file and the result goes
/// through [`normalize_task`], placeholder and all. The first cut reported the
/// task *name* as the action path, and the rule printed it as an executable
/// (#422). A task already deleted by the time of the read, or one the sensor
/// may not read, is reported as action-unknown rather than dropped.
pub(crate) fn normalize_task_scheduler_op_registered(block: &str) -> BlockOutcome {
    let tasks_dir =
        std::env::var_os("SystemRoot").map(|root| Path::new(&root).join("System32").join("Tasks"));
    normalize_task_registered_from(block, tasks_dir.as_deref())
}

/// [`normalize_task_scheduler_op_registered`] with the Tasks directory passed
/// in, so tests can point it at a temporary tree.
pub(crate) fn normalize_task_registered_from(
    block: &str,
    tasks_dir: Option<&Path>,
) -> BlockOutcome {
    let Some(ev) = xml::parse_task_scheduler_op_registered_block(block) else {
        return BlockOutcome::Unparseable;
    };
    let task_content = tasks_dir
        .and_then(|dir| read_task_definition(dir, &ev.task_name))
        .unwrap_or_default();
    normalize_task(
        xml::ScheduledTaskEvent {
            record_id: ev.record_id,
            task_name: ev.task_name,
            task_content,
            pid: ev.pid,
        },
        FLAG_PERSISTENCE_TASK_ARTIFACT,
    )
}

/// Task `task_name`'s definition, read from `tasks_dir`
/// (`%SystemRoot%\System32\Tasks`, readable by SYSTEM and Administrators only,
/// as the agent runs). `None` when the name does not map to a safe path, the
/// file is gone or unreadable, or it exceeds [`xml::MAX_TASK_DEFINITION_BYTES`].
pub(crate) fn read_task_definition(tasks_dir: &Path, task_name: &str) -> Option<String> {
    let path = tasks_dir.join(xml::task_definition_relative_path(task_name)?);
    let mut bytes = Vec::new();
    let read = File::open(&path).and_then(|file| {
        file.take(xml::MAX_TASK_DEFINITION_BYTES + 1)
            .read_to_end(&mut bytes)
    });
    if let Err(error) = read {
        tracing::debug!(%error, path = %path.display(), "task definition read-back failed");
        return None;
    }
    if bytes.len() as u64 > xml::MAX_TASK_DEFINITION_BYTES {
        tracing::debug!(path = %path.display(), "task definition over the size cap, not parsed");
        return None;
    }
    Some(xml::decode_task_definition(&bytes))
}
