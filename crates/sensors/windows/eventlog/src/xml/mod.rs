//! Pure parsing of rendered Event Log XML, one `<Event>` block per record, by substring
//! rather than an XML parser (`docs/sensors/windows/eventlog.md#xml-parsing`).
//! Platform-independent, so every CI leg unit-tests it.

#[cfg(test)]
mod fixtures;
mod records;
mod scan;
mod time;

pub use records::{
    account::{AccountCreatedEvent, parse_account_created_block},
    applocker::{AppLockerEvent, expand_applocker_path, parse_applocker_event},
    code_integrity::{CodeIntegrityEvent, parse_code_integrity_event},
    defender::{DefenderLogEvent, parse_defender_event},
    kerberos::{KerberosDelegationFailureRecord, parse_kerberos_delegation_failure_block},
    log_cleared::{LogClearedRecord, parse_log_cleared_event},
    logon::{LogonEvent, parse_logon_block},
    service::{ServiceInstallEvent, parse_service_install_block},
    session::{TerminalSessionEvent, parse_local_session_event, parse_remote_connection_event},
    task::{
        ScheduledTaskEvent, TaskSchedulerOpRegisteredEvent, parse_scheduled_task_block,
        parse_scheduled_task_update_block, parse_task_scheduler_op_registered_block,
    },
    task_definition::{
        MAX_TASK_ACTIONS, MAX_TASK_DEFINITION_BYTES, TASK_ACTION_SEPARATOR, TASK_ACTION_UNKNOWN,
        TaskAction, decode_task_definition, task_actions, task_actions_display,
        task_definition_relative_path, task_leaf_name,
    },
};
pub use scan::{extract_between, split_event_blocks, unescape_xml_entities};
pub use time::time_created_ns;
