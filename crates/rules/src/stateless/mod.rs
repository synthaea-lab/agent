//! Stateless rules: a single event is enough to decide — no history, no state.
//!
//! One module per ATT&CK tactic (or, for the two large defense-evasion families,
//! per technique); this module holds the per-event-type dispatchers that run them.

mod command_and_control;
mod credential_access;
mod defense_evasion;
mod execution;
mod impact;
mod impair_defenses;
mod indicator_removal;
mod initial_access;
mod persistence;
mod privilege_escalation;

pub(crate) use command_and_control::{check_doh_dot_connection, check_service_unusual_outbound};
pub(crate) use credential_access::check_kerberos_from_non_lsass;
pub use credential_access::evaluate_kerberos_delegation_failure;
pub use defense_evasion::evaluate_raw_volume_open;
pub(crate) use defense_evasion::{
    check_alternate_data_stream_write, check_masquerading, check_truncated_cmdline,
};
pub(crate) use execution::{check_base64_decode, check_encoded_powershell};
pub(crate) use impact::check_recovery_inhibit;
pub(crate) use impair_defenses::{
    check_event_logging_disable_exec, check_security_process_signal, check_signal_events_lost,
};
pub(crate) use indicator_removal::{
    check_log_clear_exec, check_log_file_delete, is_package_manager_comm,
};
pub use indicator_removal::{evaluate_file_set_time, evaluate_log_cleared};
pub(crate) use initial_access::check_service_write_outside_datadir;
pub(crate) use persistence::{
    check_account_creation_persistence, check_btm_launch_item_persistence, check_persistence_write,
    check_scheduled_task_persistence, check_scheduled_task_update_persistence,
    check_service_install_persistence, check_systemd_service_persistence,
};
pub(crate) use privilege_escalation::{check_ld_preload_hijack, check_proc_root_escape};
use schema::{ConnectEvent, ExecEvent, FileOpenEvent};

use crate::Alert;

/// Evaluates all stateless rules applicable to an `ExecEvent`. T1620 memfd-exec
/// (`MemfdState::check_memfd_exec`) is not among them: it now needs
/// `MemfdCreateEvent` correlation state, see that method's doc (#497).
#[must_use]
pub fn evaluate_exec(event: &ExecEvent) -> Vec<Alert> {
    check_base64_decode(event)
        .into_iter()
        .chain(check_encoded_powershell(event))
        .chain(check_masquerading(event))
        .chain(check_recovery_inhibit(event))
        .chain(check_log_clear_exec(event))
        .chain(check_event_logging_disable_exec(event))
        .chain(crate::osascript::check_osascript_password_prompt(event))
        .chain(crate::securitytool::check_security_tool_stop(event))
        .chain(crate::securitytool::check_security_tool_throttle(event))
        .chain(check_truncated_cmdline(event))
        .collect()
}

/// Evaluates all stateless rules applicable to a `FileOpenEvent`. T1053.005
/// creation ([`check_scheduled_task_persistence`]) is not among them: one
/// registration arrives twice (4698 and 106), so `RuleState::on_file_open`
/// reports it, deduplicated (#422). Neither is T1190
/// ([`check_service_write_outside_datadir`]): it needs the pid's process name,
/// which only `RuleState` can resolve (#498 review).
#[must_use]
pub fn evaluate_file_open(event: &FileOpenEvent) -> Vec<Alert> {
    check_persistence_write(event)
        .into_iter()
        .chain(check_proc_root_escape(event))
        .chain(check_scheduled_task_update_persistence(event))
        .chain(check_service_install_persistence(event))
        .chain(check_account_creation_persistence(event))
        .chain(check_systemd_service_persistence(event))
        .chain(check_btm_launch_item_persistence(event))
        .chain(check_alternate_data_stream_write(event))
        .chain(crate::securitytool::check_security_tool_cgroup_write(event))
        .collect()
}

/// Evaluates all stateless rules applicable to a `FileDeleteEvent`.
#[must_use]
pub fn evaluate_file_delete(event: &schema::FileDeleteEvent) -> Vec<Alert> {
    check_log_file_delete(event).into_iter().collect()
}

/// Evaluates all stateless rules applicable to a `SignalEvent`.
#[must_use]
pub fn evaluate_signal(event: &schema::SignalEvent) -> Vec<Alert> {
    check_security_process_signal(event)
        .into_iter()
        .chain(check_signal_events_lost(event))
        .collect()
}

/// Evaluates all stateless rules applicable to a `ConnectEvent`.
#[must_use]
pub fn evaluate_connect(event: &ConnectEvent) -> Vec<Alert> {
    check_service_unusual_outbound(event)
        .into_iter()
        .chain(check_doh_dot_connection(event))
        .chain(check_kerberos_from_non_lsass(event))
        .collect()
}
