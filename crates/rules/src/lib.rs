//! # rules
//!
//! Deterministic rule engine: hard-coded detections, one function per targeted ATT&CK
//! technique. Two categories, one module each:
//! - `stateless` — a single event evaluated at a time (`check_*`, `evaluate_*`);
//! - `state` — the correlation rules ([`RuleState`]: download followed by execution,
//!   web server → shell lineage, SELF-SPAWN, PARENT-SUSPECT, LOLBIN, BEACON), which
//!   need a sliding history of recent events.
//!
//! Migrated from `old/crates/synthaea-rules`; the false-positive exclusion lists carry
//! dated lab observations — treat them as data with provenance, not tunable noise.

mod exclusions;
mod ld_trust;
mod sliding;
mod state;
mod stateless;

pub use state::RuleState;
#[cfg(test)]
pub(crate) use stateless::{
    check_account_creation_persistence, check_base64_decode, check_btm_launch_item_persistence,
    check_encoded_powershell, check_ld_preload_hijack, check_log_clear_exec, check_log_file_delete,
    check_masquerading, check_persistence_write, check_proc_root_escape, check_recovery_inhibit,
    check_scheduled_task_persistence, check_scheduled_task_update_persistence,
    check_security_process_signal, check_service_install_persistence,
    check_systemd_service_persistence,
};
// The contract is the two dispatchers — callers (agent) route every event
// through them. The individual checks are implementation detail, re-exported
// crate-internally for the tests under `src/tests/`.
pub use stateless::{evaluate_exec, evaluate_file_delete, evaluate_file_open, evaluate_signal};

#[derive(Debug, Clone)]
pub struct Alert {
    /// ATT&CK identifier of the detected technique.
    pub technique: &'static str,
    pub message: String,
}

/// The write-intent predicate and its `O_*` constants now live in `schema`
/// (the one definition — see `schema::has_write_intent`'s doc for the history
/// of the five drifted copies). Re-exported so this crate's public surface is
/// unchanged: `agent`'s protected-resource monitoring (#71) calls it as
/// `rules::has_write_intent`.
pub use schema::has_write_intent;
#[cfg(test)]
pub(crate) use schema::{O_CREAT, O_WRONLY};

#[cfg(test)]
mod tests;
