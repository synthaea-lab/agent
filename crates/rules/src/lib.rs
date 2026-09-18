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
mod sliding;
mod state;
mod stateless;

pub use state::RuleState;
pub use stateless::{
    check_account_creation_persistence, check_base64_decode, check_encoded_powershell,
    check_persistence_write, check_proc_root_escape, check_scheduled_task_persistence,
    check_service_install_persistence, evaluate_exec, evaluate_file_open,
};

#[derive(Debug, Clone)]
pub struct Alert {
    /// ATT&CK identifier of the detected technique.
    pub technique: &'static str,
    pub message: String,
}

// Standard POSIX open(2) flag values, stable across the Linux architectures we support
// (x86_64, aarch64). Defined locally rather than via `libc`: `FileOpenEvent::flags` is
// documented as platform-native and these Linux-path rules interpret the Linux values;
// a `libc` dependency would drag platform quirks (no `O_ACCMODE` on Windows) into a
// crate that must compile everywhere.
const O_ACCMODE: u32 = 0o3;
const O_WRONLY: u32 = 0o1;
const O_RDWR: u32 = 0o2;
pub(crate) const O_CREAT: u32 = 0o100;

/// Write intent on `open(2)` flags: write access mode, or creation.
/// Shared by the stateless rules (persistence) and the stateful ones (download history);
/// also used by `agent`'s protected-resource monitoring (#71) to separate a foreign
/// process merely reading an agent file from one attempting to modify it. Interprets
/// Linux `open(2)` flag values specifically (see the `O_*` consts above) — only
/// meaningful for `FileOpenEvent`s produced by a Linux sensor.
#[must_use]
pub fn has_write_intent(flags: u32) -> bool {
    let access_mode = flags & O_ACCMODE;
    access_mode == O_WRONLY || access_mode == O_RDWR || (flags & O_CREAT) != 0
}

#[cfg(test)]
mod tests;
