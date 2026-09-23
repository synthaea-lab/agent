//! # sensor-linux-audit
//!
//! Linux fallback sensor for hosts where eBPF is unavailable or restricted (old kernels,
//! lockdown mode, some container hosts). Source: audit netlink (execve, connect).
//! Reduced fidelity versus the eBPF sensor; the conformance suite records exactly
//! what is lost. fanotify was evaluated (see `docs/sensors/linux-telemetry-matrix.md`)
//! and not built — this crate doesn't use it despite an earlier version of this doc
//! comment implying otherwise.
//!
//! Also classifies `SELinux` AVC denials (`type=AVC`) — free telemetry, since this
//! sensor already subscribes to the whole `NETLINK_AUDIT` multicast stream for
//! execve/connect. Normalized to `schema::Event::PolicyDenial` (#297) — see
//! [`classify::AuditEvent::PolicyDenial`]'s doc for what the AVC wire shape
//! does and doesn't carry.

mod classify;
mod normalize;
mod parse;

#[cfg(target_os = "linux")]
mod sensor;
#[cfg(target_os = "linux")]
mod socket;

pub use classify::{AuditEvent, classify};
pub use normalize::{connect_event, exec_event, policy_denial_event};
pub use parse::{AuditRecord, parse_audit_message};
#[cfg(target_os = "linux")]
pub use sensor::AuditSensor;
#[cfg(target_os = "linux")]
pub use socket::{AuditError, AuditSocket};
