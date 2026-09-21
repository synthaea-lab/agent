//! # sensor-linux-audit
//!
//! Linux fallback sensor for hosts where eBPF is unavailable or restricted (old kernels,
//! lockdown mode, some container hosts). Sources: audit netlink (execve, connect),
//! fanotify (file events). Reduced fidelity versus the eBPF sensor; the conformance
//! suite records exactly what is lost.

mod classify;
mod normalize;
mod parse;

#[cfg(target_os = "linux")]
mod sensor;
#[cfg(target_os = "linux")]
mod socket;

pub use classify::{AuditEvent, classify};
pub use normalize::{connect_event, exec_event};
pub use parse::{AuditRecord, parse_audit_message};
#[cfg(target_os = "linux")]
pub use sensor::AuditSensor;
#[cfg(target_os = "linux")]
pub use socket::{AuditError, AuditSocket};
