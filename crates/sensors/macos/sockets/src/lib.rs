//! # sensor-macos-sockets
//!
//! Probe-free socket-table snapshots on macOS (issue #358) — the sibling of
//! `sensor-linux-netlink`'s `sock_diag` path (#92), and the one macOS source
//! that needs **no entitlement**: it delivers listening-port telemetry and the
//! LISTENER-DRIFT baseline on hosts where the `EndpointSecurity` grant hasn't
//! landed yet.
//!
//! Mechanism: a libproc walk (`proc_listpids` → per-pid fd tables →
//! `PROC_PIDFDSOCKETINFO`), done in a C shim compiled against the SDK's own
//! headers — `socket_fdinfo` is a union-heavy struct whose layout is exactly
//! what this workspace never transcribes into Rust by hand (the
//! `sensor-macos` ES shim set the precedent). Unlike the Linux inode join,
//! attribution is direct: the walk is per-process, so pid, **real ppid**,
//! uid/gid and executable path ride every entry.
//!
//! Snapshot semantics are [`schema::ListenPortEvent`]'s own: poll-time
//! timestamps, short-lived listeners between polls invisible, detection value
//! in the drift across snapshots. Established sockets are snapshotted (for
//! callers that want the table) but deliberately produce no event — the NE
//! flow stream (#33) is the connection source, and a poll echo would
//! double-count (the same documented gap as the Linux crate).
//!
//! Like its poll/tail siblings there is no [`schema::sensor::Sensor`]
//! implementation — `agent::commands::macos` seeds the listener baseline from
//! one startup snapshot and runs the poll loop alongside the other sensors.

pub mod normalize;
pub mod raw;

#[cfg(target_os = "macos")]
mod snapshot;
pub use normalize::listen_port_event;
pub use raw::{SocketSnapshotEntry, SocketState};
#[cfg(target_os = "macos")]
pub use snapshot::{listen_port_events, snapshot};

/// Errors from the snapshot path.
#[derive(Debug, thiserror::Error)]
pub enum SocketsError {
    /// The initial pid enumeration failed (shim return code) — per-process
    /// failures are silent skips by design, this is the walk not starting at
    /// all.
    #[error("socket-table snapshot failed (libproc pid enumeration, rc = {0})")]
    Snapshot(i32),
}
