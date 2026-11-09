//! # sensor-macos-sockets
//!
//! Listening-TCP-socket snapshots on macOS through a libproc walk in a C shim,
//! the one macOS source that needs no entitlement. Each entry carries pid,
//! real ppid, uid/gid and executable path. Only listeners become
//! [`schema::ListenPortEvent`]s: connections come from the Network Extension
//! flow stream. There is no [`schema::sensor::Sensor`] implementation; the
//! agent polls `snapshot`. See `docs/sensors/macos/sockets.md`.

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
