//! # sensor-windows-sockets
//!
//! Probe-free socket-table snapshots on Windows (issue #366) — the sibling of
//! `sensor-linux-netlink`'s `sock_diag` path (#92) and `sensor-macos-sockets`
//! (#358). It gives Windows the LISTENER-DRIFT rule the other two platforms
//! already have: ETW's Kernel-Network provider reports connects and sends, but
//! nothing says "this process is now accepting connections on port N".
//!
//! Mechanism: `GetExtendedTcpTable` with `TCP_TABLE_OWNER_PID_LISTENER`, and
//! `GetExtendedUdpTable` with `UDP_TABLE_OWNER_PID` (issue #676 — UDP has no
//! "listener" filter, so every bound endpoint comes back, noise included;
//! see the `snapshot` function's own doc comment, Windows-only so not linked
//! here), each once for IPv4 and once for IPv6, joined to one `Toolhelp32`
//! process snapshot for the parent pid and executable name. Unprivileged:
//! both tables are world-readable; only the owner attribution of protected
//! processes can come back empty, and it is then reported empty, never
//! guessed.
//!
//! Snapshot semantics are [`schema::ListenPortEvent`]'s own: poll-time
//! timestamps, short-lived listeners between polls invisible, detection value in
//! the drift across snapshots. Only listeners are queried — connections are the
//! ETW stream's job, and a poll echo would double-count.
//!
//! Like its Linux/macOS siblings there is no [`schema::sensor::Sensor`]
//! implementation — `agent::commands::windows` seeds the listener baseline from
//! one startup snapshot and runs the poll loop beside the ETW and Event Log
//! sensors.

pub mod normalize;
pub mod raw;

#[cfg(windows)]
mod snapshot;
pub use normalize::listen_port_event;
pub use raw::ListenerEntry;
#[cfg(windows)]
pub use snapshot::{listen_port_events, snapshot};

/// Errors from the snapshot path.
#[derive(Debug, thiserror::Error)]
pub enum SocketsError {
    /// `GetExtendedTcpTable` or `GetExtendedUdpTable` failed for one address
    /// family (Win32 error code). A failed process snapshot is not an error —
    /// entries then carry no attribution beyond the pid.
    #[error("GetExtended{protocol}Table failed for {family} (win32 error {code})")]
    Table {
        /// `"Tcp"` or `"Udp"`.
        protocol: &'static str,
        /// `"IPv4"` or `"IPv6"`.
        family: &'static str,
        /// The Win32 error code returned.
        code: u32,
    },
}
