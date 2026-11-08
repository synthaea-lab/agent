//! # sensor-windows-sockets
//!
//! Probe-free socket-table snapshots on Windows (issue #366) — the sibling of
//! `sensor-linux-netlink`'s `sock_diag` path (#92) and `sensor-macos-sockets`
//! (#358). It gives Windows the LISTENER-DRIFT rule the other two platforms
//! already have: ETW's Kernel-Network provider reports connects and sends, but
//! nothing says "this process is now accepting connections on port N".
//!
//! Mechanism: `GetExtendedTcpTable` with `TCP_TABLE_OWNER_PID_LISTENER`, and
//! `GetExtendedUdpTable` with `UDP_TABLE_OWNER_PID` (<https://github.com/synthaea-lab/agent/issues/40> — UDP has no
//! "listener" filter, so every bound endpoint comes back; the agent's path
//! drops the ones on an ephemeral port, see [`is_drift_relevant`]),
//! each once for IPv4 and once for IPv6, joined to one `Toolhelp32`
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
pub use raw::{EPHEMERAL_UDP_PORTS, ListenerEntry, is_drift_relevant};
#[cfg(windows)]
pub use snapshot::{listen_port_events_for_drift, snapshot, snapshot_for_drift};

/// Which IP Helper table a [`SocketsError::Table`] failure came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// `GetExtendedTcpTable`.
    Tcp,
    /// `GetExtendedUdpTable`.
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Protocol::Tcp => "Tcp",
            Protocol::Udp => "Udp",
        })
    }
}

/// Errors from the snapshot path.
#[derive(Debug, thiserror::Error)]
pub enum SocketsError {
    /// `GetExtendedTcpTable` or `GetExtendedUdpTable` failed for one address
    /// family (Win32 error code). A failed process snapshot is not an error —
    /// entries then carry no attribution beyond the pid.
    #[error("GetExtended{protocol}Table failed for {family} (win32 error {code})")]
    Table {
        /// Which table — `GetExtendedTcpTable` or `GetExtendedUdpTable`.
        protocol: Protocol,
        /// `"IPv4"` or `"IPv6"`.
        family: &'static str,
        /// The Win32 error code returned.
        code: u32,
    },
}
