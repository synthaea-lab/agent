//! # sensor-windows-sockets
//!
//! Listening-socket snapshots on Windows for the LISTENER-DRIFT rule: ETW's
//! Kernel-Network provider reports connects and sends, never "this process now
//! accepts connections on port N". `GetExtendedTcpTable` (listeners) and
//! `GetExtendedUdpTable` (every bound endpoint, filtered by
//! [`is_drift_relevant`]), each for IPv4 and IPv6, are joined to one
//! `Toolhelp32` snapshot for the parent pid and image. Both tables are
//! world-readable; an owner that cannot be attributed is reported empty, never
//! guessed.
//!
//! There is no [`schema::sensor::Sensor`] implementation: the agent polls
//! `snapshot`. See `docs/sensors/windows/sockets.md`.

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
