//! Owned Rust mirror of the shim's flat socket records — cross-platform on
//! purpose so [`crate::normalize`] is unit-testable on any host (the same
//! raw/normalize split as the crate's macOS siblings).

use std::net::SocketAddr;

/// TCP state of a snapshotted socket, as the shim classified it (the raw
/// `TCPS_*` values never cross into Rust).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    /// `TCPS_LISTEN`: the only state that produces an event today.
    Listen,
    /// `TCPS_ESTABLISHED`.
    Established,
    /// Any other TCP state (`SYN_SENT`, `TIME_WAIT`, ...) — snapshotted but not
    /// interesting to the current consumers.
    Other,
}

/// One TCP socket from a snapshot, attributed to the process whose fd table
/// it was found in. Unlike the Linux netlink sibling there is no inode join —
/// the libproc walk is per-process, so attribution (pid, ppid, uid/gid,
/// executable path) comes with the socket. A listener shared across forked
/// workers therefore appears once **per holding process**, which is the
/// attribution consumers want anyway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketSnapshotEntry {
    /// Process holding the socket in its fd table.
    pub pid: u32,
    /// Parent of that process (`pbi_ppid`).
    pub ppid: u32,
    /// Effective uid of the owning process.
    pub uid: u32,
    /// Effective gid of the owning process (`pbi_gid`).
    pub gid: u32,
    /// Executable path; `None` when unresolvable (process died mid-walk).
    pub process_path: Option<String>,
    /// Local address and port (`insi_laddr`/`insi_lport`).
    pub local: SocketAddr,
    /// Peer address and port (`insi_faddr`/`insi_fport`). No consumer reads it today: only
    /// `Listen` entries become events, and they use `local`.
    pub remote: SocketAddr,
    /// TCP state as the shim classified it.
    pub state: SocketState,
}
