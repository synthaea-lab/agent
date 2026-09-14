//! # sensor-linux-netlink
//!
//! Kernel netlink families as a supplementary, zero-probe source:
//! - `sock_diag` — periodic socket-table snapshots (listening/established with
//!   inode→pid join): listen-port telemetry and drift detection without a probe.
//! - `nfnetlink conntrack` — flow accounting (bytes/packets/duration per flow),
//!   giving beacon detection volume/periodicity features events alone lack.
//! - proc connector — fork/exec/exit notifications as a cheap cross-check for the
//!   eBPF stream (a gap between the two is itself a tamper signal).
//!
//! No special kernel config; runs where eBPF cannot; complements, never replaces,
//! the probe-based sensors.
//!
//! **Status (issue #92, foundation):** `sock_diag` is done — [`snapshot`] queries
//! TCP listening/established sockets (IPv4 + IPv6) via a hand-rolled
//! `NETLINK_SOCK_DIAG` client ([`wire`]/[`socket`]) and joins each one to its
//! owning PID(s) by scanning `/proc` ([`proc_join`]), the same technique `ss`/
//! `lsof` use. Verified against this dev machine's real kernel — no root needed
//! (confirmed empirically: `sock_diag` for TCP works unprivileged, unlike
//! conntrack below).
//!
//! **conntrack is also done** — [`conntrack_socket::dump`] queries the kernel's
//! conntrack table (IPv4 + IPv6) over `NETLINK_NETFILTER`/`ctnetlink`
//! ([`conntrack_attrs`]/[`conntrack_socket`]), decoding each flow's 5-tuple
//! (both directions), status, timeout, and packet/byte accounting when the
//! kernel provides it. This is the recursive `nlattr` tree (`CTA_TUPLE_ORIG` ->
//! `CTA_TUPLE_IP` -> `CTA_IP_V4_SRC`) that made conntrack "a full netlink
//! sub-protocol of its own" rather than a `sock_diag`-sized job — confirmed
//! against a real capture on this dev machine byte for byte before being
//! pinned into tests. Accounting (`CTA_COUNTERS_*`) requires
//! `net.netfilter.nf_conntrack_acct=1` on the target kernel — off by default,
//! confirmed empirically (no counters attribute appears at all until it is
//! turned on) — see [`conntrack_socket`]'s doc. Unprivileged reachability of
//! conntrack is not characterized (every capture here ran as root).
//!
//! **`CTA_PROTOINFO`'s TCP state is also decoded** — [`TcpState`], from
//! `CTA_PROTOINFO` -> `CTA_PROTOINFO_TCP` -> `CTA_PROTOINFO_TCP_STATE`, a
//! third level of `nlattr` nesting beyond the tuple's two. Only present for
//! TCP flows — confirmed against a real capture on this dev machine: UDP
//! dump entries carry no `CTA_PROTOINFO` attribute at all. The sibling
//! `CTA_PROTOINFO_TCP_WSCALE_*`/`_FLAGS_*` sub-attributes are decoded on the
//! wire but not surfaced — not needed for beacon volume/periodicity
//! features, same scoping call as `CTA_STATUS`'s individual `IPS_*` bits.
//!
//! **proc connector** (`NETLINK_CONNECTOR`, fork/exec/exit) is a separate,
//! independent foundation slice — see PR #179, not part of this one.
//!
//! **proc connector is also done** — [`ProcEventSubscription`] subscribes to the
//! kernel's `CN_IDX_PROC` multicast group over `NETLINK_CONNECTOR`
//! ([`proc_events`]/[`proc_socket`]) and decodes fork/exec/exit broadcasts. Root/
//! `CAP_NET_ADMIN`-only (unlike `sock_diag`): confirmed against this dev
//! machine that the kernel rejects the subscribe with `EPERM` for an
//! unprivileged caller, reported back as a proper `NetlinkError`, not a panic.
//!
//! Deliberately **not** here yet:
//! - No `schema::Event` variant or [`schema::sensor::Sensor`] implementation
//!   for sock_diag, conntrack, or proc connector: volume/periodicity beacon
//!   features and the eBPF cross-check both need `crates/correlator`/
//!   `crates/tamper` wiring that doesn't exist for this data yet — nothing to
//!   push into today.
//! - UDP sockets — `sock_diag` supports them, but "listen/established" (this
//!   issue's own wording) is TCP-state terminology; UDP would need its own
//!   category, not a states-mask filter.
//! - Periodic re-snapshotting / drift detection between snapshots — [`snapshot`]
//!   is a one-shot query; a caller decides the cadence. No lab VM here to
//!   validate the issue's "listening-port drift" done-when item against.
//! - `PROC_EVENT_UID`/`_GID`/`_SID`/`_PTRACE`/`_COMM`/`_COREDUMP` — decoded as
//!   [`ProcEvent::Other`] rather than their own variants; nothing in the eBPF
//!   stream to cross-check them against yet (see [`proc_events`]).

mod conntrack_attrs;
mod proc_events;
mod proc_join;
mod wire;

#[cfg(target_os = "linux")]
mod conntrack_socket;
#[cfg(target_os = "linux")]
mod proc_socket;
#[cfg(target_os = "linux")]
mod socket;

use std::net::SocketAddr;

pub use conntrack_attrs::{ConntrackFlow, FlowCounters, FlowTuple, TcpState};
#[cfg(target_os = "linux")]
pub use conntrack_socket::dump as dump_conntrack;
pub use proc_events::ProcEvent;
#[cfg(target_os = "linux")]
pub use proc_socket::ProcEventSubscription;
#[cfg(target_os = "linux")]
pub use socket::NetlinkError;
pub use wire::{DiagMsg, TCP_ESTABLISHED, TCP_LISTEN};

/// A TCP socket's state, as reported by `sock_diag`. This crate only ever
/// requests [`TCP_ESTABLISHED`]/[`TCP_LISTEN`] (see the crate doc), so `Other` is
/// purely defensive — a kernel returning something outside the requested mask
/// would be a bug worth seeing, not a panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    Established,
    Listen,
    Other(u8),
}

impl From<u8> for SocketState {
    fn from(raw: u8) -> Self {
        match raw {
            TCP_ESTABLISHED => Self::Established,
            TCP_LISTEN => Self::Listen,
            other => Self::Other(other),
        }
    }
}

/// One socket from a [`snapshot`], joined to the PID(s) holding it open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketSnapshotEntry {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: SocketState,
    /// UID of the socket's owning process, from the kernel — independent of the
    /// `/proc` join below, and still populated even when that join finds nothing.
    pub uid: u32,
    pub inode: u32,
    /// PIDs whose open file descriptors point at this socket's inode. Usually
    /// one; more than one when a listener is shared across forked workers before
    /// `exec`; empty when the owning process is in another user's `/proc/<pid>/fd`
    /// (unreadable without root) or already exited between the two queries.
    pub pids: Vec<u32>,
}

impl From<DiagMsg> for SocketSnapshotEntry {
    fn from(msg: DiagMsg) -> Self {
        Self {
            local: SocketAddr::new(msg.local, msg.local_port),
            remote: SocketAddr::new(msg.remote, msg.remote_port),
            state: SocketState::from(msg.state),
            uid: msg.uid,
            inode: msg.inode,
            pids: Vec::new(),
        }
    }
}

/// Takes one snapshot of TCP listening/established sockets, joined to their
/// owning PID(s) where `/proc` permissions allow it.
///
/// # Errors
///
/// See [`NetlinkError`] — the query fails as a whole (rather than returning a
/// partial list) if the kernel can't be reached at all.
#[cfg(target_os = "linux")]
pub fn snapshot() -> Result<Vec<SocketSnapshotEntry>, NetlinkError> {
    let states = (1u32 << TCP_ESTABLISHED) | (1u32 << TCP_LISTEN);
    let msgs = socket::query_tcp_sockets(states)?;
    let inode_pids = proc_join::inode_to_pids();

    Ok(msgs
        .into_iter()
        .map(|msg| {
            let mut entry = SocketSnapshotEntry::from(msg);
            entry.pids = inode_pids
                .get(&u64::from(entry.inode))
                .cloned()
                .unwrap_or_default();
            entry
        })
        .collect())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn snapshot_runs_end_to_end_against_the_real_kernel_and_proc() {
        let entries = snapshot().expect("unprivileged snapshot must succeed");
        // Nondeterministic which sockets exist right now — the properties that
        // must hold regardless: every entry has a real state (not garbage from a
        // parsing bug) and, when a PID was found, it's still a plausible PID
        // (nonzero — PID 0 is not a real process).
        for entry in &entries {
            assert!(!matches!(entry.state, SocketState::Other(_)));
            for &pid in &entry.pids {
                assert_ne!(pid, 0);
            }
        }
    }

    #[test]
    fn socket_state_from_u8_covers_the_requested_states_and_falls_back() {
        assert_eq!(SocketState::from(TCP_ESTABLISHED), SocketState::Established);
        assert_eq!(SocketState::from(TCP_LISTEN), SocketState::Listen);
        assert_eq!(SocketState::from(7), SocketState::Other(7));
    }
}
