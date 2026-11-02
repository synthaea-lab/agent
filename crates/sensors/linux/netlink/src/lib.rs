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
//! **`schema::Event` wiring, for listening sockets:** [`listen_port_events`] maps
//! a [`snapshot`] to [`schema::Event::ListenPort`] (`schema` `SCHEMA_VERSION` 10 ->
//! 11) — the mapping issue #92's "listening-port drift" done-when item needs.
//! [`proc_meta`] resolves the `comm`/`ppid`/`gid` a [`schema::EventMeta`] needs
//! from `/proc/<pid>/status` (uid comes straight from the kernel via `sock_diag` —
//! see [`SocketSnapshotEntry::uid`]'s doc); [`normalize`] does the pure
//! entry-plus-proc-info -> `Event` mapping, same split as `sensor-linux`'s own
//! `normalize` module. A joined PID that can't be resolved (exited between the two
//! `/proc` reads, or another user's process without permission) is silently
//! skipped rather than emitted with fabricated metadata — a per-poll, best-effort
//! sample, not a guaranteed-complete one. Established sockets aren't mapped (no
//! drift semantics for them, see [`normalize::listen_port_event`]'s doc); this
//! crate still doesn't decide the polling cadence or run the drift comparison
//! itself — a caller (not yet written) calls [`listen_port_events`] repeatedly and
//! diffs consecutive results. No lab VM here to validate that live, same gap as
//! before this wiring existed.
//!
//! **`schema::Event` wiring, for conntrack flows:** [`conntrack_flow_events`] maps
//! a [`dump_conntrack`] dump to [`schema::Event::NetworkFlow`] (`schema`
//! `SCHEMA_VERSION` 11 -> 12) — the mapping issue #92's "conntrack features reach
//! the correlator" done-when item needs. A conntrack entry carries no PID at all
//! from the kernel, unlike `sock_diag`'s inode->pid join — attribution instead
//! joins the flow's tuple against a concurrent [`snapshot`]'s
//! `local`/`remote`/state, see [`normalize::conntrack_flow_events_for`]'s doc for
//! the two-orientation match this needs (outbound vs. locally-accepted) and why
//! `orig`/`reply`'s byte counters must be swapped for one of them relative to
//! "sent"/"received". TCP only — [`snapshot`] never queries UDP sockets, so a UDP
//! flow can never find a match (checked explicitly, not left to chance). A flow
//! nothing could attribute (already closed, permission-denied `/proc/<pid>/fd`,
//! or genuinely no matching local socket) produces no event, same discipline as
//! [`listen_port_events`]. Two kernel queries taken back to back, not atomically
//! — see [`conntrack_flow_events`]'s doc. Still not here: `crates/correlator`
//! wiring (below) and periodic polling/the beacon-scenario validation itself — no
//! lab VM here to generate one live.
//!
//! Deliberately **not** here yet:
//! - `schema::Event` wiring for the proc connector (the eBPF cross-check): the
//!   issue's role for it is a *tamper* signal (divergence from the eBPF stream),
//!   which may not want to be a `schema::Event` at all rather than an internal
//!   `crates/tamper` comparison — not a call this Linux-only slice should make
//!   alone.
//! - `crates/correlator` wiring: [`listen_port_events`]/[`conntrack_flow_events`]
//!   produce `schema::Event`s, but nothing in this crate hands them to
//!   `correlator::EventBus` — that's the caller's job (the same one that would own
//!   the polling cadence above), and no such caller exists yet for this crate's
//!   data.
//! - UDP in the agent: [`snapshot_udp`]/[`listen_port_events_udp`] exist (a bound,
//!   unconnected UDP socket is `TCP_CLOSE` in `sock_diag`, so it is its own
//!   [`SocketState::Unconnected`], not a states-mask variant of `Listen`), but
//!   they report every bound socket, ephemeral client ports included. The noise
//!   filter issue #676 asks for needs a real capture; until it exists the agent
//!   keeps calling the TCP-only [`listen_port_events`].
//! - Periodic re-snapshotting / drift detection between snapshots — [`snapshot`]
//!   is a one-shot query; a caller decides the cadence. No lab VM here to
//!   validate the issue's "listening-port drift" done-when item against.
//! - `PROC_EVENT_UID`/`_GID`/`_SID`/`_PTRACE`/`_COMM`/`_COREDUMP` — decoded as
//!   [`ProcEvent::Other`] rather than their own variants; nothing in the eBPF
//!   stream to cross-check them against yet (see [`proc_events`]).

// The pure codec/normalize modules compile on every OS so their unit tests run
// anywhere, but their only callers are the linux-gated socket modules below —
// off-Linux, the lib target legitimately has unused items (same idiom as
// `agent/src/health.rs`). The lint stays live on Linux, where dead code is real.
mod conntrack_attrs;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod normalize;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod proc_events;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod proc_join;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod proc_meta;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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
pub use wire::{DiagMsg, IPPROTO_TCP, IPPROTO_UDP, TCP_CLOSE, TCP_ESTABLISHED, TCP_LISTEN};

/// A socket's state, as reported by `sock_diag`. This crate only ever requests
/// [`TCP_ESTABLISHED`]/[`TCP_LISTEN`] for TCP and [`TCP_CLOSE`] for UDP (see the
/// crate doc), so `Other` is purely defensive — a kernel returning something outside the requested mask
/// would be a bug worth seeing, not a panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    Established,
    Listen,
    /// A UDP socket bound to a local port and not `connect()`ed: the datagram
    /// equivalent of [`Self::Listen`] (`sock_diag` reports it as `TCP_CLOSE`).
    Unconnected,
    Other(u8),
}

impl From<u8> for SocketState {
    fn from(raw: u8) -> Self {
        match raw {
            TCP_ESTABLISHED => Self::Established,
            TCP_LISTEN => Self::Listen,
            TCP_CLOSE => Self::Unconnected,
            other => Self::Other(other),
        }
    }
}

/// One socket from a [`snapshot`], joined to the PID(s) holding it open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketSnapshotEntry {
    /// `IPPROTO_TCP` or `IPPROTO_UDP`: the dump this entry came from.
    pub protocol: u8,
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
    /// A TCP entry: [`snapshot`] is the TCP dump. [`snapshot_udp`] uses
    /// [`SocketSnapshotEntry::from_diag`] with `IPPROTO_UDP`.
    fn from(msg: DiagMsg) -> Self {
        Self::from_diag(msg, IPPROTO_TCP)
    }
}

impl SocketSnapshotEntry {
    /// An entry from one `sock_diag` dump message; `protocol` is the `IPPROTO_*` that
    /// dump was for, since the message itself does not carry it.
    #[must_use]
    pub fn from_diag(msg: DiagMsg, protocol: u8) -> Self {
        Self {
            protocol,
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

/// Takes one snapshot of the bound, unconnected UDP sockets (IPv4 and IPv6),
/// joined to their owning PID(s) like [`snapshot`].
///
/// This is every bound UDP socket, not only servers: DNS client sockets, QUIC and
/// media sockets on ephemeral ports all appear. Issue #676 asks for a noise filter
/// calibrated on a real capture, which does not exist yet, so nothing in the agent
/// calls this; it is the unfiltered mechanism the filter will sit in front of, same
/// split as `sensor-windows-sockets`.
///
/// # Errors
///
/// See [`NetlinkError`] — same failure mode as [`snapshot`].
#[cfg(target_os = "linux")]
pub fn snapshot_udp() -> Result<Vec<SocketSnapshotEntry>, NetlinkError> {
    let msgs = socket::query_sockets(IPPROTO_UDP, 1u32 << TCP_CLOSE)?;
    let inode_pids = proc_join::inode_to_pids();

    Ok(msgs
        .into_iter()
        .map(|msg| {
            let mut entry = SocketSnapshotEntry::from_diag(msg, IPPROTO_UDP);
            entry.pids = inode_pids
                .get(&u64::from(entry.inode))
                .cloned()
                .unwrap_or_default();
            entry
        })
        .collect())
}

/// Takes one [`snapshot_udp`] and maps every bound UDP socket to a
/// [`schema::Event::ListenPort`] with `protocol` `IPPROTO_UDP`, attributed like
/// [`listen_port_events`]. Unfiltered, see [`snapshot_udp`].
///
/// # Errors
///
/// See [`NetlinkError`] — same failure mode as [`snapshot_udp`], which this wraps.
#[cfg(target_os = "linux")]
pub fn listen_port_events_udp(timestamp_ns: u64) -> Result<Vec<schema::Event>, NetlinkError> {
    let entries = snapshot_udp()?;
    Ok(entries
        .iter()
        .flat_map(|entry| {
            entry.pids.iter().filter_map(move |&pid| {
                let proc = proc_meta::resolve(pid)?;
                normalize::listen_port_event(entry, pid, &proc, timestamp_ns)
            })
        })
        .collect())
}

/// Takes one [`snapshot`] and maps every listening socket to a
/// [`schema::Event::ListenPort`], attributed to each PID that holds it open (see
/// [`SocketSnapshotEntry::pids`]'s doc — usually one, occasionally several for a
/// pre-`exec` shared listener, none when unattributable). `timestamp_ns` is
/// stamped on every event as the snapshot time (see
/// [`schema::ListenPortEvent`]'s doc on what that does and doesn't mean).
///
/// Established sockets and unattributed listeners produce no event — see the
/// crate doc's "`schema::Event` wiring" section for why that's a deliberate,
/// documented gap rather than a bug.
///
/// # Errors
///
/// See [`NetlinkError`] — same failure mode as [`snapshot`], which this wraps.
#[cfg(target_os = "linux")]
pub fn listen_port_events(timestamp_ns: u64) -> Result<Vec<schema::Event>, NetlinkError> {
    let entries = snapshot()?;
    Ok(entries
        .iter()
        .flat_map(|entry| {
            entry.pids.iter().filter_map(move |&pid| {
                let proc = proc_meta::resolve(pid)?;
                normalize::listen_port_event(entry, pid, &proc, timestamp_ns)
            })
        })
        .collect())
}

/// Dumps the kernel's conntrack table and a `sock_diag` snapshot, and maps every
/// TCP flow the two can jointly attribute to a [`schema::Event::NetworkFlow`] —
/// the mapping issue #92's "conntrack features reach the correlator" done-when
/// item needs (`schema` `SCHEMA_VERSION` 11 -> 12). See
/// [`normalize::conntrack_flow_events_for`] for the attribution join (why a flow
/// needs a concurrent `sock_diag` snapshot at all) and what it does and doesn't
/// cover (TCP only, UDP flows never match). `timestamp_ns` is stamped on every
/// event as the poll time, same caveat as [`listen_port_events`].
///
/// Two independent kernel queries ([`dump_conntrack`] and [`snapshot`]) are taken
/// back to back, not atomically — a flow that closes or a socket that's replaced
/// between the two is simply unattributed this poll rather than mismatched, since
/// [`normalize::conntrack_flow_events_for`]'s join requires an exact tuple match.
///
/// # Errors
///
/// See [`NetlinkError`] — either query failing as a whole fails this call; a flow
/// this crate merely couldn't *attribute* is not an error (see above).
#[cfg(target_os = "linux")]
pub fn conntrack_flow_events(timestamp_ns: u64) -> Result<Vec<schema::Event>, NetlinkError> {
    let flows = dump_conntrack()?;
    let sockets = snapshot()?;
    Ok(flows
        .iter()
        .flat_map(|flow| {
            normalize::conntrack_flow_events_for(flow, &sockets, proc_meta::resolve, timestamp_ns)
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
        assert_eq!(SocketState::from(TCP_CLOSE), SocketState::Unconnected);
        assert_eq!(SocketState::from(2), SocketState::Other(2));
    }

    /// TCP and UDP bound on one address and port, so each path is checked against the
    /// other's socket rather than against a port number another process may share
    /// (#1057 fixed the same flake in the Windows collector). Retries when the UDP bind
    /// finds the number taken.
    fn tcp_and_udp_on_one_port() -> (
        std::net::TcpListener,
        std::net::UdpSocket,
        std::net::SocketAddr,
    ) {
        for _ in 0..16 {
            let listener =
                std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral listener");
            let addr = listener.local_addr().expect("local addr");
            if let Ok(socket) = std::net::UdpSocket::bind(addr) {
                return (listener, socket, addr);
            }
        }
        panic!("no 127.0.0.1 port free for both TCP and UDP after 16 tries");
    }

    /// The protocols of this process's listen-port events at `addr`.
    fn protocols_at(events: &[schema::Event], addr: std::net::SocketAddr) -> Vec<u8> {
        let me = std::process::id();
        events
            .iter()
            .filter_map(|event| match event {
                schema::Event::ListenPort(l)
                    if l.local_addr == addr.ip()
                        && l.local_port == addr.port()
                        && l.meta.pid == me =>
                {
                    Some(l.protocol)
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_bound_udp_socket_is_seen_as_a_udp_listener_owned_by_this_process() {
        // The `ncat -u -l` done-when item, with this test process as the listener, and a
        // TCP listener on the same address and port that only the TCP path may report.
        let (_listener, _socket, addr) = tcp_and_udp_on_one_port();
        let me = std::process::id();

        let entries = snapshot_udp().expect("unprivileged UDP snapshot must succeed");
        let ours: Vec<_> = entries.iter().filter(|e| e.local == addr).collect();
        assert_eq!(ours.len(), 1, "one UDP entry at {addr}: {ours:?}");
        assert_eq!(ours[0].protocol, IPPROTO_UDP);
        assert_eq!(ours[0].state, SocketState::Unconnected);
        assert!(
            ours[0].pids.contains(&me),
            "pids {:?} must include {me}",
            ours[0].pids
        );

        let udp = listen_port_events_udp(42).expect("must succeed, same as snapshot_udp()");
        assert_eq!(protocols_at(&udp, addr), [IPPROTO_UDP]);
        // The TCP path sees the TCP listener there and never the UDP socket: that is the
        // whole reason for the protocol field.
        let tcp = listen_port_events(42).expect("TCP events");
        assert_eq!(protocols_at(&tcp, addr), [IPPROTO_TCP]);
    }

    #[test]
    fn listen_port_events_runs_end_to_end_against_the_real_kernel_and_proc() {
        let events = listen_port_events(42).expect("must succeed, same as snapshot()");
        // Nondeterministic whether any listening socket with an attributable PID
        // exists right now — the property that must hold regardless: every event
        // this produced really is a ListenPort variant with the stamped
        // timestamp and a nonzero PID (proc_meta::resolve only ever returns
        // Some for a PID it actually read from /proc).
        for event in &events {
            let schema::Event::ListenPort(listen) = &event else {
                panic!("listen_port_events must only ever produce ListenPort events");
            };
            assert_eq!(listen.meta.timestamp_ns, 42);
            assert_ne!(listen.meta.pid, 0);
        }
    }

    #[test]
    fn conntrack_flow_events_runs_end_to_end_against_the_real_kernel_and_proc() {
        // Unlike sock_diag, conntrack's unprivileged reachability isn't
        // characterized (crate doc) — every capture this crate was built against
        // ran as root. Same EPERM-tolerant pattern as proc_socket's live test:
        // skip rather than fail when this dev environment isn't privileged.
        let events = match conntrack_flow_events(42) {
            Ok(events) => events,
            Err(NetlinkError::Kernel(errno)) if errno == libc::EPERM => {
                eprintln!("skipping: kernel rejected the conntrack dump with EPERM — needs root");
                return;
            }
            Err(e) => panic!("unexpected netlink error: {e}"),
        };
        // Nondeterministic whether any TCP flow this host both has in conntrack
        // and can attribute to a live socket exists right now — the property
        // that must hold regardless: every event produced really is a
        // NetworkFlow variant with the stamped timestamp, a nonzero PID, and
        // TCP's protocol number.
        for event in &events {
            let schema::Event::NetworkFlow(flow) = &event else {
                panic!("conntrack_flow_events must only ever produce NetworkFlow events");
            };
            assert_eq!(flow.meta.timestamp_ns, 42);
            assert_ne!(flow.meta.pid, 0);
            assert_eq!(flow.protocol, wire::IPPROTO_TCP);
        }
    }
}
