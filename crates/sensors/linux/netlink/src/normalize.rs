//! `sock_diag`/conntrack → [`schema::Event`] normalization. Pure functions, same
//! discipline as `sensor-linux`'s `normalize` module: platform-independent,
//! unit-tested directly (the platform-specific part is the snapshot/dump/`/proc`
//! reads upstream of this, not the mapping itself).
//!
//! [`listen_port_event`] covers issue #92's "listening-port drift" done-when item;
//! [`conntrack_flow_events_for`] covers its "conntrack features reach the
//! correlator" one — see that function's doc for the attribution join a conntrack
//! entry needs before it can become an event at all.

use std::net::SocketAddr;

use schema::{Event, EventMeta, ListenPortEvent, NetworkFlowEvent, User};

use crate::{
    ConntrackFlow, SocketSnapshotEntry, SocketState, proc_meta::ProcInfo, wire::IPPROTO_TCP,
};

/// Builds one [`schema::Event::ListenPort`] for `entry` attributed to `pid`, using
/// `proc` (already resolved by [`crate::proc_meta::resolve`]) for the metadata
/// `sock_diag` itself doesn't carry. `timestamp_ns` is the caller's snapshot time
/// (see [`schema::ListenPortEvent`]'s doc on what that does and doesn't mean).
///
/// Returns `None` when `entry.state` isn't [`SocketState::Listen`] — established
/// sockets have no listen-port drift semantics, so a caller iterating a full
/// snapshot can pass every entry through this function and simply skip `None`s
/// rather than pre-filtering by state itself.
#[must_use]
pub fn listen_port_event(
    entry: &SocketSnapshotEntry,
    pid: u32,
    proc: &ProcInfo,
    timestamp_ns: u64,
) -> Option<Event> {
    if entry.state != SocketState::Listen {
        return None;
    }
    Some(Event::ListenPort(ListenPortEvent {
        meta: EventMeta {
            pid,
            ppid: proc.ppid,
            // uid from the kernel (sock_diag), not /proc — see SocketSnapshotEntry's
            // doc: authoritative and race-free, unlike everything else here.
            user: User::Unix {
                uid: entry.uid,
                gid: proc.gid,
            },
            timestamp_ns,
            comm: proc.comm.clone(),
            container: None, // sock_diag has no cgroup to read this from (issue #80's
                             // technique needs an actual /proc/<pid>/cgroup read,
                             // not plumbed into this crate — a further follow-up).
        },
        local_addr: entry.local.ip(),
        local_port: entry.local.port(),
    }))
}

/// Finds the [`SocketSnapshotEntry`] `flow` belongs to, and which side of the
/// flow's tuple is the *peer* from this host's perspective.
///
/// A conntrack entry carries no PID — attribution only works by matching its
/// `orig` tuple (address/port/protocol) against a concurrent `sock_diag`
/// snapshot's [`SocketSnapshotEntry::local`]/`remote`, which does carry PIDs (via
/// the `/proc` join [`crate::snapshot`] already did). Only [`SocketState::Established`]
/// entries are checked — a `Listen` entry's `remote` is always the wildcard
/// `0.0.0.0:0`, so it can never match a real peer. Two orientations are tried
/// because `orig` records the tuple as the connection's *initiator* saw it, which
/// is this host for an outbound connection (`orig.src` = local) but the remote
/// peer for one accepted here (`orig.dst` = local) — `ctnetlink` doesn't say which,
/// so both are checked and whichever one matches a real local socket wins.
///
/// Only TCP (`IPPROTO_TCP`) flows are matched: [`crate::snapshot`] only ever
/// queries TCP sockets (see its doc), so a UDP flow could never find a real
/// match here even by coincidence — worth ruling out explicitly rather than
/// relying on that being merely unlikely.
///
/// Also returns whether `orig` runs from this host outward (`true`) or from the
/// peer inward (`false`) — [`ConntrackFlow::counters_orig`]/`counters_reply` are
/// recorded along the tuple's own direction, not "local"/"peer", so a caller
/// mapping them to `bytes_sent`/`bytes_received` must know which end `orig` starts
/// from or it reports the two swapped for every inbound (locally-accepted) flow.
fn attribute_flow<'a>(
    flow: &ConntrackFlow,
    sockets: &'a [SocketSnapshotEntry],
) -> Option<(&'a SocketSnapshotEntry, SocketAddr, bool)> {
    if flow.orig.protocol != IPPROTO_TCP {
        return None;
    }
    let (src_port, dst_port) = (flow.orig.src_port?, flow.orig.dst_port?);
    sockets.iter().find_map(|sock| {
        if sock.state != SocketState::Established {
            return None;
        }
        let outbound = sock.local.ip() == flow.orig.src
            && sock.local.port() == src_port
            && sock.remote.ip() == flow.orig.dst
            && sock.remote.port() == dst_port;
        if outbound {
            return Some((sock, sock.remote, true));
        }
        let inbound = sock.local.ip() == flow.orig.dst
            && sock.local.port() == dst_port
            && sock.remote.ip() == flow.orig.src
            && sock.remote.port() == src_port;
        inbound.then_some((sock, sock.remote, false))
    })
}

/// Builds one [`schema::Event::NetworkFlow`] per PID attributed to `flow` (see
/// [`attribute_flow`]), using `resolve` ([`crate::proc_meta::resolve`] in
/// production, injected here so the mapping stays testable without `/proc`) to
/// fill in the metadata `sock_diag`/conntrack don't carry between them. A flow
/// nothing could attribute — already torn down, or owned by another user's
/// unreadable `/proc/<pid>/fd` — produces no events, same discipline as
/// [`listen_port_event`] returning `None` rather than fabricating metadata.
#[must_use]
pub fn conntrack_flow_events_for(
    flow: &ConntrackFlow,
    sockets: &[SocketSnapshotEntry],
    resolve: impl Fn(u32) -> Option<ProcInfo>,
    timestamp_ns: u64,
) -> Vec<Event> {
    let Some((sock, peer, outbound)) = attribute_flow(flow, sockets) else {
        return Vec::new();
    };
    // orig runs local->peer for an outbound flow, peer->local for an inbound one
    // (see attribute_flow's doc) — swap which counters side is "sent" accordingly.
    let (sent, received) = if outbound {
        (flow.counters_orig, flow.counters_reply)
    } else {
        (flow.counters_reply, flow.counters_orig)
    };
    sock.pids
        .iter()
        .filter_map(|&pid| {
            let proc = resolve(pid)?;
            Some(Event::NetworkFlow(NetworkFlowEvent {
                meta: EventMeta {
                    pid,
                    ppid: proc.ppid,
                    // uid from the kernel (sock_diag), not /proc — same reasoning as
                    // listen_port_event.
                    user: User::Unix {
                        uid: sock.uid,
                        gid: proc.gid,
                    },
                    timestamp_ns,
                    comm: proc.comm.clone(),
                    container: None, // see listen_port_event's identical note.
                },
                daddr: peer.ip(),
                dport: peer.port(),
                protocol: flow.orig.protocol,
                bytes_sent: sent.map(|c| c.bytes),
                bytes_received: received.map(|c| c.bytes),
                packets_sent: sent.map(|c| c.packets),
                packets_received: received.map(|c| c.packets),
            }))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;

    fn listening_entry() -> SocketSnapshotEntry {
        SocketSnapshotEntry {
            local: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 31337),
            remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            state: SocketState::Listen,
            uid: 0,
            inode: 78967,
            pids: vec![4242],
        }
    }

    fn proc() -> ProcInfo {
        ProcInfo {
            comm: "sshd-backdoor".into(),
            ppid: 1,
            gid: 0,
        }
    }

    #[test]
    fn builds_a_listen_port_event_from_a_listening_entry() {
        let event = listen_port_event(&listening_entry(), 4242, &proc(), 1_756_900_090_000_000_000)
            .expect("a Listen-state entry must produce an event");
        let Event::ListenPort(listen) = &event else {
            panic!("expected Event::ListenPort, got {event:?}");
        };
        assert_eq!(listen.meta.pid, 4242);
        assert_eq!(listen.meta.ppid, 1);
        assert_eq!(listen.meta.comm, "sshd-backdoor");
        assert_eq!(listen.meta.user, User::Unix { uid: 0, gid: 0 });
        assert_eq!(listen.local_port, 31337);
    }

    #[test]
    fn established_entries_produce_no_event() {
        let mut entry = listening_entry();
        entry.state = SocketState::Established;
        assert!(listen_port_event(&entry, 4242, &proc(), 0).is_none());
    }

    fn v4(a: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(a))
    }

    fn resolve_map(entries: &[(u32, ProcInfo)]) -> impl Fn(u32) -> Option<ProcInfo> + '_ {
        move |pid| {
            entries
                .iter()
                .find(|(p, _)| *p == pid)
                .map(|(_, info)| info.clone())
        }
    }

    /// An outbound flow: this host (10.0.0.5:51000) connected out to a peer
    /// (203.0.113.9:443) — `orig` therefore runs local -> peer.
    fn outbound_flow() -> ConntrackFlow {
        ConntrackFlow {
            orig: crate::FlowTuple {
                src: v4([10, 0, 0, 5]),
                dst: v4([203, 0, 113, 9]),
                protocol: IPPROTO_TCP,
                src_port: Some(51000),
                dst_port: Some(443),
            },
            reply: crate::FlowTuple {
                src: v4([203, 0, 113, 9]),
                dst: v4([10, 0, 0, 5]),
                protocol: IPPROTO_TCP,
                src_port: Some(443),
                dst_port: Some(51000),
            },
            status: 0,
            timeout_secs: 0,
            mark: 0,
            id: 1,
            counters_orig: Some(crate::FlowCounters {
                packets: 9,
                bytes: 1240,
            }),
            counters_reply: Some(crate::FlowCounters {
                packets: 11,
                bytes: 8890,
            }),
            tcp_state: None,
        }
    }

    fn established_socket(pid: u32) -> SocketSnapshotEntry {
        SocketSnapshotEntry {
            local: SocketAddr::new(v4([10, 0, 0, 5]), 51000),
            remote: SocketAddr::new(v4([203, 0, 113, 9]), 443),
            state: SocketState::Established,
            uid: 0,
            inode: 99001,
            pids: vec![pid],
        }
    }

    #[test]
    fn outbound_flow_maps_orig_to_sent_and_reply_to_received() {
        let sockets = [established_socket(4242)];
        let entries = [(4242, proc())];
        let events = conntrack_flow_events_for(
            &outbound_flow(),
            &sockets,
            resolve_map(&entries),
            1_756_900_090_000_000_000,
        );
        let [Event::NetworkFlow(flow)] = events.as_slice() else {
            panic!("expected exactly one NetworkFlow event, got {events:?}");
        };
        assert_eq!(flow.meta.pid, 4242);
        assert_eq!(flow.daddr, v4([203, 0, 113, 9]));
        assert_eq!(flow.dport, 443);
        assert_eq!(flow.bytes_sent, Some(1240));
        assert_eq!(flow.bytes_received, Some(8890));
        assert_eq!(flow.packets_sent, Some(9));
        assert_eq!(flow.packets_received, Some(11));
    }

    #[test]
    fn inbound_flow_swaps_orig_and_reply_relative_to_the_local_host() {
        // Same wire flow as outbound_flow, but this host is the one that got
        // connected to (10.0.0.5:51000 is the local socket's *remote* here) —
        // orig therefore runs peer -> local, so bytes_sent must come from
        // counters_reply, not counters_orig.
        let sockets = [SocketSnapshotEntry {
            local: SocketAddr::new(v4([203, 0, 113, 9]), 443),
            remote: SocketAddr::new(v4([10, 0, 0, 5]), 51000),
            state: SocketState::Established,
            uid: 0,
            inode: 99002,
            pids: vec![9000],
        }];
        let entries = [(9000, proc())];
        let events =
            conntrack_flow_events_for(&outbound_flow(), &sockets, resolve_map(&entries), 0);
        let [Event::NetworkFlow(flow)] = events.as_slice() else {
            panic!("expected exactly one NetworkFlow event, got {events:?}");
        };
        assert_eq!(flow.daddr, v4([10, 0, 0, 5]));
        assert_eq!(flow.dport, 51000);
        assert_eq!(flow.bytes_sent, Some(8890)); // reply direction, now local->peer
        assert_eq!(flow.bytes_received, Some(1240));
    }

    #[test]
    fn flow_with_no_matching_socket_produces_no_event() {
        let sockets = [established_socket(4242)];
        let mut flow = outbound_flow();
        flow.orig.dst_port = Some(9999); // no socket matches this peer port
        let events = conntrack_flow_events_for(&flow, &sockets, resolve_map(&[(4242, proc())]), 0);
        assert!(events.is_empty());
    }

    #[test]
    fn non_tcp_flow_is_never_attributed() {
        let sockets = [established_socket(4242)];
        let mut flow = outbound_flow();
        flow.orig.protocol = 17; // IPPROTO_UDP — snapshot() only ever queries TCP
        let events = conntrack_flow_events_for(&flow, &sockets, resolve_map(&[(4242, proc())]), 0);
        assert!(events.is_empty());
    }

    #[test]
    fn flow_without_accounting_still_produces_an_event_with_no_counters() {
        let sockets = [established_socket(4242)];
        let mut flow = outbound_flow();
        flow.counters_orig = None;
        flow.counters_reply = None;
        let events = conntrack_flow_events_for(&flow, &sockets, resolve_map(&[(4242, proc())]), 0);
        let [Event::NetworkFlow(flow_event)] = events.as_slice() else {
            panic!("expected exactly one NetworkFlow event, got {events:?}");
        };
        assert_eq!(flow_event.bytes_sent, None);
        assert_eq!(flow_event.bytes_received, None);
    }

    #[test]
    fn an_unresolvable_pid_produces_no_event() {
        let sockets = [established_socket(4242)];
        let events = conntrack_flow_events_for(&outbound_flow(), &sockets, |_| None, 0);
        assert!(events.is_empty());
    }
}
