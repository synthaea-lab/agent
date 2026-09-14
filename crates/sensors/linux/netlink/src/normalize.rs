//! `sock_diag` snapshot → [`schema::Event`] normalization. Pure functions, same
//! discipline as `sensor-linux`'s `normalize` module: platform-independent,
//! unit-tested directly (the platform-specific part is the snapshot/`/proc` reads
//! upstream of this, not the mapping itself).
//!
//! Only listening sockets become events here — [`crate::SocketState::Established`]
//! entries are part of [`crate::snapshot`]'s result (useful on their own, e.g. for
//! future connection telemetry) but issue #92's "listening-port drift" done-when
//! item is specifically about [`schema::ListenPortEvent`], so that's the only
//! mapping this module owns for now.

use schema::{Event, EventMeta, ListenPortEvent, User};

use crate::{SocketSnapshotEntry, SocketState, proc_meta::ProcInfo};

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
}
