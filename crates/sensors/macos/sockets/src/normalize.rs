//! Maps snapshot entries into `schema` events — pure and cross-platform.
//!
//! Only listeners map today: `Event::ListenPort` is the existing snapshot
//! shape (its doc already states the poll-time-timestamp semantics), and the
//! LISTENER-DRIFT rule consumes macOS entries exactly like Linux ones.
//! Established sockets stay in the raw snapshot for the baseline/seeding
//! caller but produce no event — the discrete NE flow stream (#33) is the
//! connection source; a poll echo of it would double-count (the same
//! deliberate gap the Linux netlink crate documents).

use schema::{Event, EventMeta, ListenPortEvent, User};

use crate::raw::{SocketSnapshotEntry, SocketState};

/// Short process name from the executable path.
fn comm(path: Option<&str>) -> String {
    let path = path.unwrap_or("");
    path.rsplit('/').next().unwrap_or(path).to_string()
}

/// Maps one snapshot entry to a [`schema::Event::ListenPort`], `None` for
/// non-listening states. `timestamp_ns` is the snapshot time, stamped on the
/// event per [`schema::ListenPortEvent`]'s own semantics.
#[must_use]
pub fn listen_port_event(entry: &SocketSnapshotEntry, timestamp_ns: u64) -> Option<Event> {
    if entry.state != SocketState::Listen {
        return None;
    }
    Some(Event::ListenPort(ListenPortEvent {
        meta: EventMeta {
            pid: entry.pid,
            ppid: entry.ppid,
            user: User::Unix {
                uid: entry.uid,
                gid: entry.gid,
            },
            timestamp_ns,
            comm: comm(entry.process_path.as_deref()),
            container: None,
        },
        local_addr: entry.local.ip(),
        local_port: entry.local.port(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(state: SocketState) -> SocketSnapshotEntry {
        SocketSnapshotEntry {
            pid: 4242,
            ppid: 1,
            uid: 501,
            gid: 20,
            process_path: Some("/usr/sbin/sshd".to_string()),
            local: "0.0.0.0:22".parse().unwrap(),
            remote: "0.0.0.0:0".parse().unwrap(),
            state,
        }
    }

    #[test]
    fn listener_maps_with_full_attribution() {
        let Some(Event::ListenPort(listen)) = listen_port_event(&entry(SocketState::Listen), 7)
        else {
            panic!("a listener must map to Event::ListenPort");
        };
        assert_eq!(listen.local_port, 22);
        assert_eq!(listen.meta.pid, 4242);
        assert_eq!(
            listen.meta.ppid, 1,
            "libproc gives real ppid, unlike the Linux join"
        );
        assert_eq!(listen.meta.comm, "sshd");
        assert_eq!(listen.meta.user, User::Unix { uid: 501, gid: 20 });
        assert_eq!(listen.meta.timestamp_ns, 7);
    }

    #[test]
    fn ipv6_listeners_are_first_class() {
        let mut e = entry(SocketState::Listen);
        e.local = "[::]:4444".parse().unwrap();
        assert!(matches!(
            listen_port_event(&e, 0),
            Some(Event::ListenPort(l)) if l.local_addr.is_ipv6() && l.local_port == 4444
        ));
    }

    #[test]
    fn non_listening_states_produce_no_event() {
        assert!(listen_port_event(&entry(SocketState::Established), 0).is_none());
        assert!(listen_port_event(&entry(SocketState::Other), 0).is_none());
    }

    #[test]
    fn missing_path_stays_honest_not_fabricated() {
        let mut e = entry(SocketState::Listen);
        e.process_path = None;
        let Some(Event::ListenPort(listen)) = listen_port_event(&e, 0) else {
            panic!("must still map — the port fact stands on its own");
        };
        assert_eq!(listen.meta.comm, "");
    }
}
