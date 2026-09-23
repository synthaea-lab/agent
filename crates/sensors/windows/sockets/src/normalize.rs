//! Maps snapshot entries into `schema` events — pure and cross-platform.

use schema::{Event, EventMeta, ListenPortEvent, User};

use crate::raw::ListenerEntry;

/// Maps one listener to a [`schema::Event::ListenPort`], stamped with
/// `timestamp_ns` as the snapshot time per [`schema::ListenPortEvent`]'s
/// semantics.
///
/// `user` is [`User::Unknown`]: the IP Helper table carries no token, and
/// opening every owner's token each poll to recover it would cost a handle per
/// listener for a field LISTENER-DRIFT does not read. `ppid` is 0 when the
/// owner was not in the process snapshot.
#[must_use]
pub fn listen_port_event(entry: &ListenerEntry, timestamp_ns: u64) -> Event {
    Event::ListenPort(ListenPortEvent {
        meta: EventMeta {
            pid: entry.pid,
            ppid: entry.ppid.unwrap_or(0),
            user: User::Unknown,
            timestamp_ns,
            comm: entry.process_name.clone().unwrap_or_default(),
            container: None, // Windows: no container support
        },
        local_addr: entry.local.ip(),
        local_port: entry.local.port(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> ListenerEntry {
        ListenerEntry {
            pid: 1234,
            ppid: Some(700),
            process_name: Some("svchost.exe".to_string()),
            local: "0.0.0.0:135".parse().unwrap(),
        }
    }

    #[test]
    fn listener_maps_with_snapshot_attribution() {
        let Event::ListenPort(listen) = listen_port_event(&entry(), 7) else {
            panic!("a listener must map to Event::ListenPort");
        };
        assert_eq!(listen.local_port, 135);
        assert_eq!(listen.meta.pid, 1234);
        assert_eq!(listen.meta.ppid, 700);
        assert_eq!(listen.meta.comm, "svchost.exe");
        assert_eq!(listen.meta.user, User::Unknown);
        assert_eq!(listen.meta.timestamp_ns, 7);
    }

    #[test]
    fn ipv6_listeners_are_first_class() {
        let mut e = entry();
        e.local = "[::]:4444".parse().unwrap();
        let Event::ListenPort(listen) = listen_port_event(&e, 0) else {
            panic!("must map");
        };
        assert!(listen.local_addr.is_ipv6());
        assert_eq!(listen.local_port, 4444);
    }

    #[test]
    fn unattributed_owner_stays_honest_not_fabricated() {
        let mut e = entry();
        e.ppid = None;
        e.process_name = None;
        let Event::ListenPort(listen) = listen_port_event(&e, 0) else {
            panic!("the port fact stands on its own");
        };
        assert_eq!(listen.meta.ppid, 0);
        assert_eq!(listen.meta.comm, "");
    }
}
