//! Normalizes `AuditEvent` into `schema::Event`.
//! Platform-independent, unit-testable on any OS.

use crate::classify::AuditEvent;
use schema::{Event, ExecEvent, ConnectEvent, EventMeta, User};

/// Converts `AuditEvent::Exec` to `schema::Event::Exec`.
///
/// # Panics
///
/// Panics if called on a non-Exec event (internal misuse).
pub fn exec_event(evt: &AuditEvent, timestamp_ns: u64) -> Event {
    let AuditEvent::Exec { pid, uid, gid, image_path, argv } = evt else {
        panic!("normalize::exec_event called on non-Exec event");
    };

    Event::Exec(ExecEvent {
        meta: EventMeta {
            timestamp_ns,
            pid: *pid,
            ppid: 0,  // HONEST: audit doesn't provide this
            user: User::Unix { uid: *uid, gid: *gid },
            comm: comm_from_path(image_path),
            container: None,  // Phase 1: no container attribution
        },
        image_path: image_path.clone(),
        cmdline: argv.join(" "),
        argv: argv.clone(),
        parent_comm: None,       // HONEST: audit doesn't track parent
        parent_image_path: None,
        sha256: None,            // Filled by enrichment
        signature: None,
    })
}

/// Converts `AuditEvent::Connect` to `schema::Event::Connect`.
///
/// # Panics
///
/// Panics if called on a non-Connect event (internal misuse).
pub fn connect_event(evt: &AuditEvent, timestamp_ns: u64) -> Event {
    let AuditEvent::Connect { pid, uid, gid, remote_addr, protocol: _ } = evt else {
        panic!("normalize::connect_event called on non-Connect event");
    };

    Event::Connect(ConnectEvent {
        meta: EventMeta {
            timestamp_ns,
            pid: *pid,
            ppid: 0,
            user: User::Unix { uid: *uid, gid: *gid },
            comm: String::from("unknown"),  // audit doesn't provide comm
            container: None,
        },
        daddr: remote_addr.ip(),
        dport: remote_addr.port(),
    })
}

/// Extract comm from `image_path` (`"/usr/bin/ls"` -> `"ls"`)
fn comm_from_path(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn normalize_exec() {
        let audit_evt = AuditEvent::Exec {
            pid: 1234,
            uid: 1000,
            gid: 1000,
            image_path: "/bin/ls".to_string(),
            argv: vec!["/bin/ls".to_string(), "-la".to_string()],
        };

        let schema_evt = exec_event(&audit_evt, 1234567890_000_000_000);
        match schema_evt {
            Event::Exec(e) => {
                assert_eq!(e.meta.pid, 1234);
                assert_eq!(e.meta.ppid, 0); // Honest: no ppid from audit
                assert_eq!(e.meta.comm, "ls");
                assert_eq!(e.image_path, "/bin/ls");
                assert_eq!(e.cmdline, "/bin/ls -la");
                assert_eq!(e.argv, vec!["/bin/ls", "-la"]);
                assert_eq!(e.parent_comm, None);
                assert_eq!(e.parent_image_path, None);
            }
            _ => panic!("expected Event::Exec"),
        }
    }

    #[test]
    fn normalize_connect() {
        let audit_evt = AuditEvent::Connect {
            pid: 5678,
            uid: 1001,
            gid: 1001,
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443),
            protocol: 6,
        };

        let schema_evt = connect_event(&audit_evt, 9876543210_000_000_000);
        match schema_evt {
            Event::Connect(e) => {
                assert_eq!(e.meta.pid, 5678);
                assert_eq!(e.meta.ppid, 0); // Honest: no ppid from audit
                assert_eq!(e.daddr, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
                assert_eq!(e.dport, 443);
            }
            _ => panic!("expected Event::Connect"),
        }
    }

    #[test]
    fn comm_extraction() {
        assert_eq!(comm_from_path("/usr/bin/python3"), "python3");
        assert_eq!(comm_from_path("./local"), "local");
        assert_eq!(comm_from_path("bare"), "bare");
    }
}
