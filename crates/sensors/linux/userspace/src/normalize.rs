//! Wire → schema normalization. Pure functions, platform-independent, unit-tested on
//! every CI leg — the Linux-only part of this crate is loading/draining, not this.
//!
//! `boot_epoch_offset_ns` is the difference between the epoch clock and the monotonic
//! clock the probes stamp events with (`bpf_ktime_get_ns`); the sensor computes it
//! once at startup and passes it here so schema timestamps are epoch nanoseconds.

use schema::{ConnectEvent, Event, EventMeta, ExecEvent, FileOpenEvent, User};
use sensor_linux_wire as wire;

/// Decodes a fixed comm buffer: NUL-terminated, kernel-truncated to 15 bytes — a
/// sensor property (reported by conformance), not a schema limit.
fn comm_str(comm: &[u8; wire::TASK_COMM_LEN]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

fn meta(meta: &wire::EventMeta, boot_epoch_offset_ns: u64) -> EventMeta {
    EventMeta {
        pid: meta.pid,
        ppid: meta.ppid,
        user: User::Unix {
            uid: meta.uid,
            gid: meta.gid,
        },
        timestamp_ns: meta.timestamp_ns.saturating_add(boot_epoch_offset_ns),
        comm: comm_str(&meta.comm),
    }
}

/// The wire cmdline is the raw argv buffer (`\0`-separated). Schema wants both the
/// argv vector and a single display cmdline; `image_path` is best-effort `argv[0]`
/// until the probes capture the resolved image path (a `\0`-terminated buffer can
/// carry a trailing empty element — filtered).
#[must_use]
pub fn exec(event: &wire::ExecEvent, boot_epoch_offset_ns: u64) -> Event {
    let raw = &event.cmdline[..(event.cmdline_len as usize).min(wire::MAX_CMDLINE_LEN)];
    let argv: Vec<String> = raw
        .split(|&b| b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    Event::Exec(ExecEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns),
        image_path: argv.first().cloned().unwrap_or_default(),
        cmdline: argv.join(" "),
        argv,
        // The probes read real_parent->tgid but not the parent comm yet — lineage
        // stays None until the probe captures it (capabilities say so honestly).
        parent_comm: None,
        parent_image_path: None,
        sha256: None,
        signature: None,
    })
}

#[must_use]
pub fn file_open(event: &wire::FileOpenEvent, boot_epoch_offset_ns: u64) -> Event {
    let raw = &event.path[..(event.path_len as usize).min(wire::MAX_PATH_LEN)];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    Event::FileOpen(FileOpenEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns),
        path: String::from_utf8_lossy(&raw[..end]).into_owned(),
        flags: event.flags,
    })
}

#[must_use]
pub fn connect(event: &wire::ConnectEvent, boot_epoch_offset_ns: u64) -> Event {
    let daddr = if event.is_ipv6 {
        std::net::IpAddr::V6(event.daddr_v6.into())
    } else {
        std::net::IpAddr::V4(event.daddr_v4.into())
    };
    Event::Connect(ConnectEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns),
        daddr,
        dport: event.dport,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire_meta(comm: &[u8]) -> wire::EventMeta {
        let mut c = [0u8; wire::TASK_COMM_LEN];
        c[..comm.len()].copy_from_slice(comm);
        wire::EventMeta {
            pid: 42,
            ppid: 7,
            uid: 1000,
            gid: 1000,
            timestamp_ns: 1_000,
            comm: c,
        }
    }

    #[test]
    fn exec_splits_argv_and_joins_cmdline() {
        let mut cmdline = [0u8; wire::MAX_CMDLINE_LEN];
        let raw = b"curl\0-o\0/tmp/x\0";
        cmdline[..raw.len()].copy_from_slice(raw);
        let event = wire::ExecEvent {
            meta: wire_meta(b"curl"),
            cmdline,
            cmdline_len: raw.len() as u16,
        };
        let Event::Exec(e) = exec(&event, 500) else {
            panic!("wrong variant")
        };
        assert_eq!(e.argv, ["curl", "-o", "/tmp/x"]);
        assert_eq!(e.cmdline, "curl -o /tmp/x");
        assert_eq!(e.image_path, "curl");
        assert_eq!(e.meta.timestamp_ns, 1_500, "boot offset applied");
        assert_eq!(
            e.meta.user,
            schema::User::Unix {
                uid: 1000,
                gid: 1000
            }
        );
    }

    #[test]
    fn file_open_trims_nul_padding() {
        let mut path = [0u8; wire::MAX_PATH_LEN];
        let raw = b"/etc/cron.d/job\0";
        path[..raw.len()].copy_from_slice(raw);
        let event = wire::FileOpenEvent {
            meta: wire_meta(b"touch"),
            path,
            path_len: raw.len() as u16,
            flags: 0o101,
        };
        let Event::FileOpen(e) = file_open(&event, 0) else {
            panic!("wrong variant")
        };
        assert_eq!(e.path, "/etc/cron.d/job");
        assert_eq!(e.flags, 0o101);
        assert_eq!(e.meta.comm, "touch");
    }

    #[test]
    fn connect_maps_both_families() {
        let v4 = wire::ConnectEvent {
            meta: wire_meta(b"nc"),
            daddr_v4: [127, 0, 0, 11],
            daddr_v6: [0; 16],
            dport: 4444,
            is_ipv6: false,
        };
        let Event::Connect(e) = connect(&v4, 0) else {
            panic!("wrong variant")
        };
        // Byte order preserved (the 2026-08-13 reversal bug stays fixed).
        assert_eq!(e.daddr.to_string(), "127.0.0.11");
        assert_eq!(e.dport, 4444);

        let mut d6 = [0u8; 16];
        d6[0] = 0x20;
        d6[1] = 0x01;
        d6[15] = 0x01;
        let v6 = wire::ConnectEvent {
            meta: wire_meta(b"nc"),
            daddr_v4: [0; 4],
            daddr_v6: d6,
            dport: 8443,
            is_ipv6: true,
        };
        let Event::Connect(e) = connect(&v6, 0) else {
            panic!("wrong variant")
        };
        assert_eq!(e.daddr.to_string(), "2001::1");
    }

    #[test]
    fn hostile_comm_is_lossy_not_fatal() {
        let event = wire::FileOpenEvent {
            meta: wire_meta(&[0xff, 0xfe, b'x']),
            path: [0; wire::MAX_PATH_LEN],
            path_len: 0,
            flags: 0,
        };
        let Event::FileOpen(e) = file_open(&event, 0) else {
            panic!("wrong variant")
        };
        assert!(e.meta.comm.contains('\u{fffd}'), "{:?}", e.meta.comm);
    }
}
