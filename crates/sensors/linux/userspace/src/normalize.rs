//! Wire → schema normalization. Pure functions, platform-independent, unit-tested on
//! every CI leg — the Linux-only part of this crate is loading/draining, not this.
//!
//! `boot_epoch_offset_ns` is the difference between the epoch clock and the monotonic
//! clock the probes stamp events with (`bpf_ktime_get_ns`); the sensor computes it
//! once at startup and passes it here so schema timestamps are epoch nanoseconds.

use schema::{ConnectEvent, Event, EventMeta, ExecEvent, FileOpenEvent, User};
use sensor_linux_wire as wire;

/// Tripwire: bumping the wire ABI must come here to revisit the mappings below.
const _: () = assert!(wire::WIRE_VERSION == 3);

/// Decodes a fixed comm buffer: NUL-terminated, kernel-truncated to 15 bytes — a
/// sensor property (reported by conformance), not a schema limit.
fn comm_str(comm: &[u8; wire::TASK_COMM_LEN]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

/// Same, but an empty buffer means "not captured" rather than the empty string —
/// the probe leaves `pcomm` zeroed when the fork-lineage map had no entry.
fn comm_opt(comm: &[u8; wire::TASK_COMM_LEN]) -> Option<String> {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    (end != 0).then(|| String::from_utf8_lossy(&comm[..end]).into_owned())
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

/// `image_path` is the authoritative image the kernel loaded (`ExecEvent::image`, from
/// the `sched_process_exec` tracepoint), never `argv[0]`. `argv` is passed in by the
/// caller — the Linux sensor reads it from `/proc/<pid>/cmdline` when it drains the
/// event (issue #152; empty for a process that already exited). `cmdline` is a
/// space-joined rendering of `argv` for display and Sigma matching; consumers that
/// need the exact tokens use `argv` (or `ExecEvent::ml_cmdline`). `parent_comm` is the
/// fork-lineage entry, or `None` when the parent predated the probe and priming
/// missed it.
#[must_use]
pub fn exec(event: &wire::ExecEvent, boot_epoch_offset_ns: u64, argv: Vec<String>) -> Event {
    let image_raw = &event.image[..(event.image_len as usize).min(wire::MAX_PATH_LEN)];
    let image_end = image_raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(image_raw.len());
    let image_path = String::from_utf8_lossy(&image_raw[..image_end]).into_owned();

    Event::Exec(ExecEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns),
        image_path,
        cmdline: argv.join(" "),
        argv,
        parent_comm: comm_opt(&event.pcomm),
        // eBPF has the parent comm but not its full path — see #107.
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

    fn wire_exec(image: &[u8], pcomm: &[u8]) -> wire::ExecEvent {
        let mut image_buf = [0u8; wire::MAX_PATH_LEN];
        image_buf[..image.len()].copy_from_slice(image);
        let mut pcomm_buf = [0u8; wire::TASK_COMM_LEN];
        pcomm_buf[..pcomm.len()].copy_from_slice(pcomm);
        wire::ExecEvent {
            meta: wire_meta(b"curl"),
            image: image_buf,
            image_len: image.len() as u16,
            pcomm: pcomm_buf,
        }
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn exec_keeps_argv_and_joins_cmdline() {
        let event = wire_exec(b"/usr/bin/curl", b"bash");
        let Event::Exec(e) = exec(&event, 500, argv(&["curl", "-o", "/tmp/x"])) else {
            panic!("wrong variant")
        };
        assert_eq!(e.argv, ["curl", "-o", "/tmp/x"]);
        assert_eq!(e.cmdline, "curl -o /tmp/x");
        assert_eq!(e.image_path, "/usr/bin/curl");
        assert_eq!(e.parent_comm.as_deref(), Some("bash"));
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
    fn exec_image_path_ignores_spoofed_argv0() {
        // execve("/tmp/evil", {"/usr/sbin/sshd", ...}, ...)
        let event = wire_exec(b"/tmp/evil", b"bash");
        let Event::Exec(e) = exec(&event, 0, argv(&["/usr/sbin/sshd", "-D"])) else {
            panic!("wrong variant")
        };
        assert_eq!(
            e.image_path, "/tmp/evil",
            "image is the kernel's, not argv[0]"
        );
        assert_eq!(
            e.argv[0], "/usr/sbin/sshd",
            "argv kept verbatim for analysis"
        );
    }

    #[test]
    fn exec_empty_argv_when_process_already_exited() {
        // /proc/<pid>/cmdline gone by drain time — image_path still authoritative.
        let event = wire_exec(b"/bin/sh", b"bash");
        let Event::Exec(e) = exec(&event, 0, Vec::new()) else {
            panic!("wrong variant")
        };
        assert!(e.argv.is_empty());
        assert_eq!(e.cmdline, "");
        assert_eq!(e.image_path, "/bin/sh");
    }

    #[test]
    fn exec_parent_comm_absent_when_lineage_missed() {
        let event = wire_exec(b"/bin/sh", b"");
        let Event::Exec(e) = exec(&event, 0, argv(&["sh"])) else {
            panic!("wrong variant")
        };
        assert_eq!(e.parent_comm, None);
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
