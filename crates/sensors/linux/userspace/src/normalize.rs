//! Wire → schema normalization. Pure functions, platform-independent, unit-tested on
//! every CI leg — the Linux-only part of this crate is loading/draining, not this.
//!
//! `boot_epoch_offset_ns` is the difference between the epoch clock and the monotonic
//! clock the probes stamp events with (`bpf_ktime_get_ns`); the sensor computes it
//! once at startup and passes it here so schema timestamps are epoch nanoseconds.

use schema::{
    BpfEvent, ConnectEvent, ContainerContext, Event, EventMeta, ExecEvent, FileChmodEvent,
    FileChownEvent, FileDeleteEvent, FileOpenEvent, FileRemovexattrEvent, FileRenameEvent,
    FileSetxattrEvent, FileWriteEvent, KernelModuleAction, KernelModuleEvent, MountEvent,
    SignalEvent, SocketAcceptEvent, SocketBindEvent, SocketListenEvent, UdpSendEvent, User,
};
use sensor_linux_wire as wire;

/// Tripwire: bumping the wire ABI must come here to revisit the mappings below.
///
/// v5 (#90) only added `TlsCaptureEvent`/`ReadlineInputEvent` — neither is imported
/// here, and none of the structs this module maps (`EventMeta`, `ExecEvent`,
/// `ConnectEvent`, `FileOpenEvent`, `ContainerContext`) changed shape, so the
/// mappings below still hold; bumped straight to 5 after that audit.
///
/// v6 (#262) added `FileWriteEvent`, `FileDeleteEvent`, `FileRenameEvent` — new
/// mapping functions `file_write`/`file_delete`/`file_rename` added below, same
/// `meta()` helper reused; no existing mapping changed shape.
///
/// v7 (#263) added `SocketBindEvent` — new `socket_bind` mapping function below,
/// same address-family logic as `connect`; no existing mapping changed shape.
///
/// v8 (#262 Phase 2) added `FileChmodEvent`/`FileChownEvent` — new mapping functions
/// `file_chmod`/`file_chown` added below, same path-decoding shape as `file_delete`;
/// no existing mapping changed shape.
///
/// v9 (#263 Phase 2) added `UdpSendEvent` — new `udp_send` mapping function below,
/// same address-family logic as `connect`/`socket_bind`, reusing the schema type
/// already shared with the Windows ETW UDP producer; no existing mapping changed
/// shape.
///
/// v10 (#263 Phase 2) added `SocketListenEvent` — new `socket_listen` mapping
/// function below, converting the wire struct's `addr_resolved` bool + zeroed
/// fields into `Option<IpAddr>`/`Option<u16>` on the schema side; no existing
/// mapping changed shape.
///
/// v11 (#263 Phase 2) added `SocketAcceptEvent` — new `socket_accept` mapping
/// function below, same address-family logic as `connect`/`socket_bind`; no
/// existing mapping changed shape.
///
/// v12 (#262 Phase 3) added `FileSetxattrEvent`/`FileRemovexattrEvent` — new
/// mapping functions `file_setxattr`/`file_removexattr` below, same path-decoding
/// shape as `file_chmod`/`file_chown` plus a second nul-padded field (the xattr
/// `name`); no existing mapping changed shape.
///
/// v13 (#362 and #264, originally claimed as v12 — see that constant's doc) added
/// `MountEvent`/`SignalEvent` and `KernelModuleEvent`/`BpfEvent`. `mount` turns
/// zero-length `source`/`fs_type` (umount2(2) has neither) into `None`, matching
/// how the macOS producer reports them absent. `signal` takes `target_image_path`
/// from the caller rather than the wire event — the probe filters to the agent's
/// own pid (v1 scope), which the sensor already knows its own exe path for
/// without a `/proc/<pid>/exe` readlink per event. `kernel_module` turns the wire
/// struct's `action: u8` discriminant into `schema::KernelModuleAction` and its
/// always-populated `fd`/`image_len` sentinels (`-1`/`0` when not applicable to
/// the action) into `Option`s. No existing mapping changed shape.
const _: () = assert!(wire::WIRE_VERSION == 13);

/// Same, but an empty buffer means "not captured" rather than the empty string —
/// the probe leaves `pcomm` zeroed when the fork-lineage map had no entry.
fn comm_opt(comm: &[u8; wire::TASK_COMM_LEN]) -> Option<String> {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    (end != 0).then(|| String::from_utf8_lossy(&comm[..end]).into_owned())
}

/// `container` is resolved by the caller: the id from `meta.cgroup_id` (captured
/// kernel-side, resolved against cgroupfs — issue #204) at drain time, `image`/
/// `name` from a cached Docker/containerd socket lookup keyed on that id (issue
/// #80 — both halves of the attribution this crate's doc comment on
/// `ContainerContext` originally deferred).
fn meta(
    meta: &wire::EventMeta,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> EventMeta {
    EventMeta {
        pid: meta.pid,
        ppid: meta.ppid,
        user: User::Unix {
            uid: meta.uid,
            gid: meta.gid,
        },
        timestamp_ns: meta.timestamp_ns.saturating_add(boot_epoch_offset_ns),
        comm: wire::comm_str(&meta.comm),
        container,
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
pub fn exec(
    event: &wire::ExecEvent,
    boot_epoch_offset_ns: u64,
    argv: Vec<String>,
    container: Option<ContainerContext>,
) -> Event {
    let image_raw = &event.image[..(event.image_len as usize).min(wire::MAX_PATH_LEN)];
    let image_end = image_raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(image_raw.len());
    let image_path = String::from_utf8_lossy(&image_raw[..image_end]).into_owned();

    Event::Exec(ExecEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
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
pub fn file_open(
    event: &wire::FileOpenEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let raw = &event.path[..(event.path_len as usize).min(wire::MAX_PATH_LEN)];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    Event::FileOpen(FileOpenEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        path: String::from_utf8_lossy(&raw[..end]).into_owned(),
        flags: event.flags,
    })
}

#[must_use]
pub fn file_write(
    event: &wire::FileWriteEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    Event::FileWrite(FileWriteEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        fd: event.fd,
        bytes_requested: event.bytes_requested,
    })
}

#[must_use]
pub fn file_delete(
    event: &wire::FileDeleteEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let raw = &event.path[..(event.path_len as usize).min(wire::MAX_PATH_LEN)];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    Event::FileDelete(FileDeleteEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        path: String::from_utf8_lossy(&raw[..end]).into_owned(),
    })
}

#[must_use]
pub fn file_rename(
    event: &wire::FileRenameEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let old_raw = &event.old_path[..(event.old_path_len as usize).min(wire::MAX_PATH_LEN)];
    let old_end = old_raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(old_raw.len());
    let new_raw = &event.new_path[..(event.new_path_len as usize).min(wire::MAX_PATH_LEN)];
    let new_end = new_raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(new_raw.len());
    Event::FileRename(FileRenameEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        old_path: String::from_utf8_lossy(&old_raw[..old_end]).into_owned(),
        new_path: String::from_utf8_lossy(&new_raw[..new_end]).into_owned(),
    })
}

#[must_use]
pub fn file_chmod(
    event: &wire::FileChmodEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let raw = &event.path[..(event.path_len as usize).min(wire::MAX_PATH_LEN)];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    Event::FileChmod(FileChmodEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        path: String::from_utf8_lossy(&raw[..end]).into_owned(),
        mode: event.mode,
    })
}

#[must_use]
pub fn file_chown(
    event: &wire::FileChownEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let raw = &event.path[..(event.path_len as usize).min(wire::MAX_PATH_LEN)];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    Event::FileChown(FileChownEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        path: String::from_utf8_lossy(&raw[..end]).into_owned(),
        uid: event.uid,
        gid: event.gid,
    })
}

#[must_use]
pub fn file_setxattr(
    event: &wire::FileSetxattrEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let path_raw = &event.path[..(event.path_len as usize).min(wire::MAX_PATH_LEN)];
    let path_end = path_raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(path_raw.len());
    let name_raw = &event.name[..(event.name_len as usize).min(wire::MAX_XATTR_NAME_LEN)];
    let name_end = name_raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_raw.len());
    Event::FileSetxattr(FileSetxattrEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        path: String::from_utf8_lossy(&path_raw[..path_end]).into_owned(),
        name: String::from_utf8_lossy(&name_raw[..name_end]).into_owned(),
    })
}

#[must_use]
pub fn file_removexattr(
    event: &wire::FileRemovexattrEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let path_raw = &event.path[..(event.path_len as usize).min(wire::MAX_PATH_LEN)];
    let path_end = path_raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(path_raw.len());
    let name_raw = &event.name[..(event.name_len as usize).min(wire::MAX_XATTR_NAME_LEN)];
    let name_end = name_raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_raw.len());
    Event::FileRemovexattr(FileRemovexattrEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        path: String::from_utf8_lossy(&path_raw[..path_end]).into_owned(),
        name: String::from_utf8_lossy(&name_raw[..name_end]).into_owned(),
    })
}

#[must_use]
pub fn connect(
    event: &wire::ConnectEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let daddr = if event.is_ipv6 {
        std::net::IpAddr::V6(event.daddr_v6.into())
    } else {
        std::net::IpAddr::V4(event.daddr_v4.into())
    };
    Event::Connect(ConnectEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        daddr,
        dport: event.dport,
    })
}

#[must_use]
pub fn socket_bind(
    event: &wire::SocketBindEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let laddr = if event.is_ipv6 {
        std::net::IpAddr::V6(event.laddr_v6.into())
    } else {
        std::net::IpAddr::V4(event.laddr_v4.into())
    };
    Event::SocketBind(SocketBindEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        local_addr: laddr,
        local_port: event.lport,
    })
}

#[must_use]
pub fn udp_send(
    event: &wire::UdpSendEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let daddr = if event.is_ipv6 {
        std::net::IpAddr::V6(event.daddr_v6.into())
    } else {
        std::net::IpAddr::V4(event.daddr_v4.into())
    };
    Event::UdpSend(UdpSendEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        daddr,
        dport: event.dport,
        size: event.size,
    })
}

#[must_use]
pub fn socket_listen(
    event: &wire::SocketListenEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let (local_addr, local_port) = if event.addr_resolved {
        let addr = if event.is_ipv6 {
            std::net::IpAddr::V6(event.laddr_v6.into())
        } else {
            std::net::IpAddr::V4(event.laddr_v4.into())
        };
        (Some(addr), Some(event.lport))
    } else {
        (None, None)
    };
    Event::SocketListen(SocketListenEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        local_addr,
        local_port,
        backlog: event.backlog,
    })
}

#[must_use]
pub fn socket_accept(
    event: &wire::SocketAcceptEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let peer_addr = if event.is_ipv6 {
        std::net::IpAddr::V6(event.peer_addr_v6.into())
    } else {
        std::net::IpAddr::V4(event.peer_addr_v4.into())
    };
    Event::SocketAccept(SocketAcceptEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        listen_fd: event.listen_fd,
        accepted_fd: event.accepted_fd,
        peer_addr,
        peer_port: event.peer_port,
    })
}

#[must_use]
pub fn mount(
    event: &wire::MountEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let mp_raw = &event.mount_point[..(event.mount_point_len as usize).min(wire::MAX_PATH_LEN)];
    let mp_end = mp_raw.iter().position(|&b| b == 0).unwrap_or(mp_raw.len());
    let source = (event.source_len > 0).then(|| {
        let raw = &event.source[..(event.source_len as usize).min(wire::MAX_PATH_LEN)];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        String::from_utf8_lossy(&raw[..end]).into_owned()
    });
    let fs_type = (event.fs_type_len > 0).then(|| {
        let raw = &event.fs_type[..(event.fs_type_len as usize).min(wire::MAX_FS_TYPE_LEN)];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        String::from_utf8_lossy(&raw[..end]).into_owned()
    });
    Event::Mount(MountEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        mount_point: String::from_utf8_lossy(&mp_raw[..mp_end]).into_owned(),
        source,
        fs_type,
        readonly: event.readonly,
        mounted: event.mounted,
    })
}

/// `target_image_path` is the caller's, not the wire event's — see this module's
/// `WIRE_VERSION` v12 changelog for why.
#[must_use]
pub fn signal(
    event: &wire::SignalEvent,
    boot_epoch_offset_ns: u64,
    target_image_path: Option<String>,
    container: Option<ContainerContext>,
) -> Event {
    Event::Signal(SignalEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        signal: event.signal,
        target_pid: event.target_pid,
        target_image_path,
    })
}

#[must_use]
pub fn kernel_module(
    event: &wire::KernelModuleEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let action = match event.action {
        1 => KernelModuleAction::LoadFd,
        2 => KernelModuleAction::Unload,
        _ => KernelModuleAction::Load,
    };
    let name = if event.name_len > 0 {
        let raw = &event.name[..(event.name_len as usize).min(wire::MAX_MODULE_NAME_LEN)];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        Some(String::from_utf8_lossy(&raw[..end]).into_owned())
    } else {
        None
    };
    Event::KernelModule(KernelModuleEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        action,
        name,
        fd: (event.fd >= 0).then_some(event.fd),
        image_len: (event.image_len > 0).then_some(event.image_len),
    })
}

#[must_use]
pub fn bpf_operation(
    event: &wire::BpfEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    Event::BpfOperation(BpfEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        cmd: event.cmd,
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
            cgroup_id: 0,
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
        let Event::Exec(e) = exec(&event, 500, argv(&["curl", "-o", "/tmp/x"]), None) else {
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
        let Event::Exec(e) = exec(&event, 0, argv(&["/usr/sbin/sshd", "-D"]), None) else {
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
        let Event::Exec(e) = exec(&event, 0, Vec::new(), None) else {
            panic!("wrong variant")
        };
        assert!(e.argv.is_empty());
        assert_eq!(e.cmdline, "");
        assert_eq!(e.image_path, "/bin/sh");
    }

    #[test]
    fn exec_parent_comm_absent_when_lineage_missed() {
        let event = wire_exec(b"/bin/sh", b"");
        let Event::Exec(e) = exec(&event, 0, argv(&["sh"]), None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.parent_comm, None);
    }

    #[test]
    fn exec_carries_container_id_only_when_image_name_unresolved() {
        let event = wire_exec(b"/usr/sbin/nginx", b"");
        let id = "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456".to_string();
        let ctx = ContainerContext {
            id: id.clone(),
            image: None,
            name: None,
        };
        let Event::Exec(e) = exec(&event, 0, argv(&["nginx"]), Some(ctx)) else {
            panic!("wrong variant")
        };
        let container = e.meta.container.expect("container attributed");
        assert_eq!(container.id, id);
        assert_eq!(container.image, None, "socket lookup pending/failed");
        assert_eq!(container.name, None, "socket lookup pending/failed");
    }

    #[test]
    fn exec_carries_container_image_and_name_when_resolved() {
        let event = wire_exec(b"/usr/sbin/nginx", b"");
        let ctx = ContainerContext {
            id: "abc123".to_string(),
            image: Some("nginx:1.27".to_string()),
            name: Some("web1".to_string()),
        };
        let Event::Exec(e) = exec(&event, 0, argv(&["nginx"]), Some(ctx)) else {
            panic!("wrong variant")
        };
        let container = e.meta.container.expect("container attributed");
        assert_eq!(container.image.as_deref(), Some("nginx:1.27"));
        assert_eq!(container.name.as_deref(), Some("web1"));
    }

    #[test]
    fn bare_metal_process_has_no_container() {
        let event = wire_exec(b"/usr/bin/curl", b"bash");
        let Event::Exec(e) = exec(&event, 0, argv(&["curl"]), None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.meta.container, None);
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
        let Event::FileOpen(e) = file_open(&event, 0, None) else {
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
        let Event::Connect(e) = connect(&v4, 0, None) else {
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
        let Event::Connect(e) = connect(&v6, 0, None) else {
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
        let Event::FileOpen(e) = file_open(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert!(e.meta.comm.contains('\u{fffd}'), "{:?}", e.meta.comm);
    }

    #[test]
    fn file_write_carries_fd_and_requested_bytes_not_a_path() {
        let event = wire::FileWriteEvent {
            meta: wire_meta(b"tar"),
            fd: 4,
            bytes_requested: 65_536,
        };
        let Event::FileWrite(e) = file_write(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.fd, 4);
        assert_eq!(e.bytes_requested, 65_536);
        assert_eq!(e.meta.comm, "tar");
    }

    #[test]
    fn file_delete_trims_nul_padding() {
        let mut path = [0u8; wire::MAX_PATH_LEN];
        let raw = b"/var/log/auth.log\0";
        path[..raw.len()].copy_from_slice(raw);
        let event = wire::FileDeleteEvent {
            meta: wire_meta(b"rm"),
            path,
            path_len: raw.len() as u16,
        };
        let Event::FileDelete(e) = file_delete(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.path, "/var/log/auth.log");
    }

    #[test]
    fn file_rename_keeps_old_and_new_path_distinct() {
        let mut old_path = [0u8; wire::MAX_PATH_LEN];
        let old_raw = b"/home/user/invoice.pdf\0";
        old_path[..old_raw.len()].copy_from_slice(old_raw);
        let mut new_path = [0u8; wire::MAX_PATH_LEN];
        let new_raw = b"/home/user/invoice.pdf.locked\0";
        new_path[..new_raw.len()].copy_from_slice(new_raw);
        let event = wire::FileRenameEvent {
            meta: wire_meta(b"encryptor"),
            old_path,
            old_path_len: old_raw.len() as u16,
            new_path,
            new_path_len: new_raw.len() as u16,
        };
        let Event::FileRename(e) = file_rename(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.old_path, "/home/user/invoice.pdf");
        assert_eq!(e.new_path, "/home/user/invoice.pdf.locked");
    }

    #[test]
    fn file_chmod_carries_mode_and_trims_nul_padding() {
        let mut path = [0u8; wire::MAX_PATH_LEN];
        let raw = b"/tmp/backdoor\0";
        path[..raw.len()].copy_from_slice(raw);
        let event = wire::FileChmodEvent {
            meta: wire_meta(b"chmod"),
            path,
            path_len: raw.len() as u16,
            mode: 0o4755,
        };
        let Event::FileChmod(e) = file_chmod(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.path, "/tmp/backdoor");
        assert_eq!(e.mode, 0o4755);
    }

    #[test]
    fn file_chown_carries_uid_and_gid_distinctly() {
        let mut path = [0u8; wire::MAX_PATH_LEN];
        let raw = b"/tmp/backdoor\0";
        path[..raw.len()].copy_from_slice(raw);
        let event = wire::FileChownEvent {
            meta: wire_meta(b"chown"),
            path,
            path_len: raw.len() as u16,
            uid: 0,
            gid: 1000,
        };
        let Event::FileChown(e) = file_chown(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.path, "/tmp/backdoor");
        assert_eq!(e.uid, 0);
        assert_eq!(e.gid, 1000);
    }

    #[test]
    fn file_setxattr_carries_path_and_name_distinctly() {
        let mut path = [0u8; wire::MAX_PATH_LEN];
        let raw_path = b"/tmp/backdoor\0";
        path[..raw_path.len()].copy_from_slice(raw_path);
        let mut name = [0u8; wire::MAX_XATTR_NAME_LEN];
        let raw_name = b"security.capability\0";
        name[..raw_name.len()].copy_from_slice(raw_name);
        let event = wire::FileSetxattrEvent {
            meta: wire_meta(b"setcap"),
            path,
            path_len: raw_path.len() as u16,
            name,
            name_len: raw_name.len() as u16,
        };
        let Event::FileSetxattr(e) = file_setxattr(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.path, "/tmp/backdoor");
        assert_eq!(e.name, "security.capability");
    }

    #[test]
    fn file_removexattr_carries_path_and_name_distinctly() {
        let mut path = [0u8; wire::MAX_PATH_LEN];
        let raw_path = b"/tmp/backdoor\0";
        path[..raw_path.len()].copy_from_slice(raw_path);
        let mut name = [0u8; wire::MAX_XATTR_NAME_LEN];
        let raw_name = b"security.selinux\0";
        name[..raw_name.len()].copy_from_slice(raw_name);
        let event = wire::FileRemovexattrEvent {
            meta: wire_meta(b"evade"),
            path,
            path_len: raw_path.len() as u16,
            name,
            name_len: raw_name.len() as u16,
        };
        let Event::FileRemovexattr(e) = file_removexattr(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.path, "/tmp/backdoor");
        assert_eq!(e.name, "security.selinux");
    }

    #[test]
    fn socket_bind_maps_both_families() {
        let v4 = wire::SocketBindEvent {
            meta: wire_meta(b"nc"),
            laddr_v4: [0, 0, 0, 0],
            laddr_v6: [0; 16],
            lport: 4444,
            is_ipv6: false,
        };
        let Event::SocketBind(e) = socket_bind(&v4, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.local_addr.to_string(), "0.0.0.0");
        assert_eq!(e.local_port, 4444);

        let mut l6 = [0u8; 16];
        l6[15] = 0x01;
        let v6 = wire::SocketBindEvent {
            meta: wire_meta(b"nc"),
            laddr_v4: [0; 4],
            laddr_v6: l6,
            lport: 8443,
            is_ipv6: true,
        };
        let Event::SocketBind(e) = socket_bind(&v6, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.local_addr.to_string(), "::1");
    }

    #[test]
    fn udp_send_carries_size_and_maps_both_families() {
        let v4 = wire::UdpSendEvent {
            meta: wire_meta(b"dig"),
            daddr_v4: [8, 8, 8, 8],
            daddr_v6: [0; 16],
            dport: 53,
            is_ipv6: false,
            size: 42,
        };
        let Event::UdpSend(e) = udp_send(&v4, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.daddr.to_string(), "8.8.8.8");
        assert_eq!(e.dport, 53);
        assert_eq!(e.size, 42);

        let mut d6 = [0u8; 16];
        d6[15] = 0x01;
        let v6 = wire::UdpSendEvent {
            meta: wire_meta(b"dig"),
            daddr_v4: [0; 4],
            daddr_v6: d6,
            dport: 53,
            is_ipv6: true,
            size: 512,
        };
        let Event::UdpSend(e) = udp_send(&v6, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.daddr.to_string(), "::1");
        assert_eq!(e.size, 512);
    }

    #[test]
    fn socket_listen_resolved_carries_correlated_address() {
        let event = wire::SocketListenEvent {
            meta: wire_meta(b"nc"),
            laddr_v4: [0, 0, 0, 0],
            laddr_v6: [0; 16],
            lport: 4444,
            is_ipv6: false,
            addr_resolved: true,
            backlog: 1,
        };
        let Event::SocketListen(e) = socket_listen(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.local_addr.unwrap().to_string(), "0.0.0.0");
        assert_eq!(e.local_port, Some(4444));
        assert_eq!(e.backlog, 1);
    }

    #[test]
    fn socket_listen_unresolved_carries_no_address() {
        // Probe attached after bind(), or the kernel implicit-bound at listen()
        // time — this sensor never saw a matching bind() for this (pid, fd).
        let event = wire::SocketListenEvent {
            meta: wire_meta(b"nc"),
            laddr_v4: [9, 9, 9, 9], // garbage: must be ignored when unresolved
            laddr_v6: [0; 16],
            lport: 9999,
            is_ipv6: false,
            addr_resolved: false,
            backlog: 128,
        };
        let Event::SocketListen(e) = socket_listen(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.local_addr, None);
        assert_eq!(e.local_port, None);
        assert_eq!(e.backlog, 128);
    }

    #[test]
    fn socket_accept_carries_peer_not_local_address() {
        let event = wire::SocketAcceptEvent {
            meta: wire_meta(b"sshd"),
            listen_fd: 3,
            accepted_fd: 7,
            peer_addr_v4: [203, 0, 113, 42],
            peer_addr_v6: [0; 16],
            peer_port: 54321,
            is_ipv6: false,
        };
        let Event::SocketAccept(e) = socket_accept(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.listen_fd, 3);
        assert_eq!(e.accepted_fd, 7);
        assert_eq!(e.peer_addr.to_string(), "203.0.113.42");
        assert_eq!(e.peer_port, 54321);
    }

    fn packed_str<const N: usize>(s: &[u8]) -> ([u8; N], u16) {
        let mut buf = [0u8; N];
        buf[..s.len()].copy_from_slice(s);
        (buf, s.len() as u16)
    }

    #[test]
    fn mount_carries_source_and_fs_type() {
        let (mount_point, mount_point_len) = packed_str::<{ wire::MAX_PATH_LEN }>(b"/mnt/x");
        let (source, source_len) = packed_str::<{ wire::MAX_PATH_LEN }>(b"/");
        let (fs_type, fs_type_len) = packed_str::<{ wire::MAX_FS_TYPE_LEN }>(b"ext4");
        let event = wire::MountEvent {
            meta: wire_meta(b"mount"),
            mount_point,
            mount_point_len,
            source,
            source_len,
            fs_type,
            fs_type_len: fs_type_len as u8,
            readonly: false,
            mounted: true,
        };
        let Event::Mount(e) = mount(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.mount_point, "/mnt/x");
        assert_eq!(e.source.as_deref(), Some("/"));
        assert_eq!(e.fs_type.as_deref(), Some("ext4"));
        assert!(e.mounted);
        assert!(!e.readonly);
    }

    #[test]
    fn mount_readonly_bind_remount_is_flagged() {
        let (mount_point, mount_point_len) = packed_str::<{ wire::MAX_PATH_LEN }>(b"/");
        let event = wire::MountEvent {
            meta: wire_meta(b"mount"),
            mount_point,
            mount_point_len,
            source: [0; wire::MAX_PATH_LEN],
            source_len: 0,
            fs_type: [0; wire::MAX_FS_TYPE_LEN],
            fs_type_len: 0,
            readonly: true,
            mounted: true,
        };
        let Event::Mount(e) = mount(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert!(e.readonly);
        assert_eq!(e.source, None, "no source arg on this call shape");
        assert_eq!(e.fs_type, None);
    }

    #[test]
    fn unmount_has_no_source_or_fs_type() {
        let (mount_point, mount_point_len) = packed_str::<{ wire::MAX_PATH_LEN }>(b"/mnt/x");
        let event = wire::MountEvent {
            meta: wire_meta(b"umount"),
            mount_point,
            mount_point_len,
            source: [0; wire::MAX_PATH_LEN],
            source_len: 0,
            fs_type: [0; wire::MAX_FS_TYPE_LEN],
            fs_type_len: 0,
            readonly: false,
            mounted: false,
        };
        let Event::Mount(e) = mount(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert!(!e.mounted);
        assert_eq!(e.source, None);
        assert_eq!(e.fs_type, None);
    }

    #[test]
    fn signal_meta_is_the_sender_not_the_target() {
        let event = wire::SignalEvent {
            meta: wire_meta(b"bash"),
            signal: 9,
            target_pid: 400,
        };
        let Event::Signal(e) = signal(
            &event,
            0,
            Some("/usr/local/bin/synthaea-agent".to_string()),
            None,
        ) else {
            panic!("wrong variant")
        };
        assert_eq!(e.signal, 9);
        assert_eq!(e.target_pid, 400);
        assert_eq!(e.meta.comm, "bash", "meta must stay the sender");
        assert_eq!(
            e.target_image_path.as_deref(),
            Some("/usr/local/bin/synthaea-agent")
        );
    }

    fn wire_kernel_module(name: &[u8]) -> wire::KernelModuleEvent {
        let mut name_buf = [0u8; wire::MAX_MODULE_NAME_LEN];
        name_buf[..name.len()].copy_from_slice(name);
        wire::KernelModuleEvent {
            meta: wire_meta(b"rmmod"),
            name: name_buf,
            name_len: name.len() as u16,
            fd: -1,
            image_len: 0,
            flags: 0,
            action: 2,
        }
    }

    #[test]
    fn kernel_module_unload_carries_the_name() {
        let event = wire_kernel_module(b"evil_rootkit");
        let Event::KernelModule(e) = kernel_module(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.action, KernelModuleAction::Unload);
        assert_eq!(e.name.as_deref(), Some("evil_rootkit"));
        assert_eq!(e.fd, None);
        assert_eq!(e.image_len, None);
    }

    #[test]
    fn kernel_module_load_has_no_name_but_has_image_len() {
        let mut event = wire_kernel_module(b"");
        event.action = 0;
        event.image_len = 4096;
        let Event::KernelModule(e) = kernel_module(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.action, KernelModuleAction::Load);
        assert_eq!(e.name, None);
        assert_eq!(e.fd, None);
        assert_eq!(e.image_len, Some(4096));
    }

    #[test]
    fn kernel_module_load_fd_carries_the_fd_not_a_name() {
        let mut event = wire_kernel_module(b"");
        event.action = 1;
        event.fd = 5;
        let Event::KernelModule(e) = kernel_module(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.action, KernelModuleAction::LoadFd);
        assert_eq!(e.name, None);
        assert_eq!(e.fd, Some(5));
        assert_eq!(e.image_len, None);
    }

    #[test]
    fn bpf_operation_carries_the_raw_cmd() {
        let event = wire::BpfEvent {
            meta: wire_meta(b"evil_loader"),
            cmd: 5, // BPF_PROG_LOAD
        };
        let Event::BpfOperation(e) = bpf_operation(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.cmd, 5);
    }
}
