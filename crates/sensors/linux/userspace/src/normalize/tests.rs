use schema::{
    ContainerContext, Event, FileRenameEvent, IdentityChangeKind, KernelModuleAction,
    NamespaceSyscall,
};
use sensor_linux_wire as wire;

use super::{
    file::{
        AT_FDCWD, FILETIME_UNIX_EPOCH, OPEN_FLAGS_MASK, join_resolved, resolve_dirfd_path,
        set_time_path, unix_to_filetime,
    },
    process::exe_path_for_pid,
    *,
};

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
        process_generation: 0,
        parent_generation: 0,
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
        grandparent_pid: 0,
        parent_execd: 0,
        grandparent_generation: 0,
        argv_total: 0,
        argv_head_len: 0,
        argv_tail_len: 0,
    }
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_string()).collect()
}

#[test]
fn exec_keeps_argv_and_joins_cmdline() {
    let event = wire_exec(b"/usr/bin/curl", b"bash");
    let Event::Exec(e) = exec(
        &event,
        500,
        argv(&["curl", "-o", "/tmp/x"]),
        Some(0),
        Vec::new(),
        None,
    ) else {
        panic!("wrong variant")
    };
    assert_eq!(e.argv, ["curl", "-o", "/tmp/x"]);
    assert_eq!(e.cmdline, "curl -o /tmp/x");
    assert!(!e.cmdline_truncated);
    assert_eq!(e.argv_omitted_bytes, Some(0));
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

/// The argv-window design's truth table, the probe rows: bytes known to lie between the windows set
/// the
/// flag; a whole block or an unknown count does not.
#[test]
fn omitted_argv_bytes_set_the_truncation_flag_only_when_known_to_be_missing() {
    let event = wire_exec(b"/bin/sh", b"bash");
    for (omitted, flagged) in [(Some(0), false), (Some(2048), true), (None, false)] {
        let Event::Exec(e) = exec(
            &event,
            0,
            argv(&["sh", "-c", "x"]),
            omitted,
            Vec::new(),
            None,
        ) else {
            panic!("wrong variant")
        };
        assert_eq!(e.cmdline_truncated, flagged, "{omitted:?}");
        assert_eq!(e.argv_omitted_bytes, omitted);
    }
}

#[test]
fn exec_cuts_a_padded_argv_and_flags_it() {
    // #1112: an unprivileged exec with ~2 MiB of control bytes once became a
    // 21.6 MB detection, refused for good by the server, taking its whole spool
    // segment with it. Control bytes are the worst case: 6 JSON bytes each.
    let event = wire_exec(b"/bin/sh", b"bash");
    let padding = "\u{1}".repeat(2 * 1024 * 1024);
    let event = exec(
        &event,
        0,
        argv(&["sh", "-c", &padding]),
        Some(0),
        Vec::new(),
        None,
    );
    let Event::Exec(e) = &event else {
        panic!("wrong variant")
    };
    assert!(e.cmdline_truncated);
    assert_eq!(
        e.argv_omitted_bytes, None,
        "a budget cut does not measure what it dropped"
    );
    assert_eq!(e.argv[..2], ["sh", "-c"], "the head is kept");
    assert!(e.cmdline.len() < schema::ARGV_CAPTURE_BUDGET);
    let serialized = serde_json::to_vec(&event).expect("an event serializes");
    assert!(
        serialized.len() < 512 * 1024,
        "one exec serializes to {} bytes",
        serialized.len()
    );
}

#[test]
fn exec_image_path_ignores_spoofed_argv0() {
    // execve("/tmp/evil", {"/usr/sbin/sshd", ...}, ...)
    let event = wire_exec(b"/tmp/evil", b"bash");
    let Event::Exec(e) = exec(
        &event,
        0,
        argv(&["/usr/sbin/sshd", "-D"]),
        None,
        Vec::new(),
        None,
    ) else {
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
    let Event::Exec(e) = exec(&event, 0, Vec::new(), None, Vec::new(), None) else {
        panic!("wrong variant")
    };
    assert!(e.argv.is_empty());
    assert_eq!(e.cmdline, "");
    assert_eq!(e.image_path, "/bin/sh");
}

#[test]
fn exec_carries_security_env_when_present() {
    let event = wire_exec(b"/usr/bin/ls", b"bash");
    let env = vec![("LD_PRELOAD".to_string(), "/tmp/evil.so".to_string())];
    let Event::Exec(e) = exec(&event, 0, argv(&["ls"]), None, env.clone(), None) else {
        panic!("wrong variant")
    };
    assert_eq!(e.env_security, env);
}

#[test]
fn exec_security_env_empty_for_plain_exec() {
    let event = wire_exec(b"/usr/bin/ls", b"bash");
    let Event::Exec(e) = exec(&event, 0, argv(&["ls"]), None, Vec::new(), None) else {
        panic!("wrong variant")
    };
    assert!(e.env_security.is_empty());
}

#[test]
fn exec_parent_comm_absent_when_lineage_missed() {
    let event = wire_exec(b"/bin/sh", b"");
    let Event::Exec(e) = exec(&event, 0, argv(&["sh"]), None, Vec::new(), None) else {
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
    let Event::Exec(e) = exec(&event, 0, argv(&["nginx"]), None, Vec::new(), Some(ctx)) else {
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
    let Event::Exec(e) = exec(&event, 0, argv(&["nginx"]), None, Vec::new(), Some(ctx)) else {
        panic!("wrong variant")
    };
    let container = e.meta.container.expect("container attributed");
    assert_eq!(container.image.as_deref(), Some("nginx:1.27"));
    assert_eq!(container.name.as_deref(), Some("web1"));
}

#[test]
fn bare_metal_process_has_no_container() {
    let event = wire_exec(b"/usr/bin/curl", b"bash");
    let Event::Exec(e) = exec(&event, 0, argv(&["curl"]), None, Vec::new(), None) else {
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

/// #1129: `openat(.., 0x4000_0000 | O_RDONLY)` succeeds and the probe records the bit, so
/// an unprivileged process raised T1543.002 with a path of its choosing. The synthetic bits
/// are cleared; every real `open(2)` flag, `O_TMPFILE` included, is kept.
#[test]
fn an_open_cannot_carry_a_synthetic_flag() {
    let open = |flags: u32| {
        let mut path = [0u8; wire::MAX_PATH_LEN];
        path[..11].copy_from_slice(b"/etc/passwd");
        let event = wire::FileOpenEvent {
            meta: wire_meta(b"forge"),
            path,
            path_len: 11,
            flags,
        };
        let Event::FileOpen(e) = file_open(&event, 0, None) else {
            panic!("wrong variant")
        };
        e.flags
    };
    for synthetic in [
        schema::FLAG_PERSISTENCE_ARTIFACT,
        schema::FLAG_PERSISTENCE_TASK_ARTIFACT,
        schema::FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN,
        schema::FLAG_PERSISTENCE_ACCOUNT_ARTIFACT,
        schema::FLAG_PERSISTENCE_SYSTEMD_ARTIFACT,
        schema::FLAG_PERSISTENCE_BTM_ARTIFACT,
        schema::FLAG_APPLICATION_BLOCKED,
        schema::FLAG_PERSISTENCE_TASK_UPDATE_ARTIFACT,
    ] {
        assert_eq!(open(synthetic | 0o2), 0o2, "{synthetic:#010x}");
    }
    assert_eq!(open(u32::MAX), OPEN_FLAGS_MASK);
    // O_TMPFILE | O_RDWR (with O_DIRECTORY) and O_PATH | O_CLOEXEC stay whole.
    assert_eq!(open(0x0041_0002), 0x0041_0002);
    assert_eq!(open(0x0020_0000 | 0o2_000_000), 0x0020_0000 | 0o2_000_000);
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
        reserved: 0,
        old_dfd: AT_FDCWD,
        new_dfd: AT_FDCWD,
    };
    let Event::FileRename(e) = file_rename(&event, 0, None) else {
        panic!("wrong variant")
    };
    assert_eq!(e.old_path, "/home/user/invoice.pdf");
    assert_eq!(e.new_path, "/home/user/invoice.pdf.locked");
}

#[test]
fn exe_path_for_pid_returns_none_for_a_nonexistent_pid() {
    // Cross-platform: /proc doesn't exist at all on non-Linux, and this
    // pid won't exist as a real process either way — both must degrade
    // to None, not panic or error out through the caller.
    assert_eq!(exe_path_for_pid(u32::MAX), None);
}

#[test]
#[cfg(target_os = "linux")]
fn exe_path_for_pid_resolves_the_calling_processes_own_pid() {
    let resolved = exe_path_for_pid(std::process::id()).expect("this process is real");
    assert!(
        resolved.starts_with('/'),
        "expected an absolute path, got {resolved}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn file_rename_carries_the_renaming_processes_executable_path() {
    let mut old_path = [0u8; wire::MAX_PATH_LEN];
    let old_raw = b"/home/user/invoice.pdf\0";
    old_path[..old_raw.len()].copy_from_slice(old_raw);
    let mut new_path = [0u8; wire::MAX_PATH_LEN];
    let new_raw = b"/home/user/invoice.pdf.locked\0";
    new_path[..new_raw.len()].copy_from_slice(new_raw);
    let mut meta = wire_meta(b"encryptor");
    meta.pid = std::process::id();
    let event = wire::FileRenameEvent {
        meta,
        old_path,
        old_path_len: old_raw.len() as u16,
        new_path,
        new_path_len: new_raw.len() as u16,
        reserved: 0,
        old_dfd: AT_FDCWD,
        new_dfd: AT_FDCWD,
    };
    let Event::FileRename(e) = file_rename(&event, 0, None) else {
        panic!("wrong variant")
    };
    assert!(
        e.executable_path.is_some_and(|p| p.starts_with('/')),
        "expected the test binary's own exe path"
    );
}

fn set_time_event(names: &[&str], flags: u16) -> wire::FileSetTimeEvent {
    let mut components = [[0u8; wire::SET_TIME_COMPONENT_LEN]; wire::SET_TIME_COMPONENTS];
    for (slot, name) in components.iter_mut().zip(names) {
        slot[..name.len()].copy_from_slice(name.as_bytes());
    }
    wire::FileSetTimeEvent {
        meta: wire_meta(b"touch"),
        components,
        depth: names.len() as u8,
        reserved0: 0,
        flags,
        reserved1: 0,
        atime_sec: 123, // set only when the flag says so
        atime_nsec: 0,
        mtime_sec: 1_262_304_000, // 2010-01-01T00:00:00Z
        mtime_nsec: 500,
    }
}

#[test]
fn file_set_time_reports_only_the_times_the_caller_chose_in_filetime_units() {
    let event = set_time_event(&["a.sh", "tmp"], wire::SET_TIME_MTIME);
    let Event::FileSetTime(e) = file_set_time(&event, 0, None) else {
        panic!("expected FileSetTime")
    };
    assert_eq!(e.path, "/tmp/a.sh");
    assert_eq!(e.last_access_time, None);
    assert_eq!(e.creation_time, None);
    assert_eq!(e.change_time, None);
    // 2010-01-01 is 129_067_776_000_000_000 in FILETIME; 500 ns is five 100 ns ticks.
    assert_eq!(e.last_write_time, Some(129_067_776_000_000_005));
}

#[test]
fn file_set_time_path_is_joined_root_first_and_marks_an_incomplete_chain() {
    let whole = set_time_event(&["auth.log", "log", "var"], wire::SET_TIME_MTIME);
    assert_eq!(set_time_path(&whole), "/var/log/auth.log");
    let cut = set_time_event(
        &["auth.log", "log"],
        wire::SET_TIME_MTIME | wire::SET_TIME_TRUNCATED,
    );
    assert_eq!(set_time_path(&cut), "/.../log/auth.log");
    // A file at the root, an empty slot and a depth past the array are all handled.
    assert_eq!(set_time_path(&set_time_event(&["x"], 0)), "/x");
    assert_eq!(set_time_path(&set_time_event(&[], 0)), "/");
    let mut deep = set_time_event(&["a"], 0);
    deep.depth = 200;
    assert!(set_time_path(&deep).ends_with("/a") || set_time_path(&deep) == "/a");
}

#[test]
fn file_set_time_never_produces_an_unchanged_sentinel_or_wraps() {
    assert_eq!(unix_to_filetime(i64::MIN, 0), 1, "before 1601");
    assert_eq!(unix_to_filetime(i64::MAX, 0), i64::MAX, "past the range");
    assert_eq!(unix_to_filetime(0, -5), FILETIME_UNIX_EPOCH, "bad nsec");
    for t in [
        unix_to_filetime(-11_644_473_600, 0),
        unix_to_filetime(-20_000_000_000, 0),
    ] {
        assert!(t > 0, "{t}");
    }
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
fn udp_recv_reports_the_sender_and_received_size_for_both_families() {
    let v4 = wire::UdpRecvEvent {
        meta: wire_meta(b"dnsd"),
        peer_addr_v4: [203, 0, 113, 42],
        peer_addr_v6: [0; 16],
        peer_port: 53,
        is_ipv6: false,
        size: 31,
    };
    let Event::UdpRecv(e) = udp_recv(&v4, 0, None) else {
        panic!("wrong variant")
    };
    assert_eq!(e.peer_addr.to_string(), "203.0.113.42");
    assert_eq!(e.peer_port, 53);
    assert_eq!(e.size, 31);

    let mut p6 = [0u8; 16];
    p6[15] = 0x01;
    let v6 = wire::UdpRecvEvent {
        meta: wire_meta(b"dnsd"),
        peer_addr_v4: [0; 4],
        peer_addr_v6: p6,
        peer_port: 5353,
        is_ipv6: true,
        size: 64,
    };
    let Event::UdpRecv(e) = udp_recv(&v6, 0, None) else {
        panic!("wrong variant")
    };
    assert_eq!(e.peer_addr.to_string(), "::1");
    assert_eq!(e.peer_port, 5353);
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

#[test]
fn socket_create_maps_domain_type_protocol_and_fd_one_to_one() {
    // AF_PACKET (17) / SOCK_RAW (3): the shape worth flagging, not an
    // AF_INET socket bind/connect would already show.
    let event = wire::SocketCreateEvent {
        meta: wire_meta(b"tcpdump"),
        domain: 17,
        socket_type: 3,
        protocol: 768,
        fd: 5,
    };
    let Event::SocketCreate(e) = socket_create(&event, 0, None) else {
        panic!("wrong variant")
    };
    assert_eq!(e.domain, 17);
    assert_eq!(e.socket_type, 3);
    assert_eq!(e.protocol, 768);
    assert_eq!(e.fd, 5);
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
    let parties = SignalParties {
        target_image_path: Some("/usr/local/bin/synthaea-agent".to_string()),
        ..SignalParties::default()
    };
    let Event::Signal(e) = signal(&event, 0, parties, None) else {
        panic!("wrong variant")
    };
    assert_eq!(e.signal, 9);
    assert_eq!(e.target_unit, None);
    assert_eq!(e.target_pid, 400);
    assert_eq!(e.meta.comm, "bash", "meta must stay the sender");
    assert_eq!(
        e.target_image_path.as_deref(),
        Some("/usr/local/bin/synthaea-agent")
    );
}

#[test]
fn the_unreliable_sender_bit_is_stripped_from_the_signal_and_becomes_a_flag() {
    let event = wire::SignalEvent {
        meta: wire_meta(b"python3"),
        signal: 9 | wire::SIGNAL_SENDER_UNRELIABLE,
        target_pid: 612,
    };
    let parties = SignalParties {
        target_unit: Some("auditd".to_string()),
        ..SignalParties::default()
    };
    let Event::Signal(e) = signal(&event, 0, parties, None) else {
        panic!("wrong variant")
    };
    assert_eq!(e.signal, 9);
    assert!(e.sender_unreliable);
    let plain = wire::SignalEvent { signal: 9, ..event };
    let Event::Signal(e) = signal(&plain, 0, SignalParties::default(), None) else {
        panic!("wrong variant")
    };
    assert!(!e.sender_unreliable);
}

#[test]
fn lost_signals_become_a_signal_event_carrying_the_count() {
    let Event::Signal(e) = signals_lost(40, 1234, 5) else {
        panic!("wrong variant")
    };
    assert_eq!((e.signals_lost, e.signal, e.target_pid), (40, 0, 0));
    assert_eq!((e.meta.pid, e.meta.timestamp_ns), (1234, 5));
}

#[test]
fn a_signal_to_a_security_tool_carries_its_unit_and_the_exe_read_at_scan_time() {
    let event = wire::SignalEvent {
        meta: wire_meta(b"pkill"),
        signal: 9,
        target_pid: 612,
    };
    let parties = SignalParties {
        target_image_path: Some("/usr/sbin/auditd".to_string()),
        target_unit: Some("auditd".to_string()),
        ..SignalParties::default()
    };
    let Event::Signal(e) = signal(&event, 0, parties, None) else {
        panic!("wrong variant")
    };
    assert_eq!(e.target_pid, 612);
    assert_eq!(e.target_unit.as_deref(), Some("auditd"));
    assert_eq!(e.target_image_path.as_deref(), Some("/usr/sbin/auditd"));
    assert_eq!(e.meta.comm, "pkill", "meta must stay the sender");
}

#[test]
fn a_signal_says_whether_its_sender_is_the_watchdog() {
    let event = wire::SignalEvent {
        meta: wire_meta(b"watchdog"),
        signal: 9,
        target_pid: 400,
    };
    let parties = SignalParties {
        sender_is_watchdog: true,
        ..SignalParties::default()
    };
    let Event::Signal(e) = signal(&event, 0, parties, None) else {
        panic!("wrong variant")
    };
    assert!(e.sender_is_watchdog);
    assert_eq!(e.target_unit, None);
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
    let Event::KernelModule(e) = kernel_module(&event, None, 0, None) else {
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
    let Event::KernelModule(e) = kernel_module(&event, None, 0, None) else {
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
    let Event::KernelModule(e) = kernel_module(&event, None, 0, None) else {
        panic!("wrong variant")
    };
    assert_eq!(e.action, KernelModuleAction::LoadFd);
    assert_eq!(e.name, None);
    assert_eq!(e.fd, Some(5));
    assert_eq!(e.path, None);
    assert_eq!(e.image_len, None);
}

#[test]
fn kernel_module_load_fd_carries_the_resolved_path() {
    let mut event = wire_kernel_module(b"");
    event.action = 1;
    event.fd = 5;
    let path = "/usr/lib/modules/6.12.0/kernel/drivers/net/dummy.ko.xz";
    let Event::KernelModule(e) = kernel_module(&event, Some(path.into()), 0, None) else {
        panic!("wrong variant")
    };
    assert_eq!(e.path.as_deref(), Some(path));
}

#[test]
fn kernel_module_path_only_applies_to_load_fd() {
    // A path from the caller is ignored for init_module/delete_module,
    // which have no fd to resolve.
    let event = wire_kernel_module(b"evil_rootkit");
    let Event::KernelModule(e) = kernel_module(&event, Some("/x.ko".into()), 0, None) else {
        panic!("wrong variant")
    };
    assert_eq!(e.path, None);
}

#[test]
fn prctl_carries_the_option_and_the_full_64_bit_argument() {
    // A capability number or a SECBIT_* mask fits 32 bits, but the syscall
    // argument is an `unsigned long`: nothing may narrow it on the way.
    let event = wire::PrctlEvent {
        meta: wire_meta(b"sandbox_init"),
        option: schema::PR_SET_SECUREBITS,
        arg: 0x1_0000_0003,
    };
    let Event::Prctl(e) = prctl(&event, 0, None) else {
        panic!("wrong variant")
    };
    assert_eq!(e.option, schema::PR_SET_SECUREBITS);
    assert_eq!(e.arg, 0x1_0000_0003);
    assert_eq!(e.meta.comm, "sandbox_init");
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

#[test]
fn identity_change_setuid_has_only_real() {
    let event = wire::IdentityChangeEvent {
        meta: wire_meta(b"su"),
        kind: 0,
        real: 1000,
        effective: 0,
        saved: 0,
    };
    let Event::IdentityChange(e) = identity_change(&event, 0, None) else {
        panic!("wrong variant")
    };
    assert_eq!(e.kind, IdentityChangeKind::SetUid);
    assert_eq!(e.real, 1000);
    assert_eq!(e.effective, None);
    assert_eq!(e.saved, None);
}

#[test]
fn identity_change_setresuid_carries_all_three() {
    let event = wire::IdentityChangeEvent {
        meta: wire_meta(b"su"),
        kind: 2,
        real: 1000,
        effective: 1000,
        saved: 0,
    };
    let Event::IdentityChange(e) = identity_change(&event, 0, None) else {
        panic!("wrong variant")
    };
    assert_eq!(e.kind, IdentityChangeKind::SetResUid);
    assert_eq!(e.real, 1000);
    assert_eq!(e.effective, Some(1000));
    assert_eq!(e.saved, Some(0));
}

#[test]
fn identity_change_setfsgid_has_only_real() {
    let event = wire::IdentityChangeEvent {
        meta: wire_meta(b"su"),
        kind: 5,
        real: 1000,
        effective: 0,
        saved: 0,
    };
    let Event::IdentityChange(e) = identity_change(&event, 0, None) else {
        panic!("wrong variant")
    };
    assert_eq!(e.kind, IdentityChangeKind::SetFsGid);
    assert_eq!(e.effective, None);
    assert_eq!(e.saved, None);
}

#[test]
fn cap_set_carries_the_full_64_bit_sets() {
    // CAP_SYS_ADMIN (21, low word) and CAP_BPF (39, high word, #457).
    let caps = 1 << 21 | 1 << 39;
    let event = wire::CapSetEvent {
        meta: wire_meta(b"evil"),
        target_pid: 0,
        effective: caps,
        permitted: caps,
        inheritable: 0,
    };
    let Event::CapSet(e) = cap_set(&event, 0, None) else {
        panic!("wrong variant")
    };
    assert_eq!(e.target_pid, 0);
    assert_eq!(e.effective, caps);
    assert_eq!(e.permitted, caps);
    assert_eq!(e.inheritable, 0);
}

#[test]
fn namespace_setns_carries_the_fd() {
    let event = wire::NamespaceEvent {
        meta: wire_meta(b"nsenter"),
        syscall: 0,
        fd: 3,
        flags: 0x4000_0000,
    };
    let Event::Namespace(e) = namespace(&event, 0, None) else {
        panic!("wrong variant")
    };
    assert_eq!(e.syscall, NamespaceSyscall::SetNs);
    assert_eq!(e.fd, Some(3));
    assert_eq!(e.flags, 0x4000_0000);
}

#[test]
fn namespace_unshare_has_no_fd() {
    let event = wire::NamespaceEvent {
        meta: wire_meta(b"unshare"),
        syscall: 1,
        fd: -1,
        flags: 0x0002_0000,
    };
    let Event::Namespace(e) = namespace(&event, 0, None) else {
        panic!("wrong variant")
    };
    assert_eq!(e.syscall, NamespaceSyscall::Unshare);
    assert_eq!(e.fd, None);
    assert_eq!(e.flags, 0x0002_0000);
}

fn rename_with(pid: u32, old: &[u8], old_dfd: i32, new: &[u8], new_dfd: i32) -> FileRenameEvent {
    let mut old_path = [0u8; wire::MAX_PATH_LEN];
    old_path[..old.len()].copy_from_slice(old);
    let mut new_path = [0u8; wire::MAX_PATH_LEN];
    new_path[..new.len()].copy_from_slice(new);
    let mut meta = wire_meta(b"mv");
    meta.pid = pid;
    let event = wire::FileRenameEvent {
        meta,
        old_path,
        old_path_len: old.len() as u16,
        new_path,
        new_path_len: new.len() as u16,
        reserved: 0,
        old_dfd,
        new_dfd,
    };
    let Event::FileRename(e) = file_rename(&event, 0, None) else {
        panic!("wrong variant")
    };
    e
}

#[test]
fn an_absolute_rename_path_is_never_touched() {
    let e = rename_with(u32::MAX, b"/tmp/a\0", AT_FDCWD, b"/tmp/b\0", 3);
    assert_eq!(
        (e.old_path.as_str(), e.new_path.as_str()),
        ("/tmp/a", "/tmp/b")
    );
}

#[test]
fn a_relative_path_whose_process_is_gone_stays_as_the_sensor_reported_it() {
    // No such pid: nothing to resolve against, so no guess.
    let e = rename_with(u32::MAX, b"f1\0", AT_FDCWD, b"f1.bak\0", AT_FDCWD);
    assert_eq!((e.old_path.as_str(), e.new_path.as_str()), ("f1", "f1.bak"));
}

#[test]
fn a_negative_dirfd_other_than_the_cwd_is_not_resolved() {
    assert_eq!(resolve_dirfd_path(std::process::id(), -1, b"x"), "x");
}

#[test]
#[cfg(target_os = "linux")]
fn a_relative_path_is_resolved_against_the_processs_cwd_for_at_fdcwd() {
    let cwd = std::env::current_dir().unwrap();
    let resolved = resolve_dirfd_path(std::process::id(), AT_FDCWD, b"f1.bak");
    assert_eq!(resolved, format!("{}/f1.bak", cwd.display()));
}

#[test]
#[cfg(target_os = "linux")]
fn a_relative_path_is_resolved_against_a_real_directory_fd() {
    use std::os::fd::AsRawFd as _;
    let dir = std::env::temp_dir().join(format!("normalize-dfd-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let handle = std::fs::File::open(&dir).unwrap();
    let canonical = std::fs::canonicalize(&dir).unwrap();

    let resolved = resolve_dirfd_path(std::process::id(), handle.as_raw_fd(), b"usr/bin/x");

    assert_eq!(resolved, format!("{}/usr/bin/x", canonical.display()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[cfg(target_os = "linux")]
fn a_dirfd_that_is_not_a_directory_is_not_resolved() {
    use std::os::fd::AsRawFd as _;
    let (reader, _writer) = std::io::pipe().unwrap();
    // /proc/<pid>/fd/<n> reads as `pipe:[ino]`, which is no directory.
    assert_eq!(
        resolve_dirfd_path(std::process::id(), reader.as_raw_fd(), b"x"),
        "x"
    );
}

#[test]
fn a_deleted_directory_is_not_a_base() {
    let base = std::path::Path::new("/tmp/gone (deleted)");
    assert_eq!(join_resolved(base, "f"), None);
    assert_eq!(join_resolved(std::path::Path::new("pipe:[1]"), "f"), None);
    assert_eq!(
        join_resolved(std::path::Path::new("/tmp/"), "f").as_deref(),
        Some("/tmp/f")
    );
}
/// A `DnsUdpQueryEvent` carrying `message` as its payload, from `dig` to 8.8.8.8.
fn dns_udp_event(message: &[u8]) -> wire::DnsUdpQueryEvent {
    let mut payload = [0u8; wire::MAX_DNS_UDP_PAYLOAD];
    let kept = message.len().min(payload.len());
    payload[..kept].copy_from_slice(&message[..kept]);
    wire::DnsUdpQueryEvent {
        meta: wire_meta(b"dig"),
        daddr_v4: [8, 8, 8, 8],
        daddr_v6: [0; 16],
        dport: 53,
        payload_len: kept as u16,
        is_ipv6: false,
        payload,
    }
}

/// A standard recursive query for `name` (dotted), type `qtype`.
fn dns_message(name: &str, qtype: u16) -> Vec<u8> {
    let mut m = vec![0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        m.push(label.len() as u8);
        m.extend(label.bytes());
    }
    m.push(0);
    m.extend(qtype.to_be_bytes());
    m.extend([0, 1]);
    m
}

#[test]
fn a_dns_udp_query_becomes_a_dns_query_event_with_no_answer() {
    let event = dns_udp_event(&dns_message("www.example.com", 28));
    let Some(Event::DnsQuery(e)) = dns_udp_query(&event, 0, None) else {
        panic!("a query must map to Event::DnsQuery")
    };
    assert_eq!(e.query, "www.example.com");
    assert_eq!(e.qtype, 28);
    // The response is not captured: no result, and a status that claims nothing.
    assert_eq!(e.result, None);
    assert!(e.results.is_empty());
    assert!(!e.results_truncated);
    assert_eq!(e.status, 0);
    assert_eq!(e.meta.comm, "dig");
}

#[test]
fn a_dns_udp_query_for_a_private_name_is_redacted_like_the_uprobe_path() {
    let event = dns_udp_event(&dns_message("db01.prod.internal", 1));
    let Some(Event::DnsQuery(e)) = dns_udp_query(&event, 0, None) else {
        panic!("wrong variant")
    };
    assert_eq!(e.query, "[REDACTED].internal");
}

#[test]
fn a_payload_that_is_not_a_dns_query_maps_to_nothing() {
    for junk in [
        b"#!/bin/sh\necho hello world, a script written to a reused descriptor\n".as_slice(),
        &[0u8; 40],
    ] {
        assert!(dns_udp_query(&dns_udp_event(junk), 0, None).is_none());
    }
}

#[test]
fn the_captured_length_bounds_what_is_read() {
    // The message is complete in the buffer, but the kernel said fewer bytes were copied:
    // the rest is zero fill, not data, and a cut question is refused.
    let message = dns_message("www.example.com", 1);
    let mut event = dns_udp_event(&message);
    event.payload_len = 20;
    assert!(dns_udp_query(&event, 0, None).is_none());
    // A length past the buffer is clamped, not trusted.
    event.payload_len = u16::MAX;
    assert!(dns_udp_query(&event, 0, None).is_some());
}
