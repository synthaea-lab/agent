//! Rule engine tests: shared event builders here; one submodule per rule family
//! (`linux` — stateless + download/exec/web-server lineage; `windows` —
//! SELF-SPAWN, PARENT-SUSPECT, LOLBIN, BEACON).

use schema::{ConnectEvent, EventMeta, ExecEvent, FileOpenEvent, User};

use crate::{
    O_CREAT, O_WRONLY, RuleState, check_base64_decode, check_persistence_write,
    exclusions::{BEACON_THRESHOLD, SELF_SPAWN_THRESHOLD},
};

const O_RDONLY: u32 = 0;

fn meta() -> EventMeta {
    EventMeta {
        pid: 1234,
        ppid: 1,
        user: User::Unix {
            uid: 1000,
            gid: 1000,
        },
        timestamp_ns: 0,
        comm: String::new(),
        container: None,
    }
}

fn exec_event(cmdline: &str) -> ExecEvent {
    ExecEvent {
        meta: meta(),
        image_path: String::new(),
        cmdline: cmdline.to_string(),
        argv: vec![],
        parent_comm: None,
        parent_image_path: None,
        sha256: None,
        signature: None,
    }
}

fn exec_event_full(pid: u32, ppid: u32, comm: &str, cmdline: &str, timestamp_ns: u64) -> ExecEvent {
    let mut event = exec_event(cmdline);
    event.meta.pid = pid;
    event.meta.ppid = ppid;
    event.meta.timestamp_ns = timestamp_ns;
    event.meta.comm = comm.to_string();
    event
}

/// A Windows-flavoured exec event (`User::Windows`). SELF-SPAWN is gated on the
/// platform (Windows-calibrated, no comm allowlist — see the rule doc), so its
/// tests build events this way; `exec_event_full` stays `User::Unix`.
fn exec_event_win(pid: u32, ppid: u32, comm: &str, cmdline: &str, timestamp_ns: u64) -> ExecEvent {
    let mut event = exec_event_full(pid, ppid, comm, cmdline, timestamp_ns);
    event.meta.user = User::Windows {
        sid: "S-1-5-21-0-0-0-1000".to_string(),
        integrity_level: Some(0x2000),
    };
    event
}

fn file_open_event(path: &str, flags: u32) -> FileOpenEvent {
    FileOpenEvent {
        meta: meta(),
        path: path.to_string(),
        flags,
    }
}

fn file_open_event_full(
    pid: u32,
    comm: &str,
    path: &str,
    flags: u32,
    timestamp_ns: u64,
) -> FileOpenEvent {
    let mut event = file_open_event(path, flags);
    event.meta.pid = pid;
    event.meta.timestamp_ns = timestamp_ns;
    event.meta.comm = comm.to_string();
    event
}

fn connect_event_full(
    pid: u32,
    comm: &str,
    daddr_v4: [u8; 4],
    dport: u16,
    timestamp_ns: u64,
) -> ConnectEvent {
    let mut meta = meta();
    meta.pid = pid;
    meta.timestamp_ns = timestamp_ns;
    meta.comm = comm.to_string();
    ConnectEvent {
        meta,
        daddr: std::net::IpAddr::V4(daddr_v4.into()),
        dport,
    }
}

mod linux;
mod windows;
