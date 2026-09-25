//! Rule engine tests: shared event builders here; one submodule per rule family
//! (`linux` — stateless + download/exec/web-server lineage; `windows` —
//! SELF-SPAWN, PARENT-SUSPECT, LOLBIN, BEACON; `quarantine` — download-provenance
//! mark → exec, T1204.002).

use schema::{
    ConnectEvent, ContainerContext, EventMeta, ExecEvent, FileOpenEvent, ListenPortEvent,
    NetworkFlowEvent, User,
};

use crate::{
    O_CREAT, O_WRONLY, RuleState, check_account_creation_persistence, check_base64_decode,
    check_btm_launch_item_persistence, check_encoded_powershell, check_ld_preload_hijack,
    check_persistence_write, check_proc_root_escape, check_scheduled_task_persistence,
    check_scheduled_task_update_persistence, check_service_install_persistence,
    check_systemd_service_persistence,
    exclusions::{
        AUTH_FAILURE_THRESHOLD, BEACON_THRESHOLD, RANSOMWARE_RENAME_THRESHOLD,
        RANSOMWARE_RENAME_WINDOW_NS, SELF_SPAWN_THRESHOLD,
    },
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
        ..schema::fixtures::meta()
    }
}

fn exec_event(cmdline: &str) -> ExecEvent {
    ExecEvent {
        meta: meta(),
        cmdline: cmdline.to_string(),
        ..schema::fixtures::exec()
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

fn file_rename_event_full(
    pid: u32,
    comm: &str,
    old_path: &str,
    new_path: &str,
    timestamp_ns: u64,
) -> schema::FileRenameEvent {
    let mut event = schema::FileRenameEvent {
        old_path: old_path.to_string(),
        new_path: new_path.to_string(),
        ..schema::fixtures::file_rename()
    };
    event.meta = meta();
    event.meta.pid = pid;
    event.meta.timestamp_ns = timestamp_ns;
    event.meta.comm = comm.to_string();
    event
}

fn file_open_event_containerized(path: &str, container_id: &str) -> FileOpenEvent {
    let mut event = file_open_event(path, O_RDONLY);
    event.meta.container = Some(ContainerContext {
        id: container_id.to_string(),
        image: None,
        name: None,
    });
    event
}

/// Every alert the agent would raise for one `FileOpenEvent` on a fresh state:
/// the stateless dispatcher plus `RuleState::on_file_open`, as `agent`'s sink
/// routes it.
fn all_file_open_alerts(event: &FileOpenEvent) -> Vec<crate::Alert> {
    let mut alerts = crate::evaluate_file_open(event);
    alerts.extend(RuleState::new().on_file_open(event));
    alerts
}

/// A `FileOpenEvent` shaped like what `sensor-windows-eventlog` pushes on a
/// Security event 4698 (scheduled task creation): the `flags` field carries the
/// `FLAG_PERSISTENCE_TASK_ARTIFACT` bit, `path` is the task's action path, and
/// `comm` is the task's leaf name.
fn file_open_event_scheduled_task(task_name: &str, action_path: &str) -> FileOpenEvent {
    let mut event = file_open_event(action_path, schema::FLAG_PERSISTENCE_TASK_ARTIFACT);
    event.meta.comm = task_name.to_string();
    event
}

/// A `FileOpenEvent` shaped like what `sensor-windows-eventlog` pushes on a
/// Security event 4702 (scheduled task updated): the
/// `FLAG_PERSISTENCE_TASK_UPDATE_ARTIFACT` bit, `path` the task's *new* action
/// path, `comm` the task's leaf name.
fn file_open_event_scheduled_task_update(task_name: &str, action_path: &str) -> FileOpenEvent {
    let mut event = file_open_event(action_path, schema::FLAG_PERSISTENCE_TASK_UPDATE_ARTIFACT);
    event.meta.comm = task_name.to_string();
    event
}

/// A `FileOpenEvent` shaped like what `sensor-windows-eventlog` pushes on a
/// System event 7045 (service install): the `flags` field carries the
/// `FLAG_PERSISTENCE_ARTIFACT` bit, `path` is the service's image path, and
/// `comm` is the service name.
fn file_open_event_service_install(service_name: &str, image_path: &str) -> FileOpenEvent {
    let mut event = file_open_event(image_path, schema::FLAG_PERSISTENCE_ARTIFACT);
    event.meta.comm = service_name.to_string();
    event
}

/// A `FileOpenEvent` shaped like what `sensor-windows-eventlog` pushes on a
/// Security event 4720 (local account creation): the `flags` field carries the
/// `FLAG_PERSISTENCE_ACCOUNT_ARTIFACT` bit, `path` is the new account's SID,
/// and `comm` is the SAM name.
fn file_open_event_account_created(account_name: &str, sid: &str) -> FileOpenEvent {
    let mut event = file_open_event(sid, schema::FLAG_PERSISTENCE_ACCOUNT_ARTIFACT);
    event.meta.comm = account_name.to_string();
    event
}

/// A `FileOpenEvent` shaped like what `sensor-linux-journal`'s
/// `persistence::UnitPersistenceTracker` pushes on a unit's first observed
/// start: the `flags` field carries the `FLAG_PERSISTENCE_SYSTEMD_ARTIFACT`
/// bit, and both `path` and `comm` are the unit name (no separate image-path
/// field exists on this side, unlike the Windows 7045 shape).
fn file_open_event_systemd_unit(unit_name: &str) -> FileOpenEvent {
    let mut event = file_open_event(unit_name, schema::FLAG_PERSISTENCE_SYSTEMD_ARTIFACT);
    event.meta.comm = unit_name.to_string();
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

fn network_flow_event_full(
    pid: u32,
    comm: &str,
    local_port: u16,
    daddr_v4: [u8; 4],
    dport: u16,
    timestamp_ns: u64,
) -> NetworkFlowEvent {
    let mut meta = meta();
    meta.pid = pid;
    meta.timestamp_ns = timestamp_ns;
    meta.comm = comm.to_string();
    NetworkFlowEvent {
        meta,
        local_port,
        daddr: std::net::IpAddr::V4(daddr_v4.into()),
        dport,
        protocol: 6, // IPPROTO_TCP
        ..schema::fixtures::network_flow()
    }
}

fn listen_port_event_full(
    pid: u32,
    comm: &str,
    local_addr_v4: [u8; 4],
    local_port: u16,
    timestamp_ns: u64,
) -> ListenPortEvent {
    let mut meta = meta();
    meta.pid = pid;
    meta.timestamp_ns = timestamp_ns;
    meta.comm = comm.to_string();
    ListenPortEvent {
        meta,
        local_addr: std::net::IpAddr::V4(local_addr_v4.into()),
        local_port,
    }
}

mod coverage;
mod linux;
mod persistence;
mod quarantine;
mod tamper;
mod windows;
