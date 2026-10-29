//! Rule engine tests: shared event builders here; one submodule per rule family
//! (`linux` — stateless + download/exec/web-server lineage; `windows` —
//! SELF-SPAWN, PARENT-SUSPECT, LOLBIN, BEACON; `quarantine` — download-provenance
//! mark → exec, T1204.002).

use schema::{
    ConnectEvent, ContainerContext, EventMeta, ExecEvent, FileOpenEvent, ListenPortEvent,
    NetworkFlowEvent, PolicyDenialEvent, User,
};

use crate::{
    O_CREAT, O_WRONLY, RuleState, check_account_creation_persistence, check_base64_decode,
    check_btm_launch_item_persistence, check_doh_dot_connection, check_encoded_powershell,
    check_kerberos_from_non_lsass, check_ld_preload_hijack, check_persistence_write,
    check_proc_root_escape, check_scheduled_task_persistence,
    check_scheduled_task_update_persistence, check_service_install_persistence,
    check_service_unusual_outbound, check_systemd_service_persistence,
    exclusions::{
        AUTH_FAILURE_THRESHOLD, BEACON_THRESHOLD, BURST_WRITE_BYTES_THRESHOLD,
        MEMFD_EXEC_WINDOW_NS, POLICY_DENIAL_ALERT_CAP, POLICY_DENIAL_SUBJECT_CAP,
        RANSOMWARE_RENAME_THRESHOLD, RANSOMWARE_RENAME_WINDOW_NS, SCAN_SPREAD_THRESHOLD,
        SCAN_SPREAD_WINDOW_NS, SELF_SPAWN_THRESHOLD, SELF_SPAWN_TRUSTED_THRESHOLD,
        TOUCHED_FILES_PER_PID, TOUCHED_FILES_PID_CAP,
    },
    state::COUNTER_CAP,
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

fn file_delete_event_full(
    pid: u32,
    comm: &str,
    path: &str,
    timestamp_ns: u64,
) -> schema::FileDeleteEvent {
    schema::FileDeleteEvent {
        path: path.to_string(),
        meta: EventMeta {
            pid,
            comm: comm.to_string(),
            timestamp_ns,
            ..meta()
        },
    }
}

/// A `memfd_create` returning fd 3 — the first free descriptor after stdio, and the
/// `<n>` every `/proc/self/fd/3` exec in these tests names.
fn memfd_create_event_full(pid: u32, timestamp_ns: u64) -> schema::MemfdCreateEvent {
    memfd_create_event_with_fd(pid, timestamp_ns, 3)
}

fn memfd_create_event_with_fd(pid: u32, timestamp_ns: u64, fd: i32) -> schema::MemfdCreateEvent {
    schema::MemfdCreateEvent {
        meta: EventMeta {
            pid,
            timestamp_ns,
            ..meta()
        },
        fd,
        ..schema::fixtures::memfd_create()
    }
}

fn file_write_event_full(
    pid: u32,
    comm: &str,
    bytes_requested: u64,
    timestamp_ns: u64,
) -> schema::FileWriteEvent {
    schema::FileWriteEvent {
        meta: EventMeta {
            pid,
            comm: comm.to_string(),
            timestamp_ns,
            ..meta()
        },
        bytes_requested,
        ..schema::fixtures::file_write()
    }
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
        protocol: schema::IPPROTO_TCP,
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
        protocol: schema::IPPROTO_TCP,
    }
}

fn policy_denial_event_full(
    mechanism: &str,
    subject_context: Option<&str>,
    object_context: Option<&str>,
    object_class: Option<&str>,
    enforced: bool,
) -> PolicyDenialEvent {
    PolicyDenialEvent {
        meta: meta(),
        mechanism: mechanism.to_string(),
        subject_context: subject_context.map(str::to_string),
        object_context: object_context.map(str::to_string),
        object_class: object_class.map(str::to_string),
        enforced,
        ..schema::fixtures::policy_denial()
    }
}

mod bits;

/// Like [`policy_denial_event_full`], with an explicit `action` (#813): the other
/// helper's many callers don't care about it (it defaults to `None` via
/// `schema::fixtures::policy_denial()`), so it stays a 5-argument helper and this one
/// is reached for only the few tests that do.
fn policy_denial_event_with_action(
    subject_context: Option<&str>,
    object_context: Option<&str>,
    object_class: Option<&str>,
    action: Option<&str>,
) -> PolicyDenialEvent {
    PolicyDenialEvent {
        action: action.map(str::to_string),
        ..policy_denial_event_full(
            "selinux",
            subject_context,
            object_context,
            object_class,
            true,
        )
    }
}

std::thread_local! {
    static CAPTURED_LOGS: std::cell::RefCell<Option<Vec<u8>>> =
        const { std::cell::RefCell::new(None) };
}

/// Writes into the calling thread's [`captured_logs`] buffer, or nowhere when that
/// thread is not capturing.
struct ThreadCapture;

impl std::io::Write for ThreadCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        CAPTURED_LOGS.with_borrow_mut(|captured| {
            if let Some(captured) = captured {
                captured.extend_from_slice(buf);
            }
        });
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Runs `f` and returns what it logged through `tracing` on the calling thread.
///
/// One process-wide subscriber, installed once, that routes each thread's output to
/// that thread's own buffer — not `tracing::subscriber::with_default` (#876, #885).
/// While a scoped subscriber is the only live dispatcher, `tracing-core` (0.1.36)
/// computes a callsite's cached interest from the default of whichever thread
/// registers it, so a parallel test hitting the same `warn!` first, with no
/// subscriber of its own, caches it as "never" for the whole process and the
/// capturing test reads nothing. A global default is every thread's default, so no
/// registration order can disable a callsite under it.
fn captured_logs(f: impl FnOnce()) -> String {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_writer(|| ThreadCapture)
            .with_ansi(false)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("no other test in this binary sets a global subscriber");
    });
    CAPTURED_LOGS.with_borrow_mut(|captured| *captured = Some(Vec::new()));
    f();
    let captured = CAPTURED_LOGS
        .with_borrow_mut(Option::take)
        .unwrap_or_default();
    String::from_utf8_lossy(&captured).into_owned()
}

#[test]
fn captured_logs_sees_a_callsite_another_thread_registered_first() {
    // The #876/#885 race made deterministic: under `with_default`, the spawned thread
    // (no subscriber of its own) registers the callsite as "never" and the capturing
    // thread's own call is then filtered out before dispatch, so this read 0.
    fn probe() {
        tracing::warn!("captured-logs probe");
    }
    let logs = captured_logs(|| {
        std::thread::spawn(probe).join().expect("probe thread");
        probe();
    });
    assert_eq!(
        logs.matches("captured-logs probe").count(),
        1,
        "exactly this thread's line, not zero and not the other thread's too: {logs}"
    );
}

mod ads;
mod coverage;
mod credfiles;
mod egressdomain;
mod linux;
mod logon;
mod motw_removal;
mod persistence;
mod policy_denial_windows;
mod quarantine;
mod ransomware_windows;
mod raw_volume;
mod rdp;
mod recon;
mod scan_vertical;
mod security_discovery;
mod securitytool;
mod service_stop;
mod session;
mod ssh_fanout;
mod staging;
mod sudo;
mod tamper;
mod timestomp;
mod windows;
