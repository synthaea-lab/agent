//! Loading and attaching the eBPF side: the embedded object, the tracepoint
//! programs, and the `PROC_LINEAGE` map seeding. The public pieces
//! (`load_ebpf`, `load_program`, [`TRACEPOINTS`]) also serve the agent's
//! preflight, which loads programs without attaching them. Split out of
//! `sensor.rs` when that file had accumulated five concerns.

use schema::sensor::SensorError;

use crate::proc::{parse_stat_ppid_comm, parse_stat_starttime};

/// The message-to-error helper every module in this crate shares.
pub(crate) fn err(msg: String) -> SensorError {
    msg.into()
}

/// The tracepoints implemented to date: (program, category, name). `sched_process_fork`
/// and `sched_process_exit` maintain the `PROC_LINEAGE` map (parent pid/comm) that the
/// other probes read — attach them first so it is populating before events flow.
///
/// Both `sys_enter_openat` and `sys_enter_open` are attached: musl (and every busybox
/// applet linked against it) still issues the plain `open(2)` syscall directly, while
/// glibc rewrites `open()` into `openat(AT_FDCWD, ...)` since 2.26 — attaching only one
/// of the two misses file opens on whichever libc doesn't use it. Both feed the same
/// `FileOpenEvent`/`file_open` event type.
///
/// `sys_enter_write` (write/delete/rename telemetry, issue #262) covers `write(2)`
/// only — `writev`/`pwrite64`/`pwritev` are not yet attached. `sys_enter_unlink`/
/// `sys_enter_unlinkat` and `sys_enter_rename`/`sys_enter_renameat`/
/// `sys_enter_renameat2` are each attached in pairs/triples for the same libc-variant
/// reason as open above. `sys_enter_chmod`/`sys_enter_fchmodat` and
/// `sys_enter_chown`/`sys_enter_lchown`/`sys_enter_fchownat` (issue #262 Phase 2)
/// follow the same pattern — the fd-only variants (`fchmod`/`fchown`) are deferred.
///
/// `sys_enter_accept{,4}`/`sys_exit_accept{,4}` (issue #263 Phase 2) are this
/// sensor's first `sys_exit_*` attachments — `accept`/`accept4`'s peer address is
/// only populated once the kernel-side call returns, so the enter and exit halves
/// are attached as a pair (`ebpf/src/main.rs`'s `ACCEPT_ARGS` map correlates them).
///
/// `sys_enter_recvfrom`/`sys_exit_recvfrom` (issue #263) use the same pair for the
/// sender's address (`ebpf/src/main.rs`'s `RECVFROM_ARGS`).
///
/// `sys_enter_setxattr`/`sys_enter_removexattr` (issue #262 Phase 3) cover the
/// plain path-taking syscalls only — `lsetxattr`/`fsetxattr` (symlink/fd-only
/// variants) are deferred, same posture as `chmod`/`chown`'s fd-only siblings.
///
/// `sys_enter_mount`/`sys_enter_umount` (issue #362) feed `Event::Mount` — note
/// `sys_enter_umount`, not `sys_enter_umount2`: glibc's `umount2(2)` libc wrapper
/// maps to a kernel syscall the kernel itself names plain `umount`
/// (`fs/namespace.c`'s `SYSCALL_DEFINE2(umount, ...)`), confirmed live on the lab
/// (`sys_enter_umount2` does not exist). `move_mount(2)` is deferred (see
/// `sensor-linux-wire`'s `WIRE_VERSION` v13 changelog). `sys_enter_kill`/
/// `sys_enter_tgkill` feed `Event::Signal`, filtered
/// kernel-side to the agent's own pid by `SIGNAL_WATCH_PID` — [`write_signal_watch_pid`]
/// **must** run before these two are attached, same ordering requirement
/// `prime_proc_lineage` documents for the fork/exit pair above. `sys_enter_tkill` is
/// not attached — see `sensor-linux-wire`'s `WIRE_VERSION` v13 changelog for why.
///
/// `sys_enter_ptrace`/`sys_enter_process_vm_readv`/`sys_enter_process_vm_writev`/
/// `sys_enter_memfd_create` (issue #265) round out process injection/debugging
/// telemetry — no libc-variant pairing needed, each has exactly one syscall name.
pub const TRACEPOINTS: &[(&str, &str, &str)] = &[
    ("sched_process_fork", "sched", "sched_process_fork"),
    ("sched_process_exit", "sched", "sched_process_exit"),
    ("sched_process_exec", "sched", "sched_process_exec"),
    ("sys_enter_openat", "syscalls", "sys_enter_openat"),
    ("sys_enter_open", "syscalls", "sys_enter_open"),
    ("sys_enter_connect", "syscalls", "sys_enter_connect"),
    ("sys_enter_write", "syscalls", "sys_enter_write"),
    ("sys_enter_unlink", "syscalls", "sys_enter_unlink"),
    ("sys_enter_unlinkat", "syscalls", "sys_enter_unlinkat"),
    ("sys_enter_rename", "syscalls", "sys_enter_rename"),
    ("sys_enter_renameat", "syscalls", "sys_enter_renameat"),
    ("sys_enter_renameat2", "syscalls", "sys_enter_renameat2"),
    ("sys_enter_bind", "syscalls", "sys_enter_bind"),
    ("sys_enter_chmod", "syscalls", "sys_enter_chmod"),
    ("sys_enter_fchmodat", "syscalls", "sys_enter_fchmodat"),
    ("sys_enter_chown", "syscalls", "sys_enter_chown"),
    ("sys_enter_lchown", "syscalls", "sys_enter_lchown"),
    ("sys_enter_fchownat", "syscalls", "sys_enter_fchownat"),
    ("sys_enter_sendto", "syscalls", "sys_enter_sendto"),
    ("sys_enter_listen", "syscalls", "sys_enter_listen"),
    ("sys_enter_accept", "syscalls", "sys_enter_accept"),
    ("sys_enter_accept4", "syscalls", "sys_enter_accept4"),
    ("sys_exit_accept", "syscalls", "sys_exit_accept"),
    ("sys_exit_accept4", "syscalls", "sys_exit_accept4"),
    ("sys_enter_recvfrom", "syscalls", "sys_enter_recvfrom"),
    ("sys_exit_recvfrom", "syscalls", "sys_exit_recvfrom"),
    ("sys_enter_setxattr", "syscalls", "sys_enter_setxattr"),
    ("sys_enter_removexattr", "syscalls", "sys_enter_removexattr"),
    ("sys_enter_mount", "syscalls", "sys_enter_mount"),
    ("sys_enter_umount", "syscalls", "sys_enter_umount"),
    ("sys_enter_kill", "syscalls", "sys_enter_kill"),
    ("sys_enter_tgkill", "syscalls", "sys_enter_tgkill"),
    ("sys_enter_init_module", "syscalls", "sys_enter_init_module"),
    (
        "sys_enter_finit_module",
        "syscalls",
        "sys_enter_finit_module",
    ),
    (
        "sys_enter_delete_module",
        "syscalls",
        "sys_enter_delete_module",
    ),
    ("sys_enter_bpf", "syscalls", "sys_enter_bpf"),
    ("sys_enter_prctl", "syscalls", "sys_enter_prctl"),
    ("sys_enter_ptrace", "syscalls", "sys_enter_ptrace"),
    (
        "sys_enter_process_vm_readv",
        "syscalls",
        "sys_enter_process_vm_readv",
    ),
    (
        "sys_enter_process_vm_writev",
        "syscalls",
        "sys_enter_process_vm_writev",
    ),
    (
        "sys_enter_memfd_create",
        "syscalls",
        "sys_enter_memfd_create",
    ),
    // Pairs with the enter probe above: the returned fd only exists here (#510).
    ("sys_exit_memfd_create", "syscalls", "sys_exit_memfd_create"),
    ("sys_enter_setuid", "syscalls", "sys_enter_setuid"),
    ("sys_enter_setgid", "syscalls", "sys_enter_setgid"),
    ("sys_enter_setresuid", "syscalls", "sys_enter_setresuid"),
    ("sys_enter_setresgid", "syscalls", "sys_enter_setresgid"),
    ("sys_enter_setfsuid", "syscalls", "sys_enter_setfsuid"),
    ("sys_enter_setfsgid", "syscalls", "sys_enter_setfsgid"),
    ("sys_enter_capset", "syscalls", "sys_enter_capset"),
    ("sys_enter_setns", "syscalls", "sys_enter_setns"),
    ("sys_enter_unshare", "syscalls", "sys_enter_unshare"),
];

/// `sensor_linux_wire::LineageEntry` is `repr(C)` over two `u32`, a `[u8; 16]` and a `u64`,
/// laid out with no implicit padding (`reserved` is explicit) — every bit pattern is
/// valid, so it is plain-old-data. A transparent newtype carries the
/// `aya::Pod` impl (the orphan rule forbids implementing it on the wire type directly).
#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodLineage(sensor_linux_wire::LineageEntry);

// SAFETY: see the doc comment above — POD, no padding invariants, no invalid bit
// patterns.
unsafe impl aya::Pod for PodLineage {}

/// Loads the compiled eBPF object (bytecode embedded at build time), without
/// initializing the eBPF logger or loading/attaching any individual program. Shared
/// between the agent's preflight and [`LinuxSensor`](crate::LinuxSensor)'s `Sensor::run`.
///
/// # Errors
///
/// Returns [`SensorError`] when the embedded eBPF object fails to load (kernel
/// too old, verifier refusal at load, or missing BTF).
#[cfg(ebpf_embedded)]
pub fn load_ebpf() -> Result<aya::Ebpf, SensorError> {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: plain FFI call with a valid pointer to a stack-owned rlimit.
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        tracing::debug!(ret, "remove limit on locked memory failed");
    }

    load_embedded(None).map_err(|e| err(format!("failed to load the eBPF object: {e}")))
}

#[cfg(ebpf_embedded)]
fn load_embedded(tamper_pin: Option<&std::path::Path>) -> Result<aya::Ebpf, aya::EbpfError> {
    // `sched_process_fork`'s record layout differs across kernels (issue #415): feed
    // the probe the running kernel's offsets, or leave it disabled (it then inserts
    // nothing, and lineage falls back to the `/proc` priming snapshot) rather than
    // let it read garbage pids at a compiled-in guess.
    let fork = crate::tracefs::read_fork_layout();
    let (known, comm_offset, comm_data_loc, parent_pid_offset, child_pid_offset) = match fork {
        Some(l) => {
            tracing::info!(
                parent_comm_offset = l.parent_comm_offset,
                parent_comm_data_loc = l.parent_comm_data_loc,
                parent_pid_offset = l.parent_pid_offset,
                child_pid_offset = l.child_pid_offset,
                "sched_process_fork layout read from tracefs"
            );
            (
                1u32,
                l.parent_comm_offset,
                u32::from(l.parent_comm_data_loc),
                l.parent_pid_offset,
                l.child_pid_offset,
            )
        }
        None => {
            tracing::warn!(
                "sched_process_fork format unreadable or unrecognised (tracefs not mounted \
                 at /sys/kernel/tracing or /sys/kernel/debug/tracing?) — fork lineage \
                 disabled; exec events keep the parent only for processes primed from \
                 /proc at startup"
            );
            (0, 8, 0, 24, 44)
        }
    };

    let mut loader = aya::EbpfLoader::new();
    loader
        .override_global("FORK_LAYOUT_KNOWN", &known, true)
        .override_global("FORK_PARENT_COMM_OFFSET", &comm_offset, true)
        .override_global("FORK_PARENT_COMM_DATA_LOC", &comm_data_loc, true)
        .override_global("FORK_PARENT_PID_OFFSET", &parent_pid_offset, true)
        .override_global("FORK_CHILD_PID_OFFSET", &child_pid_offset, true);
    if let Some(path) = tamper_pin {
        loader.map_pin_path("SIGNAL_TAMPER_LAST", path);
    }
    loader.load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/sensor-linux-ebpf"
    )))
}

/// bpffs directory holding the agent's pinned maps (issue #362).
#[cfg(ebpf_embedded)]
const PIN_DIR: &str = "/sys/fs/bpf/synthaea";

/// Pin path of `SIGNAL_TAMPER_LAST`. Versioned by `WIRE_VERSION`: aya reuses an
/// existing pin as-is without checking its value size, so a pin left by an agent
/// built against another `SignalEvent` layout must never be picked up.
#[cfg(ebpf_embedded)]
fn tamper_pin_path() -> std::path::PathBuf {
    std::path::Path::new(PIN_DIR).join(format!(
        "signal_tamper_last_v{}",
        sensor_linux_wire::WIRE_VERSION
    ))
}

/// What [`reclaim_foreign_pin`] found at the pin path.
#[derive(Debug)]
#[cfg_attr(not(ebpf_embedded), allow(dead_code))]
enum PinState {
    /// No pin: nothing to do.
    Absent,
    /// The pin belongs to this user: aya reuses it, which is the point of pinning.
    Ours,
    /// A pin left by another user was removed, so a fresh one can be created.
    Reclaimed { owner: u32 },
    /// A pin left by another user is still there: this user cannot remove it.
    Stuck { owner: u32, error: std::io::Error },
}

/// Removes a pin that another user left (#589). A host that ran the agent as root
/// before the packaged unit (an older package, a lab run) keeps
/// `signal_tamper_last_v*` owned by `root:root 0600`, which the unprivileged
/// `synthaea` agent can neither open nor replace: it then started without the pin and
/// logged only a generic warning. The pin directory is the agent's own (`0700`, owned
/// by it), and unlinking needs write access to the directory, not to the file, so the
/// agent can clear the stale entry itself. Only a pin owned by someone else is
/// touched; its own is the cross-restart state this exists to keep.
#[cfg_attr(not(ebpf_embedded), allow(dead_code))]
fn reclaim_foreign_pin(pin: &std::path::Path, me: u32) -> PinState {
    use std::os::unix::fs::MetadataExt as _;

    let Ok(meta) = std::fs::symlink_metadata(pin) else {
        return PinState::Absent;
    };
    if meta.uid() == me {
        return PinState::Ours;
    }
    let owner = meta.uid();
    match std::fs::remove_file(pin) {
        Ok(()) => PinState::Reclaimed { owner },
        Err(error) => PinState::Stuck { owner, error },
    }
}

/// [`load_ebpf`] for `LinuxSensor::run` (issue #362): same object, but
/// `SIGNAL_TAMPER_LAST` is pinned under [`PIN_DIR`] so it outlives the agent. A
/// `SIGKILL` is then still attributable after the restart that follows it. Without
/// bpffs (not mounted, or no permission to
/// create the directory) the object loads unpinned instead, with a warning: the
/// sensor keeps running, only cross-restart `SIGKILL` attribution is lost.
///
/// # Errors
///
/// Same as [`load_ebpf`].
#[cfg(ebpf_embedded)]
pub(crate) fn load_ebpf_for_run() -> Result<aya::Ebpf, SensorError> {
    use std::os::unix::fs::PermissionsExt as _;

    let pin = tamper_pin_path();
    let pinned = std::fs::create_dir_all(PIN_DIR)
        .and_then(|()| std::fs::set_permissions(PIN_DIR, std::fs::Permissions::from_mode(0o700)))
        .map_err(|e| e.to_string())
        .and_then(|()| {
            // SAFETY: `geteuid` takes no arguments, touches no memory and cannot fail.
            let me = unsafe { libc::geteuid() };
            match reclaim_foreign_pin(&pin, me) {
                PinState::Reclaimed { owner } => tracing::info!(
                    pin = %pin.display(),
                    owner,
                    "removed a SIGNAL_TAMPER_LAST pin left by another user; creating a fresh one"
                ),
                PinState::Stuck { owner, error } => tracing::warn!(
                    pin = %pin.display(),
                    owner,
                    %error,
                    "a SIGNAL_TAMPER_LAST pin left by another user cannot be removed by this \
                     user: remove it with `sudo rm {}` and restart",
                    pin.display()
                ),
                PinState::Absent | PinState::Ours => {}
            }
            load_embedded(Some(&pin)).map_err(|e| e.to_string())
        });
    match pinned {
        Ok(ebpf) => Ok(ebpf),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "could not pin SIGNAL_TAMPER_LAST under {PIN_DIR}: a SIGKILL sent to the \
                 agent will not be attributable after its restart"
            );
            load_ebpf()
        }
    }
}

/// This build carries no embedded probes (bpf-linker was absent at build time — see
/// build.rs). The sensor is present but cannot start; the error says how to fix it.
///
/// # Errors
///
/// Always errors in this build configuration — the message says how to provision
/// the eBPF toolchain and rebuild.
#[cfg(not(ebpf_embedded))]
pub fn load_ebpf() -> Result<aya::Ebpf, SensorError> {
    Err(err(
        "sensor-linux was built without embedded eBPF probes (bpf-linker not on PATH \
         at build time) — provision the eBPF toolchain (lab/provisioning/linux-toolchain.sh) \
         and rebuild"
            .to_string(),
    ))
}

/// See the `ebpf_embedded` variant: this build cannot load anything.
///
/// # Errors
///
/// Always, same as [`load_ebpf`] in this configuration.
#[cfg(not(ebpf_embedded))]
pub(crate) fn load_ebpf_for_run() -> Result<aya::Ebpf, SensorError> {
    load_ebpf()
}

/// Loads (kernel verifier included) the program `program_name` without attaching it.
///
/// # Errors
///
/// Returns [`SensorError`] when the program is missing from the eBPF object, is
/// not a tracepoint, or is rejected by the kernel verifier.
pub fn load_program(ebpf: &mut aya::Ebpf, program_name: &str) -> Result<(), SensorError> {
    let program: &mut aya::programs::TracePoint = ebpf
        .program_mut(program_name)
        .ok_or_else(|| err(format!("program `{program_name}` not found in eBPF object")))?
        .try_into()
        .map_err(|e| err(format!("`{program_name}` is not a tracepoint: {e}")))?;
    program
        .load()
        .map_err(|e| err(format!("kernel verifier rejected `{program_name}`: {e}")))?;
    Ok(())
}

pub(crate) fn attach_tracepoint(
    ebpf: &mut aya::Ebpf,
    program_name: &str,
    category: &str,
    name: &str,
) -> Result<(), SensorError> {
    load_program(ebpf, program_name)?;
    let program: &mut aya::programs::TracePoint = ebpf
        .program_mut(program_name)
        .expect("loaded just above")
        .try_into()
        .expect("checked just above");
    program.attach(category, name).map_err(|e| {
        err(format!(
            "failed to attach {category}:{name} tracepoint (needs CAP_BPF/root): {e}"
        ))
    })?;
    Ok(())
}

/// Pre-fills the `PROC_LINEAGE` eBPF map with the processes already running, read from
/// `/proc`. Without this, `ppid`/`parent_comm` are only known for processes that
/// `fork()` *after* the probe attaches — every already-running service (nginx, sshd,
/// systemd units started at boot) would report `ppid = 0`. Best-effort: a `/proc/<pid>`
/// that vanishes mid-scan is skipped; a full map stops the scan. There is a small race
/// window (a process forking between this scan and the `sched_process_fork` attach) —
/// accepted, it self-heals on that process's next child.
pub(crate) fn prime_proc_lineage(ebpf: &mut aya::Ebpf) -> Result<u32, SensorError> {
    let map = ebpf
        .map_mut("PROC_LINEAGE")
        .ok_or_else(|| err("map PROC_LINEAGE not found in eBPF object".to_string()))?;
    let mut lineage: aya::maps::HashMap<_, u32, PodLineage> = aya::maps::HashMap::try_from(map)
        .map_err(|e| err(format!("PROC_LINEAGE is not a hash map: {e}")))?;

    let entries = std::fs::read_dir("/proc").map_err(|e| err(format!("read /proc: {e}")))?;
    // First pass: every process's identity, so the second can name each parent's
    // incarnation (issue #519) whichever order `/proc` lists them in.
    let mut scanned: Vec<(u32, u32, String, u64)> = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(stat) = std::fs::read(entry.path().join("stat")) else {
            continue;
        };
        let Ok(stat) = std::str::from_utf8(&stat) else {
            continue;
        };
        let Some((ppid, comm)) = parse_stat_ppid_comm(stat) else {
            continue;
        };
        // The pid's incarnation stamp. A process that predates the agent never went
        // through our `sched_process_fork`, so its stamp is its own `starttime`,
        // tagged so it can never equal a live `bpf_ktime_get_ns()` stamp. `0` ("no
        // stamp") when `starttime` is unreadable: better unknown than wrong.
        let generation = parse_stat_starttime(stat)
            .map_or(0, |ticks| ticks | sensor_linux_wire::PRIMED_GENERATION_BIT);
        scanned.push((pid, ppid, comm.to_string(), generation));
    }
    let generation_of: std::collections::HashMap<u32, u64> =
        scanned.iter().map(|(pid, _, _, g)| (*pid, *g)).collect();

    let mut primed = 0u32;
    for (pid, ppid, comm, generation) in &scanned {
        let mut val = sensor_linux_wire::LineageEntry {
            ppid: *ppid,
            comm: [0u8; sensor_linux_wire::TASK_COMM_LEN],
            reserved: 0,
            generation: *generation,
            parent_generation: generation_of.get(ppid).copied().unwrap_or(0),
        };
        let bytes = comm.as_bytes();
        let n = bytes.len().min(sensor_linux_wire::TASK_COMM_LEN);
        val.comm[..n].copy_from_slice(&bytes[..n]);

        if lineage.insert(*pid, PodLineage(val), 0).is_ok() {
            primed += 1;
        }
    }
    Ok(primed)
}

/// Writes the agent's own pid into `SIGNAL_WATCH_PID` (issue #362) — **must** run
/// before `sys_enter_kill`/`sys_enter_tgkill` are attached, otherwise those probes
/// read the map's zero-initialized default (`0`, which `is_watched_signal_target`
/// treats as "watch nothing") and silently drop every signal sent to the agent
/// until this call catches up. Same self-pid `own_pid` computation
/// `LinuxSensor::run_async`'s drain loop excludes its own events with (issue #340) —
/// deliberately not the identical value in general (a future watchdog/multi-pid
/// extension would diverge here), just the same source for this v1's single slot.
///
/// # Errors
///
/// Returns [`SensorError`] when `SIGNAL_WATCH_PID` is missing from the eBPF object
/// or the write itself fails.
pub(crate) fn write_signal_watch_pid(ebpf: &mut aya::Ebpf, pid: u32) -> Result<(), SensorError> {
    let map = ebpf
        .map_mut("SIGNAL_WATCH_PID")
        .ok_or_else(|| err("map SIGNAL_WATCH_PID not found in eBPF object".to_string()))?;
    let mut watch: aya::maps::Array<_, u32> = aya::maps::Array::try_from(map)
        .map_err(|e| err(format!("SIGNAL_WATCH_PID is not an array map: {e}")))?;
    watch
        .set(0, pid, 0)
        .map_err(|e| err(format!("failed to write SIGNAL_WATCH_PID: {e}")))
}

/// `sensor_linux_wire::SignalEvent` is `repr(C)` over integers and byte arrays, so
/// every bit pattern is valid. Same newtype reasoning as [`PodLineage`].
#[repr(transparent)]
#[derive(Clone, Copy)]
pub(crate) struct PodSignal(pub(crate) sensor_linux_wire::SignalEvent);

// SAFETY: see the doc comment above.
unsafe impl aya::Pod for PodSignal {}

/// Handle on `SIGNAL_TAMPER_LAST` (issue #362): the last `SIGKILL` the probes saw
/// aimed at the agent, written kernel-side before delivery.
pub(crate) type TamperSlot = aya::maps::Array<aya::maps::MapData, PodSignal>;

/// Takes `SIGNAL_TAMPER_LAST` out of `ebpf`.
///
/// # Errors
///
/// Returns [`SensorError`] when the map is missing from the eBPF object or is not
/// an array of `SignalEvent`.
pub(crate) fn take_tamper_slot(ebpf: &mut aya::Ebpf) -> Result<TamperSlot, SensorError> {
    let map = ebpf
        .take_map("SIGNAL_TAMPER_LAST")
        .ok_or_else(|| err("map SIGNAL_TAMPER_LAST not found in eBPF object".to_string()))?;
    aya::maps::Array::try_from(map)
        .map_err(|e| err(format!("SIGNAL_TAMPER_LAST is not an array map: {e}")))
}

/// The recorded `SIGKILL`, if any. An all-zero slot (never written, or cleared)
/// has a zero timestamp, which no real event has.
pub(crate) fn read_tamper_slot(slot: &TamperSlot) -> Option<sensor_linux_wire::SignalEvent> {
    let PodSignal(event) = slot.get(&0, 0).ok()?;
    (event.meta.timestamp_ns != 0).then_some(event)
}

/// Zeroes the slot, so the same `SIGKILL` is never reported twice.
///
/// # Errors
///
/// Returns [`SensorError`] when the map write fails.
pub(crate) fn clear_tamper_slot(slot: &mut TamperSlot) -> Result<(), SensorError> {
    // SAFETY: `SignalEvent` is plain-old-data (see `PodSignal`), so all-zero is a
    // valid value.
    let zero: sensor_linux_wire::SignalEvent = unsafe { core::mem::zeroed() };
    slot.set(0, PodSignal(zero), 0)
        .map_err(|e| err(format!("failed to clear SIGNAL_TAMPER_LAST: {e}")))
}

#[cfg(all(test, target_os = "linux"))]
mod pin_tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use super::*;

    fn dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sensor-pin-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn my_uid(path: &std::path::Path) -> u32 {
        std::fs::metadata(path).unwrap().uid()
    }

    #[test]
    fn no_pin_means_nothing_to_do() {
        let d = dir("absent");
        assert!(matches!(
            reclaim_foreign_pin(&d.join("signal_tamper_last_v21"), my_uid(&d)),
            PinState::Absent
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_pin_this_user_owns_is_kept() {
        let d = dir("ours");
        let pin = d.join("signal_tamper_last_v21");
        std::fs::write(&pin, b"x").unwrap();
        assert!(matches!(
            reclaim_foreign_pin(&pin, my_uid(&d)),
            PinState::Ours
        ));
        assert!(pin.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_pin_another_user_left_is_removed() {
        let d = dir("foreign");
        let pin = d.join("signal_tamper_last_v21");
        std::fs::write(&pin, b"x").unwrap();
        std::fs::set_permissions(&pin, std::fs::Permissions::from_mode(0o600)).unwrap();
        // The file is ours; the agent running as some other uid sees it as foreign.
        let other = my_uid(&d) + 1;
        assert!(matches!(
            reclaim_foreign_pin(&pin, other),
            PinState::Reclaimed { owner } if owner == my_uid(&d)
        ));
        assert!(!pin.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_foreign_pin_in_a_directory_we_cannot_write_is_reported_not_hidden() {
        let d = dir("stuck");
        let pin = d.join("signal_tamper_last_v21");
        std::fs::write(&pin, b"x").unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o555)).unwrap();
        let state = reclaim_foreign_pin(&pin, my_uid(&d) + 1);
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        // root ignores directory permissions, where the removal simply succeeds.
        if !matches!(state, PinState::Reclaimed { .. }) {
            assert!(matches!(state, PinState::Stuck { .. }), "{state:?}");
            assert!(pin.exists());
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}
