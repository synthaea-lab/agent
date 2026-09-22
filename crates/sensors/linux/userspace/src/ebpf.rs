//! Loading and attaching the eBPF side: the embedded object, the tracepoint
//! programs, and the `PROC_LINEAGE` map seeding. The public pieces
//! (`load_ebpf`, `load_program`, [`TRACEPOINTS`]) also serve the agent's
//! preflight, which loads programs without attaching them. Split out of
//! `sensor.rs` when that file had accumulated five concerns.

use schema::sensor::SensorError;

use crate::proc::parse_stat_ppid_comm;

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
];

/// `sensor_linux_wire::LineageEntry` is `repr(C)` over a `u32` and a `[u8; 16]` — every
/// bit pattern is valid, so it is plain-old-data. A transparent newtype carries the
/// `aya::Pod` impl (the orphan rule forbids implementing it on the wire type directly).
#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodLineage(sensor_linux_wire::LineageEntry);

// SAFETY: see the doc comment above — POD, no padding invariants, no invalid bit
// patterns.
unsafe impl aya::Pod for PodLineage {}

/// Loads the compiled eBPF object (bytecode embedded at build time), without
/// initializing the eBPF logger or loading/attaching any individual program. Shared
/// between the agent's preflight and [`LinuxSensor::run`].
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

    let ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/sensor-linux-ebpf"
    )))
    .map_err(|e| err(format!("failed to load the eBPF object: {e}")))?;
    Ok(ebpf)
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
    let mut primed = 0u32;
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
        let mut val = sensor_linux_wire::LineageEntry {
            ppid,
            comm: [0u8; sensor_linux_wire::TASK_COMM_LEN],
        };
        let bytes = comm.as_bytes();
        let n = bytes.len().min(sensor_linux_wire::TASK_COMM_LEN);
        val.comm[..n].copy_from_slice(&bytes[..n]);

        if lineage.insert(pid, PodLineage(val), 0).is_ok() {
            primed += 1;
        }
    }
    Ok(primed)
}
