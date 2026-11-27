//! Loading and attaching the eBPF side: the embedded object, the raw tracepoint
//! programs, and the `PROC_LINEAGE` map seeding. The public pieces
//! (`load_ebpf`, `load_program`, [`RAW_TRACEPOINTS`]) also serve the agent's
//! preflight, which loads programs without attaching them. Split out of
//! `sensor.rs` when that file had accumulated five concerns.

use schema::sensor::SensorError;

use crate::proc::{parse_stat_ppid_comm, primed_generation};

/// The message-to-error helper every module in this crate shares.
pub(crate) fn err(msg: String) -> SensorError {
    msg.into()
}

/// Raw tracepoints attached by the sensor: three scheduler hooks, shared
/// syscall entry/exit routers and `signal_generate`. The routers preserve the syscall handlers,
/// including the paired `accept`, `recvfrom`, and `memfd_create` exit events.
pub const RAW_TRACEPOINTS: &[(&str, &str)] = &[
    ("raw_sched_process_fork", "sched_process_fork"),
    ("raw_sched_process_exit", "sched_process_exit"),
    ("raw_sched_process_exec", "sched_process_exec"),
    (SYS_ENTER_PROGRAM, "sys_enter"),
    ("raw_sys_exit", "sys_exit"),
    (DNS_UDP_PROGRAM, "sys_enter"),
    // Signals to the processes of the listed security units (#1103), through `SIGNAL_WATCH_TOOLS`.
    ("raw_signal_generate", "signal_generate"),
];

/// The UDP/53 DNS capture (#458 part 3): its own program on `sys_enter`, attached only when the
/// sensor is built with [`crate::LinuxSensor::with_dns_udp_capture`]. It is in [`RAW_TRACEPOINTS`] so
/// the preflight loads it through the verifier like the others, and the sensor skips it otherwise.
pub const DNS_UDP_PROGRAM: &str = "raw_dns_udp_enter";

/// The syscall-entry router with the file path filters inline (`RAW_TRACEPOINTS` lists it).
pub const SYS_ENTER_PROGRAM: &str = "raw_sys_enter";

/// The same router whose file handlers tail-call the [`FILE_FILTER_PROGRAMS`] (#351): the path
/// scan is verified once per kind instead of inside the router, which leaves the router far under
/// the verifier's budget. Attached in place of [`SYS_ENTER_PROGRAM`] when the kernel loads it; a
/// JIT that cannot mix tail calls with BPF-to-BPF calls (i686, arm64 before 6.0, no JIT) refuses
/// it, and the sensor keeps the inline router.
pub const SYS_ENTER_TAIL_CALL_PROGRAM: &str = "raw_sys_enter_tc";

/// The file handlers' filter-and-output programs (#351), each with its
/// `sensor_linux_wire::file_filter` slot in `FILE_FILTER_PROGS`. Loaded, never attached:
/// `raw_sys_enter` tail-calls them. The agent's preflight loads them through the verifier like
/// [`RAW_TRACEPOINTS`].
pub const FILE_FILTER_PROGRAMS: &[(&str, u32)] = {
    use sensor_linux_wire::file_filter::{
        CHMOD, CHOWN, COUNT, DELETE, OPEN, REMOVEXATTR, RENAME, SETXATTR,
    };
    const PROGRAMS: &[(&str, u32)] = &[
        ("raw_file_open_filter", OPEN),
        ("raw_file_delete_filter", DELETE),
        ("raw_file_rename_filter", RENAME),
        ("raw_file_chmod_filter", CHMOD),
        ("raw_file_chown_filter", CHOWN),
        ("raw_file_setxattr_filter", SETXATTR),
        ("raw_file_removexattr_filter", REMOVEXATTR),
    ];
    // Every slot filled, each once: an empty slot would leave its events unfiltered.
    assert!(PROGRAMS.len() == COUNT as usize);
    let mut seen = [false; COUNT as usize];
    let mut i = 0;
    while i < PROGRAMS.len() {
        let slot = PROGRAMS[i].1 as usize;
        assert!(slot < COUNT as usize && !seen[slot]);
        seen[slot] = true;
        i += 1;
    }
    PROGRAMS
};

/// `sensor_linux_wire::LineageEntry` is `repr(C)` over two `u32`, a `[u8; 16]` and a `u64`,
/// laid out with no implicit padding (`execd` is explicit) — every bit pattern is
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

    load_embedded(None)
}

/// A probe path the object carries but runs only when a load-time global enables it, with the
/// BTF offsets it reads through. The globals are `.rodata` constants: left at 0, the verifier
/// prunes the path, so the agent and `verify_probes` must set the same list (#310). `N` ties
/// the names to the offset values a caller passes, so the two cannot drift in length.
#[cfg(ebpf_embedded)]
struct GatedPath<const N: usize> {
    enabled: &'static str,
    offsets: [&'static str; N],
}

/// `inode_setattr` timestamp hook (#1044): `iattr` and `dentry` field offsets.
#[cfg(ebpf_embedded)]
const INODE_SETATTR: GatedPath<5> = GatedPath {
    enabled: "INODE_SETATTR_ENABLED",
    offsets: [
        "IATTR_VALID_OFFSET",
        "IATTR_ATIME_OFFSET",
        "IATTR_MTIME_OFFSET",
        "DENTRY_PARENT_OFFSET",
        "DENTRY_NAME_PTR_OFFSET",
    ],
};

/// argv read at exec (#48): `task_struct.mm` and `mm_struct.arg_{start,end}` offsets.
#[cfg(ebpf_embedded)]
const EXEC_ARGV: GatedPath<3> = GatedPath {
    enabled: "EXEC_ARGV_ENABLED",
    offsets: ["TASK_MM_OFFSET", "MM_ARG_START_OFFSET", "MM_ARG_END_OFFSET"],
};

#[cfg(ebpf_embedded)]
static ENABLED: u32 = 1;

/// Stand-in for the BTF offsets when only the verifier's view matters: every gated path reads
/// through `bpf_probe_read_kernel`, where an offset is a scalar added to the source pointer,
/// so any small value exercises the same instructions as the kernel's real offsets.
#[cfg(ebpf_embedded)]
const STAND_IN_OFFSET: u32 = 8;

/// Sets `path`'s enabled flag and its offsets, `must_exist` as everywhere here: a renamed
/// global fails the load instead of leaving the path disabled.
#[cfg(ebpf_embedded)]
fn enable_gated<'a, const N: usize>(
    loader: &mut aya::EbpfLoader<'a>,
    path: &GatedPath<N>,
    offsets: &'a [u32; N],
) {
    loader.override_global(path.enabled, &ENABLED, true);
    for (&name, value) in path.offsets.iter().zip(offsets) {
        loader.override_global(name, value, true);
    }
}

/// A loader for the embedded object with every optional probe path enabled and stand-in
/// offsets, for checking what the kernel's verifier accepts (`examples/verify_probes.rs`):
/// the same gated paths the agent enables when BTF resolves their offsets, so the check
/// covers the code that ships (#310). Not for running the sensor: the offsets are not the
/// kernel's.
#[cfg(ebpf_embedded)]
#[must_use]
pub fn verifier_loader() -> aya::EbpfLoader<'static> {
    let mut loader = aya::EbpfLoader::new();
    enable_gated(&mut loader, &INODE_SETATTR, &[STAND_IN_OFFSET; 5]);
    enable_gated(&mut loader, &EXEC_ARGV, &[STAND_IN_OFFSET; 3]);
    loader
}

#[cfg(ebpf_embedded)]
fn load_embedded(tamper_pin: Option<&std::path::Path>) -> Result<aya::Ebpf, SensorError> {
    let offsets = crate::btf::read_scheduler_field_offsets().map_err(|e| {
        err(format!(
            "could not read required fields from kernel BTF: {e}"
        ))
    })?;

    // The `inode_setattr` hook (#1044) is optional: a kernel whose `iattr`/`dentry` layout
    // cannot be read leaves it disabled in the object, it never blocks the sensor. Bound
    // before the loader, which keeps the references until `load`.
    let setattr = crate::btf::read_inode_setattr_offsets()
        .map_err(|e| {
            tracing::warn!(error = %e, "inode_setattr offsets unavailable: timestamp hook disabled");
        })
        .ok();
    // argv at exec (https://github.com/synthaea-lab/agent/issues/48) is optional the same way: without the offsets the probe reads none
    // and the drain falls back to `/proc/<pid>/cmdline`.
    let argv = crate::btf::read_exec_argv_offsets()
        .map_err(|e| {
            tracing::warn!(error = %e, "exec argv offsets unavailable: argv read from /proc only");
        })
        .ok();
    // In `GatedPath` field order; bound before the loader, which keeps the references.
    let setattr = setattr.map(|o| {
        [
            o.ia_valid,
            o.ia_atime,
            o.ia_mtime,
            o.dentry_parent,
            o.dentry_name_ptr,
        ]
    });
    let argv = argv.map(|o| [o.task_mm, o.mm_arg_start, o.mm_arg_end]);

    let mut loader = aya::EbpfLoader::new();
    loader
        .override_global("TASK_PID_OFFSET", &offsets.task_pid, true)
        .override_global("TASK_TGID_OFFSET", &offsets.task_tgid, true)
        .override_global("TASK_COMM_OFFSET", &offsets.task_comm, true)
        .override_global("BINPRM_FILENAME_OFFSET", &offsets.binprm_filename, true)
        .override_global("SYSCALL_ARG_OFFSETS", &offsets.syscall_args, true)
        .override_global("SYSCALL_NR_OFFSET", &offsets.syscall_nr, true);
    if let Some(values) = &setattr {
        enable_gated(&mut loader, &INODE_SETATTR, values);
    }
    if let Some(values) = &argv {
        enable_gated(&mut loader, &EXEC_ARGV, values);
    }
    if let Some(path) = tamper_pin {
        loader.map_pin_path("SIGNAL_TAMPER_LAST", path);
    }
    let mut ebpf = loader
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/sensor-linux-ebpf"
        )))
        .map_err(|e| err(format!("failed to load eBPF object: {e}")))?;
    crate::syscall::populate_dispatch(&mut ebpf)?;
    Ok(ebpf)
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
         at build time) — provision the eBPF toolchain (packaging/toolchain/linux-toolchain.sh) \
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

/// Loads (kernel verifier included) the raw-tracepoint program `program_name` without attaching it.
///
/// # Errors
///
/// Returns [`SensorError`] when the program is missing from the eBPF object, is
/// not a raw tracepoint, or is rejected by the kernel verifier.
pub fn load_program(ebpf: &mut aya::Ebpf, program_name: &str) -> Result<(), SensorError> {
    let program: &mut aya::programs::RawTracePoint = ebpf
        .program_mut(program_name)
        .ok_or_else(|| err(format!("program `{program_name}` not found in eBPF object")))?
        .try_into()
        .map_err(|e| err(format!("`{program_name}` is not a raw tracepoint: {e}")))?;
    program
        .load()
        .map_err(|e| err(format!("kernel verifier rejected `{program_name}`: {e}")))?;
    Ok(())
}

/// Loads each [`FILE_FILTER_PROGRAMS`] program and puts it in its `FILE_FILTER_PROGS` slot
/// (#351), so the file handlers filter their events. Slot by slot: a program the kernel refuses
/// leaves only its own slot empty, and only that kind's events go out unfiltered. `ebpf` must
/// outlive the sensor: the kernel empties a program array when its last userspace handle closes.
///
/// Returns the programs that could not be put in their slot, each with why; the caller logs them
/// and runs on.
///
/// # Errors
///
/// Returns [`SensorError`] when the map itself is missing or not a program array: then no slot
/// can be filled, and every file event kind goes out unfiltered.
pub(crate) fn populate_file_filters(
    ebpf: &mut aya::Ebpf,
) -> Result<Vec<(&'static str, SensorError)>, SensorError> {
    let mut failed = Vec::new();
    let mut fds = Vec::with_capacity(FILE_FILTER_PROGRAMS.len());
    for &(name, slot) in FILE_FILTER_PROGRAMS {
        match load_program(ebpf, name).and_then(|()| program_fd(ebpf, name)) {
            Ok(fd) => fds.push((name, slot, fd)),
            Err(e) => failed.push((name, e)),
        }
    }
    let map = ebpf
        .map_mut("FILE_FILTER_PROGS")
        .ok_or_else(|| err("eBPF map FILE_FILTER_PROGS is missing".to_owned()))?;
    let mut progs = aya::maps::ProgramArray::try_from(map)
        .map_err(|e| err(format!("FILE_FILTER_PROGS is not a program array: {e}")))?;
    for (name, slot, fd) in &fds {
        if let Err(e) = progs.set(*slot, fd, 0) {
            failed.push((
                name,
                err(format!("populate FILE_FILTER_PROGS[{slot}]: {e}")),
            ));
        }
    }
    Ok(failed)
}

/// An owned copy of a loaded program's fd, so the map can be borrowed while it is set.
fn program_fd(ebpf: &aya::Ebpf, name: &str) -> Result<aya::programs::ProgramFd, SensorError> {
    ebpf.program(name)
        .ok_or_else(|| err(format!("program `{name}` not found in eBPF object")))?
        .fd()
        .map_err(|e| e.to_string())
        .and_then(|fd| fd.try_clone().map_err(|e| e.to_string()))
        .map_err(|e| err(format!("`{name}` has no usable fd: {e}")))
}

/// Attaches `sys_enter`'s router: [`SYS_ENTER_TAIL_CALL_PROGRAM`] when `filters_ready` (every
/// filter slot filled) and the kernel loads it, [`SYS_ENTER_PROGRAM`] otherwise (#351).
///
/// # Errors
///
/// Returns [`SensorError`] when the inline router cannot be attached either.
pub(crate) fn attach_sys_enter(
    ebpf: &mut aya::Ebpf,
    filters_ready: bool,
) -> Result<(), SensorError> {
    if filters_ready {
        match attach_raw_tracepoint(ebpf, SYS_ENTER_TAIL_CALL_PROGRAM, "sys_enter") {
            Ok(()) => {
                tracing::info!(
                    "sensor-linux: sys_enter router filters file events through tail calls"
                );
                return Ok(());
            }
            Err(e) => tracing::warn!(
                error = %e,
                "sensor-linux: tail-call sys_enter router refused: keeping the inline filters"
            ),
        }
    }
    attach_raw_tracepoint(ebpf, SYS_ENTER_PROGRAM, "sys_enter")
}

pub(crate) fn attach_raw_tracepoint(
    ebpf: &mut aya::Ebpf,
    program_name: &str,
    tracepoint: &str,
) -> Result<(), SensorError> {
    load_program(ebpf, program_name)?;
    let program: &mut aya::programs::RawTracePoint = ebpf
        .program_mut(program_name)
        .expect("loaded just above")
        .try_into()
        .map_err(|e| err(format!("`{program_name}` is not a raw tracepoint: {e}")))?;
    program.attach(tracepoint).map_err(|e| {
        err(format!(
            "failed to attach raw tracepoint `{tracepoint}` (needs CAP_BPF and CAP_PERFMON or root): {e}"
        ))
    })?;
    Ok(())
}

/// Attaches the `inode_setattr` BPF-LSM hook (#1044) in this object, so its ring buffer is
/// the one the sensor drains. `Err` is the ordinary "this kernel cannot" outcome (no
/// BPF-LSM BTF, `bpf` not in the active `lsm=` list, verifier refusal): the caller logs it
/// and runs without the hook.
pub(crate) fn attach_inode_setattr(ebpf: &mut aya::Ebpf) -> Result<(), SensorError> {
    let btf = aya::Btf::from_sys_fs().map_err(|e| err(format!("no kernel BTF: {e}")))?;
    let program: &mut aya::programs::Lsm = ebpf
        .program_mut("inode_setattr")
        .ok_or_else(|| err("program `inode_setattr` not found in eBPF object".to_string()))?
        .try_into()
        .map_err(|e| err(format!("`inode_setattr` is not an LSM program: {e}")))?;
    program
        .load("inode_setattr", &btf)
        .map_err(|e| err(format!("kernel verifier rejected `inode_setattr`: {e}")))?;
    program
        .attach()
        .map_err(|e| err(format!("failed to attach LSM hook `inode_setattr`: {e}")))?;
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
        let generation = primed_generation(stat);
        scanned.push((pid, ppid, comm.to_string(), generation));
    }
    let generation_of: std::collections::HashMap<u32, u64> =
        scanned.iter().map(|(pid, _, _, g)| (*pid, *g)).collect();

    let mut primed = 0u32;
    for (pid, ppid, comm, generation) in &scanned {
        let mut val = sensor_linux_wire::LineageEntry {
            ppid: *ppid,
            comm: [0u8; sensor_linux_wire::TASK_COMM_LEN],
            // Predates the agent: nothing says it never exec'd (see `LineageEntry::execd`).
            execd: 1,
            generation: *generation,
            parent_generation: generation_of.get(ppid).copied().unwrap_or(0),
        };
        let bytes = comm.as_bytes();
        let n = bytes.len().min(sensor_linux_wire::TASK_COMM_LEN);
        val.comm[..n].copy_from_slice(&bytes[..n]);

        if lineage.insert(pid, &PodLineage(val), 0).is_ok() {
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
        .set(0, &pid, 0)
        .map_err(|e| err(format!("failed to write SIGNAL_WATCH_PID: {e}")))
}

/// Takes `SIGNAL_WATCH_TOOLS` (#1103) out of `ebpf`: the tgids of the processes of the listed
/// security units, which `raw_signal_generate` reads.
///
/// # Errors
///
/// Returns [`SensorError`] when the map is missing from the eBPF object or is not a hash map of
/// `u32` to `u64`.
pub(crate) fn take_signal_watch_tools(
    ebpf: &mut aya::Ebpf,
) -> Result<aya::maps::HashMap<aya::maps::MapData, u32, u64>, SensorError> {
    let map = ebpf
        .take_map("SIGNAL_WATCH_TOOLS")
        .ok_or_else(|| err("map SIGNAL_WATCH_TOOLS not found in eBPF object".to_string()))?;
    aya::maps::HashMap::try_from(map).map_err(|e| {
        err(format!(
            "SIGNAL_WATCH_TOOLS is not a u32 -> u64 hash map: {e}"
        ))
    })
}

/// Takes the per-CPU counter of tool signals lost to a full `SIGNAL_EVENTS` ring (#1103).
///
/// # Errors
///
/// Returns [`SensorError`] when the map is missing or is not a per-CPU array of `u64`.
pub(crate) fn take_signal_tool_drops(
    ebpf: &mut aya::Ebpf,
) -> Result<aya::maps::PerCpuArray<aya::maps::MapData, u64>, SensorError> {
    let map = ebpf
        .take_map("SIGNAL_TOOL_DROPS")
        .ok_or_else(|| err("map SIGNAL_TOOL_DROPS not found in eBPF object".to_string()))?;
    aya::maps::PerCpuArray::try_from(map)
        .map_err(|e| err(format!("SIGNAL_TOOL_DROPS is not a per-CPU u64 array: {e}")))
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
    slot.set(0, &PodSignal(zero), 0)
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
