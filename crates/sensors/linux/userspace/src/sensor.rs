//! The Linux sensor itself: loading/attaching the eBPF programs, reading the ring
//! buffers, dispatching normalized events to an `EventSink`. Migrated from
//! `old/crates/synthaea-sensor-linux`.
//!
//! `load_ebpf`/`load_program`/`TRACEPOINTS` stay `pub`: the agent's status command
//! reuses them for the preflight (loads each program without attaching it), which is
//! not part of the `Sensor` contract.

use std::{
    collections::{HashMap, VecDeque},
    os::unix::fs::MetadataExt,
    path::Path,
    sync::{Arc, Mutex},
};

use schema::{
    ContainerContext,
    sensor::{Capabilities, EventSink, Sensor, SensorError},
};
use tokio::sync::Notify;
use tracing::warn;

use crate::{docker::DockerContainerInfo, normalize};

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
/// reason as open above.
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

fn err(msg: String) -> SensorError {
    msg.into()
}

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

fn attach_tracepoint(
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

/// Splits a NUL-separated `/proc/<pid>/cmdline` blob into argv tokens. The kernel
/// gives exactly the `execve` argument vector, each element NUL-terminated; a trailing
/// empty element from the final NUL is dropped, and any interior empty argument is
/// kept (a process is free to pass `""`). Non-UTF-8 bytes are replaced, never fatal.
fn parse_proc_cmdline(blob: &[u8]) -> Vec<String> {
    let trimmed = blob.strip_suffix(b"\0").unwrap_or(blob);
    if trimmed.is_empty() {
        return Vec::new();
    }
    trimmed
        .split(|&b| b == 0)
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

/// argv of `pid`, read from `/proc/<pid>/cmdline` when the `exec` event is drained.
///
/// Deliberately not read in the probe: that needed a `mm_struct` frozen offset, the
/// last non-portable read (issue #152). Two consequences, both accepted because
/// `cmdline`/`argv` are display/analysis inputs and never an identity — that is
/// `image_path`, still read authoritatively in the probe at `sched_process_exec`:
///
/// - **Race.** A process that exits in the few milliseconds before userspace drains
///   the ring buffer leaves no `/proc` entry (empty argv); if its pid is already
///   reused in that window the argv is the successor's.
/// - **Not exec-time.** `/proc/<pid>/cmdline` reflects `mm->arg_*` *now*, not at
///   `execve`. A process can rewrite its own argv region (write through
///   `arg_start..arg_end`, or move the pointers with `prctl(PR_SET_MM_ARG_*)`) between
///   exec and the drain, so a cmdline-substring rule (base64 decode, `curl | sh`) can
///   be evaded or spoofed by a process willing to scribble its own stack. The old
///   probe-side read captured argv atomically at exec and did not have this gap.
///   Tightening it — a `/proc` read triggered from the probe via task-work, or an
///   `arg_start` snapshot once aya has CO-RE — is a separate follow-up, not this
///   change.
///
/// Not usable on `WSL2`: kernel 6.6 returns `ENOENT` here for every pid, including
/// a live `sleep 60` with a confirmed parent — the `WSL` interop layer between the
/// eBPF context and the agent's `/proc` view, not the drain race. `WSL2` is out of
/// `lab/MATRIX.md`; recorded so it is not re-investigated (Nikolas, 2026-09-10, #155).
fn read_proc_cmdline(pid: u32) -> Vec<String> {
    match std::fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(blob) => parse_proc_cmdline(&blob),
        // The expected exit race (process already gone) is silent; anything else
        // (EACCES, EIO) is worth a line when tracing a capture gap on some kernel.
        Err(e) if is_proc_exit_race(&e) => Vec::new(),
        Err(e) => {
            tracing::debug!(pid, error = %e, "read /proc/<pid>/cmdline failed");
            Vec::new()
        }
    }
}

/// Whether an error from reading `/proc/<pid>/*` is the process having already exited
/// (the accepted race) rather than a real capture gap. `open()` on a dead pid gives
/// `ENOENT`; a `read()` that loses the task mid-flight can surface `ESRCH`, which
/// `std::io` maps to `Uncategorized`, not `NotFound` — so the raw errno is checked too.
fn is_proc_exit_race(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::NotFound || e.raw_os_error() == Some(libc::ESRCH)
}

/// Extracts a container id from one `/proc/<pid>/cgroup` line's path (the part after
/// the last `:` — format is `hierarchy-id:controller-list:path`, and cgroup v2's
/// single-hierarchy line has an empty controller list, `0::/path`). Recognizes the
/// two layouts actually seen on this binding's targets:
///
/// - cgroup v1 / cgroupfs naming: a path segment that is exactly the 64 hex-char id
///   (`/docker/<id>`, `/docker/<id>/init`).
/// - cgroup v2 / systemd unit naming: `docker-<id>.scope` or `cri-containerd-<id>.scope`
///   (containerd without Docker in front — still relevant since #80 mentions the
///   containerd socket alongside Docker's).
///
/// Kubernetes' `kubepods` slice nesting is deliberately not special-cased (pod/
/// namespace context is out of scope for issue #80) — the container-id segment inside
/// it matches the same two patterns regardless of what wraps it.
fn extract_container_id(cgroup_path: &str) -> Option<String> {
    fn is_hex_id(s: &str) -> bool {
        s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
    }

    cgroup_path.split('/').find_map(|segment| {
        let candidate = segment
            .strip_suffix(".scope")
            .and_then(|s| {
                s.strip_prefix("docker-")
                    .or_else(|| s.strip_prefix("cri-containerd-"))
            })
            .unwrap_or(segment);
        is_hex_id(candidate).then(|| candidate.to_string())
    })
}

/// Finds the container id owning cgroup id `cgroup_id` — the value
/// `bpf_get_current_cgroup_id()` captured kernel-side, at the moment the probe fired
/// (see `sensor_linux_wire::EventMeta::cgroup_id`) — by walking `cgroupfs_root` for
/// the directory whose inode matches, then extracting the id from that directory's
/// own path via [`extract_container_id`].
///
/// This is what actually closes issue #204's race. The approach it replaced read
/// `/proc/<pid>/cgroup` at drain time, which requires the *pid* to still exist —
/// reliably lost for a process whose entire lifetime is one syscall (e.g. a bare
/// `cat <path>`, confirmed against a real Docker daemon: `/proc/<pid>/cgroup` was
/// already gone on the very first attempt, every time). A container's own
/// directory under cgroupfs persists for the container's entire lifetime,
/// independent of any individual short-lived process inside it, so keying
/// attribution off the cgroup id — captured while the process was still executing
/// the syscall, not resolved lazily afterward — has nothing left to race against.
///
/// Split from [`CgroupIdCache::resolve`] so tests can point it at a fake directory
/// tree instead of the real `/sys/fs/cgroup`.
///
/// Assumes the cgroup v2 unified hierarchy: `bpf_get_current_cgroup_id()` always
/// reads the v2 `dfl_cgrp`, regardless of whether v1 controllers are also mounted,
/// and the labs this binding targets (Alpine/Debian/Arch, recent kernels) all
/// default to it. A host running cgroup v1 only would not find a match here — not
/// addressed, the same "known limitation, not this issue's scope" posture the rest
/// of this module's container attribution already has.
fn container_id_from_cgroupfs(cgroupfs_root: &Path, cgroup_id: u64) -> Option<String> {
    /// Cgroup trees are shallow in practice (a handful of slice/scope levels); this
    /// just bounds the recursion rather than expecting to ever hit it.
    const MAX_WALK_DEPTH: u8 = 12;

    fn walk(dir: &Path, cgroup_id: u64, depth: u8) -> Option<String> {
        if depth > MAX_WALK_DEPTH {
            return None;
        }
        let entries = std::fs::read_dir(dir).ok()?;
        for entry in entries.flatten() {
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if !metadata.is_dir() {
                continue;
            }
            let path = entry.path();
            if metadata.ino() == cgroup_id {
                return extract_container_id(&path.to_string_lossy());
            }
            if let Some(id) = walk(&path, cgroup_id, depth + 1) {
                return Some(id);
            }
        }
        None
    }

    walk(cgroupfs_root, cgroup_id, 0)
}

/// The real cgroupfs mount this binding targets.
const CGROUPFS_ROOT: &str = "/sys/fs/cgroup";

/// Bounded cache over [`container_id_from_cgroupfs`], keyed by cgroup id rather
/// than pid — see that function's doc for why this is what closes issue #204's
/// race.
///
/// No retry logic, unlike the pid-keyed cache this replaces: a cgroup id captured
/// kernel-side at syscall time is already the process's real cgroup membership at
/// that exact instant, not a value that needs time to "settle" the way a later
/// `/proc` read did — there is nothing here to retry.
struct CgroupIdCache {
    entries: HashMap<u64, Option<String>>,
    order: VecDeque<u64>,
}

/// Arbitrary but generous, same rationale as the pid-keyed cache this replaces:
/// bound growth rather than let it grow forever. The number of *containers* a host
/// runs over its uptime is normally far smaller than the number of *pids* the old
/// cache had to bound, so this is not expected to ever actually fill up.
const CGROUP_ID_CACHE_CAP: usize = 4096;

impl CgroupIdCache {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn resolve(&mut self, cgroup_id: u64) -> Option<String> {
        // 0 is never a real container's cgroup id (the eBPF side falls back to it
        // when the helper is unavailable) — skip the walk rather than pay a full
        // cgroupfs scan just to cache a `None` for it.
        if cgroup_id == 0 {
            return None;
        }
        self.resolve_with(cgroup_id, |id| {
            container_id_from_cgroupfs(Path::new(CGROUPFS_ROOT), id)
        })
    }

    /// `resolve`'s actual logic, parameterized over the fetch so tests can inject a
    /// call-counting stub instead of walking a real cgroupfs.
    fn resolve_with(
        &mut self,
        cgroup_id: u64,
        fetch: impl Fn(u64) -> Option<String>,
    ) -> Option<String> {
        if let Some(cached) = self.entries.get(&cgroup_id) {
            return cached.clone();
        }

        let id = fetch(cgroup_id);
        self.entries.insert(cgroup_id, id.clone());
        self.order.push_back(cgroup_id);
        if self.order.len() > CGROUP_ID_CACHE_CAP
            && let Some(oldest) = self.order.pop_front()
        {
            self.entries.remove(&oldest);
        }
        id
    }
}

/// One entry in [`DockerInfoCache`]: either a lookup is already running for this
/// container id (don't start a second one), or it finished with whatever it found
/// (`DockerContainerInfo`'s fields are already `Option` for "asked, got nothing").
enum DockerLookupState {
    Pending,
    Done(DockerContainerInfo),
}

/// Cache of Docker daemon socket lookups, keyed by container id, shared between the
/// event-processing loop and the background tasks it spawns to do the actual
/// lookups.
///
/// Unlike [`CgroupIdCache`] (per cgroup id, cheap, synchronous), resolving a
/// container id to its image/name needs a round trip to another daemon over
/// `/var/run/docker.sock` ([`crate::docker::lookup`]) — too slow to do inline on
/// the same task that drains ring buffers, so a first sighting of a container id
/// spawns a background task and the event that triggered it goes out with just the
/// id (image/name filled in once the lookup completes, for every event after
/// that).
///
/// Not bounded like `CgroupIdCache`: the number of *containers* a host runs over
/// its uptime is normally far smaller than the number of *pids* `CgroupIdCache`'s
/// predecessor had to bound, so unbounded growth here is a much smaller concern —
/// revisit if a host doing heavy container churn (a CI runner, say) ever makes
/// this show up in profiling, same as the pid-keyed cache was itself once a
/// deferred concern (issue #199).
type DockerInfoCache = Arc<Mutex<HashMap<String, DockerLookupState>>>;

/// Resolves `cgroup_id`'s full [`ContainerContext`] (id, plus image/name if the
/// Docker socket lookup for that id has completed): the id comes from
/// `container_ids` (cheap, synchronous, cached per cgroup id); on the id's first
/// sighting this spawns a background lookup into `docker_cache` and returns the id
/// alone for now — image/name catch up on the *next* event for the same
/// container, not this one.
fn container_context(
    cgroup_id: u64,
    container_ids: &mut CgroupIdCache,
    docker_cache: &DockerInfoCache,
) -> Option<ContainerContext> {
    let id = container_ids.resolve(cgroup_id)?;

    let info = {
        let mut cache = docker_cache.lock().unwrap();
        match cache.get(&id) {
            Some(DockerLookupState::Done(info)) => Some(info.clone()),
            Some(DockerLookupState::Pending) => None,
            None => {
                cache.insert(id.clone(), DockerLookupState::Pending);
                let cache = Arc::clone(docker_cache);
                let lookup_id = id.clone();
                tokio::task::spawn(async move {
                    let info = crate::docker::lookup(&lookup_id).await.unwrap_or_default();
                    cache
                        .lock()
                        .unwrap()
                        .insert(lookup_id, DockerLookupState::Done(info));
                });
                None
            }
        }
    };

    Some(ContainerContext {
        id,
        image: info.as_ref().and_then(|i| i.image.clone()),
        name: info.as_ref().and_then(|i| i.name.clone()),
    })
}

/// Splits a `/proc/<pid>/stat` line into `(ppid, comm)`. `comm` is parenthesised and
/// may itself contain spaces and `)` (e.g. `(a )b)`), so the fields after it are read
/// from the last `)`, not by whitespace-splitting the whole line.
fn parse_stat_ppid_comm(stat: &str) -> Option<(u32, &str)> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let comm = stat.get(open + 1..close)?;
    // After ") " comes: state (1 field), then ppid.
    let rest = stat.get(close + 1..)?;
    let mut fields = rest.split_whitespace();
    let _state = fields.next()?;
    let ppid: u32 = fields.next()?.parse().ok()?;
    Some((ppid, comm))
}

/// Pre-fills the `PROC_LINEAGE` eBPF map with the processes already running, read from
/// `/proc`. Without this, `ppid`/`parent_comm` are only known for processes that
/// `fork()` *after* the probe attaches — every already-running service (nginx, sshd,
/// systemd units started at boot) would report `ppid = 0`. Best-effort: a `/proc/<pid>`
/// that vanishes mid-scan is skipped; a full map stops the scan. There is a small race
/// window (a process forking between this scan and the `sched_process_fork` attach) —
/// accepted, it self-heals on that process's next child.
fn prime_proc_lineage(ebpf: &mut aya::Ebpf) -> Result<u32, SensorError> {
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

/// Difference between the epoch clock and `CLOCK_MONOTONIC` (which the probes stamp
/// events with), computed once at startup — see `normalize`.
fn boot_epoch_offset_ns() -> u64 {
    let epoch_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: plain FFI call writing into a valid stack-owned timespec.
    let mono_ns = if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } == 0 {
        // Saturating, matching sensor-linux-uprobes' copy of this function —
        // the two must not drift (a candidate for sensor-linux-wire).
        (ts.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(ts.tv_nsec as u64)
    } else {
        0
    };
    epoch_ns.saturating_sub(mono_ns)
}

/// Linux sensor (eBPF). `run` blocks until Ctrl-C or [`Sensor::stop`].
pub struct LinuxSensor {
    stop: Arc<Notify>,
}

impl Default for LinuxSensor {
    fn default() -> Self {
        Self::new()
    }
}

/// Drains every ready item from one ring buffer, decoding `$wire_ty` and forwarding
/// the event `$to_event` builds from it. `$to_event` is `Fn(&$wire_ty) -> Event` so
/// each leg can enrich with its own reads: exec's `/proc/<pid>/cmdline`, and all
/// three's container attribution (issue #80/#204) — the latter no longer touches
/// `/proc` at all, resolving `$wire_ty::meta.cgroup_id` against cgroupfs instead
/// (see [`CgroupIdCache`]), specifically to avoid re-triggering `read_proc_cmdline`'s
/// exact `spawn_blocking` tradeoff on every file-open/connect event, not just exec.
macro_rules! drain {
    ($guard:expr, $wire_ty:ty, $sink:expr, $to_event:expr) => {{
        let mut guard = $guard.map_err(|e| err(format!("ring buffer poll failed: {e}")))?;
        let rb = guard.get_inner_mut();
        while let Some(item) = rb.next() {
            if item.len() >= core::mem::size_of::<$wire_ty>() {
                // SAFETY: the length was checked against size_of::<$wire_ty>() above,
                // the wire types are repr(C) plain-old-data, and read_unaligned
                // handles the ring buffer's arbitrary alignment.
                let event = unsafe { core::ptr::read_unaligned(item.as_ptr() as *const $wire_ty) };
                $sink.on_event($to_event(&event));
            }
        }
        guard.clear_ready();
    }};
}

impl LinuxSensor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            stop: Arc::new(Notify::new()),
        }
    }

    async fn run_async(&mut self, sink: Box<dyn EventSink>) -> Result<(), SensorError> {
        let mut ebpf = load_ebpf()?;
        let offset = boot_epoch_offset_ns();

        match aya_log::EbpfLogger::init(&mut ebpf) {
            Err(e) => {
                warn!(error = %e, "failed to initialize eBPF logger");
            }
            Ok(logger) => {
                let mut logger =
                    tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)
                        .map_err(|e| err(format!("eBPF logger fd: {e}")))?;
                tokio::task::spawn(async move {
                    loop {
                        // No unwrap: nothing holds this task's JoinHandle, so a
                        // panic here would be swallowed silently. An fd error
                        // means the logger fd is gone — stop draining, loudly.
                        let mut guard = match logger.readable_mut().await {
                            Ok(guard) => guard,
                            Err(e) => {
                                warn!(error = %e, "eBPF log drain stopped");
                                break;
                            }
                        };
                        guard.get_inner_mut().flush();
                        guard.clear_ready();
                    }
                });
            }
        }

        // Seed parent lineage from /proc *before* attaching, so already-running
        // processes are known from the first event (see `prime_proc_lineage`).
        match prime_proc_lineage(&mut ebpf) {
            Ok(n) => tracing::info!(
                primed = n,
                "sensor-linux: primed processes into PROC_LINEAGE"
            ),
            Err(e) => warn!(
                error = %e,
                "sensor-linux: PROC_LINEAGE priming failed — ppid known only for post-attach forks"
            ),
        }

        for (program, category, name) in TRACEPOINTS {
            attach_tracepoint(&mut ebpf, program, category, name)?;
        }

        let mut ring = |map: &str| -> Result<_, SensorError> {
            let m = ebpf
                .take_map(map)
                .ok_or_else(|| err(format!("map {map} not found in eBPF object")))?;
            let rb = aya::maps::RingBuf::try_from(m)
                .map_err(|e| err(format!("map {map} is not a ring buffer: {e}")))?;
            tokio::io::unix::AsyncFd::with_interest(rb, tokio::io::Interest::READABLE)
                .map_err(|e| err(format!("ring buffer fd for {map}: {e}")))
        };
        let mut exec_ring_buf = ring("EXEC_EVENTS")?;
        let mut file_open_ring_buf = ring("FILE_OPEN_EVENTS")?;
        let mut connect_ring_buf = ring("CONNECT_EVENTS")?;
        let mut file_write_ring_buf = ring("FILE_WRITE_EVENTS")?;
        let mut file_delete_ring_buf = ring("FILE_DELETE_EVENTS")?;
        let mut file_rename_ring_buf = ring("FILE_RENAME_EVENTS")?;
        let mut socket_bind_ring_buf = ring("SOCKET_BIND_EVENTS")?;

        tracing::info!(
            "sensor-linux: listening for exec/open/connect/write/delete/rename/bind events"
        );

        let mut container_ids = CgroupIdCache::new();
        let docker_cache: DockerInfoCache = Arc::new(Mutex::new(HashMap::new()));
        let ctrl_c = tokio::signal::ctrl_c();
        tokio::pin!(ctrl_c);
        loop {
            tokio::select! {
                _ = &mut ctrl_c => break,
                _ = self.stop.notified() => break,
                guard = exec_ring_buf.readable_mut() => {
                    // One synchronous procfs read per exec event, on this task (see
                    // `read_proc_cmdline`'s doc comment on why this hasn't warranted
                    // `spawn_blocking` yet). Container attribution no longer touches
                    // `/proc` at all — see `CgroupIdCache`.
                    drain!(guard, sensor_linux_wire::ExecEvent, sink, |e: &sensor_linux_wire::ExecEvent| {
                        normalize::exec(e, offset, read_proc_cmdline(e.meta.pid), container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                    });
                }
                guard = file_open_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::FileOpenEvent, sink,
                        |e: &sensor_linux_wire::FileOpenEvent| {
                            normalize::file_open(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = connect_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::ConnectEvent, sink,
                        |e: &sensor_linux_wire::ConnectEvent| {
                            normalize::connect(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = file_write_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::FileWriteEvent, sink,
                        |e: &sensor_linux_wire::FileWriteEvent| {
                            normalize::file_write(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = file_delete_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::FileDeleteEvent, sink,
                        |e: &sensor_linux_wire::FileDeleteEvent| {
                            normalize::file_delete(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = file_rename_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::FileRenameEvent, sink,
                        |e: &sensor_linux_wire::FileRenameEvent| {
                            normalize::file_rename(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = socket_bind_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::SocketBindEvent, sink,
                        |e: &sensor_linux_wire::SocketBindEvent| {
                            normalize::socket_bind(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
            }
        }
        tracing::info!("sensor-linux: exiting");

        Ok(())
    }
}

impl Sensor for LinuxSensor {
    fn name(&self) -> &str {
        "linux-ebpf"
    }

    /// Every event carries uid/gid from `bpf_get_current_uid_gid` and a `ppid` from the
    /// `PROC_LINEAGE` fork-tracking map (`/proc`-primed at startup); exec events also
    /// carry the parent `comm`. `parent_lineage` reflects that.
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            exec_events: true,
            file_events: true,
            connect_events: true,
            user_attribution: true,
            parent_lineage: true,
            auth_events: false,
        }
    }

    /// Builds its own tokio runtime (the trait signature is synchronous) and blocks
    /// on it until Ctrl-C or `stop()`.
    fn run(&mut self, sink: Box<dyn EventSink>) -> Result<(), SensorError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| err(format!("failed to create the tokio runtime: {e}")))?;
        rt.block_on(self.run_async(sink))
    }

    /// `Notify` rather than a plain boolean flag: interrupts `select!` immediately
    /// (no polling latency). Wired for an external caller (multi-sensor agent
    /// orchestrating shutdown); the CLI path still relies on Ctrl-C.
    fn stop(&mut self) {
        self.stop.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        collections::HashMap,
        os::unix::fs::MetadataExt,
        path::Path,
        sync::{Arc, Mutex},
    };

    use super::{
        CGROUP_ID_CACHE_CAP, CgroupIdCache, DockerInfoCache, DockerLookupState, container_context,
        container_id_from_cgroupfs, extract_container_id, is_proc_exit_race, parse_proc_cmdline,
        parse_stat_ppid_comm,
    };
    use crate::docker::DockerContainerInfo;

    #[test]
    fn cmdline_splits_on_nul_and_drops_trailing_empty() {
        assert_eq!(
            parse_proc_cmdline(b"curl\0-o\0/tmp/x\0"),
            ["curl", "-o", "/tmp/x"]
        );
    }

    #[test]
    fn cmdline_without_trailing_nul() {
        // The kernel normally NUL-terminates the last arg, but be liberal.
        assert_eq!(parse_proc_cmdline(b"ls\0-la"), ["ls", "-la"]);
    }

    #[test]
    fn cmdline_empty_for_kernel_thread_or_dead_process() {
        assert!(parse_proc_cmdline(b"").is_empty());
        assert!(parse_proc_cmdline(b"\0").is_empty());
    }

    #[test]
    fn cmdline_keeps_interior_empty_argument() {
        assert_eq!(parse_proc_cmdline(b"sh\0\0-c\0"), ["sh", "", "-c"]);
    }

    #[test]
    fn cmdline_non_utf8_is_lossy_not_fatal() {
        let out = parse_proc_cmdline(b"\xff\xfe\0-x\0");
        assert_eq!(out.len(), 2);
        assert!(out[0].contains('\u{fffd}'));
        assert_eq!(out[1], "-x");
    }

    #[test]
    fn proc_exit_race_is_silent_for_enoent_and_esrch_only() {
        use std::io::{Error, ErrorKind};
        // open() on a dead pid — mapped to NotFound
        assert!(is_proc_exit_race(&Error::from(ErrorKind::NotFound)));
        // read() losing the task mid-flight — ESRCH, which std::io leaves Uncategorized
        assert!(is_proc_exit_race(&Error::from_raw_os_error(libc::ESRCH)));
        // a real capture gap on some kernel must still get logged
        assert!(!is_proc_exit_race(&Error::from_raw_os_error(libc::EACCES)));
        assert!(!is_proc_exit_race(&Error::from_raw_os_error(libc::EIO)));
    }

    const DOCKER_ID: &str = "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456";

    #[test]
    fn cgroup_v1_docker_path() {
        assert_eq!(
            extract_container_id(&format!("/docker/{DOCKER_ID}")),
            Some(DOCKER_ID.to_string())
        );
        // A sub-cgroup under the container (e.g. `/docker/<id>/init`) still matches.
        assert_eq!(
            extract_container_id(&format!("/docker/{DOCKER_ID}/init")),
            Some(DOCKER_ID.to_string())
        );
    }

    #[test]
    fn cgroup_v2_systemd_docker_scope() {
        assert_eq!(
            extract_container_id(&format!("/system.slice/docker-{DOCKER_ID}.scope")),
            Some(DOCKER_ID.to_string())
        );
    }

    #[test]
    fn cgroup_v2_containerd_without_docker() {
        assert_eq!(
            extract_container_id(&format!("/system.slice/cri-containerd-{DOCKER_ID}.scope")),
            Some(DOCKER_ID.to_string())
        );
    }

    #[test]
    fn cgroup_kubepods_nesting_still_matches() {
        // Pod/namespace context is out of scope (#80); the id inside the nesting is not.
        assert_eq!(
            extract_container_id(&format!(
                "/kubepods.slice/kubepods-burstable.slice/cri-containerd-{DOCKER_ID}.scope"
            )),
            Some(DOCKER_ID.to_string())
        );
    }

    #[test]
    fn cgroup_bare_metal_process_has_no_container() {
        assert_eq!(extract_container_id("/user.slice/user-1000.slice"), None);
        assert_eq!(extract_container_id("/init.scope"), None);
        assert_eq!(extract_container_id("/system.slice/sshd.service"), None);
    }

    #[test]
    fn cgroup_id_wrong_length_does_not_match() {
        // 63 hex chars — one short of a real id, must not false-positive.
        assert_eq!(extract_container_id("/docker/abc123"), None);
    }

    /// Builds `root/a/b/.../<id>` (one subdir per path segment) and returns the
    /// leaf's inode, so tests can drive [`container_id_from_cgroupfs`] against a
    /// fake cgroupfs tree instead of the real `/sys/fs/cgroup`. Callers clean up
    /// `root` themselves.
    fn make_cgroup_dir(root: &Path, relative_path: &str) -> u64 {
        let dir = root.join(relative_path.trim_start_matches('/'));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::metadata(&dir).unwrap().ino()
    }

    fn temp_cgroupfs_root(test_name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "sensor-linux-cgroupfs-test-{test_name}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn cgroupfs_walk_finds_a_matching_docker_scope_by_inode() {
        let root = temp_cgroupfs_root("finds-match");
        let target_ino = make_cgroup_dir(&root, &format!("system.slice/docker-{DOCKER_ID}.scope"));
        // A sibling directory the walk must not mistake for the target.
        make_cgroup_dir(&root, "system.slice/sshd.service");

        assert_eq!(
            container_id_from_cgroupfs(&root, target_ino),
            Some(DOCKER_ID.to_string())
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn cgroupfs_walk_no_match_is_none() {
        let root = temp_cgroupfs_root("no-match");
        make_cgroup_dir(&root, "user.slice/user-1000.slice");

        // An inode that exists nowhere under `root`.
        assert_eq!(container_id_from_cgroupfs(&root, u64::MAX), None);

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn stat_simple() {
        let stat = "1234 (bash) S 1000 1234 1234 34816 1789 4194304 ...";
        assert_eq!(parse_stat_ppid_comm(stat), Some((1000, "bash")));
    }

    #[test]
    fn stat_comm_with_spaces_and_parens() {
        // The kernel does not sanitise comm; `)` and spaces inside it are why the
        // fields are read from the last `)`, not by splitting the whole line.
        let stat = "42 (a ) b) S 7 42 42 0 -1 4194560 100 0 0 0";
        assert_eq!(parse_stat_ppid_comm(stat), Some((7, "a ) b")));
    }

    #[test]
    fn stat_kernel_thread_ppid_zero() {
        let stat = "2 (kthreadd) S 0 0 0 0 -1 2129984 0 0";
        assert_eq!(parse_stat_ppid_comm(stat), Some((0, "kthreadd")));
    }

    #[test]
    fn stat_garbage_is_none() {
        assert_eq!(parse_stat_ppid_comm("not a stat line"), None);
        assert_eq!(parse_stat_ppid_comm("123 (x) S notanumber"), None);
    }

    #[test]
    fn cgroup_id_cache_fetches_once_per_cgroup_id() {
        // Same reasoning as the pid-keyed cache this replaces (#199): resolving the
        // same cgroup id twice should not re-walk cgroupfs a second time.
        let mut cache = CgroupIdCache::new();
        let calls = Cell::new(0u32);
        let fetch = |_id: u64| {
            calls.set(calls.get() + 1);
            Some("abc".to_string())
        };

        assert_eq!(cache.resolve_with(42, fetch), Some("abc".to_string()));
        assert_eq!(cache.resolve_with(42, fetch), Some("abc".to_string()));
        assert_eq!(cache.resolve_with(42, fetch), Some("abc".to_string()));
        assert_eq!(
            calls.get(),
            1,
            "second/third resolve of the same cgroup id must hit the cache, not fetch again"
        );
    }

    #[test]
    fn cgroup_id_cache_none_result_is_cached_too() {
        // A bare-metal process (no container) resolves to `None` — that negative
        // result must be cached too, same "no re-fetch" reasoning as a `Some`.
        // Unlike the pid-keyed cache this replaces, there is no retry window here:
        // a cgroup id captured at syscall time is already settled, so the very
        // first `None` is trusted immediately.
        let mut cache = CgroupIdCache::new();
        let calls = Cell::new(0u32);
        let fetch = |_id: u64| {
            calls.set(calls.get() + 1);
            None
        };

        assert_eq!(cache.resolve_with(7, fetch), None);
        assert_eq!(cache.resolve_with(7, fetch), None);
        assert_eq!(cache.resolve_with(7, fetch), None);
        assert_eq!(
            calls.get(),
            1,
            "a None result must be cached on the very first fetch"
        );
    }

    #[test]
    fn cgroup_id_cache_distinct_ids_each_fetch_once() {
        let mut cache = CgroupIdCache::new();
        let calls = Cell::new(0u32);
        let fetch = |id: u64| {
            calls.set(calls.get() + 1);
            Some(format!("container-{id}"))
        };

        assert_eq!(
            cache.resolve_with(1, fetch),
            Some("container-1".to_string())
        );
        assert_eq!(
            cache.resolve_with(2, fetch),
            Some("container-2".to_string())
        );
        assert_eq!(
            cache.resolve_with(1, fetch),
            Some("container-1".to_string())
        );
        assert_eq!(
            calls.get(),
            2,
            "one fetch per distinct cgroup id, regardless of resolve order"
        );
    }

    #[test]
    fn cgroup_id_cache_evicts_oldest_once_over_capacity() {
        let mut cache = CgroupIdCache::new();
        let fetch = |id: u64| Some(format!("c{id}"));

        for id in 0..CGROUP_ID_CACHE_CAP as u64 {
            cache.resolve_with(id, fetch);
        }
        assert_eq!(cache.entries.len(), CGROUP_ID_CACHE_CAP);

        // One more id pushes the cache over capacity: the oldest (id 0) must be
        // evicted so the cache stays bounded rather than growing forever.
        cache.resolve_with(CGROUP_ID_CACHE_CAP as u64, fetch);
        assert_eq!(cache.entries.len(), CGROUP_ID_CACHE_CAP);
        assert!(
            !cache.entries.contains_key(&0),
            "oldest entry should have been evicted"
        );

        // Evicting id 0 means it is no longer cached — re-resolving it must fetch
        // again (proves eviction removed it from `entries`, not just `order`).
        let refetch_calls = Cell::new(0u32);
        let counting_fetch = |_id: u64| {
            refetch_calls.set(refetch_calls.get() + 1);
            Some("c0-again".to_string())
        };
        cache.resolve_with(0, counting_fetch);
        assert_eq!(refetch_calls.get(), 1);
    }

    #[test]
    fn cgroup_id_zero_never_walks_cgroupfs() {
        // 0 is the eBPF side's fallback when the helper is unavailable, never a
        // real cgroup's id — must short-circuit to `None` without even calling
        // `resolve_with`'s fetch.
        let mut cache = CgroupIdCache::new();
        assert_eq!(cache.resolve(0), None);
        assert!(
            !cache.entries.contains_key(&0),
            "id 0 must not even be cached"
        );
    }

    fn empty_docker_cache() -> DockerInfoCache {
        Arc::new(Mutex::new(HashMap::new()))
    }

    #[test]
    fn container_context_none_when_cgroup_id_has_no_container() {
        let mut ids = CgroupIdCache::new();
        ids.entries.insert(7, None); // pre-seeded: resolved, no container
        let docker_cache = empty_docker_cache();

        assert_eq!(container_context(7, &mut ids, &docker_cache), None);
    }

    #[tokio::test]
    async fn container_context_returns_id_only_while_docker_lookup_pending() {
        let mut ids = CgroupIdCache::new();
        ids.entries.insert(7, Some("abc123".to_string()));
        let docker_cache = empty_docker_cache();

        let ctx = container_context(7, &mut ids, &docker_cache).expect("has a container id");
        assert_eq!(ctx.id, "abc123");
        assert_eq!(ctx.image, None, "lookup was just spawned, not resolved yet");
        assert_eq!(ctx.name, None);

        // A second call for the same id, before the background lookup has had any
        // chance to run (no `.await` in between), must not spawn a second one —
        // observable as the cache entry staying a single `Pending`, not two
        // overlapping tasks racing to write their result.
        let ctx2 = container_context(7, &mut ids, &docker_cache).expect("still has a container id");
        assert_eq!(ctx2.image, None);
        assert!(matches!(
            docker_cache.lock().unwrap().get("abc123"),
            Some(DockerLookupState::Pending)
        ));
    }

    #[tokio::test]
    async fn container_context_uses_resolved_docker_info() {
        let mut ids = CgroupIdCache::new();
        ids.entries.insert(7, Some("abc123".to_string()));
        let docker_cache = empty_docker_cache();
        docker_cache.lock().unwrap().insert(
            "abc123".to_string(),
            DockerLookupState::Done(DockerContainerInfo {
                image: Some("nginx:1.27".to_string()),
                name: Some("web1".to_string()),
            }),
        );

        let ctx = container_context(7, &mut ids, &docker_cache).expect("has a container id");
        assert_eq!(ctx.image.as_deref(), Some("nginx:1.27"));
        assert_eq!(ctx.name.as_deref(), Some("web1"));
    }

    #[tokio::test]
    async fn container_context_survives_a_failed_lookup() {
        // `Done(default)` — the shape a failed/negative lookup leaves behind — must
        // still produce a valid `ContainerContext` with just the id, not panic or
        // re-spawn a lookup forever.
        let mut ids = CgroupIdCache::new();
        ids.entries.insert(7, Some("abc123".to_string()));
        let docker_cache = empty_docker_cache();
        docker_cache.lock().unwrap().insert(
            "abc123".to_string(),
            DockerLookupState::Done(DockerContainerInfo::default()),
        );

        let ctx = container_context(7, &mut ids, &docker_cache).expect("has a container id");
        assert_eq!(ctx.id, "abc123");
        assert_eq!(ctx.image, None);
        assert_eq!(ctx.name, None);
    }
}
