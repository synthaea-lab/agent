//! The Linux sensor itself: loading/attaching the eBPF programs, reading the ring
//! buffers, dispatching normalized events to an `EventSink`. Migrated from
//! `old/crates/synthaea-sensor-linux`.
//!
//! `load_ebpf`/`load_program`/`TRACEPOINTS` stay `pub`: the agent's status command
//! reuses them for the preflight (loads each program without attaching it), which is
//! not part of the `Sensor` contract.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use log::warn;
use schema::sensor::{Capabilities, EventSink, Sensor, SensorError};
use schema::ContainerContext;
use tokio::sync::Notify;

use crate::docker::DockerContainerInfo;
use crate::normalize;

/// The tracepoints implemented to date: (program, category, name). `sched_process_fork`
/// and `sched_process_exit` maintain the `PROC_LINEAGE` map (parent pid/comm) that the
/// other probes read — attach them first so it is populating before events flow.
///
/// Both `sys_enter_openat` and `sys_enter_open` are attached: musl (and every busybox
/// applet linked against it) still issues the plain `open(2)` syscall directly, while
/// glibc rewrites `open()` into `openat(AT_FDCWD, ...)` since 2.26 — attaching only one
/// of the two misses file opens on whichever libc doesn't use it. Both feed the same
/// `FileOpenEvent`/`file_open` event type.
pub const TRACEPOINTS: &[(&str, &str, &str)] = &[
    ("sched_process_fork", "sched", "sched_process_fork"),
    ("sched_process_exit", "sched", "sched_process_exit"),
    ("sched_process_exec", "sched", "sched_process_exec"),
    ("sys_enter_openat", "syscalls", "sys_enter_openat"),
    ("sys_enter_open", "syscalls", "sys_enter_open"),
    ("sys_enter_connect", "syscalls", "sys_enter_connect"),
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
        log::debug!("remove limit on locked memory failed, ret is: {ret}");
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
            log::debug!("read /proc/{pid}/cmdline: {e}");
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

/// Parses `/proc/<pid>/cgroup` (one `hierarchy-id:controllers:path` line per
/// hierarchy — a single `0::/path` line under the cgroup v2 unified hierarchy this
/// binding targets) and returns the first line whose path attributes to a container.
fn parse_cgroup_container_id(contents: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        line.rsplit_once(':')
            .and_then(|(_, path)| extract_container_id(path))
    })
}

/// Container id of `pid`'s cgroup, read from `/proc/<pid>/cgroup` when the event is
/// drained — same drain-time-not-exec-time tradeoff as [`read_proc_cmdline`] (a process
/// cannot change its own cgroup membership the way it can rewrite argv, so there is no
/// spoofing concern here, just the same exit race). `None` on a bare-metal/VM process,
/// not just on a read failure — most events have no container to attribute.
///
/// `id` is the full 64-hex-char id from the cgroup path — resolving it to an
/// image/name is [`DockerInfoCache`]'s job, a separate cached lookup against the
/// daemon socket (issue #80's item 1, the other half of the split #169 left here).
///
/// Known coverage gap, confirmed against a real Docker daemon: a process whose entire
/// lifetime is one `open()` then exit (e.g. a bare `cat <path>`, as opposed to a shell
/// that keeps the fd/process around) reliably loses this race — `/proc/<pid>/cgroup` is
/// already gone by the *first* attempt, every time, because the drain loop cannot catch
/// up within such a short lifetime. [`ContainerIdCache`]'s retry budget does not help
/// here (it targets a *different* race — `runc`'s init window, where the read succeeds
/// but the cgroup hasn't settled yet — not a process that is already gone). A
/// container-conditioned rule ([`crate::normalize`]'s callers; see `check_proc_root_escape`
/// in `rules`) will not fire for a one-shot command, only for a process that stays alive
/// past its triggering syscall. Not addressed here: fixing it needs the container id
/// captured kernel-side (e.g. `bpf_get_current_cgroup_id()` at event capture time) rather
/// than resolved lazily against `/proc` at drain time.
fn read_container_id(pid: u32) -> Option<String> {
    match std::fs::read_to_string(format!("/proc/{pid}/cgroup")) {
        Ok(contents) => parse_cgroup_container_id(&contents),
        Err(e) if is_proc_exit_race(&e) => None,
        Err(e) => {
            log::debug!("read /proc/{pid}/cgroup: {e}");
            None
        }
    }
}

/// Bounded cache over [`read_container_id`], keyed by pid.
///
/// Without this, every `file_open`/`exec`/`connect` event triggers a fresh
/// `/proc/<pid>/cgroup` read — and for `file_open` specifically, that read is
/// *itself* an `open()` syscall, which the `file_open` probe captures as a new
/// `file_open` event for the same pid, which asks this same question again,
/// forever: an unbounded, self-sustaining loop that pins a CPU core from the
/// moment the agent starts (issue #199). The `drain!` call sites' own prior
/// doc comment already flagged this exact shape of fix as a deferred
/// followup ("revisit with a per-cgroup cache if a file-event-heavy workload
/// makes it show up in profiling") — it has.
///
/// A pid's cgroup membership does not change once it's *settled* — but it is
/// not settled from the pid's very first instant. Caught against a real
/// `docker exec` while validating #80's image/name lookup: `runc`'s init
/// process does several `file_open`s (setting up the target namespaces)
/// *before* it moves itself into the container's cgroup and `execve`s into
/// the target command — same pid throughout. Caching whatever the first
/// observation says, permanently, latches every containerized process to
/// `None` forever, the instant its very first file open is captured. Fixed by
/// giving a `None` result a small number of retries — [`NONE_RETRY_LIMIT`] —
/// before it's trusted as final; a genuinely bare-metal process pays that
/// same bounded number of extra `/proc/<pid>/cgroup` reads once, which is
/// exactly the "small constant multiplier, not unbounded" tradeoff the whole
/// cache exists to keep. A resolved `Some(id)` is still cached immediately
/// and permanently — nothing about a container id becomes wrong once seen.
struct ContainerIdCache {
    entries: HashMap<u32, CacheEntry>,
    order: VecDeque<u32>,
}

#[derive(Clone)]
struct CacheEntry {
    id: Option<String>,
    /// Only meaningful while `id` is `None` — how many `None` results in a row
    /// this pid has produced. Irrelevant, and left alone, once `id` is `Some`.
    none_attempts: u8,
}

/// Arbitrary but generous: a box with this many *concurrently live* distinct
/// pids producing file/exec/connect events between evictions would need to be
/// under genuinely unusual load — bound it rather than let it grow forever.
const CONTAINER_ID_CACHE_CAP: usize = 4096;

/// How many consecutive `None` reads a pid gets before its `None` is trusted
/// as final. Small: the `runc`-init-to-execve window observed in practice is
/// a handful of `file_open`s, not dozens.
const NONE_RETRY_LIMIT: u8 = 5;

impl ContainerIdCache {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn resolve(&mut self, pid: u32) -> Option<String> {
        self.resolve_with(pid, read_container_id)
    }

    /// `resolve`'s actual logic, parameterized over the fetch so tests can inject a
    /// call-counting stub instead of touching real `/proc` entries.
    fn resolve_with(&mut self, pid: u32, fetch: impl Fn(u32) -> Option<String>) -> Option<String> {
        if let Some(cached) = self.entries.get(&pid)
            && (cached.id.is_some() || cached.none_attempts >= NONE_RETRY_LIMIT)
        {
            return cached.id.clone();
        }

        let id = fetch(pid);
        let is_new_pid = !self.entries.contains_key(&pid);
        let none_attempts = match &id {
            Some(_) => 0,
            None => {
                self.entries
                    .get(&pid)
                    .map_or(0, |e| e.none_attempts)
                    .saturating_add(1)
            }
        };
        self.entries.insert(
            pid,
            CacheEntry {
                id: id.clone(),
                none_attempts,
            },
        );

        if is_new_pid {
            self.order.push_back(pid);
            if self.order.len() > CONTAINER_ID_CACHE_CAP
                && let Some(oldest) = self.order.pop_front()
            {
                self.entries.remove(&oldest);
            }
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
/// Unlike [`ContainerIdCache`] (per pid, cheap, synchronous), resolving a container
/// id to its image/name needs a round trip to another daemon over `/var/run/docker
/// .sock` ([`crate::docker::lookup`]) — too slow to do inline on the same task that
/// drains ring buffers, so a first sighting of a container id spawns a background
/// task and the event that triggered it goes out with just the id (image/name
/// filled in once the lookup completes, for every event after that).
///
/// Not bounded like `ContainerIdCache`: the number of *containers* a host runs
/// over its uptime is normally far smaller than the number of *pids*, so unbounded
/// growth here is a much smaller concern — revisit if a host doing heavy container
/// churn (a CI runner, say) ever makes this show up in profiling, same as
/// `ContainerIdCache` was itself once a deferred concern (issue #199).
type DockerInfoCache = Arc<Mutex<HashMap<String, DockerLookupState>>>;

/// Resolves `pid`'s full [`ContainerContext`] (id, plus image/name if the Docker
/// socket lookup for that id has completed): the id comes from `container_ids`
/// (cheap, synchronous, cached per pid); on the id's first sighting this spawns a
/// background lookup into `docker_cache` and returns the id alone for now — image/
/// name catch up on the *next* event for the same container, not this one.
fn container_context(
    pid: u32,
    container_ids: &mut ContainerIdCache,
    docker_cache: &DockerInfoCache,
) -> Option<ContainerContext> {
    let id = container_ids.resolve(pid)?;

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
        (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
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
/// each leg can enrich with its own procfs reads (exec: `/proc/<pid>/cmdline`; all
/// three: `/proc/<pid>/cgroup` for container attribution, issue #80).
///
/// The container-id read runs on every file-open/connect event, not just exec — a
/// higher rate than the cmdline read that motivated the `spawn_blocking` discussion
/// on `read_proc_cmdline`. Accepted for this attribution foundation (still a
/// pseudo-fs read, no syscall that blocks on the target's locks); revisit with a
/// per-cgroup cache if a file-event-heavy workload makes it show up in profiling —
/// deferred rather than guessed at, same as the Docker/containerd socket lookup this
/// id is meant to feed.
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
                warn!("failed to initialize eBPF logger: {e}");
            }
            Ok(logger) => {
                let mut logger =
                    tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)
                        .map_err(|e| err(format!("eBPF logger fd: {e}")))?;
                tokio::task::spawn(async move {
                    loop {
                        let mut guard = logger.readable_mut().await.unwrap();
                        guard.get_inner_mut().flush();
                        guard.clear_ready();
                    }
                });
            }
        }

        // Seed parent lineage from /proc *before* attaching, so already-running
        // processes are known from the first event (see `prime_proc_lineage`).
        match prime_proc_lineage(&mut ebpf) {
            Ok(n) => log::info!("sensor-linux: primed {n} processes into PROC_LINEAGE"),
            Err(e) => warn!(
                "sensor-linux: PROC_LINEAGE priming failed ({e}) — ppid known only for post-attach forks"
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

        log::info!("sensor-linux: listening for exec/open/connect events");

        let mut container_ids = ContainerIdCache::new();
        let docker_cache: DockerInfoCache = Arc::new(Mutex::new(HashMap::new()));
        let ctrl_c = tokio::signal::ctrl_c();
        tokio::pin!(ctrl_c);
        loop {
            tokio::select! {
                _ = &mut ctrl_c => break,
                _ = self.stop.notified() => break,
                guard = exec_ring_buf.readable_mut() => {
                    // Two synchronous procfs reads per exec event, on this task (see
                    // `read_proc_cmdline`'s doc comment on why this hasn't warranted
                    // `spawn_blocking` yet — `/proc/<pid>/cgroup` has the same
                    // pseudo-fs-cheap, mmap_lock-independent profile).
                    drain!(guard, sensor_linux_wire::ExecEvent, sink, |e: &sensor_linux_wire::ExecEvent| {
                        normalize::exec(e, offset, read_proc_cmdline(e.meta.pid), container_context(e.meta.pid, &mut container_ids, &docker_cache))
                    });
                }
                guard = file_open_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::FileOpenEvent, sink,
                        |e: &sensor_linux_wire::FileOpenEvent| {
                            normalize::file_open(e, offset, container_context(e.meta.pid, &mut container_ids, &docker_cache))
                        });
                }
                guard = connect_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::ConnectEvent, sink,
                        |e: &sensor_linux_wire::ConnectEvent| {
                            normalize::connect(e, offset, container_context(e.meta.pid, &mut container_ids, &docker_cache))
                        });
                }
            }
        }
        log::info!("sensor-linux: exiting");

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
    use super::{
        container_context, extract_container_id, is_proc_exit_race, parse_cgroup_container_id,
        parse_proc_cmdline, parse_stat_ppid_comm, CacheEntry, ContainerIdCache, DockerInfoCache,
        DockerLookupState, CONTAINER_ID_CACHE_CAP, NONE_RETRY_LIMIT,
    };
    use crate::docker::DockerContainerInfo;
    use std::cell::Cell;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

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

    #[test]
    fn parse_cgroup_v2_single_hierarchy_line() {
        // Real cgroup v2 layout: one `0::/path` line, no controller list.
        let contents = format!("0::/system.slice/docker-{DOCKER_ID}.scope\n");
        assert_eq!(
            parse_cgroup_container_id(&contents),
            Some(DOCKER_ID.to_string())
        );
    }

    #[test]
    fn parse_cgroup_v1_multi_hierarchy_lines() {
        // Real cgroup v1 layout: several `id:controllers:path` lines, only some of
        // which mention the container (v1 mounts one hierarchy per controller).
        let contents = format!(
            "12:pids:/docker/{DOCKER_ID}\n11:cpuset:/docker/{DOCKER_ID}\n\
             4:memory:/user.slice\n"
        );
        assert_eq!(
            parse_cgroup_container_id(&contents),
            Some(DOCKER_ID.to_string())
        );
    }

    #[test]
    fn parse_cgroup_no_container_line_is_none() {
        let contents = "0::/user.slice/user-1000.slice/session-2.scope\n";
        assert_eq!(parse_cgroup_container_id(contents), None);
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
    fn container_id_cache_fetches_once_per_pid() {
        // The bug this cache exists to fix (#199): resolving the same pid's container
        // id twice should not re-run the fetch a second time. `read_container_id`
        // itself does an `open()` that the real `file_open` probe would capture as a
        // brand new event for the same pid — this is what turns a single re-fetch
        // into an unbounded loop, so "no re-fetch" is the entire point of the cache.
        let mut cache = ContainerIdCache::new();
        let calls = Cell::new(0u32);
        let fetch = |_pid: u32| {
            calls.set(calls.get() + 1);
            Some("abc".to_string())
        };

        assert_eq!(cache.resolve_with(42, fetch), Some("abc".to_string()));
        assert_eq!(cache.resolve_with(42, fetch), Some("abc".to_string()));
        assert_eq!(cache.resolve_with(42, fetch), Some("abc".to_string()));
        assert_eq!(calls.get(), 1, "second/third resolve of the same pid must hit the cache, not fetch again");
    }

    #[test]
    fn container_id_cache_none_result_is_retried_then_cached() {
        // A bare-metal process (no container) resolves to `None` — eventually that
        // negative result must be cached too, or every one of its events
        // re-triggers the same self-feeding `open()` loop the cache exists to stop.
        // But not on the very first `None`: see `NONE_RETRY_LIMIT`'s doc comment
        // (the `runc`-init-before-execve window) for why an immediate-permanent
        // `None` latch is itself a bug, not just over-caution.
        let mut cache = ContainerIdCache::new();
        let calls = Cell::new(0u32);
        let fetch = |_pid: u32| {
            calls.set(calls.get() + 1);
            None
        };

        for _ in 0..NONE_RETRY_LIMIT {
            assert_eq!(cache.resolve_with(7, fetch), None);
        }
        assert_eq!(
            calls.get(),
            u32::from(NONE_RETRY_LIMIT),
            "each call up to the retry limit must actually re-fetch"
        );

        // Past the limit: cached, no more fetching.
        assert_eq!(cache.resolve_with(7, fetch), None);
        assert_eq!(cache.resolve_with(7, fetch), None);
        assert_eq!(calls.get(), u32::from(NONE_RETRY_LIMIT), "no fetch past the retry limit");
    }

    #[test]
    fn container_id_cache_some_result_stops_retrying_immediately() {
        // A container id that only shows up after a couple of `None`s (the
        // `runc`-init window) must be cached the moment it resolves, not after
        // `NONE_RETRY_LIMIT` more calls.
        let mut cache = ContainerIdCache::new();
        let calls = Cell::new(0u32);
        let responses = [None, None, Some("abc123".to_string())];
        let fetch = |_pid: u32| {
            let i = calls.get() as usize;
            calls.set(calls.get() + 1);
            responses.get(i).cloned().flatten()
        };

        assert_eq!(cache.resolve_with(7, fetch), None);
        assert_eq!(cache.resolve_with(7, fetch), None);
        assert_eq!(cache.resolve_with(7, fetch), Some("abc123".to_string()));
        assert_eq!(calls.get(), 3);

        // Cached from here on — no more fetching, even well past what would have
        // been the `None` retry limit.
        for _ in 0..(NONE_RETRY_LIMIT as u32 + 5) {
            assert_eq!(cache.resolve_with(7, fetch), Some("abc123".to_string()));
        }
        assert_eq!(calls.get(), 3, "resolved id must not be re-fetched, ever");
    }

    #[test]
    fn container_id_cache_distinct_pids_each_fetch_once() {
        let mut cache = ContainerIdCache::new();
        let calls = Cell::new(0u32);
        let fetch = |pid: u32| {
            calls.set(calls.get() + 1);
            Some(format!("container-{pid}"))
        };

        assert_eq!(cache.resolve_with(1, fetch), Some("container-1".to_string()));
        assert_eq!(cache.resolve_with(2, fetch), Some("container-2".to_string()));
        assert_eq!(cache.resolve_with(1, fetch), Some("container-1".to_string()));
        assert_eq!(calls.get(), 2, "one fetch per distinct pid, regardless of resolve order");
    }

    #[test]
    fn container_id_cache_evicts_oldest_once_over_capacity() {
        let mut cache = ContainerIdCache::new();
        let fetch = |pid: u32| Some(format!("c{pid}"));

        for pid in 0..CONTAINER_ID_CACHE_CAP as u32 {
            cache.resolve_with(pid, fetch);
        }
        assert_eq!(cache.entries.len(), CONTAINER_ID_CACHE_CAP);

        // One more pid pushes the cache over capacity: the oldest (pid 0) must be
        // evicted so the cache stays bounded rather than growing forever.
        cache.resolve_with(CONTAINER_ID_CACHE_CAP as u32, fetch);
        assert_eq!(cache.entries.len(), CONTAINER_ID_CACHE_CAP);
        assert!(!cache.entries.contains_key(&0), "oldest entry should have been evicted");

        // Evicting pid 0 means it is no longer cached — re-resolving it must fetch
        // again (proves eviction removed it from `entries`, not just `order`).
        let refetch_calls = Cell::new(0u32);
        let counting_fetch = |_pid: u32| {
            refetch_calls.set(refetch_calls.get() + 1);
            Some("c0-again".to_string())
        };
        cache.resolve_with(0, counting_fetch);
        assert_eq!(refetch_calls.get(), 1);
    }

    fn empty_docker_cache() -> DockerInfoCache {
        Arc::new(Mutex::new(HashMap::new()))
    }

    #[test]
    fn container_context_none_when_pid_has_no_container() {
        let mut ids = ContainerIdCache::new();
        ids.entries.insert(7, CacheEntry { id: None, none_attempts: NONE_RETRY_LIMIT }); // pre-seeded: settled, no container
        let docker_cache = empty_docker_cache();

        assert_eq!(container_context(7, &mut ids, &docker_cache), None);
    }

    #[tokio::test]
    async fn container_context_returns_id_only_while_docker_lookup_pending() {
        let mut ids = ContainerIdCache::new();
        ids.entries.insert(7, CacheEntry { id: Some("abc123".to_string()), none_attempts: 0 });
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
        let mut ids = ContainerIdCache::new();
        ids.entries.insert(7, CacheEntry { id: Some("abc123".to_string()), none_attempts: 0 });
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
        let mut ids = ContainerIdCache::new();
        ids.entries.insert(7, CacheEntry { id: Some("abc123".to_string()), none_attempts: 0 });
        let docker_cache = empty_docker_cache();
        docker_cache
            .lock()
            .unwrap()
            .insert("abc123".to_string(), DockerLookupState::Done(DockerContainerInfo::default()));

        let ctx = container_context(7, &mut ids, &docker_cache).expect("has a container id");
        assert_eq!(ctx.id, "abc123");
        assert_eq!(ctx.image, None);
        assert_eq!(ctx.name, None);
    }
}
