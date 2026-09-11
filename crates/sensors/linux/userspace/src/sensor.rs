//! The Linux sensor itself: loading/attaching the eBPF programs, reading the ring
//! buffers, dispatching normalized events to an `EventSink`. Migrated from
//! `old/crates/synthaea-sensor-linux`.
//!
//! `load_ebpf`/`load_program`/`TRACEPOINTS` stay `pub`: the agent's status command
//! reuses them for the preflight (loads each program without attaching it), which is
//! not part of the `Sensor` contract.

use std::sync::Arc;

use log::warn;
use schema::sensor::{Capabilities, EventSink, Sensor, SensorError};
use tokio::sync::Notify;

use crate::normalize;

/// The tracepoints implemented to date: (program, category, name). `sched_process_fork`
/// and `sched_process_exit` maintain the `PROC_LINEAGE` map (parent pid/comm) that the
/// other probes read — attach them first so it is populating before events flow.
pub const TRACEPOINTS: &[(&str, &str, &str)] = &[
    ("sched_process_fork", "sched", "sched_process_fork"),
    ("sched_process_exit", "sched", "sched_process_exit"),
    ("sched_process_exec", "sched", "sched_process_exec"),
    ("sys_enter_openat", "syscalls", "sys_enter_openat"),
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
/// the exec path can enrich with a `/proc/<pid>/cmdline` read the others do not need.
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

        let ctrl_c = tokio::signal::ctrl_c();
        tokio::pin!(ctrl_c);
        loop {
            tokio::select! {
                _ = &mut ctrl_c => break,
                _ = self.stop.notified() => break,
                guard = exec_ring_buf.readable_mut() => {
                    // One synchronous procfs read per exec event, on this task. A
                    // `/proc/<pid>/cmdline` read is normally served from pseudo-fs
                    // without blocking (it can still stall on `mmap_lock` contention or
                    // a page fault in the target's mm), so it does not warrant
                    // `spawn_blocking` today; if an exec storm ever makes it show up,
                    // batch the drained pids and read them off the reactor instead.
                    drain!(guard, sensor_linux_wire::ExecEvent, sink, |e: &sensor_linux_wire::ExecEvent| {
                        normalize::exec(e, offset, read_proc_cmdline(e.meta.pid))
                    });
                }
                guard = file_open_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::FileOpenEvent, sink,
                        |e: &sensor_linux_wire::FileOpenEvent| normalize::file_open(e, offset));
                }
                guard = connect_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::ConnectEvent, sink,
                        |e: &sensor_linux_wire::ConnectEvent| normalize::connect(e, offset));
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
    use super::{is_proc_exit_race, parse_proc_cmdline, parse_stat_ppid_comm};

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
}
