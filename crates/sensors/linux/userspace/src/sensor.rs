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

/// The three tracepoints implemented to date: (program, category, name).
pub const TRACEPOINTS: &[(&str, &str, &str)] = &[
    ("sched_process_exec", "sched", "sched_process_exec"),
    ("sys_enter_openat", "syscalls", "sys_enter_openat"),
    ("sys_enter_connect", "syscalls", "sys_enter_connect"),
];

fn err(msg: String) -> SensorError {
    msg.into()
}

/// Loads the compiled eBPF object (bytecode embedded at build time), without
/// initializing the eBPF logger or loading/attaching any individual program. Shared
/// between the agent's preflight and [`LinuxSensor::run`].
#[cfg(ebpf_embedded)]
pub fn load_ebpf() -> Result<aya::Ebpf, SensorError> {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
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

/// Difference between the epoch clock and CLOCK_MONOTONIC (which the probes stamp
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

/// Drains every ready item from one ring buffer, decoding `W` and forwarding the
/// normalized event.
macro_rules! drain {
    ($guard:expr, $wire_ty:ty, $normalize:path, $sink:expr, $offset:expr) => {{
        let mut guard = $guard.map_err(|e| err(format!("ring buffer poll failed: {e}")))?;
        let rb = guard.get_inner_mut();
        while let Some(item) = rb.next() {
            if item.len() >= core::mem::size_of::<$wire_ty>() {
                let event = unsafe { core::ptr::read_unaligned(item.as_ptr() as *const $wire_ty) };
                $sink.on_event($normalize(&event, $offset));
            }
        }
        guard.clear_ready();
    }};
}

impl LinuxSensor {
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
                    drain!(guard, sensor_linux_wire::ExecEvent, normalize::exec, sink, offset)
                }
                guard = file_open_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::FileOpenEvent, normalize::file_open, sink, offset)
                }
                guard = connect_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::ConnectEvent, normalize::connect, sink, offset)
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

    /// All three tracepoints are attached in `run_async`, and every event carries
    /// uid/gid from `bpf_get_current_uid_gid` — capabilities reflect that.
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            exec_events: true,
            file_events: true,
            connect_events: true,
            user_attribution: true,
            parent_lineage: false,
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
