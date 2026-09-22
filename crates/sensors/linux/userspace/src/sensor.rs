//! The Linux sensor itself: loading/attaching the eBPF programs, reading the ring
//! buffers, dispatching normalized events to an `EventSink`. Migrated from
//! `old/crates/synthaea-sensor-linux`.
//!
//! `load_ebpf`/`load_program`/`TRACEPOINTS` stay `pub`: the agent's status command
//! reuses them for the preflight (loads each program without attaching it), which is
//! not part of the `Sensor` contract.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use schema::sensor::{Capabilities, EventSink, Sensor, SensorError};
use tokio::sync::Notify;
use tracing::warn;

use crate::{
    container::{CgroupIdCache, DockerInfoCache, container_context},
    ebpf::{TRACEPOINTS, attach_tracepoint, err, load_ebpf, prime_proc_lineage},
    normalize,
    proc::read_proc_cmdline,
};

/// See `sensor_linux_wire::boot_epoch_offset_ns` — computed once at startup.
/// (Consolidated there by #295; a parallel branch merge resurrected the old
/// local copy once already — if you are reading a full implementation here
/// again, the same thing happened again.)
fn boot_epoch_offset_ns() -> u64 {
    sensor_linux_wire::boot_epoch_offset_ns()
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
        let mut file_chmod_ring_buf = ring("FILE_CHMOD_EVENTS")?;
        let mut file_chown_ring_buf = ring("FILE_CHOWN_EVENTS")?;
        let mut udp_send_ring_buf = ring("UDP_SEND_EVENTS")?;
        let mut socket_listen_ring_buf = ring("SOCKET_LISTEN_EVENTS")?;

        tracing::info!(
            "sensor-linux: listening for exec/open/connect/write/delete/rename/bind/chmod/chown/udp_send/listen events"
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
                guard = file_chmod_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::FileChmodEvent, sink,
                        |e: &sensor_linux_wire::FileChmodEvent| {
                            normalize::file_chmod(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = file_chown_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::FileChownEvent, sink,
                        |e: &sensor_linux_wire::FileChownEvent| {
                            normalize::file_chown(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = udp_send_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::UdpSendEvent, sink,
                        |e: &sensor_linux_wire::UdpSendEvent| {
                            normalize::udp_send(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = socket_listen_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::SocketListenEvent, sink,
                        |e: &sensor_linux_wire::SocketListenEvent| {
                            normalize::socket_listen(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
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
