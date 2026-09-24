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
    time::Duration,
};

use schema::sensor::{Capabilities, EventSink, Sensor, SensorError};
use tokio::sync::Notify;
use tracing::warn;

use crate::{
    container::{CgroupIdCache, DockerInfoCache, container_context},
    ebpf::{
        TRACEPOINTS, TamperSlot, attach_tracepoint, clear_tamper_slot, err, load_ebpf_for_run,
        prime_proc_lineage, read_tamper_slot, take_tamper_slot, write_signal_watch_pid,
    },
    normalize,
    proc::{read_proc_cmdline, read_proc_environ_security},
};

/// See `sensor_linux_wire::boot_epoch_offset_ns` — computed once at startup.
/// (Consolidated there by #295; a parallel branch merge resurrected the old
/// local copy once already — if you are reading a full implementation here
/// again, the same thing happened again.)
fn boot_epoch_offset_ns() -> u64 {
    sensor_linux_wire::boot_epoch_offset_ns()
}

/// How often [`sweep_survived_sigkill`] runs.
const TAMPER_SWEEP_INTERVAL: Duration = Duration::from_secs(10);

/// Age past which a `SIGKILL` recorded against this very process is known not to
/// have landed. Delivery happens within the sender's `kill(2)` call, microseconds
/// after the probe fires, so a live agent one second later survived it.
const SIGKILL_SURVIVED_AFTER_NS: u64 = 1_000_000_000;

/// Clears `SIGNAL_TAMPER_LAST` when it holds a `SIGKILL` aimed at this process
/// that the process survived (issue #362). The probe fires at syscall entry,
/// before the permission check, so an unprivileged `kill -9` that fails with
/// `EPERM` still fills the slot. Left there, the next restart (a clean
/// `systemctl restart` included) would blame that sender for a kill that never
/// happened. The live `Event::Signal` from the ring buffer already reported the
/// attempt itself. Waiting [`SIGKILL_SURVIVED_AFTER_NS`] rather than clearing on
/// that ring-buffer event keeps a real kill from racing its own record away.
fn sweep_survived_sigkill(slot: &mut TamperSlot, own_pid: u32, boot_epoch_offset_ns: u64) {
    let Some(recorded) = read_tamper_slot(slot) else {
        return;
    };
    let recorded_at = recorded
        .meta
        .timestamp_ns
        .saturating_add(boot_epoch_offset_ns);
    let age = schema::time::now_ns().saturating_sub(recorded_at);
    if recorded.target_pid == own_pid
        && age > SIGKILL_SURVIVED_AFTER_NS
        && let Err(e) = clear_tamper_slot(slot)
    {
        warn!(error = %e, "sensor-linux: could not clear a survived SIGKILL record");
    }
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

/// Upper bound on items one `drain!` call takes from a ring buffer before returning
/// control to `select!` (issue #326). `RingBuf::next()` is a synchronous read of live
/// shared memory with no `.await` in this loop — under a sustained producer (e.g. a
/// tight `write(2)` loop) it can keep returning `Some` indefinitely, and a loop with
/// no yield point never gives `select!` a chance to re-poll the other nine branches,
/// starving them completely rather than just statistically disadvantaging them. This
/// cap forces a return to the top of the `select!` loop regularly, which re-polls
/// every branch and lets tokio's cooperative-scheduling budget actually enforce
/// fairness between them.
const MAX_ITEMS_PER_DRAIN: usize = 256;

/// Drains up to [`MAX_ITEMS_PER_DRAIN`] ready items from one ring buffer, decoding
/// `$wire_ty` and forwarding the event `$to_event` builds from it. `$to_event` is
/// `Fn(&$wire_ty) -> Event` so each leg can enrich with its own reads: exec's
/// `/proc/<pid>/cmdline`, and all three's container attribution (issue #80/#204) —
/// the latter no longer touches `/proc` at all, resolving `$wire_ty::meta.cgroup_id`
/// against cgroupfs instead (see [`CgroupIdCache`]), specifically to avoid
/// re-triggering `read_proc_cmdline`'s exact `spawn_blocking` tradeoff on every
/// file-open/connect event, not just exec.
macro_rules! drain {
    ($guard:expr, $wire_ty:ty, $sink:expr, $own_pid:expr, $to_event:expr) => {{
        let mut guard = $guard.map_err(|e| err(format!("ring buffer poll failed: {e}")))?;
        let rb = guard.get_inner_mut();
        let mut drained = 0usize;
        while drained < MAX_ITEMS_PER_DRAIN {
            let Some(item) = rb.next() else { break };
            drained += 1;
            if item.len() >= core::mem::size_of::<$wire_ty>() {
                // SAFETY: the length was checked against size_of::<$wire_ty>() above,
                // the wire types are repr(C) plain-old-data, and read_unaligned
                // handles the ring buffer's arbitrary alignment.
                let event = unsafe { core::ptr::read_unaligned(item.as_ptr() as *const $wire_ty) };
                let schema_event = $to_event(&event);
                // Self-exclusion (issue #340): the agent's own activity — most
                // visibly its own `write(2)` calls appending to `events.jsonl` —
                // is itself observed by this same sensor, re-triggering the very
                // write that produced it and amplifying without bound (capped
                // from a full hang only by MAX_ITEMS_PER_DRAIN above, #326).
                // Standard EDR practice: never feed the agent's own pid back
                // into its own telemetry.
                if schema_event.meta().pid != $own_pid {
                    $sink.on_event(schema_event);
                }
            }
        }
        // Only clear readiness once the buffer actually ran dry. If we stopped
        // because we hit the cap, more data is still waiting — leaving the
        // ready-flag set makes the next `select!` iteration re-poll this branch
        // immediately instead of blocking for the next epoll edge, which is what
        // continues draining it without starving the other branches in the meantime.
        if drained < MAX_ITEMS_PER_DRAIN {
            guard.clear_ready();
        }
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
        let mut ebpf = load_ebpf_for_run()?;
        let offset = boot_epoch_offset_ns();
        // Computed early (not just for #340's drain-time self-exclusion below) so
        // `write_signal_watch_pid` can seed `SIGNAL_WATCH_PID` before the
        // `sys_enter_kill`/`sys_enter_tgkill` probes are attached (issue #362) —
        // attaching them first would let a signal land before the map holds
        // anything but its zero-initialized default, which the probe treats as
        // "watch nothing" and silently drops.
        let own_pid = std::process::id();
        write_signal_watch_pid(&mut ebpf, own_pid)?;
        // The signal filter only ever watches this process (v1 scope), so this is
        // resolved once rather than per event — see `normalize::signal`'s doc
        // comment.
        let self_exe = std::env::current_exe()
            .ok()
            .map(|p| p.display().to_string());

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
        let mut socket_accept_ring_buf = ring("SOCKET_ACCEPT_EVENTS")?;
        let mut file_setxattr_ring_buf = ring("FILE_SETXATTR_EVENTS")?;
        let mut file_removexattr_ring_buf = ring("FILE_REMOVEXATTR_EVENTS")?;
        let mut mount_ring_buf = ring("MOUNT_EVENTS")?;
        let mut signal_ring_buf = ring("SIGNAL_EVENTS")?;
        let mut kernel_module_ring_buf = ring("KERNEL_MODULE_EVENTS")?;
        let mut bpf_ring_buf = ring("BPF_EVENTS")?;
        let mut ptrace_ring_buf = ring("PTRACE_EVENTS")?;
        let mut process_vm_read_ring_buf = ring("PROCESS_VM_READ_EVENTS")?;
        let mut process_vm_write_ring_buf = ring("PROCESS_VM_WRITE_EVENTS")?;
        let mut memfd_create_ring_buf = ring("MEMFD_CREATE_EVENTS")?;
        let mut identity_change_ring_buf = ring("IDENTITY_CHANGE_EVENTS")?;
        let mut capset_ring_buf = ring("CAPSET_EVENTS")?;
        let mut namespace_ring_buf = ring("NAMESPACE_EVENTS")?;

        tracing::info!(
            "sensor-linux: listening for exec/open/connect/write/delete/rename/bind/chmod/chown/udp_send/listen/accept/setxattr/removexattr/mount/signal/kernel_module/bpf/ptrace/process_vm_readv/process_vm_writev/memfd_create/identity_change/capset/namespace events"
        );

        let mut container_ids = CgroupIdCache::new();
        let docker_cache: DockerInfoCache = Arc::new(Mutex::new(HashMap::new()));
        // Issue #340: excluded from every drain below so the sensor never re-observes
        // its own syscalls (most visibly its `write(2)`s to `events.jsonl`).
        // Issue #362: a SIGKILL recorded by the previous agent instance, the one
        // this process presumably restarted after. Replayed through the normal
        // `Event::Signal` path, so the tamper rule attributes it like a live one.
        let mut tamper_slot = take_tamper_slot(&mut ebpf)?;
        if let Some(previous) = read_tamper_slot(&tamper_slot) {
            tracing::warn!(
                sender_pid = previous.meta.pid,
                target_pid = previous.target_pid,
                "sensor-linux: the previous agent instance was sent SIGKILL, reporting it"
            );
            sink.on_event(normalize::signal(
                &previous,
                offset,
                self_exe.clone(),
                container_context(previous.meta.cgroup_id, &mut container_ids, &docker_cache),
            ));
            clear_tamper_slot(&mut tamper_slot)?;
        }
        let mut tamper_sweep = tokio::time::interval(TAMPER_SWEEP_INTERVAL);
        let ctrl_c = tokio::signal::ctrl_c();
        tokio::pin!(ctrl_c);
        loop {
            tokio::select! {
                _ = &mut ctrl_c => break,
                _ = self.stop.notified() => break,
                _ = tamper_sweep.tick() => {
                    sweep_survived_sigkill(&mut tamper_slot, own_pid, offset);
                }
                guard = exec_ring_buf.readable_mut() => {
                    // Two synchronous procfs reads per exec event, on this task (see
                    // `read_proc_cmdline`'s doc comment on why this hasn't warranted
                    // `spawn_blocking` yet — `read_proc_environ_security` is the same
                    // file family, same tradeoff). Container attribution no longer
                    // touches `/proc` at all — see `CgroupIdCache`.
                    drain!(guard, sensor_linux_wire::ExecEvent, sink, own_pid, |e: &sensor_linux_wire::ExecEvent| {
                        normalize::exec(e, offset, read_proc_cmdline(e.meta.pid), read_proc_environ_security(e.meta.pid), container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                    });
                }
                guard = file_open_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::FileOpenEvent, sink, own_pid,
                        |e: &sensor_linux_wire::FileOpenEvent| {
                            normalize::file_open(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = connect_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::ConnectEvent, sink, own_pid,
                        |e: &sensor_linux_wire::ConnectEvent| {
                            normalize::connect(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = file_write_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::FileWriteEvent, sink, own_pid,
                        |e: &sensor_linux_wire::FileWriteEvent| {
                            normalize::file_write(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = file_delete_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::FileDeleteEvent, sink, own_pid,
                        |e: &sensor_linux_wire::FileDeleteEvent| {
                            normalize::file_delete(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = file_rename_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::FileRenameEvent, sink, own_pid,
                        |e: &sensor_linux_wire::FileRenameEvent| {
                            normalize::file_rename(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = socket_bind_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::SocketBindEvent, sink, own_pid,
                        |e: &sensor_linux_wire::SocketBindEvent| {
                            normalize::socket_bind(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = file_chmod_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::FileChmodEvent, sink, own_pid,
                        |e: &sensor_linux_wire::FileChmodEvent| {
                            normalize::file_chmod(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = file_chown_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::FileChownEvent, sink, own_pid,
                        |e: &sensor_linux_wire::FileChownEvent| {
                            normalize::file_chown(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = udp_send_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::UdpSendEvent, sink, own_pid,
                        |e: &sensor_linux_wire::UdpSendEvent| {
                            normalize::udp_send(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = socket_listen_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::SocketListenEvent, sink, own_pid,
                        |e: &sensor_linux_wire::SocketListenEvent| {
                            normalize::socket_listen(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = socket_accept_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::SocketAcceptEvent, sink, own_pid,
                        |e: &sensor_linux_wire::SocketAcceptEvent| {
                            normalize::socket_accept(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = file_setxattr_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::FileSetxattrEvent, sink, own_pid,
                        |e: &sensor_linux_wire::FileSetxattrEvent| {
                            normalize::file_setxattr(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = file_removexattr_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::FileRemovexattrEvent, sink, own_pid,
                        |e: &sensor_linux_wire::FileRemovexattrEvent| {
                            normalize::file_removexattr(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = mount_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::MountEvent, sink, own_pid,
                        |e: &sensor_linux_wire::MountEvent| {
                            normalize::mount(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = signal_ring_buf.readable_mut() => {
                    // container_context resolves the SENDER's container (meta is
                    // the sender, same convention as every other event type) —
                    // relevant for e.g. attributing a container-escape kill attempt
                    // to the container it came from.
                    drain!(guard, sensor_linux_wire::SignalEvent, sink, own_pid,
                        |e: &sensor_linux_wire::SignalEvent| {
                            normalize::signal(e, offset, self_exe.clone(), container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = kernel_module_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::KernelModuleEvent, sink, own_pid,
                        |e: &sensor_linux_wire::KernelModuleEvent| {
                            normalize::kernel_module(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = bpf_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::BpfEvent, sink, own_pid,
                        |e: &sensor_linux_wire::BpfEvent| {
                            normalize::bpf_operation(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = ptrace_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::PtraceEvent, sink, own_pid,
                        |e: &sensor_linux_wire::PtraceEvent| {
                            normalize::ptrace(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = process_vm_read_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::ProcessVmReadEvent, sink, own_pid,
                        |e: &sensor_linux_wire::ProcessVmReadEvent| {
                            normalize::process_vm_read(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = process_vm_write_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::ProcessVmWriteEvent, sink, own_pid,
                        |e: &sensor_linux_wire::ProcessVmWriteEvent| {
                            normalize::process_vm_write(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = memfd_create_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::MemfdCreateEvent, sink, own_pid,
                        |e: &sensor_linux_wire::MemfdCreateEvent| {
                            normalize::memfd_create(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = identity_change_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::IdentityChangeEvent, sink, own_pid,
                        |e: &sensor_linux_wire::IdentityChangeEvent| {
                            normalize::identity_change(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = capset_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::CapSetEvent, sink, own_pid,
                        |e: &sensor_linux_wire::CapSetEvent| {
                            normalize::cap_set(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
                        });
                }
                guard = namespace_ring_buf.readable_mut() => {
                    drain!(guard, sensor_linux_wire::NamespaceEvent, sink, own_pid,
                        |e: &sensor_linux_wire::NamespaceEvent| {
                            normalize::namespace(e, offset, container_context(e.meta.cgroup_id, &mut container_ids, &docker_cache))
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
