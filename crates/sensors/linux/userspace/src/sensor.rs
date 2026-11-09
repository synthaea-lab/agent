//! The Linux sensor itself: loading/attaching the eBPF programs, reading the ring
//! buffers, dispatching normalized events to an `EventSink`. Migrated from
//! `old/crates/synthaea-sensor-linux`.
//!
//! `load_ebpf`/`load_program`/`RAW_TRACEPOINTS` stay `pub`: the agent's status command
//! reuses them for the preflight (loads each program without attaching it), which is
//! not part of the `Sensor` contract.

use std::{sync::Arc, time::Duration};

use schema::sensor::{Capabilities, EventSink, Sensor, SensorError};
use sensor_linux_wire as wire;
use tokio::sync::Notify;
use tracing::warn;

use crate::{
    container::ContainerResolver,
    drain::exec_record,
    ebpf::{
        DNS_UDP_PROGRAM, RAW_TRACEPOINTS, TamperSlot, attach_inode_setattr, attach_raw_tracepoint,
        clear_tamper_slot, err, load_ebpf_for_run, prime_proc_lineage, read_tamper_slot,
        take_signal_tool_drops, take_signal_watch_tools, take_tamper_slot, write_signal_watch_pid,
    },
    normalize,
    parent_image::{ExecStamps, IMAGE_CACHE_CAP, ParentImageEvictions, ParentImages},
    proc::{exec_argv, read_proc_environ_security, read_proc_images},
    rings::{RingBuffers, drain_ready, drain_wire, readable_or_pending},
    unit_procs::{ToolProcs, ToolWatch, UnitResolver},
};

/// The file a `finit_module(2)` event's fd points at (#457), read from
/// `/proc/<pid>/fd/<fd>` while the event is drained. Racy by nature: the
/// loader may already have closed the fd or exited, and then this is `None`
/// (the event still carries the fd). `init_module`/`delete_module` have no fd.
fn finit_module_path(event: &wire::KernelModuleEvent) -> Option<String> {
    if event.action != 1 || event.fd < 0 {
        return None;
    }
    std::fs::read_link(format!("/proc/{}/fd/{}", event.meta.pid, event.fd))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// See `sensor_linux_wire::boot_epoch_offset_ns` — computed once at startup.
/// (Consolidated there by #295; a parallel branch merge resurrected the old
/// local copy once already — if you are reading a full implementation here
/// again, the same thing happened again.)
fn boot_epoch_offset_ns() -> u64 {
    wire::boot_epoch_offset_ns()
}

/// How often [`sweep_survived_sigkill`] runs.
const TAMPER_SWEEP_INTERVAL: Duration = Duration::from_secs(10);

/// How often the processes of the listed security units are scanned again (#1103). A restarted
/// tool's new pid is unwatched until the next scan, so this is the window a kill of it can go
/// unseen in (a few seconds, stated in `docs/detection/security-tool-stop.md`); a scan is a few
/// small reads of the cgroup tree.
const TOOL_RESCAN_INTERVAL: Duration = Duration::from_secs(5);

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

/// The image and unit reported for a signal's target. A target on the watch list is a security
/// tool: its unit and the exe read at scan time (the process may be gone by now). Anything else
/// is the agent itself (`SIGNAL_WATCH_PID`). A target that is neither (a tool gone from every
/// scan) gets no image and no unit, never the agent's: it must not read as a signal to the agent.
fn signal_target(
    event: &wire::SignalEvent,
    tool_procs: &ToolProcs,
    own_pid: u32,
    self_exe: Option<&String>,
) -> (Option<String>, Option<String>) {
    let tool = tool_procs
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&event.target_pid)
        .cloned();
    match tool {
        Some(tool) => (tool.exe, Some(tool.unit)),
        None if event.target_pid == own_pid => (self_exe.cloned(), None),
        None => (None, None),
    }
}

/// Linux sensor (eBPF). `run` blocks until Ctrl-C or [`Sensor::stop`].
pub struct LinuxSensor {
    stop: Arc<Notify>,
    evictions: Arc<ParentImageEvictions>,
    /// Whether the UDP/53 DNS capture program is attached (#458 part 3). Fixed for the life of the
    /// sensor.
    dns_udp: bool,
}

impl Default for LinuxSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxSensor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            stop: Arc::new(Notify::new()),
            evictions: Arc::new(ParentImageEvictions::default()),
            dns_udp: false,
        }
    }

    /// Attaches the UDP/53 DNS capture program (#458 part 3): the first bytes of a
    /// datagram sent to port 53, from `sendto(2)` and from `write(2)` on a socket connected to
    /// port 53, reported as `DnsQuery` events with no answer. Off by default, like the
    /// `getaddrinfo` capture it completes (`--enable-dns-capture` turns on both). Fixed at start.
    #[must_use]
    pub fn with_dns_udp_capture(mut self, enabled: bool) -> Self {
        self.dns_udp = enabled;
        self
    }

    /// The running totals of what the parent-image cache's cap drops, for the agent's health
    /// beacon (#863). The same handle for the life of the sensor, so it can be taken before the
    /// sensor is moved onto its thread.
    #[must_use]
    pub fn parent_image_evictions(&self) -> Arc<ParentImageEvictions> {
        Arc::clone(&self.evictions)
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
                // SAFETY: `logger` owns its `RingBuf<MapData>`, whose fd is the `OwnedFd`
                // aya holds in the map; it is valid and open, and aya offers no way to close,
                // replace or take it out of the logger — it is closed only when the logger
                // drops, which now happens when this `AsyncFd` drops. The fd stays open and
                // the same one for the `AsyncFd`'s whole life, and `as_raw_fd` returns it.
                let mut logger = unsafe {
                    tokio::io::unix::AsyncFd::register_with_interest(
                        logger,
                        tokio::io::Interest::READABLE,
                    )
                }
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

        // The same processes' image paths, so the first child of an already-running
        // parent resolves `parent_image_path` too (#768).
        let mut parent_images =
            ParentImages::new(IMAGE_CACHE_CAP).with_totals(Arc::clone(&self.evictions));
        for (pid, generation, image) in read_proc_images(IMAGE_CACHE_CAP) {
            parent_images.prime(pid, generation, image);
        }
        tracing::info!(
            primed = parent_images.len(),
            "sensor-linux: primed process images for parent_image_path"
        );

        // The processes of the listed security units, before `raw_signal_generate` is attached so
        // that a signal landing right after the attach already finds them (#1103).
        let mut tool_watch =
            ToolWatch::new(UnitResolver::system(), take_signal_watch_tools(&mut ebpf)?);
        tracing::info!(
            watched = tool_watch.refresh(),
            "sensor-linux: security tool processes on the signal watch list"
        );
        let tool_procs = tool_watch.procs();
        let tool_drops = take_signal_tool_drops(&mut ebpf)?;
        let mut tool_drops_seen = 0u64;
        let mut tool_rescan = tokio::time::interval(TOOL_RESCAN_INTERVAL);

        for (program, name) in RAW_TRACEPOINTS {
            // The UDP/53 capture is a program of its own, attached only when asked for.
            if *program == DNS_UDP_PROGRAM && !self.dns_udp {
                continue;
            }
            attach_raw_tracepoint(&mut ebpf, program, name)?;
        }

        // Explicit timestamp requests (T1070.006, #1044): an LSM hook, so it depends on `bpf`
        // being in the active `lsm=` list. Best-effort: without it the sensor runs as before
        // and the ring buffer below is simply not read.
        let set_time_live = match attach_inode_setattr(&mut ebpf) {
            Ok(()) => {
                tracing::info!("sensor-linux: inode_setattr LSM hook attached (timestamp changes)");
                true
            }
            Err(e) => {
                warn!(error = %e, "sensor-linux: inode_setattr hook not attached, timestamp changes are not observed");
                false
            }
        };

        let mut rings = RingBuffers::open(&mut ebpf, set_time_live)?;

        tracing::info!(
            "sensor-linux: listening for exec/open/connect/write/delete/rename/bind/chmod/chown/udp_send/udp_recv/dns_udp/listen/accept/socket_create/setxattr/removexattr/mount/signal/kernel_module/bpf/prctl/ptrace/process_vm_readv/process_vm_writev/memfd_create/identity_change/capset/namespace events"
        );

        let mut containers = ContainerResolver::new();
        let sink = &*sink;
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
                None,
                containers.resolve(previous.meta.cgroup_id),
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
                _ = tool_rescan.tick() => {
                    tool_watch.refresh();
                    // Tool signals lost to a full ring: counted in the kernel, reported when it grows.
                    if let Ok(per_cpu) = tool_drops.get(&0, 0) {
                        let total: u64 = per_cpu.iter().sum();
                        if total > tool_drops_seen {
                            let lost = total - tool_drops_seen;
                            tracing::warn!(
                                dropped = lost,
                                total,
                                "sensor-linux: signals to security tools lost, signal ring buffer full"
                            );
                            tool_drops_seen = total;
                            // A flood of lethal signals ahead of a kill is how a tool is ended
                            // unseen: report the loss as an event the rules alert on.
                            let now_ns = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
                            sink.on_event(normalize::signals_lost(lost, own_pid, now_ns));
                        }
                    }
                }
                guard = rings.exec.readable_mut() => {
                    // Two synchronous procfs reads per exec event, on this task (see
                    // `read_proc_cmdline`'s doc comment on why this hasn't warranted
                    // `spawn_blocking` yet — `read_proc_environ_security` is the same
                    // file family, same tradeoff).
                    drain_ready(guard, sink, own_pid, |record: &[u8]| {
                        let (e, windows) = exec_record(record)?;
                        let captured = exec_argv(&e, &windows);
                        let mut event = normalize::exec(&e, offset, captured.argv, captured.omitted_bytes, read_proc_environ_security(e.meta.pid), containers.resolve(e.meta.cgroup_id));
                        if let schema::Event::Exec(exec) = &mut event {
                            parent_images.annotate(exec, ExecStamps {
                                ktime_ns: e.meta.timestamp_ns,
                                grandparent_pid: e.grandparent_pid,
                                grandparent_generation: e.grandparent_generation,
                                parent_never_exec_ed: e.parent_execd == 0,
                            });
                        }
                        Some(event)
                    })?;
                }
                guard = rings.file_open.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::FileOpenEvent| normalize::file_open(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                guard = rings.connect.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::ConnectEvent| normalize::connect(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                guard = rings.file_write.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::FileWriteEvent| normalize::file_write(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                guard = rings.file_delete.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::FileDeleteEvent| normalize::file_delete(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                guard = rings.file_rename.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::FileRenameEvent| normalize::file_rename(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                guard = rings.socket_bind.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::SocketBindEvent| normalize::socket_bind(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                guard = rings.file_chmod.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::FileChmodEvent| normalize::file_chmod(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                guard = readable_or_pending(&mut rings.file_set_time) => drain_wire(guard, sink, own_pid, |e: &wire::FileSetTimeEvent| normalize::file_set_time(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                guard = rings.file_chown.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::FileChownEvent| normalize::file_chown(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                guard = rings.udp_send.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::UdpSendEvent| normalize::udp_send(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                // `None` for a payload that is not a DNS query (a reused descriptor, a stream that
                // looked like one): dropped here, never reported.
                guard = rings.dns_udp.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::DnsUdpQueryEvent| normalize::dns_udp_query(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                guard = rings.udp_recv.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::UdpRecvEvent| normalize::udp_recv(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                guard = rings.socket_listen.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::SocketListenEvent| normalize::socket_listen(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                guard = rings.socket_accept.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::SocketAcceptEvent| normalize::socket_accept(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                guard = rings.socket_create.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::SocketCreateEvent| normalize::socket_create(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                guard = rings.file_setxattr.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::FileSetxattrEvent| normalize::file_setxattr(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                guard = rings.file_removexattr.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::FileRemovexattrEvent| normalize::file_removexattr(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                guard = rings.mount.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::MountEvent| normalize::mount(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                // The container is the SENDER's (meta is the sender, as for every event type):
                // it attributes e.g. a container-escape kill attempt to the container it came from.
                guard = rings.signal.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::SignalEvent| {
                    let (image, unit) = signal_target(e, &tool_procs, own_pid, self_exe.as_ref());
                    normalize::signal(e, offset, image, unit, containers.resolve(e.meta.cgroup_id))
                })?,
                guard = rings.kernel_module.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::KernelModuleEvent| normalize::kernel_module(e, finit_module_path(e), offset, containers.resolve(e.meta.cgroup_id)))?,
                guard = rings.bpf.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::BpfEvent| normalize::bpf_operation(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                guard = rings.prctl.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::PrctlEvent| normalize::prctl(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                guard = rings.ptrace.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::PtraceEvent| normalize::ptrace(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                guard = rings.process_vm_read.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::ProcessVmReadEvent| normalize::process_vm_read(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                guard = rings.process_vm_write.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::ProcessVmWriteEvent| normalize::process_vm_write(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                guard = rings.memfd_create.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::MemfdCreateEvent| normalize::memfd_create(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                guard = rings.identity_change.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::IdentityChangeEvent| normalize::identity_change(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                guard = rings.capset.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::CapSetEvent| normalize::cap_set(e, offset, containers.resolve(e.meta.cgroup_id)))?,
                guard = rings.namespace.readable_mut() => drain_wire(guard, sink, own_pid, |e: &wire::NamespaceEvent| normalize::namespace(e, offset, containers.resolve(e.meta.cgroup_id)))?,
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
mod evictions_handle_tests {
    use std::sync::Arc;

    use super::LinuxSensor;

    #[test]
    fn the_eviction_totals_are_one_shared_handle_that_starts_at_zero() {
        let sensor = LinuxSensor::new();
        let first = sensor.parent_image_evictions();
        let second = sensor.parent_image_evictions();

        assert!(
            Arc::ptr_eq(&first, &second),
            "taken before the sensor moves to its thread, read after"
        );
        assert_eq!((first.dead(), first.live()), (0, 0));
        assert!(
            !Arc::ptr_eq(&first, &LinuxSensor::new().parent_image_evictions()),
            "each sensor has its own"
        );
    }
}
