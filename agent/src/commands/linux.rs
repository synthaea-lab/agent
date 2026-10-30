//! Linux: eBPF sensor commands. Status is a non-invasive preflight (loads the
//! programs through the kernel verifier without attaching them); run/capture
//! drive `LinuxSensor` with the appropriate sink.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use schema::sensor::{EventSink as _, Sensor as _};
use tamper::heartbeat::{SensorHeartbeat, SilenceMonitor};

use crate::{
    captures::{CaptureSet, Captures, UprobesAction, plan},
    protected::ProtectedResourceGuard,
    shutdown::{SHUTDOWN_BUDGET, ShutdownPlan, sleep_unless_stopped},
    silence::{PulsingSink, SourceStatus},
    sink::DetectionSink,
};

/// Silence deadlines (#71) fed to `SilenceMonitor::register`. The eBPF sensor and
/// the journal tail have no self-generated canary (see `silence::PulsingSink`'s
/// doc), so their deadline is generous — long enough that an ordinary host's
/// incidental activity (cron, the agent's own files, network chatter, journald's
/// own baseline logging) almost always beats it, keeping the false-positive rate
/// on an idle-but-healthy sensor low. The netlink poller ticks every
/// [`NETLINK_POLL_INTERVAL`] regardless of host activity — a real canary — so its
/// deadline can be tight: three missed polls is a genuine stall, not bad luck.
const NO_CANARY_SILENCE_DEADLINE_NS: u64 = 120_000_000_000; // 120s
const NETLINK_SILENCE_DEADLINE_NS: u64 = 3 * NETLINK_POLL_INTERVAL.as_secs() * 1_000_000_000;
/// Same shape as `NETLINK_SILENCE_DEADLINE_NS`: [`spawn_avc_reader`]'s `drain` call
/// returning at all, whether or not anything was queued, is its canary — three missed
/// cycles of [`AVC_POLL_TIMEOUT_MS`] (6s) is a genuine stall. In practice the
/// `SilenceMonitor` only checks on `silence::POLL_INTERVAL` (10s), so the deadline that
/// actually fires is "no pulse between two monitor polls", roughly 10-20s, not a literal
/// 6s — a healthy reader pulses every ≤ [`AVC_POLL_TIMEOUT_MS`] regardless, so this
/// causes no false positives.
const AVC_SILENCE_DEADLINE_NS: u64 = 3 * AVC_POLL_TIMEOUT_MS as u64 * 1_000_000;

/// The actual OS-level kill call for issue #25's automated response —
/// `response::kill_process` takes this as an injected closure rather than calling
/// `libc` itself, since `response` is base-tier-only and platform dispatch belongs
/// here (CLAUDE.md: platform-specific code stays out of library crates outside
/// `crates/sensors/*`). `SIGKILL`, not `SIGTERM`: a process correlated as
/// compromised gets no chance to catch a signal and clean up/hide/persist further.
fn terminate_process(pid: u32) -> std::io::Result<()> {
    // SAFETY: `kill` with an arbitrary pid is memory-safe — a nonexistent or
    // already-exited pid just returns `ESRCH`, surfaced via the checked return code.
    let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// `RuleState` pre-filled with the processes already running at startup — without
/// it, the parent-side exclusions and lineage rules don't apply to processes
/// launched before the agent, the most common case in practice (see `RuleState`).
/// Also seeds the LISTENER-DRIFT baseline (issue #92) from one startup
/// `sock_diag` snapshot, same reasoning: every listener already up when the
/// agent attaches (sshd, nginx started by systemd at boot) is the baseline, not
/// a finding. Best-effort — a snapshot failure (permissions, kernel support)
/// leaves the baseline empty rather than failing agent startup, same posture as
/// the netlink poller itself.
fn seeded_rule_state() -> rules::RuleState {
    let mut rule_state = rules::RuleState::new();
    rule_state.seed_from_proc();
    // T1574.006 (#363): trust the library directories this host's ld.so.conf
    // declares, on top of the built-in baseline.
    rule_state.seed_ld_trust_from_system();
    match sensor_linux_netlink::snapshot() {
        Ok(entries) => {
            rule_state.seed_listen_ports(
                entries
                    .iter()
                    .filter(|entry| entry.state == sensor_linux_netlink::SocketState::Listen)
                    .map(|entry| {
                        (
                            entry.local.ip(),
                            entry.local.port(),
                            sensor_linux_netlink::IPPROTO_TCP,
                        )
                    }), // sock_diag TCP dump only, today (issue #676)
            );
        }
        Err(e) => tracing::warn!(error = %e, "listen-port baseline: sock_diag snapshot failed"),
    }
    rule_state
}

/// Linux: non-invasive eBPF preflight (loads the programs without attaching them).
pub(crate) fn cmd_status() -> anyhow::Result<()> {
    // SAFETY: geteuid takes no arguments and cannot fail.
    let uid = unsafe { libc::geteuid() };
    if uid == 0 {
        println!("[OK]   privileges: uid=0");
    } else if has_bpf_capabilities() {
        // Not root, but the effective capability set carries what eBPF loading
        // needs — a capability-scoped deployment (systemd AmbientCapabilities)
        // is the recommended setup, not a failure (review finding: the uid-only
        // check flagged FAIL on properly capability-scoped services).
        println!("[OK]   privileges: uid={uid} with CAP_BPF/CAP_SYS_ADMIN + CAP_PERFMON");
    } else {
        println!(
            "[FAIL] privileges: not root (uid={uid}) and no CAP_BPF/CAP_PERFMON — loading an eBPF program will fail"
        );
    }

    let btf_path = "/sys/kernel/btf/vmlinux";
    if std::path::Path::new(btf_path).exists() {
        println!("[OK]   kernel BTF present ({btf_path})");
    } else {
        println!("[FAIL] kernel BTF missing ({btf_path}) — the eBPF probes cannot load");
    }

    if let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        println!("[OK]   kernel: {}", release.trim());
    }

    let mut ebpf = sensor_linux::load_ebpf()
        .map_err(|e| anyhow::anyhow!("failed to load the embedded eBPF bytecode: {e}"))?;
    let mut failures = 0u32;
    for (program_name, name) in sensor_linux::RAW_TRACEPOINTS {
        match sensor_linux::load_program(&mut ebpf, program_name) {
            Ok(()) => println!(
                "[OK]   raw tracepoint program `{program_name}` ({name}) accepted by the verifier"
            ),
            Err(e) => {
                failures += 1;
                println!("[FAIL] raw tracepoint program `{program_name}` ({name}) rejected: {e}");
            }
        }
    }

    // Scripts and provisioning gate on the exit code, not on parsing stdout —
    // a rejected probe must fail the preflight (review finding: `status` always
    // exited 0, so `agent status && agent run` proceeded onto a broken sensor).
    if failures > 0 {
        anyhow::bail!("{failures} eBPF program(s) rejected by the verifier");
    }
    Ok(())
}

/// True when the effective capability set allows eBPF loading: `CAP_SYS_ADMIN`,
/// or `CAP_BPF` plus `CAP_PERFMON` (tracepoint attachment). Read from
/// `/proc/self/status` `CapEff` — best-effort, false on any parse failure.
fn has_bpf_capabilities() -> bool {
    const CAP_SYS_ADMIN: u32 = 21;
    const CAP_PERFMON: u32 = 38;
    const CAP_BPF: u32 = 39;
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    let Some(cap_eff) = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
    else {
        return false;
    };
    let has = |bit: u32| cap_eff & (1 << bit) != 0;
    has(CAP_SYS_ADMIN) || (has(CAP_BPF) && has(CAP_PERFMON))
}

/// Selects sensor: eBPF if available, audit fallback otherwise.
/// Returns (sensor, `sensor_name`) for correct telemetry.
///
/// The third value reads what the eBPF sensor's parent-image cache has dropped, for the health
/// beacon (#863); the audit fallback has no such cache.
fn select_sensor(
    enable_dns_capture: bool,
) -> (
    Box<dyn schema::sensor::Sensor>,
    &'static str,
    Option<crate::host_counters::EvictionReader>,
) {
    if can_use_ebpf() {
        tracing::info!("Using eBPF sensor (primary)");
        // `--enable-dns-capture` also turns on the socket-level query capture (#458 part 3).
        let sensor = sensor_linux::LinuxSensor::new().with_dns_udp_capture(enable_dns_capture);
        let evictions = sensor.parent_image_evictions();
        return (
            Box::new(sensor),
            "linux-ebpf",
            Some(Box::new(move || (evictions.live(), evictions.dead()))),
        );
    }

    tracing::warn!("eBPF unavailable — using audit fallback (reduced fidelity)");
    (
        Box::new(sensor_linux_audit::AuditSensor::new()),
        "linux-audit",
        None,
    )
}

/// Checks if eBPF sensor can be loaded (privileges, BTF, verifier).
/// Tests both object loading and program loading to match `cmd_status()` behavior.
fn can_use_ebpf() -> bool {
    // Check 1: Privileges
    // SAFETY: geteuid takes no arguments and cannot fail.
    let uid = unsafe { libc::geteuid() };
    if uid != 0 && !has_bpf_capabilities() {
        tracing::debug!("eBPF preflight: no privileges");
        return false;
    }

    // Check 2: BTF present
    if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        tracing::debug!("eBPF preflight: no BTF");
        return false;
    }

    // Check 3: Can load eBPF object
    let mut ebpf = match sensor_linux::load_ebpf() {
        Ok(ebpf) => ebpf,
        Err(e) => {
            tracing::debug!(error = %e, "eBPF preflight: failed to load object");
            return false;
        }
    };

    // Check 4: Can load programs (verifier acceptance)
    // Test at least one program to catch verifier rejections (strict lockdown/LSM)
    if let Some((program_name, _name)) = sensor_linux::RAW_TRACEPOINTS.first()
        && let Err(e) = sensor_linux::load_program(&mut ebpf, program_name)
    {
        tracing::debug!(program = program_name, error = %e, "eBPF preflight: program rejected");
        return false;
    }

    true
}

/// Linux: eBPF capture + detection via `LinuxSensor` (Ctrl-C handled by the sensor),
/// plus the netlink poller (issue #92: `sock_diag`/conntrack — listen-port drift and
/// beacon detection where eBPF cannot run, or as a redundant cross-check alongside
/// it). Both feed the same `DetectionSink`, shared via `Arc` (`schema::sensor`'s
/// blanket `EventSink for Arc<T>`) since `LinuxSensor::run` needs to own its sink
/// for `Sensor`'s lifetime but the poller thread outlives no particular caller.
pub(crate) fn cmd_run(opts: super::RunOptions) -> anyhow::Result<()> {
    let super::RunOptions {
        alerts,
        events,
        storage,
        alert_details,
        enable_kill,
        enable_quarantine,
        enable_tls_capture,
        enable_readline_capture,
        enable_dns_capture,
        server,
        ipc_endpoint,
        content_dir,
        log_sources,
        deception,
        config_path,
    } = opts;
    // Kill-loudness (#71): must run before any other thread exists — the signal mask
    // set here is inherited by every thread spawned below, including `DetectionSink`'s
    // own worker threads.
    crate::kill_loudness::block_termination_signals();

    let pipeline = super::common::wire_run_pipeline(
        seeded_rule_state(),
        alerts,
        events,
        server,
        ipc_endpoint,
        content_dir,
        storage,
    )?;
    // #319. Set before any sensor starts; the one alert `wire_run_pipeline` can raise
    // itself (UPLOAD-DISABLED) is the agent's own text, not an event's.
    pipeline.sink.alert_log().set_stderr_details(alert_details);
    super::common::plant_canaries(
        &pipeline.sink,
        deception,
        storage,
        pipeline.transport.as_ref(),
    );
    let sink = Arc::clone(&pipeline.sink);

    // The watcher thread itself can start any time after the mask above — only the
    // masking has to precede every other thread. Started here (not right after the
    // masking call) so it can hold a clone of the sink's enrich queue for #341's
    // bounded shutdown drain.
    crate::kill_loudness::spawn_watcher(alerts.to_path_buf(), sink.enrich_queue().clone());

    // Select the primary sensor (eBPF or audit fallback) before creating heartbeats
    // so telemetry reports the correct sensor type.
    let (mut sensor, sensor_name, evictions) = select_sensor(enable_dns_capture);

    // Automated response (#25): policy off by default (observe-only), opted into
    // per flag. Quarantine lands next to alerts.ndjson, the same "derived, no
    // separate flag" convention `heartbeat::heartbeat_path_for` uses for #102.
    sink.enable_response(
        policy::ResponsePolicy {
            kill_enabled: enable_kill,
            quarantine_enabled: enable_quarantine,
            isolate_enabled: false,
        },
        terminate_process,
        crate::quarantine_cmd::quarantine_dir_for(alerts),
    );
    if enable_kill || enable_quarantine {
        eprintln!(
            "response: kill={enable_kill} quarantine={enable_quarantine} (see alerts.ndjson for RESPONSE-* entries)"
        );
    }

    // Sensor-silence detection (#71): one heartbeat per sensor, pulsed as each
    // processes events/polls, watched by a dedicated thread — see `silence`'s doc.
    let primary_heartbeat = SensorHeartbeat::new(sensor_name);
    let netlink_heartbeat = SensorHeartbeat::new("linux-netlink");
    let journal_heartbeat = SensorHeartbeat::new("linux-journal");
    // Only registered/pulsed if actually enabled below — an uprobes sensor that
    // never runs (the off-by-default case) must never accrue silence, or a
    // deliberately-disabled capture would eventually alert as a stalled sensor.
    let uprobes_heartbeat = SensorHeartbeat::new("linux-uprobes");
    // Same "only if it actually runs" rule (#780): started only when eBPF is
    // primary (see the spawn call below), since `AuditSensor` as primary already
    // covers AVC denials through its own heartbeat. Opened here, synchronously,
    // rather than inside the spawned thread: the heartbeat below must only be
    // registered once we know the worker runs (#780 review) — a packaged install
    // without `CAP_AUDIT_READ` on a host that has no SELinux must not accrue
    // silence for a sensor that never started, or every start raises a false
    // T1562 alert. On an SELinux host the worker runs even when the first open
    // failed (#878 review): it retries the open like it retries a reopen, pulsing
    // while it waits, so that start-up failure that clears (EMFILE, auditd briefly
    // holding the socket) recovers without a restart.
    let ebpf_primary = starts_avc_reader(sensor_name);
    // Down for a reason the agent knows (#878, #879): reported through the health beacon as a
    // silent `linux-avc` sensor, so the fleet page shows the host as degraded, rather than as
    // a heartbeat that went quiet, which is read as tampering. Only on a host with SELinux:
    // without it there is no AVC stream to lose.
    let avc_status = SourceStatus::new("linux-avc");
    let selinux = selinux_active();
    let (avc_reader, runs_avc_worker) = match ebpf_primary.then(sensor_linux_audit::AvcReader::open)
    {
        None => (None, false),
        Some(Ok(reader)) => (Some(reader), true),
        Some(Err(e)) if selinux => {
            avc_status.set_down(true);
            tracing::warn!(
                error = %e,
                "avc-reader: could not open NETLINK_AUDIT — SELinux AVC denials are not captured yet, retrying (reported as a degraded sensor, linux-avc)"
            );
            (None, true)
        }
        Some(Err(e)) => {
            tracing::info!(
                error = %e,
                "avc-reader: could not open NETLINK_AUDIT, and SELinux is not active on this host"
            );
            (None, false)
        }
    };
    let avc_heartbeat = SensorHeartbeat::new("linux-avc");
    let silence_monitor = Arc::new(Mutex::new(SilenceMonitor::new()));
    // The optional uprobe captures as configured. Nothing widens them yet: a posture overlay will
    // (ADR-0035, third slice); the supervisor below already follows the set.
    let capture_set = CaptureSet::new(Captures {
        tls: enable_tls_capture,
        readline: enable_readline_capture,
        dns: enable_dns_capture,
    });
    let uprobes_monitor = Arc::clone(&silence_monitor);
    {
        let now_ns = schema::time::now_ns();
        let mut mon = silence_monitor.lock().unwrap();
        mon.register(
            primary_heartbeat.clone(),
            NO_CANARY_SILENCE_DEADLINE_NS,
            now_ns,
        );
        mon.register(
            netlink_heartbeat.clone(),
            NETLINK_SILENCE_DEADLINE_NS,
            now_ns,
        );
        mon.register(
            journal_heartbeat.clone(),
            NO_CANARY_SILENCE_DEADLINE_NS,
            now_ns,
        );
        if runs_avc_worker {
            mon.register(avc_heartbeat.clone(), AVC_SILENCE_DEADLINE_NS, now_ns);
        }
    }
    crate::silence::spawn_monitor(silence_monitor.clone(), sink.clone());

    // Self-integrity verification (#71/#30): periodic re-check of the installed
    // binaries against the signed release manifest `updater` persisted at promote
    // time — the real root of trust the heartbeat above cannot provide (silence
    // proves a sensor stopped producing, not that the binary producing it is the
    // one that was actually shipped).
    crate::integrity::spawn_monitor(storage.state_dir.clone(), sink.clone());

    // Diffed package inventory (#87): periodic dpkg-status diff, turned into a
    // real case-attachable Detection through the normal sink path (not a
    // local-only alert like the two monitors above).
    crate::inventory::spawn_monitor(storage.state_dir.clone(), sink.clone());

    // Health beacon (#134): periodic self-diagnostics to the control plane, over
    // the silence monitor above.
    let health = super::common::health_collector(
        &pipeline,
        silence_monitor,
        vec![avc_status.clone()],
        Arc::new(crate::host_counters::AgentHostCounters::new(
            Arc::clone(&pipeline.sink),
            crate::host_counters::WatchdogReport::from_env(),
            evictions,
        )),
    );
    // Workers wound down after `sensor.run` returns (#316).
    let mut shutdown = ShutdownPlan::default();
    let (health_handle, health_stop) = health.spawn();
    shutdown.register("health-beacon", move || health_stop.stop(), health_handle);
    if let Some(transport) = pipeline.transport {
        transport.register_shutdown(&mut shutdown);
    }

    spawn_netlink_poller(sink.clone(), netlink_heartbeat, &mut shutdown);
    spawn_journal_tail(sink.clone(), journal_heartbeat, alerts);
    if runs_avc_worker {
        spawn_avc_reader(
            sink.clone(),
            avc_heartbeat,
            avc_status,
            selinux,
            avc_reader,
            &mut shutdown,
        );
    }
    crate::log_sources::spawn(sink.clone(), log_sources, alerts, &mut shutdown);
    spawn_uprobes_supervisor(
        sink.clone(),
        uprobes_heartbeat,
        uprobes_monitor,
        capture_set,
    );

    // Observation-only BPF-LSM coverage (issue #91/#313): best-effort, never
    // fails `cmd_run`. `_lsm_ebpf` must stay bound for the rest of this function
    // — dropping it detaches the hook — so it lives alongside `sensor` below,
    // both held until `sensor.run()`'s Ctrl-C return ends the process.
    let _lsm_ebpf = attach_lsm_hooks();

    // Protected-resource monitoring (#71): only the eBPF sensor produces `FileOpen`
    // events, so only its chain needs the guard — the netlink/journal sinks above
    // never see one.
    let protected = crate::protected::protected_paths(alerts, events, config_path);
    let guarded = ProtectedResourceGuard::new(sink.clone(), protected, sink.clone());
    let result = sensor.run(Box::new(PulsingSink::new(guarded, primary_heartbeat)));

    // Persist findings already accepted by the in-memory queue before the
    // uploader makes its final drain. A bounded wait preserves shutdown's
    // overall deadline if enrichment is stalled on a slow file.
    if !sink.enrich_queue().flush(std::time::Duration::from_secs(1)) {
        tracing::warn!("pending detection/event queue did not flush before shutdown");
    }

    // `sensor.run` returned (Ctrl-C or a sensor failure): wind the workers down —
    // the upload loop gets one last spool drain — within one bounded budget. What
    // is still spooled after that is redelivered on the next start (at-least-once).
    // SIGTERM/SIGHUP/SIGQUIT do not come through here: `kill_loudness`'s watcher
    // ends the process itself (after the enrich-queue flush, #341).
    let stragglers = shutdown.execute(SHUTDOWN_BUDGET);
    if !stragglers.is_empty() {
        tracing::warn!(
            ?stragglers,
            "workers still running at the shutdown deadline"
        );
    }
    result.map_err(|e| anyhow::anyhow!("sensor failed: {e}"))
}

/// Polling interval for [`spawn_netlink_poller`]. `crates/rules`' BEACON window is
/// 60s and needs 3 distinct flows inside it to ever alert — frequent enough to
/// leave room for that, without dumping the kernel's socket/conntrack tables on
/// every tick.
const NETLINK_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// Spawns the background thread that periodically snapshots `sock_diag`
/// (listen-port drift) and dumps conntrack (beacon volume features), handing the
/// resulting events to `sink` — the caller `sensor_linux_netlink`'s own crate doc
/// says doesn't exist yet: that crate produces `schema::Event`s but leaves the
/// polling cadence and the handoff to `EventSink` entirely to its caller.
///
/// Registers itself with `shutdown` (#316): the poll loop exits within one sleep
/// slice of the stop. (`EnrichQueue` and `yara::ScanQueue` workers still end with
/// the process.)
fn spawn_netlink_poller(
    sink: Arc<DetectionSink>,
    heartbeat: SensorHeartbeat,
    shutdown: &mut ShutdownPlan,
) {
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let handle = std::thread::Builder::new()
        .name("netlink-poll".into())
        .spawn(move || {
            let mut listen_warned = false;
            let mut conntrack_warned = false;
            while !worker_stop.load(Ordering::SeqCst) {
                let ts = schema::time::now_ns();
                forward_netlink_events(
                    sensor_linux_netlink::listen_port_events(ts),
                    &sink,
                    &heartbeat,
                    &mut listen_warned,
                    "listen-port",
                );
                forward_netlink_events(
                    sensor_linux_netlink::conntrack_flow_events(ts),
                    &sink,
                    &heartbeat,
                    &mut conntrack_warned,
                    "conntrack",
                );
                sleep_unless_stopped(&worker_stop, NETLINK_POLL_INTERVAL);
            }
        })
        .expect("spawning the netlink poll thread");
    shutdown.register(
        "netlink-poll",
        move || stop.store(true, Ordering::SeqCst),
        handle,
    );
}

/// Forwards one poll's events to `sink`, or logs a kernel error — once per
/// distinct failure streak (`warned`) rather than every `NETLINK_POLL_INTERVAL`,
/// since an unprivileged agent (conntrack's reachability isn't characterized
/// unprivileged, see `sensor_linux_netlink`'s crate doc) would otherwise log the
/// same `EPERM` forever. Pulses `heartbeat` on a successful poll regardless of
/// event count (#71): the poll attempt succeeding is itself the netlink
/// sensor's canary — silence here means the poll is failing or the thread is
/// stuck, not merely that the host has nothing to report.
fn forward_netlink_events(
    result: Result<Vec<schema::Event>, sensor_linux_netlink::NetlinkError>,
    sink: &DetectionSink,
    heartbeat: &SensorHeartbeat,
    warned: &mut bool,
    source: &str,
) {
    match result {
        Ok(events) => {
            *warned = false;
            heartbeat.pulse();
            for event in events {
                sink.on_event(event);
            }
        }
        Err(e) => {
            if !*warned {
                *warned = true;
                tracing::warn!(
                    source,
                    error = %e,
                    "netlink poll failed — further identical errors this run are suppressed"
                );
            }
        }
    }
}

/// How long `sensor_linux_audit::AvcReader::drain` blocks waiting for the socket
/// before returning control to [`spawn_avc_reader`] for its own stop check and
/// heartbeat pulse. Tighter than [`NETLINK_POLL_INTERVAL`]: AVC denials are a
/// real-time stream, not a snapshot to poll on a cadence, so there is no reason
/// to hold one back once it has arrived.
const AVC_POLL_TIMEOUT_MS: i32 = 2000;

/// Whether the `AvcReader` should run next to the chosen primary sensor (#780):
/// only when eBPF is primary. When `AuditSensor` is primary instead, it already
/// classifies every AVC record on the same stream through its own `Sensor::run`
/// loop — starting a second reader would double up `PolicyDenial` events, not
/// add coverage (`AvcReader`'s doc: a second socket does not steal records from
/// the first). Pulled out as its own pure function (#780 review) so the gate is
/// unit-testable without exercising `cmd_run`'s real sockets and threads.
fn starts_avc_reader(sensor_name: &str) -> bool {
    sensor_name == "linux-ebpf"
}

/// Spawns the background thread that keeps `SELinux` AVC denials reachable when
/// eBPF is the chosen primary sensor (#780): `select_sensor` picks eBPF or
/// `AuditSensor` for exec/connect, never both, so on a host where eBPF loads —
/// the normal case on a hardened, up-to-date `SELinux`-Enforcing box — the audit
/// sensor (the only place that classifies AVC records, see
/// `sensor_linux_audit::AvcReader`'s doc) never runs, and POLICY-DENIAL-DRIFT
/// (#774) goes silent on exactly the hosts it was built for.
///
/// Caller's responsibility, not enforced here: only call this when eBPF is
/// actually primary. When `AuditSensor` itself is primary, it already classifies
/// every AVC record on the same stream through its own `Sensor::run` loop —
/// starting this reader too would double up `PolicyDenial` events, not add
/// coverage (`AvcReader`'s doc: a second socket does not steal records from the
/// first, so nothing crashes, but nothing is gained either).
///
/// Best-effort, same posture as [`spawn_journal_tail`]: a missing
/// `CAP_AUDIT_READ` (unprivileged agent) is handled by the caller, which only
/// calls this once `sensor_linux_audit::AvcReader::open` has already
/// succeeded (#780 review) — not a reason to fail `cmd_run` over a source
/// `AuditSensor`-as-primary already proves can be absent without the agent
/// falling over.
fn spawn_avc_reader(
    sink: Arc<DetectionSink>,
    heartbeat: SensorHeartbeat,
    status: SourceStatus,
    report_down: bool,
    reader: Option<sensor_linux_audit::AvcReader>,
    shutdown: &mut ShutdownPlan,
) {
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let handle = std::thread::Builder::new()
        .name("avc-reader".into())
        .spawn(move || {
            run_avc_worker(
                &worker_stop,
                &status,
                report_down,
                reader,
                |reader| {
                    reader
                        .drain(sink.as_ref(), AVC_POLL_TIMEOUT_MS)
                        .map(|(_, overran)| overran)
                },
                sensor_linux_audit::AvcReader::open,
                |delay| pause_pulsing(&worker_stop, &heartbeat, delay),
                || heartbeat.pulse(),
            );
        })
        .expect("spawning the avc-reader thread");
    shutdown.register(
        "avc-reader",
        move || stop.store(true, Ordering::SeqCst),
        handle,
    );
}

/// First wait before [`run_avc_worker`] reopens a failed socket, doubled after each failure
/// (a failed reopen, or a reopened socket whose first drain fails) up to [`AVC_REOPEN_MAX`].
const AVC_REOPEN_FIRST: Duration = Duration::from_secs(1);
const AVC_REOPEN_MAX: Duration = Duration::from_secs(60);

fn next_reopen_delay(previous: Duration) -> Duration {
    (previous * 2).min(AVC_REOPEN_MAX)
}

/// Whether `SELinux` is active on this host, from the three places that say so: selinuxfs's
/// `enforce` file, the kernel's list of active security modules, and a mounted `selinuxfs`.
/// Any one is enough, because a container or a mount namespace may hide the first.
fn selinux_in(enforce_exists: bool, lsm: Option<&str>, mountinfo: Option<&str>) -> bool {
    enforce_exists
        || lsm.is_some_and(|list| list.trim().split(',').any(|module| module == "selinux"))
        || mountinfo.is_some_and(|mounts| mounts.lines().any(|line| line.contains(" - selinuxfs ")))
}

/// Whether `SELinux` is active on this host. The AVC reader only has something to capture then,
/// so only then is a reader that cannot run a degradation worth telling the control plane about.
fn selinux_active() -> bool {
    let read = |path: &str| std::fs::read_to_string(path).ok();
    selinux_in(
        std::path::Path::new("/sys/fs/selinux/enforce").exists(),
        read("/sys/kernel/security/lsm").as_deref(),
        read("/proc/self/mountinfo").as_deref(),
    )
}

/// Waits `total`, pulsing `heartbeat` after each second it has waited and returning early when
/// `stop` is set. The reader is alive and working to recover while it waits, so it must not look
/// silent: silence is read as tampering, and the beacon already says the source is down
/// ([`SourceStatus`]).
fn pause_pulsing(stop: &AtomicBool, heartbeat: &SensorHeartbeat, total: Duration) {
    let slice = Duration::from_secs(1);
    let mut left = total;
    while !stop.load(Ordering::SeqCst) && !left.is_zero() {
        let step = left.min(slice);
        sleep_unless_stopped(stop, step);
        left -= step;
        heartbeat.pulse();
    }
}

/// The body of the `avc-reader` thread, with its I/O handed in so it can be tested without a
/// netlink socket. `drain` returns whether the kernel dropped records; an error from it (a
/// transient socket error, not only `ENOBUFS`, which `drain` already absorbs) no longer ends
/// the reader for good (#878). The source is marked down, the socket is reopened after a delay
/// that doubles from [`AVC_REOPEN_FIRST`] to [`AVC_REOPEN_MAX`], and it is marked up again, and
/// the delay reset, only once a `drain` has succeeded on the reopened socket: a socket that
/// reopens and fails again keeps backing off and stays down, instead of cycling every second.
/// `reader` is `None` when the first open failed; the loop then retries it the same way. While it
/// waits it pulses, so it is not mistaken for a killed source. `report_down` is false on a host
/// with no `SELinux`, where there is no AVC stream whose loss is worth reporting.
#[allow(clippy::too_many_arguments)]
fn run_avc_worker<R, E: std::fmt::Display>(
    stop: &AtomicBool,
    status: &SourceStatus,
    report_down: bool,
    reader: Option<R>,
    mut drain: impl FnMut(&mut R) -> Result<bool, E>,
    mut reopen: impl FnMut() -> Result<R, E>,
    mut pause: impl FnMut(Duration),
    pulse: impl Fn(),
) {
    let mut recovering = reader.is_none();
    let mut reader = reader;
    let mut overruns: u64 = 0;
    let mut delay = AVC_REOPEN_FIRST;
    let mut failures: u64 = 0;
    let mark_down = |down: bool| {
        if report_down {
            status.set_down(down);
        }
    };
    while !stop.load(Ordering::SeqCst) {
        let Some(current) = reader.as_mut() else {
            pulse();
            pause(delay);
            if stop.load(Ordering::SeqCst) {
                break;
            }
            match reopen() {
                // Not up yet: the first successful drain below says so.
                Ok(fresh) => reader = Some(fresh),
                Err(e) => {
                    failures += 1;
                    // Powers of two only: a socket that stays down must not flood the log.
                    if failures.is_power_of_two() {
                        tracing::warn!(
                            error = %e,
                            failures,
                            retry_in = ?next_reopen_delay(delay),
                            "avc-reader: could not reopen the socket"
                        );
                    }
                    delay = next_reopen_delay(delay);
                }
            }
            continue;
        };
        match drain(current) {
            Ok(overran) => {
                pulse();
                if recovering {
                    recovering = false;
                    mark_down(false);
                    delay = AVC_REOPEN_FIRST;
                    failures = 0;
                    tracing::info!("avc-reader: socket back, AVC denials are captured again");
                }
                if overran {
                    overruns += 1;
                    // Powers of two only: a sustained flood must not flood the log too.
                    if overruns.is_power_of_two() {
                        tracing::warn!(
                            overruns_total = overruns,
                            "avc-reader: kernel dropped records (socket buffer overrun)"
                        );
                    }
                }
            }
            Err(e) => {
                failures += 1;
                // Powers of two only, like the failed reopens: a socket that reopens and fails
                // again must not log every cycle.
                if failures.is_power_of_two() {
                    tracing::warn!(
                        error = %e,
                        failures,
                        "avc-reader: socket error, reopening (AVC denials are not captured until it is back)"
                    );
                }
                mark_down(true);
                reader = None;
                // A reader that had been healthy starts over from the first delay; one that
                // was still recovering keeps backing off.
                delay = if recovering {
                    next_reopen_delay(delay)
                } else {
                    AVC_REOPEN_FIRST
                };
                recovering = true;
            }
        }
    }
}

/// Spawns the background thread that tails journald for auth/session events
/// (issue #93: sshd accept/fail, `sudo`/`su`, PAM sessions), mapping each into
/// `schema::AuthEvent` (`sensor_linux_journal::to_auth_event`, issue #94's shared
/// logon shape) and handing it to `sink` — same "poll/tail source with no
/// `Sensor` impl, caller owns the handoff" shape as [`spawn_netlink_poller`], see
/// `sensor_linux_journal`'s crate doc. Also runs a
/// `sensor_linux_journal::UnitPersistenceTracker` (issue #93's other half) over
/// the same stream, so a unit's first observed start lands as a
/// `FLAG_PERSISTENCE_SYSTEMD_ARTIFACT` `FileOpenEvent` too — one tail thread,
/// two independent mappings off the same classified record/event pair.
///
/// Best-effort at startup: a non-systemd init (Alpine/OpenRC, see
/// `watchdog::service::linux`'s own doc on this) has no `journalctl` at all —
/// logged once and skipped, not a reason to fail `agent run` entirely, same
/// posture as [`seeded_rule_state`]'s netlink snapshot.
///
/// Cursor persistence (issue #321): the tail resumes from the last cursor this
/// process saw (`crate::journal_cursor`, a file derived from `alerts` — same
/// convention as `heartbeat_path_for`) when one exists, falling back to
/// `journalctl`'s own "now" snapshot on a fresh install or a missing/corrupt
/// cursor file — either way the honest "no prior state" case, not an error.
/// Bounded catch-up: a restart replays whatever landed since the last persisted
/// cursor, not the whole journal from epoch.
fn spawn_journal_tail(
    sink: Arc<DetectionSink>,
    heartbeat: SensorHeartbeat,
    alerts: &std::path::Path,
) {
    let cursor_path = crate::journal_cursor::cursor_path_for(alerts);
    std::thread::Builder::new()
        .name("journal-tail".into())
        .spawn(move || {
            let cursor = crate::journal_cursor::read(&cursor_path)
                .or_else(|| sensor_linux_journal::current_cursor().ok());
            let mut child = match sensor_linux_journal::spawn_follow(cursor.as_deref()) {
                Ok(child) => child,
                Err(e) => {
                    tracing::warn!(error = %e, "journal tail: journalctl unavailable, skipping");
                    return;
                }
            };
            let Some(stdout) = child.stdout.take() else {
                tracing::warn!("journal tail: journalctl spawned without a piped stdout");
                return;
            };
            // Pulse on every line `journalctl` delivers, allowlisted or not (#71, #83):
            // `ClassifiedJournal` only yields allowlisted records, so a pulse in the
            // loop below would fire on auth and unit events alone and an idle host
            // would read as a silent sensor.
            let hook_heartbeat = heartbeat.clone();
            let journal =
                sensor_linux_journal::ClassifiedJournal::new(std::io::BufReader::new(stdout))
                    .with_line_hook(move || hook_heartbeat.pulse());
            // Our own line into journald at a fixed interval, so there is always
            // something to read back: the pulse then proves journald -> journalctl
            // -> agent delivery on a host with nothing else to log.
            spawn_journal_canary();
            let mut unit_persistence = sensor_linux_journal::UnitPersistenceTracker::new();
            for item in journal {
                // The heartbeat is pulsed per line by the hook above, not here: this
                // loop only sees the allowlisted records.
                match item {
                    Ok((record, event)) => {
                        crate::journal_cursor::write(&cursor_path, &record.cursor);
                        if let Some(auth) = sensor_linux_journal::to_auth_event(&record, &event) {
                            sink.on_event(schema::Event::Auth(auth));
                        }
                        if let Some(persistence_event) = unit_persistence.observe(&record, &event) {
                            sink.on_event(persistence_event);
                        }
                    }
                    Err(e) => {
                        // A hard I/O error ends `ClassifiedJournal`'s stream (see its
                        // doc) — nothing left to iterate, so this thread exits. No
                        // reconnect logic yet (matches the crate doc's Status section).
                        tracing::warn!(error = %e, "journal tail: stream ended");
                        break;
                    }
                }
            }
        })
        .expect("spawning the journal tail thread");
}

/// How often the agent writes its liveness line into journald. Four of these fit in
/// [`NO_CANARY_SILENCE_DEADLINE_NS`], so a missed write or two is not a silent
/// sensor, but a journald that stays gone is.
const JOURNAL_CANARY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Spawns the thread that writes `sensor_linux_journal`'s canary line into journald
/// every [`JOURNAL_CANARY_INTERVAL`] (see that crate's `canary` module for why).
/// A failed write is logged once per failure streak and retried; it is the
/// signal itself when journald is down, so it never stops the thread.
fn spawn_journal_canary() {
    std::thread::Builder::new()
        .name("journal-canary".into())
        .spawn(|| {
            let socket = std::path::Path::new(sensor_linux_journal::JOURNAL_SOCKET);
            let mut warned = false;
            loop {
                match sensor_linux_journal::send_canary(socket) {
                    Ok(()) => warned = false,
                    Err(e) if !warned => {
                        warned = true;
                        tracing::warn!(
                            error = %e,
                            "journal canary: cannot write to journald; the journal sensor will read as silent until it can"
                        );
                    }
                    Err(_) => {}
                }
                std::thread::sleep(JOURNAL_CANARY_INTERVAL);
            }
        })
        .expect("spawning the journal canary thread");
}

/// The uprobes thread that is running, and the captures it was started with.
struct RunningUprobes {
    captures: Captures,
    stop: sensor_linux_uprobes::UprobesStopHandle,
    thread: std::thread::JoinHandle<()>,
}

impl RunningUprobes {
    /// Stops the sensor and waits for the thread to end, which unloads its eBPF object. Safe on a
    /// thread that has already ended (the sensor failed): the stop is kept and the join returns.
    fn stop(self) {
        self.stop.stop();
        if self.thread.join().is_err() {
            tracing::warn!("the uprobes thread panicked");
        }
    }
}

/// Starts the uprobes sensor with exactly `captures` (issue #90: TLS plaintext taps via
/// `SSL_read`/`SSL_write` uprobes, shell readline capture; issue #267 Phase 1: DNS query capture
/// via a `getaddrinfo(3)` uprobe). `captures` is never empty: `plan` starts nothing for an empty
/// set.
fn start_uprobes(
    sink: Arc<DetectionSink>,
    heartbeat: SensorHeartbeat,
    captures: Captures,
) -> RunningUprobes {
    let mut config = sensor_linux_uprobes::UprobesConfig::new();
    if captures.tls {
        config = config.with_tls_enabled();
    }
    if captures.readline {
        config = config.with_readline_enabled();
    }
    if captures.dns {
        config = config.with_dns_enabled();
    }
    let mut sensor = sensor_linux_uprobes::UprobesSensor::with_config(config);
    let stop = sensor.stop_handle();
    let thread = std::thread::Builder::new()
        .name("uprobes".into())
        .spawn(move || {
            if let Err(e) = sensor.run(Box::new(PulsingSink::new(sink, heartbeat))) {
                tracing::warn!(error = %e, "uprobes sensor failed");
            }
        })
        .expect("spawning the uprobes sensor thread");
    RunningUprobes {
        captures,
        stop,
        thread,
    }
}

/// Keeps the uprobes thread running exactly the captures `captures` says are wanted, and keeps
/// its heartbeat watched by the silence monitor only while it runs: a capture that is off is
/// deliberate, and must never accrue silence (a stalled sensor is reported as tampering). With
/// nothing configured and nothing widened it parks on the set and costs nothing.
///
/// The sensor reads its config once, so a change **restarts** it: the eBPF object is unloaded
/// and loaded again, and capture has a gap in between (on the way up, and again when a widening
/// ends). A live attach and detach on the running sensor would avoid the gap and is a separate
/// piece of work.
fn spawn_uprobes_supervisor(
    sink: Arc<DetectionSink>,
    heartbeat: SensorHeartbeat,
    monitor: Arc<Mutex<SilenceMonitor>>,
    captures: CaptureSet,
) {
    std::thread::Builder::new()
        .name("uprobes-supervisor".into())
        .spawn(move || {
            let mut running: Option<RunningUprobes> = None;
            let mut wanted = captures.effective();
            loop {
                let current = running.as_ref().map_or(Captures::NONE, |r| r.captures);
                match plan(current, wanted) {
                    UprobesAction::Idle => {}
                    UprobesAction::Start(set) => {
                        tracing::info!(?set, "starting the uprobes sensor");
                        monitor.lock().unwrap().register(
                            heartbeat.clone(),
                            NO_CANARY_SILENCE_DEADLINE_NS,
                            schema::time::now_ns(),
                        );
                        running = Some(start_uprobes(sink.clone(), heartbeat.clone(), set));
                    }
                    UprobesAction::Restart(set) => {
                        tracing::info!(?set, "restarting the uprobes sensor with other captures: capture has a gap while it reloads");
                        if let Some(old) = running.take() {
                            old.stop();
                        }
                        running = Some(start_uprobes(sink.clone(), heartbeat.clone(), set));
                    }
                    UprobesAction::Stop => {
                        tracing::info!("stopping the uprobes sensor: no capture is wanted any more");
                        if let Some(old) = running.take() {
                            old.stop();
                        }
                        monitor.lock().unwrap().unregister(heartbeat.name());
                    }
                }
                wanted = captures.wait_until_differs(wanted);
            }
        })
        .expect("spawning the uprobes supervisor thread");
}

/// Attaches the observation-only `file_open` BPF-LSM hook (issue #91/#313) and
/// returns the `Ebpf` object that keeps it live — dropping it detaches the
/// program, so the caller must hold the return value for the process's lifetime,
/// same as the primary sensor's own internal `Ebpf` object.
///
/// Best-effort, never fails `cmd_run`: every outcome (no BPF-LSM support on this
/// kernel, compiled in but not in the active `lsm=` boot list, or a genuine
/// attach failure) is the honest capability-absent case, logged and moved past —
/// see `sensor_linux_lsm`'s crate doc on why a structured capability report
/// doesn't exist yet. Gated behind `can_use_ebpf`: a host that can't load the
/// primary eBPF object can't load this hook's object either (same compiled
/// object, same privilege/BTF preflight), so skip the attempt entirely rather
/// than log a second, redundant failure.
fn attach_lsm_hooks() -> Option<aya::Ebpf> {
    if !can_use_ebpf() {
        return None;
    }
    if !sensor_linux_lsm::detect_hook_support("file_open") {
        tracing::info!("lsm: kernel has no BPF-LSM support for `file_open`, skipping");
        return None;
    }
    let mut ebpf = match sensor_linux::load_ebpf() {
        Ok(ebpf) => ebpf,
        Err(e) => {
            tracing::warn!(error = %e, "lsm: failed to load the eBPF object for the file_open hook");
            return None;
        }
    };
    match sensor_linux_lsm::attach_file_open(&mut ebpf) {
        Ok(()) => {
            tracing::info!("lsm: file_open BPF-LSM hook attached");
            Some(ebpf)
        }
        Err(e) => {
            // BTF said the type exists but attach still failed — most commonly
            // "bpf" is not in the active `lsm=` boot list (compiled in, not
            // live). Still the honest capability-absent case, just a notch more
            // notable than "no BTF at all" since it means the operator could
            // fix this with a boot-cmdline change.
            tracing::warn!(error = %e, "lsm: file_open BPF-LSM hook did not attach");
            None
        }
    }
}

/// Linux: rules-filtered benign capture via `BaselineSink` (Ctrl-C handled by the
/// sensor). Platform-neutral by construction — other platforms join as their
/// sensors land.
pub(crate) fn cmd_capture_baseline(output: &std::path::Path) -> anyhow::Result<()> {
    let sink = crate::sink::BaselineSink::new(seeded_rule_state(), output)?;
    eprintln!("Synthaea — baseline capture (Ctrl-C to stop)");
    eprintln!("Output: {}", output.display());
    eprintln!("Perform normal activity on a CLEAN host for ~10 minutes.");
    let mut sensor = sensor_linux::LinuxSensor::new();
    let sink = crate::redact::redacting(Box::new(sink), true);
    sensor
        .run(Box::new(crate::redact::SharedSink(sink)))
        .map_err(|e| anyhow::anyhow!("sensor failed: {e}"))
}

/// Linux: raw capture, no detection — `sinks::JsonlEventSink` verbatim.
pub(crate) fn cmd_capture_events(output: &std::path::Path) -> anyhow::Result<()> {
    let sink = sinks::JsonlEventSink::open(output)?;
    eprintln!("Synthaea — raw event capture (Ctrl-C to stop)");
    eprintln!("Output: {}", output.display());
    eprintln!("Perform normal activity for ~10-15 minutes.");
    let mut sensor = sensor_linux::LinuxSensor::new();
    let sink = crate::redact::redacting(Box::new(sink), true);
    sensor
        .run(Box::new(crate::redact::SharedSink(sink)))
        .map_err(|e| anyhow::anyhow!("sensor failed: {e}"))
}

/// The journal → `AuthEvent` → rules path for the sudo/su join (T1548.003, #838):
/// the classifier, the mapping and `RuleState::on_auth` each have unit tests, but
/// only this crosses all three on journald-shaped lines.
#[cfg(test)]
mod sudo_join_tests {
    use std::io::Cursor;

    const FAILURE: &str = "pam_unix(sudo:auth): authentication failure; logname=omss uid=1000 \
                           euid=0 tty=/dev/pts/2 ruser=omss rhost=  user=omss";
    const SUCCESS: &str = "     omss : TTY=pts/2 ; PWD=/home/omss ; USER=root ; \
                           COMMAND=/bin/whoami";

    /// One `journalctl -o json` line, `second` seconds into the journal.
    fn line(second: u64, comm: &str, message: &str) -> String {
        serde_json::json!({
            "__CURSOR": format!("c{second}"),
            "__REALTIME_TIMESTAMP": (second * 1_000_000).to_string(),
            "SYSLOG_IDENTIFIER": "sudo",
            "_COMM": comm,
            "_PID": "4242",
            "_UID": "0",
            "_GID": "0",
            "MESSAGE": message,
        })
        .to_string()
    }

    /// The techniques of the alerts the rules raise over `lines`, in order.
    fn techniques(lines: &[String]) -> Vec<&'static str> {
        let journal = sensor_linux_journal::ClassifiedJournal::new(Cursor::new(lines.join("\n")));
        let mut state = rules::RuleState::new();
        let mut techniques = Vec::new();
        for item in journal {
            let (record, event) = item.expect("a well-formed journal line");
            if let Some(auth) = sensor_linux_journal::to_auth_event(&record, &event) {
                techniques.extend(state.on_auth(&auth).iter().map(|alert| alert.technique));
            }
        }
        techniques
    }

    fn five_failures(comm: &str) -> Vec<String> {
        (1..=5).map(|second| line(second, comm, FAILURE)).collect()
    }

    fn escalations(techniques: &[&str]) -> usize {
        techniques.iter().filter(|t| **t == "T1548.003").count()
    }

    #[test]
    fn five_failed_sudo_passwords_then_a_success_alert_once() {
        let mut lines = five_failures("sudo");
        lines.push(line(10, "sudo", SUCCESS));
        assert_eq!(escalations(&techniques(&lines)), 1);
    }

    #[test]
    fn a_failed_attempt_logging_command_is_not_a_success() {
        let mut lines = five_failures("sudo");
        lines.push(line(
            10,
            "sudo",
            "     omss : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/home/omss ; \
             USER=root ; COMMAND=/bin/whoami",
        ));
        assert_eq!(escalations(&techniques(&lines)), 0);
    }

    #[test]
    fn a_marker_in_the_command_does_not_hide_a_real_success() {
        let mut lines = five_failures("sudo");
        lines.push(line(
            10,
            "sudo",
            "     omss : TTY=pts/2 ; PWD=/home/omss ; USER=root ; \
             COMMAND=/bin/echo a password is required",
        ));
        assert_eq!(escalations(&techniques(&lines)), 1);
    }

    #[test]
    fn lines_logged_by_another_program_under_the_sudo_identifier_are_ignored() {
        // `logger -t sudo ...`: the identifier says sudo, the trusted `_COMM` does
        // not. Fabricated failures must not set up a join for a real success, and a
        // fabricated success must not complete one from real failures.
        let mut forged_failures = five_failures("logger");
        forged_failures.push(line(10, "sudo", SUCCESS));
        assert_eq!(escalations(&techniques(&forged_failures)), 0);

        let mut forged_success = five_failures("sudo");
        forged_success.push(line(10, "logger", SUCCESS));
        assert_eq!(escalations(&techniques(&forged_success)), 0);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };

    use super::{
        AVC_REOPEN_FIRST, AVC_REOPEN_MAX, next_reopen_delay, run_avc_worker, selinux_in,
        starts_avc_reader,
    };
    use crate::silence::SourceStatus;

    #[test]
    fn the_reopen_delay_doubles_and_stops_at_the_cap() {
        let mut delay = AVC_REOPEN_FIRST;
        let mut seen = vec![delay.as_secs()];
        for _ in 0..8 {
            delay = next_reopen_delay(delay);
            seen.push(delay.as_secs());
        }
        assert_eq!(seen, [1, 2, 4, 8, 16, 32, 60, 60, 60]);
        assert_eq!(next_reopen_delay(AVC_REOPEN_MAX), AVC_REOPEN_MAX);
    }

    #[test]
    fn selinux_is_recognised_from_any_of_its_three_signs() {
        assert!(selinux_in(true, None, None), "selinuxfs enforce file");
        assert!(selinux_in(
            false,
            Some("lockdown,capability,selinux\n"),
            None
        ));
        assert!(selinux_in(
            false,
            None,
            Some("29 22 0:25 / /sys/fs/selinux rw,relatime shared:12 - selinuxfs selinuxfs rw\n")
        ));
        // A kernel built with SELinux but running AppArmor lists neither.
        assert!(!selinux_in(
            false,
            Some("lockdown,capability,landlock,yama,apparmor\n"),
            Some("22 1 0:20 / /sys rw - sysfs sysfs rw\n")
        ));
        assert!(!selinux_in(false, None, None));
    }

    /// What `drive` records about one run of the worker.
    struct Run {
        waits: Vec<Duration>,
        drains: u32,
        pulses: u32,
        /// Whether the source was marked down at each wait.
        down_at_waits: Vec<bool>,
        down_at_end: bool,
    }

    /// Runs `run_avc_worker` with scripted I/O: `drains` is what each `drain` call returns,
    /// `reopens` what each `reopen` call returns. The worker is stopped when a script runs out.
    fn drive(
        report_down: bool,
        first_reader: Option<u32>,
        drains: Vec<Result<bool, String>>,
        reopens: Vec<Result<u32, String>>,
    ) -> Run {
        let stop = AtomicBool::new(false);
        let status = SourceStatus::new("linux-avc");
        let drains = RefCell::new(drains.into_iter());
        let reopens = RefCell::new(reopens.into_iter());
        let waits = RefCell::new(Vec::new());
        let down_at_waits = RefCell::new(Vec::new());
        let drained = Cell::new(0);
        let pulses = Cell::new(0);
        run_avc_worker(
            &stop,
            &status,
            report_down,
            first_reader,
            |_reader| {
                drained.set(drained.get() + 1);
                drains.borrow_mut().next().unwrap_or_else(|| {
                    stop.store(true, Ordering::SeqCst);
                    Ok(false)
                })
            },
            || {
                reopens.borrow_mut().next().unwrap_or_else(|| {
                    stop.store(true, Ordering::SeqCst);
                    Err("script exhausted".into())
                })
            },
            |delay| {
                waits.borrow_mut().push(delay);
                down_at_waits.borrow_mut().push(status.is_down());
            },
            || pulses.set(pulses.get() + 1),
        );
        Run {
            waits: waits.into_inner(),
            drains: drained.get(),
            pulses: pulses.get(),
            down_at_waits: down_at_waits.into_inner(),
            down_at_end: status.is_down(),
        }
    }

    fn secs(run: &Run) -> Vec<u64> {
        run.waits.iter().map(Duration::as_secs).collect()
    }

    #[test]
    fn a_socket_error_no_longer_ends_the_reader_it_is_reopened() {
        // A healthy drain, one fatal error, then the reopened socket drains again.
        let run = drive(
            true,
            Some(0),
            vec![Ok(false), Err("EIO".into())],
            vec![Ok(1)],
        );
        assert_eq!(run.waits, [AVC_REOPEN_FIRST]);
        // Three drains in all: the healthy one, the failing one, and the reopened socket's, which
        // finds the script empty and stops the worker.
        assert_eq!(run.drains, 3);
        assert!(!run.down_at_end, "up again after a drain worked");
    }

    #[test]
    fn failed_reopens_back_off_and_a_good_drain_resets_the_delay() {
        let run = drive(
            true,
            Some(0),
            vec![Err("EIO".into()), Ok(false), Err("EIO again".into())],
            vec![Err("EPERM".into()), Err("EPERM".into()), Ok(7), Ok(8)],
        );
        // 1 s, 2 s (two failed reopens), 4 s (the one that works, and its drain works); the
        // second error starts over from 1 s.
        assert_eq!(secs(&run), [1, 2, 4, 1]);
    }

    #[test]
    fn a_socket_that_reopens_and_fails_again_keeps_backing_off_and_stays_down() {
        // The reviewer's case (#889): open works, every drain fails. Each cycle used to be
        // error, 1 s, reopen, mark up, error: no backoff, a log line a second, a flapping beacon.
        let run = drive(true, Some(0), vec![Err("EIO".into()); 6], vec![Ok(1); 6]);
        assert_eq!(secs(&run), [1, 2, 4, 8, 16, 32]);
        assert!(
            run.down_at_waits.iter().all(|down| *down),
            "never reported up while no drain succeeded: {:?}",
            run.down_at_waits
        );
    }

    #[test]
    fn a_first_open_that_failed_is_retried_like_a_reopen() {
        // No reader at start (#878 review): the worker waits, opens, and reports up on a drain.
        let run = drive(true, None, vec![], vec![Err("EMFILE".into()), Ok(1)]);
        assert_eq!(secs(&run), [1, 2]);
        assert!(!run.down_at_end);
    }

    #[test]
    fn a_host_without_selinux_never_reports_the_source_down() {
        let run = drive(
            false,
            Some(0),
            vec![Err("EIO".into())],
            vec![Err("EPERM".into()), Ok(1)],
        );
        assert_eq!(secs(&run), [1, 2], "it still retries");
        assert!(run.down_at_waits.iter().all(|down| !*down));
        assert!(!run.down_at_end);
    }

    #[test]
    fn the_reader_pulses_while_it_waits_so_it_is_not_taken_for_a_killed_source() {
        let run = drive(
            true,
            Some(0),
            vec![Err("EIO".into())],
            vec![Err("EPERM".into()), Err("EPERM".into()), Ok(1)],
        );
        // One pulse per wait (three), and none from a drain that succeeded before the error.
        assert_eq!(run.waits.len(), 3);
        assert!(run.pulses >= 3, "pulsed {} times", run.pulses);
    }

    #[test]
    fn the_source_is_down_while_the_socket_is_gone_and_up_when_it_is_back() {
        use crate::health::SensorHealthSource as _;

        let status = SourceStatus::new("linux-avc");
        let monitor = std::sync::Arc::new(std::sync::Mutex::new(
            tamper::heartbeat::SilenceMonitor::new(),
        ));
        let health = crate::silence::SilenceHealthSource::new(monitor, vec![status.clone()]);
        let stop = AtomicBool::new(false);
        let during = RefCell::new(None);
        let mut drains = vec![Err("EIO".to_string())].into_iter();
        run_avc_worker(
            &stop,
            &status,
            true,
            Some(0u32),
            |_| {
                drains.next().unwrap_or_else(|| {
                    stop.store(true, Ordering::SeqCst);
                    Ok(false)
                })
            },
            || Ok(1),
            |_| *during.borrow_mut() = Some(health.sensor_health()),
            || {},
        );
        let during = during.into_inner().expect("it waited");
        assert_eq!(during.len(), 1);
        assert!(during[0].silent, "down while the socket is gone");
        assert!(health.sensor_health().is_empty(), "up once a drain worked");
    }

    #[test]
    fn a_stop_during_the_wait_ends_the_worker_without_reopening() {
        let stop = AtomicBool::new(false);
        let status = SourceStatus::new("linux-avc");
        let reopened = Cell::new(false);
        run_avc_worker(
            &stop,
            &status,
            true,
            Some(0u32),
            |_| Err::<bool, _>("EIO".to_string()),
            || {
                reopened.set(true);
                Ok(1)
            },
            |_| stop.store(true, Ordering::SeqCst),
            || {},
        );
        assert!(!reopened.get());
    }

    #[test]
    fn starts_avc_reader_when_ebpf_is_primary() {
        assert!(starts_avc_reader("linux-ebpf"));
    }

    #[test]
    fn does_not_start_avc_reader_when_audit_is_primary() {
        // AuditSensor-as-primary already classifies AVC records on its own
        // Sensor::run loop — a second reader here would double up PolicyDenial
        // events, not add coverage.
        assert!(!starts_avc_reader("linux-audit"));
    }
}
