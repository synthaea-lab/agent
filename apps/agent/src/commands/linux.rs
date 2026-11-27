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

use schema::sensor::Sensor as _;
use tamper::heartbeat::{SensorHeartbeat, SilenceMonitor};
use workers::{
    shutdown::{ShutdownPlan, sleep_unless_stopped},
    sync::LockExt,
};

use crate::{
    protected::ProtectedResourceGuard,
    silence::{PulsingSink, SourceStatus},
    sink::DetectionSink,
};

/// Silence deadlines (#71) fed to `SilenceMonitor::register`. The eBPF sensor and
/// the journal tail have no self-generated canary (see `silence::PulsingSink`'s
/// doc), so their deadline is generous — long enough that an ordinary host's
/// incidental activity (cron, the agent's own files, network chatter, journald's
/// own baseline logging) almost always beats it, keeping the false-positive rate
/// on an idle-but-healthy sensor low. The netlink poller ticks every
/// `sensor_linux_netlink::POLL_INTERVAL` regardless of host activity — a real canary — so its
/// deadline can be tight: three missed polls is a genuine stall, not bad luck.
const NO_CANARY_SILENCE_DEADLINE_NS: u64 = 120_000_000_000; // 120s
const NETLINK_SILENCE_DEADLINE_NS: u64 =
    3 * sensor_linux_netlink::POLL_INTERVAL.as_secs() * 1_000_000_000;
/// Same shape as `NETLINK_SILENCE_DEADLINE_NS`: [`spawn_avc_reader`]'s `drain` call
/// returning at all, whether or not anything was queued, is its canary — three missed
/// cycles of [`AVC_POLL_TIMEOUT_MS`] (6s) is a genuine stall. In practice the
/// `SilenceMonitor` only checks on `silence::POLL_INTERVAL` (10s), so the deadline that
/// actually fires is "no pulse between two monitor polls", roughly 10-20s, not a literal
/// 6s — a healthy reader pulses every ≤ [`AVC_POLL_TIMEOUT_MS`] regardless, so this
/// causes no false positives.
const AVC_SILENCE_DEADLINE_NS: u64 = 3 * AVC_POLL_TIMEOUT_MS as u64 * 1_000_000;

/// The actual OS-level kill call for issue #25's automated response —
/// `response::kill_process_as` takes this as an injected closure rather than calling
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
    // The sensor's own scan, so a seeded fact carries the stamp its events do (#17).
    rule_state.seed_processes(
        sensor_linux::read_seed_processes()
            .into_iter()
            .map(|p| (p.pid, p.comm, p.image, p.generation)),
    );
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
                    }), // sock_diag TCP dump only, today (https://github.com/synthaea-lab/agent/issues/40)
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
    // The tail-call router (#351): refused, the sensor keeps the inline one, so a warning only.
    match sensor_linux::load_program(&mut ebpf, sensor_linux::SYS_ENTER_TAIL_CALL_PROGRAM) {
        Ok(()) => println!(
            "[OK]   raw tracepoint program `{}` (sys_enter, tail-call filters) accepted by the verifier",
            sensor_linux::SYS_ENTER_TAIL_CALL_PROGRAM
        ),
        Err(e) => println!(
            "[WARN] raw tracepoint program `{}` refused, the sensor keeps the inline filters: {e}",
            sensor_linux::SYS_ENTER_TAIL_CALL_PROGRAM
        ),
    }
    // The file handlers' tail-call targets (#351): never attached, but refused they would leave
    // the file events unfiltered, so the preflight checks them too.
    for (program_name, _slot) in sensor_linux::FILE_FILTER_PROGRAMS {
        match sensor_linux::load_program(&mut ebpf, program_name) {
            Ok(()) => {
                println!("[OK]   file filter program `{program_name}` accepted by the verifier");
            }
            Err(e) => {
                failures += 1;
                println!("[FAIL] file filter program `{program_name}` rejected: {e}");
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

/// The pid of the watchdog that started this agent, or `None` when nothing did: the watchdog
/// sets `WATCHDOG_RESTARTS_ENV` on every agent it spawns, and is that agent's parent (#322).
/// The variable only says which process to check: the sensor trusts that pid as the watchdog
/// only if it runs the installed watchdog binary (`sensor-linux`'s `watchdog.rs`).
fn supervising_watchdog_pid() -> Option<u32> {
    std::env::var_os(config::identity::WATCHDOG_RESTARTS_ENV)?;
    Some(std::os::unix::process::parent_id())
}

/// Selects sensor: eBPF if available, audit fallback otherwise.
/// Returns (sensor, `sensor_name`) for correct telemetry.
///
/// The third value reads the eBPF sensor's loss totals for the health beacon: what its
/// parent-image cache dropped (#863) and what its probes lost to full rings (#335). The audit
/// fallback has neither.
fn select_sensor(
    enable_dns_capture: bool,
    state_dir: &std::path::Path,
) -> (
    Box<dyn schema::sensor::Sensor>,
    &'static str,
    Option<crate::host_counters::EbpfSensorTotalsReader>,
) {
    if can_use_ebpf() {
        tracing::info!("Using eBPF sensor (primary)");
        // `--enable-dns-capture` also turns on the socket-level query capture (#458 part 3).
        let sensor = sensor_linux::LinuxSensor::new()
            .with_dns_udp_capture(enable_dns_capture)
            .with_watchdog_pid(supervising_watchdog_pid());
        let evictions = sensor.parent_image_evictions();
        let ring_drops = sensor.ring_drop_totals();
        return (
            Box::new(sensor),
            "linux-ebpf",
            Some(Box::new(move || {
                let (ring_dropped, exec_ring_dropped) = ring_drops.snapshot();
                crate::host_counters::EbpfSensorTotals {
                    parent_image_evicted_live: evictions.live(),
                    parent_image_evicted_dead: evictions.dead(),
                    ring_dropped,
                    exec_ring_dropped,
                }
            })),
        );
    }

    tracing::warn!("eBPF unavailable — using audit fallback (reduced fidelity)");
    (
        Box::new(sensor_linux_audit::AuditSensor::new().with_state_dir(state_dir.to_path_buf())),
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
    // The fields bound as `_` are not ignored: `start_pipeline` reads them from `opts` below.
    let super::RunOptions {
        alerts,
        events,
        storage,
        alert_details: _,
        enable_kill,
        enable_quarantine,
        enable_tls_capture,
        enable_readline_capture,
        enable_dns_capture,
        server: _,
        ipc_endpoint: _,
        content_dir: _,
        log_sources,
        deception: _,
        detection: _,
        config_path,
    } = opts;
    // Kill-loudness (#71): must run before any other thread exists — the signal mask
    // set here is inherited by every thread spawned below, including `DetectionSink`'s
    // own worker threads.
    crate::kill_loudness::block_termination_signals();

    let pipeline = super::common::start_pipeline(&opts, seeded_rule_state())?;
    let sink = Arc::clone(&pipeline.sink);

    // The watcher thread itself can start any time after the mask above — only the
    // masking has to precede every other thread. Started here (not right after the
    // masking call) so it can hold a clone of the sink's enrich queue for #341's
    // bounded shutdown drain.
    // A stop by SIGTERM, SIGHUP or SIGQUIT ends in the watcher's `exit`, which never returns to the
    // audit sensor's own clean-stop code: the watcher removes the audit fallback's instance marker,
    // or every restart would leave one and the next start would report an unclean stop. Only this
    // instance's own marker: until the sensor has replayed it, the file is the predecessor's.
    let marker_dir = storage.state_dir.clone();
    crate::kill_loudness::spawn_watcher(
        alerts.to_path_buf(),
        sink.enrich_queue().clone(),
        move || sensor_linux_audit::killrec::remove_own_marker(&marker_dir),
    )?;

    // Select the primary sensor (eBPF or audit fallback) before creating heartbeats
    // so telemetry reports the correct sensor type.
    let (mut sensor, sensor_name, sensor_totals) =
        select_sensor(enable_dns_capture, &storage.state_dir);

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
    {
        let now_ns = schema::time::now_ns();
        let mut mon = silence_monitor.lock_recovering();
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
        if enable_tls_capture || enable_readline_capture || enable_dns_capture {
            mon.register(
                uprobes_heartbeat.clone(),
                NO_CANARY_SILENCE_DEADLINE_NS,
                now_ns,
            );
        }
        if runs_avc_worker {
            mon.register(avc_heartbeat.clone(), AVC_SILENCE_DEADLINE_NS, now_ns);
        }
    }
    crate::silence::spawn_monitor(silence_monitor.clone(), sink.clone())?;

    // Self-integrity verification (#71/#30): periodic re-check of the installed
    // binaries against the signed release manifest `updater` persisted at promote
    // time — the real root of trust the heartbeat above cannot provide (silence
    // proves a sensor stopped producing, not that the binary producing it is the
    // one that was actually shipped).
    crate::integrity::spawn_monitor(storage.state_dir.clone(), sink.clone())?;

    // Diffed package inventory (#87): periodic dpkg-status diff, turned into a
    // real case-attachable Detection through the normal sink path (not a
    // local-only alert like the two monitors above).
    crate::inventory::spawn_monitor(storage.state_dir.clone(), sink.clone())?;

    // Health beacon (#134): periodic self-diagnostics to the control plane, over
    // the silence monitor above. The eBPF sensor adds its loss totals; the audit fallback
    // has none.
    let counters = crate::host_counters::AgentHostCounters::new(
        Arc::clone(&pipeline.sink),
        crate::host_counters::WatchdogReport::from_env(),
    );
    let counters = match sensor_totals {
        Some(read) => counters.with_ebpf_sensor_totals(read),
        None => counters,
    };
    let health = super::common::health_collector(
        &pipeline,
        silence_monitor,
        vec![avc_status.clone()],
        Arc::new(counters),
    );
    // Workers wound down after `sensor.run` returns (#316).
    let mut shutdown = ShutdownPlan::default();
    let (health_handle, health_stop) = health.spawn()?;
    shutdown.register("health-beacon", move || health_stop.stop(), health_handle);
    if let Some(transport) = pipeline.transport {
        transport.register_shutdown(&mut shutdown);
    }

    spawn_netlink_poller(sink.clone(), netlink_heartbeat, &mut shutdown)?;
    spawn_journal_tail(sink.clone(), journal_heartbeat, alerts)?;
    if runs_avc_worker {
        spawn_avc_reader(
            AvcSource {
                sink: sink.clone(),
                heartbeat: avc_heartbeat,
                status: avc_status,
                selinux,
                reader: avc_reader,
            },
            &mut shutdown,
        )?;
    }
    crate::log_sources::spawn(sink.clone(), log_sources, alerts, &mut shutdown)?;
    if enable_tls_capture || enable_readline_capture || enable_dns_capture {
        spawn_uprobes_sensor(
            sink.clone(),
            uprobes_heartbeat,
            enable_tls_capture,
            enable_readline_capture,
            enable_dns_capture,
        )?;
    }

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

    // `sensor.run` returned (Ctrl-C or a sensor failure): flush the enrichment queue, then
    // wind the workers down, the upload loop getting one last spool drain (`finish_run`,
    // shared with Windows and macOS). SIGTERM/SIGHUP/SIGQUIT do not come through here:
    // `kill_loudness`'s watcher ends the process itself (after the enrich-queue flush, #341).
    super::common::finish_run(&sink, shutdown);
    result.map_err(|e| anyhow::anyhow!("sensor failed: {e}"))
}

/// Runs `sensor_linux_netlink::NetlinkPollSensor` on its own thread, pulsing
/// `heartbeat` on each successful poll, and registers it with `shutdown` (#316).
fn spawn_netlink_poller(
    sink: Arc<DetectionSink>,
    heartbeat: SensorHeartbeat,
    shutdown: &mut ShutdownPlan,
) -> std::io::Result<()> {
    let mut sensor = sensor_linux_netlink::NetlinkPollSensor::new(move || heartbeat.pulse());
    let stop = sensor.stop_handle();
    let handle = workers::spawn::spawn_named("netlink-poll", move || {
        if let Err(e) = sensor.run(Box::new(sink)) {
            tracing::warn!(error = %e, "netlink poller stopped");
        }
    })?;
    shutdown.register("netlink-poll", move || stop.stop(), handle);
    Ok(())
}

/// How long `sensor_linux_audit::AvcReader::drain` blocks waiting for the socket
/// before returning control to [`spawn_avc_reader`] for its own stop check and
/// heartbeat pulse. Tighter than the netlink poll interval: AVC denials are a
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

/// What `cmd_run` hands the AVC reader thread: the sink the denials go to, the heartbeat it
/// pulses and the status it reports through, whether `SELinux` is active on this host (only then
/// is a reader that cannot run worth reporting) and the reader opened at start-up (`None` when
/// that open failed, and the worker retries it).
struct AvcSource {
    sink: Arc<DetectionSink>,
    heartbeat: SensorHeartbeat,
    status: SourceStatus,
    selinux: bool,
    reader: Option<sensor_linux_audit::AvcReader>,
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
fn spawn_avc_reader(source: AvcSource, shutdown: &mut ShutdownPlan) -> std::io::Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let handle = workers::spawn::spawn_named("avc-reader", move || {
        let AvcSource {
            sink,
            heartbeat,
            status,
            selinux,
            reader,
        } = source;
        let io = LiveAvcIo {
            sink: sink.as_ref(),
            heartbeat: &heartbeat,
            stop: &worker_stop,
        };
        AvcWorker::new(&worker_stop, &status, selinux, io, reader).run();
    })?;
    shutdown.register(
        "avc-reader",
        move || stop.store(true, Ordering::SeqCst),
        handle,
    );
    Ok(())
}

/// First wait before [`AvcWorker`] reopens a failed socket, doubled after each failure
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

/// The I/O of the AVC worker, handed in so the loop can be tested without a netlink socket.
trait AvcIo {
    type Reader;
    type Error: std::fmt::Display;

    /// One drain of `reader`: whether the kernel dropped records. An error is a transient socket
    /// error, not only `ENOBUFS`, which the drain already absorbs.
    fn drain(&mut self, reader: &mut Self::Reader) -> Result<bool, Self::Error>;

    /// A fresh reader, after the previous one failed (or the first open did).
    fn reopen(&mut self) -> Result<Self::Reader, Self::Error>;

    /// Waits `delay`, or less when the worker is stopped.
    fn pause(&mut self, delay: Duration);

    /// Tells the silence monitor the reader is alive.
    fn pulse(&self);
}

/// The production I/O: drains into the detection sink, pulses the sensor heartbeat.
struct LiveAvcIo<'a> {
    sink: &'a DetectionSink,
    heartbeat: &'a SensorHeartbeat,
    stop: &'a AtomicBool,
}

impl AvcIo for LiveAvcIo<'_> {
    type Reader = sensor_linux_audit::AvcReader;
    type Error = sensor_linux_audit::AuditError;

    fn drain(&mut self, reader: &mut Self::Reader) -> Result<bool, Self::Error> {
        reader
            .drain(self.sink, AVC_POLL_TIMEOUT_MS)
            .map(|(_, overran)| overran)
    }

    fn reopen(&mut self) -> Result<Self::Reader, Self::Error> {
        sensor_linux_audit::AvcReader::open()
    }

    fn pause(&mut self, delay: Duration) {
        pause_pulsing(self.stop, self.heartbeat, delay);
    }

    fn pulse(&self) {
        self.heartbeat.pulse();
    }
}

/// The `avc-reader` thread's loop and the state it carries between iterations. A transient
/// error from a drain no longer ends the reader for good (#878): the source is marked down, the
/// socket is reopened after a delay that doubles from [`AVC_REOPEN_FIRST`] to [`AVC_REOPEN_MAX`],
/// and it is marked up again, and the delay reset, only once a drain has succeeded on the
/// reopened socket: a socket that reopens and fails again keeps backing off and stays down,
/// instead of cycling every second. `reader` is `None` when the first open failed; the loop then
/// retries it the same way. While it waits it pulses, so it is not mistaken for a killed source.
/// `report_down` is false on a host with no `SELinux`, where there is no AVC stream whose loss is
/// worth reporting.
struct AvcWorker<'a, I: AvcIo> {
    stop: &'a AtomicBool,
    status: &'a SourceStatus,
    report_down: bool,
    io: I,
    reader: Option<I::Reader>,
    /// Whether the socket is gone, or reopened and not yet drained successfully.
    recovering: bool,
    overruns: u64,
    failures: u64,
    delay: Duration,
}

impl<'a, I: AvcIo> AvcWorker<'a, I> {
    fn new(
        stop: &'a AtomicBool,
        status: &'a SourceStatus,
        report_down: bool,
        io: I,
        reader: Option<I::Reader>,
    ) -> Self {
        Self {
            stop,
            status,
            report_down,
            io,
            recovering: reader.is_none(),
            reader,
            overruns: 0,
            failures: 0,
            delay: AVC_REOPEN_FIRST,
        }
    }

    /// Drains until `stop` is set, reopening the socket whenever it is gone.
    fn run(mut self) {
        while !self.stop.load(Ordering::SeqCst) {
            if self.reader.is_some() {
                self.drain_once();
            } else {
                self.wait_and_reopen();
            }
        }
    }

    fn mark_down(&self, down: bool) {
        if self.report_down {
            self.status.set_down(down);
        }
    }

    /// No socket: waits (pulsing) and tries to open one. It is not marked up yet: the first
    /// successful drain says so.
    fn wait_and_reopen(&mut self) {
        self.io.pulse();
        self.io.pause(self.delay);
        if self.stop.load(Ordering::SeqCst) {
            return;
        }
        match self.io.reopen() {
            Ok(fresh) => self.reader = Some(fresh),
            Err(e) => {
                self.failures += 1;
                // Powers of two only: a socket that stays down must not flood the log.
                if self.failures.is_power_of_two() {
                    tracing::warn!(
                        error = %e,
                        failures = self.failures,
                        retry_in = ?next_reopen_delay(self.delay),
                        "avc-reader: could not reopen the socket"
                    );
                }
                self.delay = next_reopen_delay(self.delay);
            }
        }
    }

    fn drain_once(&mut self) {
        let Some(reader) = self.reader.as_mut() else {
            return;
        };
        match self.io.drain(reader) {
            Ok(overran) => self.on_drained(overran),
            Err(e) => self.on_drain_failed(&e),
        }
    }

    fn on_drained(&mut self, overran: bool) {
        self.io.pulse();
        if self.recovering {
            self.recovering = false;
            self.mark_down(false);
            self.delay = AVC_REOPEN_FIRST;
            self.failures = 0;
            tracing::info!("avc-reader: socket back, AVC denials are captured again");
        }
        if overran {
            self.overruns += 1;
            // Powers of two only: a sustained flood must not flood the log too.
            if self.overruns.is_power_of_two() {
                tracing::warn!(
                    overruns_total = self.overruns,
                    "avc-reader: kernel dropped records (socket buffer overrun)"
                );
            }
        }
    }

    fn on_drain_failed(&mut self, error: &I::Error) {
        self.failures += 1;
        // Powers of two only, like the failed reopens: a socket that reopens and fails
        // again must not log every cycle.
        if self.failures.is_power_of_two() {
            tracing::warn!(
                error = %error,
                failures = self.failures,
                "avc-reader: socket error, reopening (AVC denials are not captured until it is back)"
            );
        }
        self.mark_down(true);
        self.reader = None;
        // A reader that had been healthy starts over from the first delay; one that
        // was still recovering keeps backing off.
        self.delay = if self.recovering {
            next_reopen_delay(self.delay)
        } else {
            AVC_REOPEN_FIRST
        };
        self.recovering = true;
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
/// independent mappings off the same classified record/event pair; the stop of a unit of
/// `schema::SECURITY_SERVICES` lands as a `schema::UnitStopEvent` (#1085).
///
/// Best-effort at startup: a non-systemd init (Alpine/OpenRC, see
/// `watchdog::service::linux`'s own doc on this) has no `journalctl` at all —
/// logged once and skipped, not a reason to fail `agent run` entirely, same
/// posture as [`seeded_rule_state`]'s netlink snapshot.
///
/// Cursor persistence (issue #321): the tail resumes from the last cursor this
/// process saw (`sensor_linux_journal::cursor`, a file derived from `alerts` — same
/// convention as `heartbeat_path_for`) when one exists, falling back to
/// `journalctl`'s own "now" snapshot on a fresh install or a missing/corrupt
/// cursor file — either way the honest "no prior state" case, not an error.
/// Bounded catch-up: a restart replays whatever landed since the last persisted
/// cursor, not the whole journal from epoch.
fn spawn_journal_tail(
    sink: Arc<DetectionSink>,
    heartbeat: SensorHeartbeat,
    alerts: &std::path::Path,
) -> std::io::Result<()> {
    let cursor_path = sensor_linux_journal::cursor::cursor_path_for(alerts);
    workers::spawn::spawn_named("journal-tail", move || {
        let cursor = sensor_linux_journal::cursor::read(&cursor_path)
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
        let journal = sensor_linux_journal::ClassifiedJournal::new(std::io::BufReader::new(stdout))
            .with_line_hook(move || hook_heartbeat.pulse());
        // Our own line into journald at a fixed interval, so there is always
        // something to read back: the pulse then proves journald -> journalctl
        // -> agent delivery on a host with nothing else to log.
        if let Err(e) = spawn_journal_canary() {
            // Started from the tail's own thread, long after start-up: log it, the silence
            // heartbeat keeps pulsing on other lines, so only an idle host reports the journal
            // sensor silent.
            tracing::warn!(error = %e, "journal canary not started");
        }
        forward_journal(journal, sink.as_ref(), &cursor_path);
    })?;
    Ok(())
}

/// Forwards what the journal tail yields to `sink` until the stream ends: the auth event of
/// each record, the first start of a unit as a persistence event, the stop of a security
/// service as a unit-stop event. Each record's cursor is persisted at `cursor_path` first, so a
/// restart resumes after it.
///
/// A hard I/O error ends `ClassifiedJournal`'s stream (see its doc): nothing is left to
/// iterate, so this returns and the tail thread exits. No reconnect logic yet (matches the
/// crate doc's Status section).
///
/// The heartbeat is pulsed per line by the hook on the journal, not here: this only sees the
/// allowlisted records.
fn forward_journal(
    journal: impl Iterator<
        Item = Result<
            (
                sensor_linux_journal::JournalRecord,
                sensor_linux_journal::JournalEvent,
            ),
            sensor_linux_journal::JournalError,
        >,
    >,
    sink: &impl schema::sensor::EventSink,
    cursor_path: &std::path::Path,
) {
    let mut unit_persistence = sensor_linux_journal::UnitPersistenceTracker::new();
    for item in journal {
        let (record, event) = match item {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %e, "journal tail: stream ended");
                break;
            }
        };
        sensor_linux_journal::cursor::write(cursor_path, &record.cursor);
        if let Some(auth) = sensor_linux_journal::to_auth_event(&record, &event) {
            sink.on_event(schema::Event::Auth(auth));
        }
        if let Some(persistence_event) = unit_persistence.observe(&record, &event) {
            sink.on_event(persistence_event);
        }
        if let Some(stop_event) = sensor_linux_journal::to_unit_stop_event(&record, &event) {
            sink.on_event(stop_event);
        }
    }
}

/// How often the agent writes its liveness line into journald. Four of these fit in
/// [`NO_CANARY_SILENCE_DEADLINE_NS`], so a missed write or two is not a silent
/// sensor, but a journald that stays gone is.
const JOURNAL_CANARY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Spawns the thread that writes `sensor_linux_journal`'s canary line into journald
/// every [`JOURNAL_CANARY_INTERVAL`] (see that crate's `canary` module for why).
/// A failed write is logged once per failure streak and retried; it is the
/// signal itself when journald is down, so it never stops the thread.
fn spawn_journal_canary() -> std::io::Result<()> {
    workers::spawn::spawn_named("journal-canary", || {
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
    })?;
    Ok(())
}

/// Spawns the background thread running the uprobes sensor (issue #90: TLS
/// plaintext taps via `SSL_read`/`SSL_write` uprobes, shell readline capture;
/// issue #267 Phase 1: DNS query capture via a `getaddrinfo(3)` uprobe) when at
/// least one capture is enabled by CLI flag. Only called when the caller has
/// already checked `enable_tls_capture || enable_readline_capture ||
/// enable_dns_capture` — `cmd_run` doesn't spawn this thread at all otherwise,
/// so a deliberately-disabled capture costs nothing at runtime, not even a
/// parked thread.
///
/// The captures are read once at start and never change while the agent runs
/// (`docs/sensors/linux/uprobes.md`, "Captures are fixed at start").
///
/// Unlike [`spawn_netlink_poller`]/[`spawn_journal_tail`] above, `UprobesSensor`
/// implements `Sensor` — the same trait the primary eBPF/audit sensor does — so
/// its own blocking `run` owns this thread and `PulsingSink` (the primary sensor's
/// own wrapper) pulses `heartbeat` on every event, rather than a manual per-item
/// pulse. No `ProtectedResourceGuard` here: unlike the primary eBPF sensor, this
/// one never produces `FileOpen` events.
///
/// # Errors
///
/// The OS refused the thread; `cmd_run` exits with it like any other start-up failure. The
/// heartbeat is already registered by then, but the agent does not run.
fn spawn_uprobes_sensor(
    sink: Arc<DetectionSink>,
    heartbeat: SensorHeartbeat,
    enable_tls_capture: bool,
    enable_readline_capture: bool,
    enable_dns_capture: bool,
) -> std::io::Result<()> {
    workers::spawn::spawn_named("uprobes", move || {
        let mut config = sensor_linux_uprobes::UprobesConfig::new();
        if enable_tls_capture {
            config = config.with_tls_enabled();
        }
        if enable_readline_capture {
            config = config.with_readline_enabled();
        }
        if enable_dns_capture {
            config = config.with_dns_enabled();
        }
        let mut sensor = sensor_linux_uprobes::UprobesSensor::with_config(config);
        if let Err(e) = sensor.run(Box::new(PulsingSink::new(sink, heartbeat))) {
            tracing::warn!(error = %e, "uprobes sensor failed");
        }
    })?;
    Ok(())
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
        AVC_REOPEN_FIRST, AVC_REOPEN_MAX, AvcIo, AvcWorker, next_reopen_delay, selinux_in,
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

    /// The worker's I/O, scripted: `drains` is what each `drain` call returns, `reopens` what
    /// each `reopen` call returns. The worker is stopped when a script runs out. `on_pause` runs
    /// at each wait, after it is recorded. Interior mutability, because the worker owns the `&Script`
    /// it is given and the test reads the record afterwards.
    struct Script<'a> {
        stop: &'a AtomicBool,
        status: &'a SourceStatus,
        drains: RefCell<std::vec::IntoIter<Result<bool, String>>>,
        reopens: RefCell<std::vec::IntoIter<Result<u32, String>>>,
        waits: RefCell<Vec<Duration>>,
        down_at_waits: RefCell<Vec<bool>>,
        drained: Cell<u32>,
        reopened: Cell<u32>,
        pulses: Cell<u32>,
        on_pause: RefCell<Box<dyn FnMut() + 'a>>,
    }

    impl<'a> Script<'a> {
        fn new(
            stop: &'a AtomicBool,
            status: &'a SourceStatus,
            drains: Vec<Result<bool, String>>,
            reopens: Vec<Result<u32, String>>,
        ) -> Self {
            Self {
                stop,
                status,
                drains: RefCell::new(drains.into_iter()),
                reopens: RefCell::new(reopens.into_iter()),
                waits: RefCell::new(Vec::new()),
                down_at_waits: RefCell::new(Vec::new()),
                drained: Cell::new(0),
                reopened: Cell::new(0),
                pulses: Cell::new(0),
                on_pause: RefCell::new(Box::new(|| {})),
            }
        }
    }

    impl AvcIo for &Script<'_> {
        type Reader = u32;
        type Error = String;

        fn drain(&mut self, _reader: &mut u32) -> Result<bool, String> {
            self.drained.set(self.drained.get() + 1);
            self.drains.borrow_mut().next().unwrap_or_else(|| {
                self.stop.store(true, Ordering::SeqCst);
                Ok(false)
            })
        }

        fn reopen(&mut self) -> Result<u32, String> {
            self.reopened.set(self.reopened.get() + 1);
            self.reopens.borrow_mut().next().unwrap_or_else(|| {
                self.stop.store(true, Ordering::SeqCst);
                Err("script exhausted".into())
            })
        }

        fn pause(&mut self, delay: Duration) {
            self.waits.borrow_mut().push(delay);
            self.down_at_waits.borrow_mut().push(self.status.is_down());
            (self.on_pause.borrow_mut())();
        }

        fn pulse(&self) {
            self.pulses.set(self.pulses.get() + 1);
        }
    }

    fn drive(
        report_down: bool,
        first_reader: Option<u32>,
        drains: Vec<Result<bool, String>>,
        reopens: Vec<Result<u32, String>>,
    ) -> Run {
        let stop = AtomicBool::new(false);
        let status = SourceStatus::new("linux-avc");
        let script = Script::new(&stop, &status, drains, reopens);
        AvcWorker::new(&stop, &status, report_down, &script, first_reader).run();
        Run {
            waits: script.waits.into_inner(),
            drains: script.drained.get(),
            pulses: script.pulses.get(),
            down_at_waits: script.down_at_waits.into_inner(),
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
        let script = Script::new(&stop, &status, vec![Err("EIO".to_string())], vec![Ok(1)]);
        *script.on_pause.borrow_mut() =
            Box::new(|| *during.borrow_mut() = Some(health.sensor_health()));
        AvcWorker::new(&stop, &status, true, &script, Some(0u32)).run();
        drop(script);
        let during = during.into_inner().expect("it waited");
        assert_eq!(during.len(), 1);
        assert!(during[0].silent, "down while the socket is gone");
        assert!(health.sensor_health().is_empty(), "up once a drain worked");
    }

    #[test]
    fn a_stop_during_the_wait_ends_the_worker_without_reopening() {
        let stop = AtomicBool::new(false);
        let status = SourceStatus::new("linux-avc");
        let script = Script::new(&stop, &status, vec![Err("EIO".to_string())], vec![Ok(1)]);
        *script.on_pause.borrow_mut() = Box::new(|| stop.store(true, Ordering::SeqCst));
        AvcWorker::new(&stop, &status, true, &script, Some(0u32)).run();
        assert_eq!(script.reopened.get(), 0);
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

    /// Collects every event it is given.
    #[derive(Default)]
    struct CollectingSink(std::sync::Mutex<Vec<schema::Event>>);

    impl schema::sensor::EventSink for CollectingSink {
        fn on_event(&self, event: schema::Event) {
            self.0.lock().unwrap().push(event);
        }
    }

    const KERNEL_LINE: &str = r#"{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1","SYSLOG_IDENTIFIER":"kernel","MESSAGE":"eth0 up"}"#;
    const SUDO_LINE: &str = r#"{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"2","SYSLOG_IDENTIFIER":"sudo","_COMM":"sudo","_PID":"100","_UID":"0","_GID":"0","MESSAGE":"     lab : TTY=pts/0 ; USER=root ; COMMAND=/bin/true"}"#;
    const UNIT_START_LINE: &str = r#"{"__CURSOR":"c3","__REALTIME_TIMESTAMP":"3","_PID":"1","JOB_TYPE":"start","JOB_RESULT":"done","UNIT":"cron.service","MESSAGE":"Started cron.service."}"#;

    fn forwarded(input: &[&str]) -> (Vec<schema::Event>, Option<String>) {
        let dir = tempfile::tempdir().unwrap();
        let cursor_path = dir.path().join("agent.journal-cursor");
        let journal =
            sensor_linux_journal::ClassifiedJournal::new(std::io::Cursor::new(input.join("\n")));
        let sink = CollectingSink::default();
        super::forward_journal(journal, &sink, &cursor_path);
        (
            sink.0.into_inner().unwrap(),
            sensor_linux_journal::cursor::read(&cursor_path),
        )
    }

    #[test]
    fn the_journal_tail_forwards_an_auth_event_and_a_units_first_start() {
        let (events, _) = forwarded(&[KERNEL_LINE, SUDO_LINE, UNIT_START_LINE]);
        assert_eq!(events.len(), 2, "{events:?}");
        assert!(matches!(events[0], schema::Event::Auth(_)));
        assert!(matches!(events[1], schema::Event::FileOpen(_)));
    }

    #[test]
    fn the_journal_tail_persists_the_cursor_of_the_last_record_it_yielded() {
        let (_, cursor) = forwarded(&[KERNEL_LINE, SUDO_LINE, UNIT_START_LINE]);
        assert_eq!(cursor.as_deref(), Some("c3"));
    }

    #[test]
    fn the_journal_tail_persists_no_cursor_when_nothing_was_yielded() {
        let (events, cursor) = forwarded(&[KERNEL_LINE]);
        assert!(events.is_empty());
        assert_eq!(cursor, None);
    }
}
