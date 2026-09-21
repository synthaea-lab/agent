//! Linux: eBPF sensor commands. Status is a non-invasive preflight (loads the
//! programs through the kernel verifier without attaching them); run/capture
//! drive `LinuxSensor` with the appropriate sink.

use std::sync::{Arc, Mutex};

use schema::sensor::{EventSink as _, Sensor as _};
use tamper::heartbeat::{SensorHeartbeat, SilenceMonitor};

use crate::{
    protected::ProtectedResourceGuard,
    silence::{PulsingSink, SilenceHealthSource},
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
    match sensor_linux_netlink::snapshot() {
        Ok(entries) => {
            rule_state.seed_listen_ports(
                entries
                    .iter()
                    .filter(|entry| entry.state == sensor_linux_netlink::SocketState::Listen)
                    .map(|entry| (entry.local.ip(), entry.local.port())),
            );
        }
        Err(e) => log::warn!("listen-port baseline: sock_diag snapshot failed: {e}"),
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
    for (program_name, category, name) in sensor_linux::TRACEPOINTS {
        match sensor_linux::load_program(&mut ebpf, program_name) {
            Ok(()) => println!(
                "[OK]   program `{program_name}` ({category}:{name}) accepted by the verifier"
            ),
            Err(e) => {
                failures += 1;
                println!("[FAIL] program `{program_name}` ({category}:{name}) rejected: {e}");
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
fn select_sensor() -> (Box<dyn schema::sensor::Sensor>, &'static str) {
    if can_use_ebpf() {
        log::info!("Using eBPF sensor (primary)");
        return (Box::new(sensor_linux::LinuxSensor::new()), "linux-ebpf");
    }

    log::warn!("eBPF unavailable — using audit fallback (reduced fidelity)");
    (
        Box::new(sensor_linux_audit::AuditSensor::new()),
        "linux-audit",
    )
}

/// Checks if eBPF sensor can be loaded (privileges, BTF, verifier).
/// Tests both object loading and program loading to match `cmd_status()` behavior.
fn can_use_ebpf() -> bool {
    // Check 1: Privileges
    // SAFETY: geteuid takes no arguments and cannot fail.
    let uid = unsafe { libc::geteuid() };
    if uid != 0 && !has_bpf_capabilities() {
        log::debug!("eBPF preflight: no privileges");
        return false;
    }

    // Check 2: BTF present
    if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        log::debug!("eBPF preflight: no BTF");
        return false;
    }

    // Check 3: Can load eBPF object
    let mut ebpf = match sensor_linux::load_ebpf() {
        Ok(ebpf) => ebpf,
        Err(e) => {
            log::debug!("eBPF preflight: failed to load object: {e}");
            return false;
        }
    };

    // Check 4: Can load programs (verifier acceptance)
    // Test at least one program to catch verifier rejections (strict lockdown/LSM)
    if let Some((program_name, _category, _name)) = sensor_linux::TRACEPOINTS.first()
        && let Err(e) = sensor_linux::load_program(&mut ebpf, program_name)
    {
        log::debug!("eBPF preflight: program {program_name} rejected: {e}");
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
pub(crate) fn cmd_run(
    alerts: &std::path::Path,
    events: &std::path::Path,
    enable_kill: bool,
    enable_quarantine: bool,
) -> anyhow::Result<()> {
    // Kill-loudness (#71): must run before any other thread exists — the signal mask
    // set here is inherited by every thread spawned below, including `DetectionSink`'s
    // own worker threads.
    crate::kill_loudness::block_termination_signals();
    crate::kill_loudness::spawn_watcher(alerts.to_path_buf());

    let sink = Arc::new(DetectionSink::new(seeded_rule_state(), alerts, events)?);
    eprintln!("Synthaea agent — detection active (Ctrl-C to stop)");
    eprintln!(
        "alerts: {} · events: {}",
        alerts.display(),
        events.display()
    );

    // Select the primary sensor (eBPF or audit fallback) before creating heartbeats
    // so telemetry reports the correct sensor type.
    let (mut sensor, sensor_name) = select_sensor();

    // Automated response (#25): policy off by default (observe-only), opted into
    // per flag. Quarantine lands next to alerts.ndjson, the same "derived, no
    // separate flag" convention `heartbeat::heartbeat_path_for` uses for #102.
    sink.enable_response(
        policy::ResponsePolicy {
            kill_enabled: enable_kill,
            quarantine_enabled: enable_quarantine,
        },
        terminate_process,
        alerts.with_file_name("quarantine"),
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
    let silence_monitor = Arc::new(Mutex::new(SilenceMonitor::new()));
    {
        let now_ns = crate::time::now_ns();
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
    }
    crate::silence::spawn_monitor(silence_monitor.clone(), sink.clone());

    // Spawn health beacon thread — emits periodic self-diagnostics to the control
    // plane (issue #134). Sensor health is now the real silence-monitor snapshot
    // (#71) rather than a no-op; spool stays a no-op until that component exists.
    let health_config = crate::health::HealthCollectorConfig::default();
    let health = crate::health::HealthCollector::new(
        health_config,
        Arc::new(SilenceHealthSource::new(silence_monitor)),
        Arc::new(crate::health::NoopSpoolStats),
        Arc::new(sink.enrich_queue().clone()) as Arc<dyn crate::health::DroppedCounter>,
        |beacon| {
            // For now, just log the beacon. Once transport (#24) integration is
            // complete, this will emit via the dedicated health channel.
            log::info!(
                "health beacon: {} sensors, {} spool bytes, {} enrich dropped",
                beacon.sensors.len(),
                beacon.spool_bytes,
                beacon.enrich_dropped
            );
        },
    );
    let (_health_handle, _health_stop) = health.spawn();

    // Progress-backed liveness (#102): started before the sink moves into the
    // sensor below, since the heartbeat writer only needs a clone of the
    // shared counter, not the sink itself.
    crate::heartbeat::start(
        crate::heartbeat::heartbeat_path_for(alerts),
        sink.progress_handle(),
        crate::heartbeat::WRITE_INTERVAL,
    );

    spawn_netlink_poller(sink.clone(), netlink_heartbeat);
    spawn_journal_tail(sink.clone(), journal_heartbeat);

    // Protected-resource monitoring (#71): only the eBPF sensor produces `FileOpen`
    // events, so only its chain needs the guard — the netlink/journal sinks above
    // never see one.
    let protected = crate::protected::protected_paths(alerts, events);
    let guarded = ProtectedResourceGuard::new(sink.clone(), protected, sink);
    sensor
        .run(Box::new(PulsingSink::new(guarded, primary_heartbeat)))
        .map_err(|e| anyhow::anyhow!("sensor failed: {e}"))
    // Health beacon thread stops when the process exits (sensor.run() blocks until
    // Ctrl-C). For graceful shutdown, call health_stop.stop() before exiting.
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
/// Runs until the process exits (no `Sensor::stop`-style shutdown): `agent run`'s
/// only exit path today is Ctrl-C ending the whole process, same as every other
/// background worker here (`EnrichQueue`, `yara::ScanQueue`).
fn spawn_netlink_poller(sink: Arc<DetectionSink>, heartbeat: SensorHeartbeat) {
    std::thread::Builder::new()
        .name("netlink-poll".into())
        .spawn(move || {
            let mut listen_warned = false;
            let mut conntrack_warned = false;
            loop {
                let ts = crate::time::now_ns();
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
                std::thread::sleep(NETLINK_POLL_INTERVAL);
            }
        })
        .expect("spawning the netlink poll thread");
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
                log::warn!(
                    "netlink poll ({source}): {e} — further identical errors this run are suppressed"
                );
            }
        }
    }
}

/// Spawns the background thread that tails journald for auth/session events
/// (issue #93: sshd accept/fail, `sudo`/`su`, PAM sessions), mapping each into
/// `schema::AuthEvent` (`sensor_linux_journal::to_auth_event`, issue #94's shared
/// logon shape) and handing it to `sink` — same "poll/tail source with no
/// `Sensor` impl, caller owns the handoff" shape as [`spawn_netlink_poller`], see
/// `sensor_linux_journal`'s crate doc.
///
/// Best-effort at startup: a non-systemd init (Alpine/OpenRC, see
/// `watchdog::service::linux`'s own doc on this) has no `journalctl` at all —
/// logged once and skipped, not a reason to fail `agent run` entirely, same
/// posture as [`seeded_rule_state`]'s netlink snapshot.
fn spawn_journal_tail(sink: Arc<DetectionSink>, heartbeat: SensorHeartbeat) {
    std::thread::Builder::new()
        .name("journal-tail".into())
        .spawn(move || {
            let cursor = sensor_linux_journal::current_cursor().ok();
            let mut child = match sensor_linux_journal::spawn_follow(cursor.as_deref()) {
                Ok(child) => child,
                Err(e) => {
                    log::warn!("journal tail: journalctl unavailable, skipping ({e})");
                    return;
                }
            };
            let Some(stdout) = child.stdout.take() else {
                log::warn!("journal tail: journalctl spawned without a piped stdout");
                return;
            };
            let journal =
                sensor_linux_journal::ClassifiedJournal::new(std::io::BufReader::new(stdout));
            for item in journal {
                // Pulsed on every line the stream yields, matched or not (#71):
                // proof journalctl is still delivering, same idle-host caveat as
                // the eBPF sensor (see `silence::PulsingSink`'s doc) since journald
                // itself has no forced canary tick.
                heartbeat.pulse();
                match item {
                    Ok((record, event)) => {
                        if let Some(auth) = sensor_linux_journal::to_auth_event(&record, &event) {
                            sink.on_event(schema::Event::Auth(auth));
                        }
                    }
                    Err(e) => {
                        // A hard I/O error ends `ClassifiedJournal`'s stream (see its
                        // doc) — nothing left to iterate, so this thread exits. No
                        // reconnect logic yet (matches the crate doc's Status section).
                        log::warn!("journal tail: stream ended: {e}");
                        break;
                    }
                }
            }
        })
        .expect("spawning the journal tail thread");
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
    sensor
        .run(Box::new(sink))
        .map_err(|e| anyhow::anyhow!("sensor failed: {e}"))
}

/// Linux: raw capture, no detection — `sinks::JsonlEventSink` verbatim.
pub(crate) fn cmd_capture_events(output: &std::path::Path) -> anyhow::Result<()> {
    let sink = sinks::JsonlEventSink::open(output)?;
    eprintln!("Synthaea — raw event capture (Ctrl-C to stop)");
    eprintln!("Output: {}", output.display());
    eprintln!("Perform normal activity for ~10-15 minutes.");
    let mut sensor = sensor_linux::LinuxSensor::new();
    sensor
        .run(Box::new(sink))
        .map_err(|e| anyhow::anyhow!("sensor failed: {e}"))
}
