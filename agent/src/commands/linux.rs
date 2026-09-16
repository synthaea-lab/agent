//! Linux: eBPF sensor commands. Status is a non-invasive preflight (loads the
//! programs through the kernel verifier without attaching them); run/capture
//! drive `LinuxSensor` with the appropriate sink.

use std::sync::Arc;

use schema::sensor::{EventSink as _, Sensor as _};

use crate::sink::DetectionSink;

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

/// Linux: eBPF capture + detection via `LinuxSensor` (Ctrl-C handled by the sensor),
/// plus the netlink poller (issue #92: `sock_diag`/conntrack — listen-port drift and
/// beacon detection where eBPF cannot run, or as a redundant cross-check alongside
/// it). Both feed the same `DetectionSink`, shared via `Arc` (`schema::sensor`'s
/// blanket `EventSink for Arc<T>`) since `LinuxSensor::run` needs to own its sink
/// for `Sensor`'s lifetime but the poller thread outlives no particular caller.
pub(crate) fn cmd_run(alerts: &std::path::Path, events: &std::path::Path) -> anyhow::Result<()> {
    let sink = Arc::new(DetectionSink::new(seeded_rule_state(), alerts, events)?);
    eprintln!("Synthaea agent — detection active (Ctrl-C to stop)");
    eprintln!(
        "alerts: {} · events: {}",
        alerts.display(),
        events.display()
    );

    // Spawn health beacon thread — emits periodic self-diagnostics to the control
    // plane (issue #134). Uses no-op sources for now (sensors, spool) until those
    // components expose the necessary APIs.
    let health_config = crate::health::HealthCollectorConfig::default();
    let health = crate::health::HealthCollector::new(
        health_config,
        Arc::new(crate::health::NoopSensorHealth),
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

    spawn_netlink_poller(sink.clone());
    let mut sensor = sensor_linux::LinuxSensor::new();
    sensor
        .run(Box::new(sink))
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
fn spawn_netlink_poller(sink: Arc<DetectionSink>) {
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
                    &mut listen_warned,
                    "listen-port",
                );
                forward_netlink_events(
                    sensor_linux_netlink::conntrack_flow_events(ts),
                    &sink,
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
/// same `EPERM` forever.
fn forward_netlink_events(
    result: Result<Vec<schema::Event>, sensor_linux_netlink::NetlinkError>,
    sink: &DetectionSink,
    warned: &mut bool,
    source: &str,
) {
    match result {
        Ok(events) => {
            *warned = false;
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
