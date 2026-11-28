//! macOS: `EndpointSecurity` sensor commands (issue #32). The ES client
//! requires root, the `com.apple.developer.endpoint-security.client`
//! entitlement, and Full Disk Access — `sensor_macos::MacosSensorError` maps
//! each refusal to the operator action that fixes it, and
//! `docs/sensors/macos.md` documents the dev-signing path.

use std::sync::Arc;

use schema::sensor::{EventSink, Sensor as _};
use workers::{shutdown::ShutdownPlan, sync::LockExt as _};

/// Forwards to a shared `Arc<dyn EventSink>` — ownership plumbing to satisfy
/// `Sensor::run`'s `Box<dyn EventSink>` signature (same shape as Windows).
struct SharedSink(Arc<dyn EventSink>);

impl EventSink for SharedSink {
    fn on_event(&self, event: schema::Event) {
        self.0.on_event(event);
    }
}

/// `RuleState` pre-filled with the processes already running at startup —
/// without it, the parent-side exclusions and lineage rules don't apply to
/// processes launched before the agent, the most common case in practice (see
/// `RuleState`). macOS has no `/proc`; one `ps` snapshot at startup serves
/// (same trade-off as the Windows `tasklist` seeding).
fn seeded_rule_state() -> rules::RuleState {
    let mut map = std::collections::HashMap::new();
    if let Ok(output) = std::process::Command::new("/bin/ps")
        .args(["-axo", "pid=,comm="])
        .output()
    {
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let mut parts = line.split_whitespace();
            let (Some(pid), Some(comm)) = (parts.next(), parts.next()) else {
                continue;
            };
            if let Ok(pid) = pid.parse::<u32>() {
                // `comm` here is a full path on macOS; rules key on the short
                // name, consistent with what the sensor emits.
                let comm = comm.rsplit('/').next().unwrap_or(comm).to_string();
                map.insert(pid, comm);
            }
        }
    }
    let mut rule_state = rules::RuleState::new();
    rule_state.seed_pid_comm(map);
    // LISTENER-DRIFT baseline (#358), same reasoning as the Linux netlink
    // seeding: every listener already up when the agent attaches (launchd
    // services, AirPlay, sshd) is the baseline, not a finding. Best-effort —
    // a snapshot failure leaves the baseline empty rather than failing
    // startup.
    match sensor_macos_sockets::snapshot() {
        Ok(entries) => rule_state.seed_listen_ports(
            entries
                .iter()
                .filter(|e| e.state == sensor_macos_sockets::SocketState::Listen)
                .map(|e| (e.local.ip(), e.local.port(), schema::IPPROTO_TCP)), // libproc TCP snapshot only, today (https://github.com/synthaea-lab/agent/issues/40)
        ),
        Err(e) => tracing::warn!(error = %e, "socket snapshot for listener baseline failed"),
    }
    rule_state
}

/// Poll cadence for the socket-table snapshots — same 10s as the Linux
/// netlink poller; the tightness of the LISTENER-DRIFT window, not a
/// correctness knob.
const SOCKET_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// Spawns the background thread that snapshots the socket table every
/// [`SOCKET_POLL_INTERVAL`] and pushes listening sockets into the sink
/// (`sensor-macos-sockets`, issue #358 — the entitlement-free source).
/// Supplementary and non-fatal, same posture as the unified-log tail.
fn spawn_socket_poller(
    sink: Arc<dyn EventSink>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<()> {
    workers::spawn::spawn_named("socket-poller", move || {
        while !stop.load(std::sync::atomic::Ordering::SeqCst) {
            let now_ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
            match sensor_macos_sockets::listen_port_events(now_ns) {
                Ok(events) => {
                    for event in events {
                        sink.on_event(event);
                    }
                }
                Err(e) => tracing::warn!(error = %e, "socket-table poll failed"),
            }
            // Sleep in short slices so Ctrl-C never waits a full interval.
            let deadline = std::time::Instant::now() + SOCKET_POLL_INTERVAL;
            while std::time::Instant::now() < deadline
                && !stop.load(std::sync::atomic::Ordering::SeqCst)
            {
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        }
    })?;
    Ok(())
}

/// Spawns the background thread that tails the unified log (sudo → `Auth`,
/// TCC decisions, Gatekeeper verdicts — `sensor-macos-unifiedlog`, issue #95)
/// into the shared sink. Supplementary source, same posture as the Windows
/// Event Log sensor: its failure is logged, never fatal — `EndpointSecurity`
/// is the sensor that must work. Returns the `log stream` child so shutdown
/// can kill it (which ends the tail thread's stream and thus the thread).
fn spawn_unifiedlog_tail(
    sink: Arc<dyn EventSink>,
    counters: Arc<sensor_macos_unifiedlog::StreamCounters>,
) -> std::io::Result<Option<std::process::Child>> {
    let mut child = match sensor_macos_unifiedlog::spawn_stream() {
        Ok(child) => child,
        Err(e) => {
            tracing::warn!(error = %e, "unified-log tail: `log stream` unavailable, skipping");
            return Ok(None);
        }
    };
    let Some(stdout) = child.stdout.take() else {
        tracing::warn!("unified-log tail: `log stream` spawned without a piped stdout");
        return Ok(None);
    };
    let spawned = workers::spawn::spawn_named("unifiedlog-tail", move || {
        let stream = sensor_macos_unifiedlog::NormalizedLogStream::with_counters(
            std::io::BufReader::new(stdout),
            Arc::clone(&counters),
        );
        for item in stream {
            match item {
                Ok((_, event)) => sink.on_event(event),
                Err(e) => {
                    // A hard I/O error ends the stream — nothing left to
                    // iterate (killing the child on shutdown lands here too).
                    tracing::warn!(error = %e, "unified-log tail: stream ended");
                    break;
                }
            }
        }
        report_unified_log_losses(&counters.totals());
    });
    if let Err(e) = spawned {
        // No thread will read the child's pipe: do not leave `log stream` running.
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }
    Ok(Some(child))
}

/// Says what the unified-log tail shed or could not join, as a closing summary when its stream
/// ends (#178). While the agent runs, the stream itself warns at power-of-two totals. macOS has no
/// health beacon yet (#34), so these lines are where the counts are read.
fn report_unified_log_losses(totals: &sensor_macos_unifiedlog::StreamTotals) {
    if !totals.is_clean() {
        tracing::warn!(
            shed_events = totals.shed_events,
            tcc_shed_contexts = totals.tcc_shed_contexts,
            tcc_unmatched_results = totals.tcc_unmatched_results,
            oversize_lines = totals.oversize_lines,
            "unified-log tail: events were shed, lines dropped, or TCC records could not be joined"
        );
    }
}

/// The same for the `NetworkExtension` receiver, once per ended connection: what the agent skipped
/// on that connection because the extension speaks another version, by cause (#178). `skipped` is
/// the difference across the connection, not the cumulative totals.
fn report_network_extension_skew(skipped: &sensor_macos_network_extension::SkewTotals) {
    if !skipped.is_clean() {
        tracing::warn!(
            unparseable = skipped.unparseable,
            unknown_version = skipped.unknown_version,
            unmapped = skipped.unmapped,
            oversize_lines = skipped.oversize_lines,
            "network-extension connection: records were skipped on this connection (extension version skew or oversize lines?)"
        );
    }
}

/// Where the `NetworkExtension` providers' event pipe lives (issue #33). The
/// Swift extension reconnects here whenever the OS (re)starts it — see
/// `sensor-macos-network-extension`'s crate doc and `packaging/macos` for the
/// app-group placement this default stands in for until the packaged bundle
/// exists.
const NE_SOCKET_PATH: &str = config::identity::MACOS_NE_SOCKET;

/// Spawns the background thread that accepts `NetworkExtension` connections
/// and pumps normalized flow/DNS events into the shared sink. Supplementary
/// source, same non-fatal posture as the unified-log tail: without the
/// packaged system extension nothing ever connects, and binding may fail
/// unprivileged — both are logged, never fatal. The accept loop lives for
/// the process (torn down at exit with everything else).
fn spawn_network_extension_receiver(sink: Arc<dyn EventSink>) -> std::io::Result<()> {
    let listener =
        match sensor_macos_network_extension::listen(std::path::Path::new(NE_SOCKET_PATH)) {
            Ok(listener) => listener,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = NE_SOCKET_PATH,
                    "network-extension receiver: cannot bind, skipping (flow/DNS \
                     telemetry off)"
                );
                return Ok(());
            }
        };
    // One handle for every connection: the extension reconnects whenever the OS restarts it.
    let skew = Arc::new(sensor_macos_network_extension::SkewCounters::default());
    workers::spawn::spawn_named("ne-receiver", move || {
        let result = sensor_macos_network_extension::accept_loop(&listener, |conn| {
            let before = skew.totals();
            let stream = sensor_macos_network_extension::NormalizedNeStream::with_counters(
                std::io::BufReader::new(conn),
                Arc::clone(&skew),
            );
            for item in stream {
                match item {
                    Ok(event) => sink.on_event(event),
                    Err(e) => {
                        // One connection ended (extension restarted by
                        // the OS) — back to accept for the reconnect.
                        tracing::debug!(error = %e, "network-extension connection ended");
                        break;
                    }
                }
            }
            report_network_extension_skew(&skew.totals().since(&before));
        });
        if let Err(e) = result {
            tracing::warn!(error = %e, "network-extension receiver stopped");
        }
    })?;
    Ok(())
}

/// Runs the ES sensor (blocking, on the calling thread), the unified-log
/// tail, and the `NetworkExtension` receiver (background threads) against the
/// same sink, with Ctrl-C wired to stop the lot.
fn run_macos_sensors(sink: Box<dyn EventSink>, redact_commands: bool) -> anyhow::Result<()> {
    // Run and both capture commands funnel through here, so this is the one
    // place credential redaction has to sit in front of (#440).
    let sink = redact::event::redacting(sink, redact_commands);

    let mut sensor = sensor_macos::MacosSensor::new();
    let stop = sensor.stop_handle();

    spawn_network_extension_receiver(Arc::clone(&sink))?;
    let poll_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    spawn_socket_poller(Arc::clone(&sink), Arc::clone(&poll_stop))?;
    // Created here, not in the tail thread, so the agent holds the handle the macOS health
    // beacon (#34) will read, as `skew` is held on the network-extension side.
    let log_counters = Arc::new(sensor_macos_unifiedlog::StreamCounters::default());
    let log_child = spawn_unifiedlog_tail(Arc::clone(&sink), Arc::clone(&log_counters))?;
    let log_child = std::sync::Mutex::new(log_child);

    ctrlc::set_handler(move || {
        eprintln!("\n[!] Shutdown requested...");
        stop.stop();
        poll_stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut guard = log_child.lock_recovering();
        if let Some(child) = guard.as_mut() {
            // Ends the tail thread's stream; reaped below via wait().
            let _ = child.kill();
            let _ = child.wait();
        }
    })?;

    sensor
        .run(Box::new(SharedSink(sink)))
        .map_err(|e| anyhow::anyhow!("EndpointSecurity sensor failed: {e}"))
}

pub(crate) fn cmd_status() -> anyhow::Result<()> {
    println!("Synthaea agent — platform: macOS");
    println!("Sensors: EndpointSecurity (exec + file + BTM launch-item persistence)");
    println!("         unified-log tail (sudo auth, TCC decisions, Gatekeeper verdicts)");
    println!("         NetworkExtension receiver (flows + DNS, when the extension is installed)");
    println!("         socket-table snapshots (listening ports, 10s poll — no entitlement needed)");
    println!(
        "Requires: root, the com.apple.developer.endpoint-security.client entitlement, \
         and Full Disk Access (see docs/sensors/macos.md)."
    );
    Ok(())
}

/// Response and uprobe-capture flags are accepted for CLI-signature parity with
/// the Linux path but not wired here (same posture as Windows): kill/quarantine
/// is issue #25's Linux-first scope, and TLS/readline capture is a Linux uprobe
/// mechanism with no ES equivalent. The rest of `opts` is read by `start_pipeline`.
pub(crate) fn cmd_run(opts: super::RunOptions) -> anyhow::Result<()> {
    let pipeline = super::common::start_pipeline(&opts, seeded_rule_state())?;
    let mut shutdown = ShutdownPlan::default();
    if let Some(transport) = pipeline.transport {
        transport.register_shutdown(&mut shutdown);
    }
    let sink = Arc::clone(&pipeline.sink);
    let result = run_macos_sensors(Box::new(SharedSink(pipeline.sink)), false);
    // The enrichment flush and the upload loops' last drain, as on Linux (#147).
    super::common::finish_run(&sink, shutdown);
    result
}

pub(crate) fn cmd_capture_events(output: &std::path::Path) -> anyhow::Result<()> {
    let sink = sinks::JsonlEventSink::open(output)?;
    eprintln!("Synthaea — raw event capture (Ctrl-C to stop)");
    eprintln!("Output: {}", output.display());
    run_macos_sensors(Box::new(sink), true)
}

pub(crate) fn cmd_capture_baseline(output: &std::path::Path) -> anyhow::Result<()> {
    let sink = crate::sink::BaselineSink::new(seeded_rule_state(), output)?;
    eprintln!("Synthaea — baseline capture (Ctrl-C to stop)");
    eprintln!("Output: {}", output.display());
    run_macos_sensors(Box::new(sink), true)
}
