//! macOS: `EndpointSecurity` sensor commands (issue #32). The ES client
//! requires root, the `com.apple.developer.endpoint-security.client`
//! entitlement, and Full Disk Access — `sensor_macos::MacosSensorError` maps
//! each refusal to the operator action that fixes it, and
//! `docs/sensors/macos.md` documents the dev-signing path.

use std::sync::Arc;

use schema::sensor::{EventSink, Sensor as _};

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
    rule_state
}

/// Spawns the background thread that tails the unified log (sudo → `Auth`,
/// TCC decisions, Gatekeeper verdicts — `sensor-macos-unifiedlog`, issue #95)
/// into the shared sink. Supplementary source, same posture as the Windows
/// Event Log sensor: its failure is logged, never fatal — `EndpointSecurity`
/// is the sensor that must work. Returns the `log stream` child so shutdown
/// can kill it (which ends the tail thread's stream and thus the thread).
fn spawn_unifiedlog_tail(sink: Arc<dyn EventSink>) -> Option<std::process::Child> {
    let mut child = match sensor_macos_unifiedlog::spawn_stream() {
        Ok(child) => child,
        Err(e) => {
            tracing::warn!(error = %e, "unified-log tail: `log stream` unavailable, skipping");
            return None;
        }
    };
    let Some(stdout) = child.stdout.take() else {
        tracing::warn!("unified-log tail: `log stream` spawned without a piped stdout");
        return None;
    };
    std::thread::Builder::new()
        .name("unifiedlog-tail".into())
        .spawn(move || {
            let stream =
                sensor_macos_unifiedlog::NormalizedLogStream::new(std::io::BufReader::new(stdout));
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
        })
        .expect("spawning the unified-log tail thread");
    Some(child)
}

/// Runs the ES sensor (blocking, on the calling thread) and the unified-log
/// tail (background thread) against the same sink, with Ctrl-C wired to stop
/// both.
fn run_macos_sensors(sink: Box<dyn EventSink>) -> anyhow::Result<()> {
    let sink: Arc<dyn EventSink> = Arc::from(sink);

    let mut sensor = sensor_macos::MacosSensor::new();
    let stop = sensor.stop_handle();

    let log_child = spawn_unifiedlog_tail(Arc::clone(&sink));
    let log_child = std::sync::Mutex::new(log_child);

    ctrlc::set_handler(move || {
        eprintln!("\n[!] Shutdown requested...");
        stop.stop();
        if let Ok(mut guard) = log_child.lock()
            && let Some(child) = guard.as_mut()
        {
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
    println!(
        "Requires: root, the com.apple.developer.endpoint-security.client entitlement, \
         and Full Disk Access (see docs/sensors/macos.md)."
    );
    Ok(())
}

/// Response and uprobe-capture flags are accepted for CLI-signature parity with
/// the Linux path but not wired here (same posture as Windows): kill/quarantine
/// is issue #25's Linux-first scope, and TLS/readline capture is a Linux uprobe
/// mechanism with no ES equivalent.
pub(crate) fn cmd_run(
    alerts: &std::path::Path,
    events: &std::path::Path,
    _enable_kill: bool,
    _enable_quarantine: bool,
    _enable_tls_capture: bool,
    _enable_readline_capture: bool,
    server: Option<&str>,
) -> anyhow::Result<()> {
    let pipeline = super::common::wire_run_pipeline(seeded_rule_state(), alerts, events, server)?;
    run_macos_sensors(Box::new(SharedSink(pipeline.sink)))
}

pub(crate) fn cmd_capture_events(output: &std::path::Path) -> anyhow::Result<()> {
    let sink = sinks::JsonlEventSink::open(output)?;
    eprintln!("Synthaea — raw event capture (Ctrl-C to stop)");
    eprintln!("Output: {}", output.display());
    run_macos_sensors(Box::new(sink))
}

pub(crate) fn cmd_capture_baseline(output: &std::path::Path) -> anyhow::Result<()> {
    let sink = crate::sink::BaselineSink::new(seeded_rule_state(), output)?;
    eprintln!("Synthaea — baseline capture (Ctrl-C to stop)");
    eprintln!("Output: {}", output.display());
    run_macos_sensors(Box::new(sink))
}
