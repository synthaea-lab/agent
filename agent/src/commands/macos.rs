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

/// Runs the ES sensor (blocking, on the calling thread) with Ctrl-C wired to
/// its stop handle.
fn run_macos_sensor(sink: Box<dyn EventSink>) -> anyhow::Result<()> {
    let mut sensor = sensor_macos::MacosSensor::new();
    let stop = sensor.stop_handle();
    ctrlc::set_handler(move || {
        eprintln!("\n[!] Shutdown requested...");
        stop.stop();
    })?;
    sensor
        .run(sink)
        .map_err(|e| anyhow::anyhow!("EndpointSecurity sensor failed: {e}"))
}

pub(crate) fn cmd_status() -> anyhow::Result<()> {
    println!("Synthaea agent — platform: macOS");
    println!("Sensors: EndpointSecurity (exec + file + BTM launch-item persistence)");
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
    run_macos_sensor(Box::new(SharedSink(pipeline.sink)))
}

pub(crate) fn cmd_capture_events(output: &std::path::Path) -> anyhow::Result<()> {
    let sink = sinks::JsonlEventSink::open(output)?;
    eprintln!("Synthaea — raw event capture (Ctrl-C to stop)");
    eprintln!("Output: {}", output.display());
    run_macos_sensor(Box::new(sink))
}

pub(crate) fn cmd_capture_baseline(output: &std::path::Path) -> anyhow::Result<()> {
    let sink = crate::sink::BaselineSink::new(seeded_rule_state(), output)?;
    eprintln!("Synthaea — baseline capture (Ctrl-C to stop)");
    eprintln!("Output: {}", output.display());
    run_macos_sensor(Box::new(sink))
}
