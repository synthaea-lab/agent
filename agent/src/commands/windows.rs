//! Windows: ETW sensor commands. The kernel providers require administrator
//! privileges; Ctrl-C is wired to the sensor's stop flag here (on Linux the
//! sensor handles it itself).

use schema::sensor::Sensor as _;

use crate::sink::DetectionSink;

/// Windows equivalent: pid → comm via `tasklist` (carried over from the old agent —
/// no extra API surface; the sensor keeps its own richer store independently).
fn seeded_rule_state() -> rules::RuleState {
    let mut map = std::collections::HashMap::new();
    if let Ok(output) = std::process::Command::new("tasklist")
        .args(["/fo", "csv", "/nh"])
        .output()
    {
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            // CSV: "Image Name","PID",...
            let parts: Vec<&str> = line.splitn(3, ',').collect();
            if parts.len() < 2 {
                continue;
            }
            let comm = parts[0].trim_matches('"').to_string();
            if let Ok(pid) = parts[1].trim_matches('"').parse::<u32>() {
                map.insert(pid, comm);
            }
        }
    }
    let mut rule_state = rules::RuleState::new();
    rule_state.seed_pid_comm(map);
    rule_state
}

/// Runs a Windows sensor to completion with Ctrl-C wired to its stop flag.
fn run_windows_sensor(sink: Box<dyn schema::sensor::EventSink>) -> anyhow::Result<()> {
    let mut sensor = sensor_windows::WindowsSensor::new();
    let stop = sensor.stop_handle();
    ctrlc::set_handler(move || {
        eprintln!("\n[!] Shutdown requested...");
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
    })?;
    sensor
        .run(sink)
        .map_err(|e| anyhow::anyhow!("sensor failed: {e}"))
}

/// Windows: administrator privileges are required by the ETW kernel providers.
pub(crate) fn cmd_status() -> anyhow::Result<()> {
    println!("Synthaea agent — platform: Windows");
    println!("Sensor: ETW (Kernel-Process + Kernel-Network + Kernel-File)");
    println!("Run as administrator for the kernel providers.");
    Ok(())
}

pub(crate) fn cmd_run(alerts: &std::path::Path, events: &std::path::Path) -> anyhow::Result<()> {
    let sink = DetectionSink::new(seeded_rule_state(), alerts, events)?;
    eprintln!("Synthaea agent — detection active (Ctrl-C to stop)");
    eprintln!(
        "alerts: {} · events: {}",
        alerts.display(),
        events.display()
    );
    run_windows_sensor(Box::new(sink))
}

pub(crate) fn cmd_capture_events(output: &std::path::Path) -> anyhow::Result<()> {
    let sink = sinks::JsonlEventSink::open(output)?;
    eprintln!("Synthaea — raw event capture (Ctrl-C to stop)");
    eprintln!("Output: {}", output.display());
    run_windows_sensor(Box::new(sink))
}

pub(crate) fn cmd_capture_baseline(output: &std::path::Path) -> anyhow::Result<()> {
    let sink = crate::sink::BaselineSink::new(seeded_rule_state(), output)?;
    eprintln!("Synthaea — baseline capture (Ctrl-C to stop)");
    eprintln!("Output: {}", output.display());
    run_windows_sensor(Box::new(sink))
}
