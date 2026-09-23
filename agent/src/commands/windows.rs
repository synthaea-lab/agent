//! Windows: ETW + Event Log sensor commands. The kernel providers require
//! administrator privileges; Ctrl-C is wired to both sensors' stop flags here (on
//! Linux the sensor handles it itself).

use std::sync::{Arc, atomic::Ordering};

use schema::{
    Event,
    sensor::{EventSink, Sensor as _},
};

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

/// Forwards to a shared `Arc<dyn EventSink>` — lets two sensors run concurrently
/// against the same sink (`EventSink::on_event` takes `&self`, so this is just
/// ownership plumbing to satisfy `Sensor::run`'s `Box<dyn EventSink>` signature).
struct SharedSink(Arc<dyn EventSink>);

impl EventSink for SharedSink {
    fn on_event(&self, event: Event) {
        self.0.on_event(event);
    }
}

/// Converts the control-plane-facing `policy::EventLogPolicy` into
/// `sensor-windows-eventlog`'s own `EventLogConfig`. A manual field-by-field
/// mapping, not a `From` impl, because `tools/check-deps.py` forbids either
/// crate from depending on the other (`sensor-*` crates depend only on
/// `schema`; `policy` depends only on `schema` too) — the binary is the one
/// place both types are in scope, so it is the one place allowed to bridge
/// them. See `docs/adr/0006-eventlog-channel-allowlist-and-volume-counters.md`.
fn eventlog_config(policy: &policy::EventLogPolicy) -> sensor_windows_eventlog::EventLogConfig {
    sensor_windows_eventlog::EventLogConfig {
        service_installs_enabled: policy.service_installs_enabled,
        scheduled_tasks_enabled: policy.scheduled_tasks_enabled,
        account_creations_enabled: policy.account_creations_enabled,
        logon_events_enabled: policy.logon_events_enabled,
        // Not yet policy-configurable (issue #283 v1): the AppLocker EXE/DLL and
        // TaskScheduler-Operational channels are always on when this crate is
        // enabled. A follow-up (see the same ADR-0006 note above) will surface
        // per-channel toggles through `policy::EventLogPolicy`.
        applocker_blocks_enabled: true,
        task_scheduler_op_enabled: true,
    }
}

/// Runs the ETW sensor (blocking, on the calling thread — same as before) and the
/// Event Log persistence sensor (`sensor-windows-eventlog`, T1543.003/T1053.005/
/// logon events) on a background thread, both against the same sink, with Ctrl-C
/// wired to stop both.
///
/// The Event Log sensor is supplementary (see its crate doc): its failure is
/// logged, not fatal — the ETW sensor is the one that must work for the agent to be
/// useful at all, and a `wevtutil`/`auditpol` hiccup on one host must not take down
/// process/network/file detection with it.
fn run_windows_sensors(sink: Box<dyn EventSink>) -> anyhow::Result<()> {
    let sink: Arc<dyn EventSink> = Arc::from(sink);

    let mut etw_sensor = sensor_windows::WindowsSensor::new();
    let etw_stop = etw_sensor.stop_handle();

    // No policy-loading/distribution mechanism exists in this workspace yet
    // (see `eventlog_config`'s doc), so this is the default (every channel
    // group enabled) rather than something actually loaded from the control
    // plane — the type and the toggle are real, the wire-up to a live policy
    // document is a separate, tracked follow-up.
    let eventlog_policy = policy::EventLogPolicy::default();
    let mut eventlog_sensor =
        sensor_windows_eventlog::EventLogSensor::with_config(eventlog_config(&eventlog_policy));
    let eventlog_stop = eventlog_sensor.stop_handle();

    ctrlc::set_handler(move || {
        eprintln!("\n[!] Shutdown requested...");
        etw_stop.store(true, Ordering::SeqCst);
        eventlog_stop.store(true, Ordering::SeqCst);
    })?;

    let eventlog_thread = {
        let sink = Arc::clone(&sink);
        std::thread::spawn(move || eventlog_sensor.run(Box::new(SharedSink(sink))))
    };

    let etw_result = etw_sensor
        .run(Box::new(SharedSink(sink)))
        .map_err(|e| anyhow::anyhow!("ETW sensor failed: {e}"));

    match eventlog_thread.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!(
            "[!] Event Log sensor stopped with an error (persistence detection degraded, \
             ETW detections unaffected): {e}"
        ),
        Err(_) => eprintln!(
            "[!] Event Log sensor thread panicked (persistence detection degraded, \
             ETW detections unaffected)"
        ),
    }

    etw_result
}

/// Windows: administrator privileges are required by the ETW kernel providers.
pub(crate) fn cmd_status() -> anyhow::Result<()> {
    println!("Synthaea agent — platform: Windows");
    println!("Sensors: ETW (Kernel-Process + Kernel-Network + Kernel-File)");
    println!(
        "          Event Log polling (System/7045 + Security/4698/4624/4625/4648/4672 — \
         service and scheduled-task persistence, logon/session events)"
    );
    println!("Run as administrator for the kernel providers.");
    Ok(())
}

/// `enable_kill`/`enable_quarantine` are accepted for CLI-signature parity with the
/// Linux path but not wired here yet (issue #25 is Linux-first, matching #71/#103's
/// precedent) — `DetectionSink::enable_response` is never called, so response stays
/// fully inactive on Windows regardless of these flags. `enable_tls_capture`/
/// `enable_readline_capture` (issue #90) are Linux-uprobe-specific — ETW would need
/// its own, unrelated mechanism — so they're accepted for parity only, same as the
/// response flags.
pub(crate) fn cmd_run(opts: super::RunOptions) -> anyhow::Result<()> {
    let super::RunOptions {
        alerts,
        events,
        state_dir: _,
        enable_kill: _,
        enable_quarantine: _,
        // uprobes are a Linux mechanism — the capture flags are accepted for CLI
        // parity and inert here, same as the response flags above.
        enable_tls_capture: _,
        enable_readline_capture: _,
        server,
    } = opts;
    let pipeline = super::common::wire_run_pipeline(seeded_rule_state(), alerts, events, server)?;
    run_windows_sensors(Box::new(SharedSink(pipeline.sink)))
}

pub(crate) fn cmd_capture_events(output: &std::path::Path) -> anyhow::Result<()> {
    let sink = sinks::JsonlEventSink::open(output)?;
    eprintln!("Synthaea — raw event capture (Ctrl-C to stop)");
    eprintln!("Output: {}", output.display());
    run_windows_sensors(Box::new(sink))
}

pub(crate) fn cmd_capture_baseline(output: &std::path::Path) -> anyhow::Result<()> {
    let sink = crate::sink::BaselineSink::new(seeded_rule_state(), output)?;
    eprintln!("Synthaea — baseline capture (Ctrl-C to stop)");
    eprintln!("Output: {}", output.display());
    run_windows_sensors(Box::new(sink))
}
