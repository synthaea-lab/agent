//! Windows: ETW + Event Log sensor commands. The kernel providers require
//! administrator privileges; Ctrl-C is wired to both sensors' stop flags here (on
//! Linux the sensor handles it itself).

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use schema::{
    Event,
    sensor::{EventSink, Sensor as _},
};
use tamper::heartbeat::{SensorHeartbeat, SilenceMonitor};

use crate::silence::{PulsingSink, SilenceHealthSource};

/// Silence deadline (#71/#388) for the ETW sensor, pulsed on every event it
/// forwards. ETW is the high-volume sensor (process, file, registry, DNS...),
/// so two minutes without a single event is not an idle host. Its own
/// in-sensor canary (audit F-2) already fails the trace after 30s of total
/// silence; this is the agent-level, alerting counterpart.
const ETW_SILENCE_DEADLINE_NS: u64 = 120_000_000_000; // 120s

/// Silence deadline for each Event Log poll target. These pulse on every
/// *successful* poll tick (`POLL_INTERVAL` = 2s in the sensor), not per event,
/// so a quiet channel stays live; 60s is ~30 consecutive failed ticks, generous
/// for a `wevtutil` process spawn per tick.
const EVENTLOG_SILENCE_DEADLINE_NS: u64 = 60_000_000_000; // 60s

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
    // LISTENER-DRIFT baseline (#366), same reasoning as the Linux/macOS
    // seeding: every listener already up when the agent starts (RPC 135, SMB
    // 445, vendor services) is the baseline, not a finding. Best-effort — a
    // snapshot failure leaves the baseline empty rather than failing startup.
    match sensor_windows_sockets::snapshot() {
        Ok(entries) => {
            rule_state.seed_listen_ports(entries.iter().map(|e| (e.local.ip(), e.local.port())));
        }
        Err(e) => tracing::warn!(error = %e, "socket snapshot for listener baseline failed"),
    }
    // Issue #403: without this, the Event Log sensor's own wevtutil.exe/auditpol.exe
    // poll-loop children trip SELF-SPAWN on the agent itself.
    rule_state.seed_own_pid(std::process::id());
    rule_state
}

/// Poll cadence for the socket-table snapshots — same 10s as the Linux and
/// macOS pollers; the tightness of the LISTENER-DRIFT window, not a
/// correctness knob.
const SOCKET_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// Spawns the background thread that snapshots the listener table every
/// [`SOCKET_POLL_INTERVAL`] and pushes each listener into the sink
/// (`sensor-windows-sockets`, issue #366). Supplementary and non-fatal, same
/// posture as the Event Log sensor.
fn spawn_socket_poller(
    sink: Arc<dyn EventSink>,
    stop: Arc<AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("socket-poller".into())
        .spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                match sensor_windows_sockets::listen_port_events(schema::time::now_ns()) {
                    Ok(events) => {
                        for event in events {
                            sink.on_event(event);
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "socket-table poll failed"),
                }
                // Sleep in short slices so Ctrl-C never waits a full interval.
                let deadline = std::time::Instant::now() + SOCKET_POLL_INTERVAL;
                while std::time::Instant::now() < deadline && !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
            }
        })
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
        // Not yet policy-configurable (issue #322 v1): the transport defaults
        // to Polling — the pre-#322 behavior — so a version bump does not
        // silently change delivery mechanism on any host. A follow-up (same
        // ADR-0006 cross-crate rewiring as the per-channel toggles) will
        // surface `transport` through `policy::EventLogPolicy` for host-by-host
        // rollout of `Subscribe`.
        transport: sensor_windows_eventlog::EventLogTransport::Polling,
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

/// How often [`hold_after_primary`] re-checks the shutdown flag.
const SHUTDOWN_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

/// Runs the primary sensor to completion, then — if it failed before shutdown
/// was requested — keeps the calling thread parked until it is, so the
/// supplementary sensors on their own threads keep detecting. Returns the
/// primary's result either way.
///
/// The failure this exists for is ETW without elevation (lab, 2026-09-23): the
/// kernel session refuses to start, and the run used to stop the socket poller
/// after its first snapshot, then block joining the Event Log thread with the
/// ETW error never printed. Same degrade-don't-die posture as Linux's
/// eBPF → audit fallback with netlink running beside either.
fn hold_after_primary(
    primary: impl FnOnce() -> anyhow::Result<()>,
    shutdown: &AtomicBool,
) -> anyhow::Result<()> {
    let result = primary();
    if let Err(e) = &result
        && !shutdown.load(Ordering::SeqCst)
    {
        tracing::error!(error = %e, "ETW sensor failed; Event Log and socket-table sensors keep running");
        eprintln!(
            "[!] {e} — process/network/file detection is down (not elevated?). Event Log \
             and socket-table (LISTENER-DRIFT) sensors keep running; Ctrl-C to stop."
        );
        while !shutdown.load(Ordering::SeqCst) {
            std::thread::sleep(SHUTDOWN_CHECK_INTERVAL);
        }
    }
    result
}

/// Runs the ETW sensor (blocking, on the calling thread — same as before) and the
/// Event Log persistence sensor (`sensor-windows-eventlog`, T1543.003/T1053.005/
/// logon events) and the socket-table poller on background threads, all against
/// the same sink, with Ctrl-C wired to stop all three.
///
/// The Event Log and socket-table sensors are supplementary: their failure is
/// logged, not fatal, and a `wevtutil`/`auditpol` hiccup on one host must not take
/// down process/network/file detection with it. The converse also holds — an ETW
/// failure degrades the run to the supplementary sensors instead of ending it
/// (see [`hold_after_primary`]); the ETW error is still the run's exit result.
///
/// `silence`: when given (`agent run`, not the `capture-*` commands), each
/// sensor's heartbeat is registered on it — see [`register_heartbeats`].
fn run_windows_sensors(
    sink: Box<dyn EventSink>,
    silence: Option<&Mutex<SilenceMonitor>>,
) -> anyhow::Result<()> {
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

    // Registered before the ETW session starts (#388): if ETW fails straight
    // away, `hold_after_primary` keeps the run alive and the never-pulsed
    // `windows-etw` heartbeat turns into a T1562 silence alert.
    let etw_heartbeat = silence.map(|monitor| register_heartbeats(monitor, &eventlog_sensor));

    // Set by Ctrl-C only; also the socket poller's stop flag.
    let shutdown = Arc::new(AtomicBool::new(false));

    {
        let shutdown = Arc::clone(&shutdown);
        let eventlog_stop = Arc::clone(&eventlog_stop);
        ctrlc::set_handler(move || {
            eprintln!("\n[!] Shutdown requested...");
            etw_stop.store(true, Ordering::SeqCst);
            eventlog_stop.store(true, Ordering::SeqCst);
            shutdown.store(true, Ordering::SeqCst);
        })?;
    }

    let socket_poller = match spawn_socket_poller(Arc::clone(&sink), Arc::clone(&shutdown)) {
        Ok(handle) => Some(handle),
        Err(e) => {
            eprintln!("[!] Socket poller failed to start (LISTENER-DRIFT degraded): {e}");
            None
        }
    };

    let eventlog_thread = {
        let sink = Arc::clone(&sink);
        std::thread::spawn(move || eventlog_sensor.run(Box::new(SharedSink(sink))))
    };

    let etw_sink: Box<dyn EventSink> = match etw_heartbeat {
        Some(heartbeat) => Box::new(PulsingSink::new(SharedSink(sink), heartbeat)),
        None => Box::new(SharedSink(sink)),
    };
    let etw_result = hold_after_primary(
        || {
            etw_sensor
                .run(etw_sink)
                .map_err(|e| anyhow::anyhow!("ETW sensor failed: {e}"))
        },
        &shutdown,
    );

    // End of run: stop the supplementary sensors too. Ctrl-C has usually set
    // these already; an ETW session that ends on its own has not, and the
    // Event Log join below would otherwise block forever.
    shutdown.store(true, Ordering::SeqCst);
    eventlog_stop.store(true, Ordering::SeqCst);
    if let Some(handle) = socket_poller
        && handle.join().is_err()
    {
        eprintln!("[!] Socket poller thread panicked (LISTENER-DRIFT degraded)");
    }

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

/// Registers the Windows sensors on the silence monitor (#71/#388) and returns
/// the ETW heartbeat for the caller to pulse. ETW is pulsed per forwarded event
/// (`PulsingSink`); each *enabled* Event Log target has its own heartbeat, fed
/// by the sensor's per-target liveness counter — pulsed per successful poll,
/// so a quiet channel is not mistaken for a blinded one, and one target that
/// stops answering (e.g. Security access denied) is not masked by the others.
fn register_heartbeats(
    monitor: &Mutex<SilenceMonitor>,
    eventlog: &sensor_windows_eventlog::EventLogSensor,
) -> SensorHeartbeat {
    let etw = SensorHeartbeat::new("windows-etw");
    let now_ns = schema::time::now_ns();
    let mut monitor = monitor
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    monitor.register(etw.clone(), ETW_SILENCE_DEADLINE_NS, now_ns);
    for (name, counter) in eventlog.liveness() {
        monitor.register(
            SensorHeartbeat::from_counter(name, counter),
            EVENTLOG_SILENCE_DEADLINE_NS,
            now_ns,
        );
    }
    etw
}

/// Windows: administrator privileges are required by the ETW kernel providers.
pub(crate) fn cmd_status() -> anyhow::Result<()> {
    println!("Synthaea agent — platform: Windows");
    println!("Sensors: ETW (Kernel-Process + Kernel-Network + Kernel-File)");
    println!(
        "          Event Log polling (System/7045 + Security/4698/4624/4625/4648/4672 — \
         service and scheduled-task persistence, logon/session events)"
    );
    println!("          Socket-table snapshots (GetExtendedTcpTable — listening ports, 10s)");
    println!("Run as administrator for the kernel providers.");
    Ok(())
}

/// `enable_kill`/`enable_quarantine` are accepted for CLI-signature parity with the
/// Linux path but not wired here yet (issue #25 is Linux-first, matching #71/#103's
/// precedent) — `DetectionSink::enable_response` is never called, so response stays
/// fully inactive on Windows regardless of these flags. `enable_tls_capture`/
/// `enable_readline_capture` (issue #90) are Linux-uprobe-specific — ETW would need
/// its own, unrelated mechanism — so they're accepted for parity only, same as the
/// response flags. `enable_dns_capture` (issue #267) is the same story.
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
        enable_dns_capture: _,
        server,
        ipc_endpoint,
    } = opts;
    let pipeline = super::common::wire_run_pipeline(
        seeded_rule_state(),
        alerts,
        events,
        server,
        ipc_endpoint,
    )?;

    // Sensor-silence detection (#71/#388): the same monitor feeds T1562
    // alerts and `cli health`. Heartbeats are registered once the sensors are
    // built (`run_windows_sensors`); the monitor thread polls an empty list
    // until then, which is harmless.
    let silence_monitor = Arc::new(Mutex::new(SilenceMonitor::new()));
    let _ = pipeline
        .sensor_health
        .set(Arc::new(SilenceHealthSource::new(Arc::clone(
            &silence_monitor,
        ))));
    crate::silence::spawn_monitor(Arc::clone(&silence_monitor), Arc::clone(&pipeline.sink));

    run_windows_sensors(Box::new(SharedSink(pipeline.sink)), Some(&silence_monitor))
}

pub(crate) fn cmd_capture_events(output: &std::path::Path) -> anyhow::Result<()> {
    let sink = sinks::JsonlEventSink::open(output)?;
    eprintln!("Synthaea — raw event capture (Ctrl-C to stop)");
    eprintln!("Output: {}", output.display());
    run_windows_sensors(Box::new(sink), None)
}

pub(crate) fn cmd_capture_baseline(output: &std::path::Path) -> anyhow::Result<()> {
    let sink = crate::sink::BaselineSink::new(seeded_rule_state(), output)?;
    eprintln!("Synthaea — baseline capture (Ctrl-C to stop)");
    eprintln!("Output: {}", output.display());
    run_windows_sensors(Box::new(sink), None)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn failed_etw_keeps_supplementary_sensors_running_until_shutdown() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let trigger = {
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(300));
                shutdown.store(true, Ordering::SeqCst);
            })
        };
        let started = Instant::now();
        let result = hold_after_primary(|| Err(anyhow::anyhow!("not elevated")), &shutdown);
        trigger.join().unwrap();

        assert!(result.is_err(), "the ETW error stays the run's result");
        assert!(
            started.elapsed() >= Duration::from_millis(300),
            "must hold until shutdown, not return on the ETW failure"
        );
    }

    #[test]
    fn etw_failing_after_shutdown_ends_the_run_without_holding() {
        let shutdown = AtomicBool::new(true);
        let started = Instant::now();
        let result = hold_after_primary(|| Err(anyhow::anyhow!("session torn down")), &shutdown);
        assert!(result.is_err());
        assert!(started.elapsed() < SHUTDOWN_CHECK_INTERVAL);
    }

    #[test]
    fn clean_etw_exit_ends_the_run_without_holding() {
        let shutdown = AtomicBool::new(false);
        let started = Instant::now();
        assert!(hold_after_primary(|| Ok(()), &shutdown).is_ok());
        assert!(started.elapsed() < SHUTDOWN_CHECK_INTERVAL);
    }
}
