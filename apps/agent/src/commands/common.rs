//! Platform-independent composition of the `run` pipeline. The platform
//! modules (`linux`, `windows`) own sensor selection and platform-only wiring
//! (silence monitors, response, pollers); everything both share — transport,
//! the detection sink, the banner, the progress heartbeat — is assembled here,
//! so a new pipeline stage lands once instead of per-platform.

use std::sync::{Arc, Mutex};

use tamper::heartbeat::SilenceMonitor;

use super::localzone;
use crate::{
    health::{
        DroppedCounter, HealthCollector, HealthCollectorConfig, HostCountersSource, NoopSpoolStats,
        RarityStatsSource, SensorHealthSource, SpoolStatsSource,
    },
    ipc_handler::{AgentHandler, SensorHealthSlot},
    shutdown::{SHUTDOWN_BUDGET, ShutdownPlan},
    silence::{SilenceHealthSource, SourceStatus},
    sink::DetectionSink,
};

/// What `run` composes before handing control to the platform's sensors.
pub(crate) struct RunPipeline {
    pub(crate) sink: Arc<DetectionSink>,
    /// `Some` when `--server` was given: the upload thread is already running
    /// and the sink is spooling — see [`crate::upload`].
    // Read back by `health_collector` (spool stats + heartbeat client), which
    // only the platforms with a silence monitor call.
    #[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
    pub(crate) transport: Option<crate::upload::TransportHandle>,
    /// Where the platform deposits its sensor-health source for `cli health`
    /// (issue #388). Left empty on a platform with no silence monitor wired:
    /// the IPC handler then reports no sensors rather than invented ones.
    #[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
    pub(crate) sensor_health: SensorHealthSlot,
}

/// Plants the configured canary files and hands the sink the tripwires over them (#81).
/// Called before the sensors start, so the first touch of a canary is already matched.
///
/// The decoy tokens in those canaries are registered, as hashes, with the control plane when
/// there is one (`transport`); standalone, or with the upload disabled, they are planted and
/// never recognised anywhere.
pub(crate) fn plant_canaries(
    sink: &DetectionSink,
    deception: &config::DeceptionConfig,
    storage: &config::StorageConfig,
    transport: Option<&crate::upload::TransportHandle>,
) {
    let (tripwires, decoys) = crate::deception::start_with_decoys(deception, &storage.state_dir);
    if let Some(tripwires) = tripwires {
        sink.set_tripwires(tripwires);
        sink.set_canary_allow(crate::deception::CanaryAllow::new(deception));
        crate::deception::spawn_refresh(deception.clone(), storage.state_dir.clone());
    }
    match transport {
        Some(handle) => crate::deception::register_decoys_in_background(
            std::sync::Arc::clone(&handle.client),
            decoys,
        ),
        None if !decoys.is_empty() => tracing::info!(
            count = decoys.len(),
            "deception: no control plane, decoy credentials are planted but nothing will recognise them"
        ),
        None => {}
    }
}

/// Hands the rules the host's local time, which turns ODD-HOUR-LOGON on (<https://github.com/synthaea-lab/agent/issues/17>, <https://github.com/synthaea-lab/agent/issues/15>): the
/// platform's time zone when the host names one (daylight saving followed), and the operator's
/// `[detection] utc_offset_minutes` over it when set. An offset no timezone has is logged and
/// ignored rather than guessed; with neither the rule stays off.
pub(crate) fn apply_detection(sink: &DetectionSink, detection: &config::DetectionConfig) {
    apply_platform_zone(sink);
    apply_odd_hour_calibration(sink, detection);
    let Some(minutes) = detection.utc_offset_minutes else {
        return;
    };
    if sink.set_local_utc_offset_minutes(minutes) {
        tracing::info!(
            minutes,
            "detection: host local time set, odd-hour logon rule on"
        );
    } else {
        tracing::warn!(
            minutes,
            "detection: utc_offset_minutes is outside -720..=840, odd-hour logon rule stays off"
        );
    }
}

/// Indexes of the exempt entries that contain a backslash (`DOMAIN\name`): kept, not rejected,
/// but they match nothing today.
fn backslash_exempt_entries(entries: &[String]) -> Vec<usize> {
    entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.contains('\\'))
        .map(|(index, _)| index)
        .collect()
}

/// The operator's declared ordinary hours and exempt accounts for ODD-HOUR-LOGON (<https://github.com/synthaea-lab/agent/issues/64>);
/// nothing changes for a host that declared neither.
fn apply_odd_hour_calibration(sink: &DetectionSink, detection: &config::DetectionConfig) {
    if let Some([start, end]) = detection.work_hours {
        if sink.set_work_hours(start, end) {
            if start == 0 && end == 24 {
                tracing::info!(
                    start,
                    end,
                    "detection: odd-hour logon window declared; every hour is ordinary, so the rule will not alert"
                );
            } else {
                tracing::info!(start, end, "detection: odd-hour logon window declared");
            }
        } else {
            tracing::warn!(
                start,
                end,
                "detection: work_hours is not a window, the default 07:00-20:00 stays"
            );
        }
    }
    if !detection.odd_hour_exempt_accounts.is_empty() {
        for index in backslash_exempt_entries(&detection.odd_hour_exempt_accounts) {
            tracing::warn!(
                index,
                "detection: an exempt entry contains a backslash; no sensor reports DOMAIN\\name for a logon today, so it exempts nothing (write the bare name, or NAME|SID)"
            );
        }
        let kept = sink.set_odd_hour_exempt_accounts(&detection.odd_hour_exempt_accounts);
        tracing::info!(
            count = kept,
            "detection: accounts exempt from the odd-hour logon rule"
        );
        // A guard against drift only: `config::load` already refuses every entry the rules drop
        // (blank, over-long, a malformed SID part, past the limit), so this does not fire after a
        // normal load; both grammars are checked against one shared table of entries.
        if kept != detection.odd_hour_exempt_accounts.len() {
            tracing::warn!(
                declared = detection.odd_hour_exempt_accounts.len(),
                kept,
                "detection: some exempt entries were dropped (blank, over-long, malformed or past the limit)"
            );
        }
    }
}

/// Asks the platform for the host's time zone and gives it to the rules. Not given when the
/// host names no zone (a minimal Unix container is UTC to the C library by default, which is
/// not a choice anyone made) or the platform cannot convert the present.
fn apply_platform_zone(sink: &DetectionSink) {
    if !localzone::configured() {
        tracing::info!(
            "detection: the host names no time zone; odd-hour logon rule off unless utc_offset_minutes is set"
        );
        return;
    }
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or_default();
    if sink.set_local_zone(localzone::utc_offset_minutes_at, now_secs) {
        tracing::info!("detection: platform time zone in use, odd-hour logon rule on");
    } else {
        tracing::warn!(
            "detection: the platform gave no time zone offset; odd-hour logon rule off unless utc_offset_minutes is set"
        );
    }
}

/// Builds the shared pipeline: optional transport (spool + upload thread),
/// the detection sink (spooling into it when transport is on), the operator
/// banner, the progress-backed liveness heartbeat (#102), and the local IPC
/// control channel served to `cli` (#388).
pub(crate) fn wire_run_pipeline(
    rule_state: rules::RuleState,
    alerts: &std::path::Path,
    events: Option<&std::path::Path>,
    server: Option<crate::upload::ControlPlane<'_>>,
    ipc_endpoint: &str,
    content_dir: &std::path::Path,
    storage: &config::StorageConfig,
) -> anyhow::Result<RunPipeline> {
    // Transport first: the sink needs the spool handle at construction.
    let spool_cap = crate::upload::spool_cap_bytes(storage.spool_max_mb);
    let (transport, upload_disabled) = match server {
        None => (None, None),
        Some(control_plane) => {
            match crate::upload::start_or_disable(&control_plane, alerts, spool_cap)? {
                crate::upload::UploadStart::Running(handle) => (Some(handle), None),
                crate::upload::UploadStart::Disabled(reason) => (None, Some(reason)),
            }
        }
    };
    let spool = transport.as_ref().map(|t| Arc::clone(&t.spool));
    let detection_spool = transport.as_ref().map(|t| Arc::clone(&t.detection_spool));

    let sink = Arc::new(DetectionSink::new(
        rule_state,
        alerts,
        events,
        spool,
        detection_spool,
        content_dir,
        &crate::sink::model_root(&storage.state_dir),
    )?);
    sink.start_correlator_ticker()?;
    // The agent's own control-plane traffic is not an IOC finding (https://github.com/synthaea-lab/agent/issues/47), and only that
    // destination is: the agent's binary pointed anywhere else still raises.
    if let Some(control_plane) = &server
        && !sink.set_control_plane(control_plane.url)
    {
        tracing::warn!(
            url = control_plane.url,
            "ioc: the control-plane URL names no host; the agent's own traffic to it will raise"
        );
    }

    // The fleet common-set snapshot (ADR-0033): off unless this build embeds a `snapshot` key.
    if let Some(handle) = &transport {
        crate::snapshot_fetch::spawn_if_enabled(
            Arc::clone(&handle.client),
            content_dir.to_path_buf(),
            Arc::clone(&sink),
        );
    }

    // Said where the operator reads it (the journal) and in the alert log, where `cli` and
    // the console look: detection runs, upload does not (`offline_fallback`).
    if let Some(reason) = &upload_disabled {
        eprintln!("Synthaea agent — UPLOAD DISABLED: {reason}");
        sink.emit("UPLOAD-DISABLED", reason);
    }
    eprintln!("Synthaea agent — detection active (Ctrl-C to stop)");
    eprintln!(
        "alerts: {} · events: {}",
        alerts.display(),
        events.map_or_else(|| "off".to_string(), |p| p.display().to_string())
    );
    if let (Some(control_plane), true) = (server, transport.is_some()) {
        let url = control_plane.url;
        eprintln!(
            "server: {url} · event spool: {} · detection spool: {} (store-and-forward, at-least-once)",
            alerts.with_file_name("spool").display(),
            alerts.with_file_name("detection-spool").display(),
        );
    }

    // Progress-backed liveness (#102): started here because it only needs a
    // clone of the shared counter, not the sink itself.
    crate::heartbeat::start(
        crate::heartbeat::heartbeat_path_for(alerts),
        sink.progress_handle(),
        crate::heartbeat::WRITE_INTERVAL,
    );

    // Local control channel (#388): non-fatal by design, see `ipc_handler`.
    let sensor_health: SensorHealthSlot = Arc::new(std::sync::OnceLock::new());
    crate::ipc_handler::spawn(
        ipc_endpoint.to_string(),
        AgentHandler::new(
            sink.alert_log(),
            Arc::clone(&sensor_health),
            Arc::clone(&sink),
        ),
    );

    Ok(RunPipeline {
        sink,
        transport,
        sensor_health,
    })
}

/// Builds the health-beacon collector (#134) over the platform's silence
/// monitor, and publishes the same live snapshot to `cli health` (#388) so the
/// two never disagree. The caller spawns it and owns its shutdown.
///
/// The beacon is logged every tick and, with `--server`, sent as a `POST` to the
/// heartbeat endpoint — the signal the control plane's silent-agent detection
/// keys on (contract in `docs/architecture/control-plane.md`). Windows agents
/// were invisible to it until they called this too (#317).
#[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
pub(crate) fn health_collector(
    pipeline: &RunPipeline,
    silence_monitor: Arc<Mutex<SilenceMonitor>>,
    best_effort_sources: Vec<SourceStatus>,
    host_counters: Arc<dyn HostCountersSource>,
) -> HealthCollector {
    let spool_stats: Arc<dyn SpoolStatsSource> = match &pipeline.transport {
        Some(t) => Arc::new(crate::upload::SpoolHealth {
            events: Arc::clone(&t.spool),
            detections: Arc::clone(&t.detection_spool),
        }),
        None => Arc::new(NoopSpoolStats),
    };
    let heartbeat_client = pipeline.transport.as_ref().map(|t| Arc::clone(&t.client));
    let silence_health: Arc<dyn SensorHealthSource> = Arc::new(SilenceHealthSource::new(
        silence_monitor,
        best_effort_sources,
    ));
    let _ = pipeline.sensor_health.set(Arc::clone(&silence_health));
    HealthCollector::new(
        HealthCollectorConfig::default(),
        silence_health,
        spool_stats,
        Arc::new(pipeline.sink.enrich_queue().clone()) as Arc<dyn DroppedCounter>,
        pipeline.sink.rarity_stats() as Arc<dyn RarityStatsSource>,
        host_counters,
        move |beacon| {
            tracing::info!(
                sensors = beacon.sensors.len(),
                spool_bytes = beacon.spool_bytes,
                enrich_dropped = beacon.enrich_dropped,
                rarity_applied = beacon.rarity_applied,
                rarity_withheld = beacon.rarity_withheld,
                rarity_unapplied = beacon.rarity_unapplied,
                watchdog_restarts = beacon.watchdog_restarts,
                tamper_events = beacon.tamper_events,
                parent_image_evicted_live = beacon.parent_image_evicted_live,
                parent_image_evicted_dead = beacon.parent_image_evicted_dead,
                ioc_indicators = beacon.ioc_indicators,
                ioc_findings = beacon.ioc_findings,
                ioc_cooled_down = beacon.ioc_cooled_down,
                ioc_own_skipped = beacon.ioc_own_skipped,
                ioc_sibling_skipped = beacon.ioc_sibling_skipped,
                "health beacon"
            );
            // #24/#134: the dedicated health channel — best-effort, an
            // unreachable server is nominal (events spool; the beacon's next
            // tick retries by construction).
            if let Some(client) = &heartbeat_client
                && let Err(e) = client.send_heartbeat(&beacon)
            {
                tracing::debug!(error = %e, "health beacon heartbeat POST failed");
            }
        },
    )
}

/// How long [`finish_run`] waits for the enrichment queue to empty.
const ENRICH_FLUSH_BOUND: std::time::Duration = std::time::Duration::from_secs(1);

/// The end of `agent run`, once the primary sensor has returned (Ctrl-C or a sensor failure),
/// shared by all three platforms (#147).
///
/// 1. Flushes the enrichment queue, bounded by [`ENRICH_FLUSH_BOUND`], so findings the sink
///    already accepted reach the spool before the uploader's last drain. A stalled enrichment
///    only costs that bound, never the whole shutdown deadline.
/// 2. Winds `shutdown`'s workers down: all are signalled at once, then joined against one
///    [`SHUTDOWN_BUDGET`]. A worker still running at the deadline is logged and detached.
///
/// Whatever is still spooled afterwards is redelivered on the next start (at-least-once).
/// Returns the names of the workers that missed the deadline.
pub(crate) fn finish_run(sink: &DetectionSink, shutdown: ShutdownPlan) -> Vec<&'static str> {
    finish_run_within(sink, shutdown, SHUTDOWN_BUDGET)
}

/// [`finish_run`] with an explicit budget, so a test does not wait the production 6 s.
fn finish_run_within(
    sink: &DetectionSink,
    shutdown: ShutdownPlan,
    budget: std::time::Duration,
) -> Vec<&'static str> {
    if !sink.enrich_queue().flush(ENRICH_FLUSH_BOUND) {
        tracing::warn!("pending detection/event queue did not flush before shutdown");
    }
    let stragglers = shutdown.execute(budget);
    if !stragglers.is_empty() {
        tracing::warn!(
            ?stragglers,
            "workers still running at the shutdown deadline"
        );
    }
    stragglers
}

#[cfg(test)]
mod tests {
    use super::backslash_exempt_entries;

    #[test]
    fn an_exempt_entry_with_a_backslash_is_flagged_not_dropped() {
        let entries: Vec<String> = [
            "svc_backup",
            "CORP\\oncall",
            "ok|S-1-5-21-1-2-3-1004",
            "A\\b|S-1-5-21-1-2-3-*",
        ]
        .map(String::from)
        .to_vec();
        assert_eq!(backslash_exempt_entries(&entries), vec![1, 3]);
        assert!(backslash_exempt_entries(&[]).is_empty());
    }

    use std::sync::OnceLock;

    use tamper::heartbeat::SensorHeartbeat;

    use super::*;

    #[test]
    fn the_health_beacon_and_cli_health_read_the_same_silence_monitor() {
        // #317: Windows builds its beacon here now, and used to publish the
        // `cli health` source itself — the helper must keep doing that, over
        // the very monitor the beacon reads.
        let dir = std::env::temp_dir().join(format!("common-health-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pipeline = RunPipeline {
            sink: Arc::new(
                DetectionSink::new(
                    rules::RuleState::new(),
                    &dir.join("alerts.ndjson"),
                    Some(&dir.join("events.jsonl")),
                    None,
                    None,
                    &dir.join("content"),
                    &dir.join("ml-registry"),
                )
                .unwrap(),
            ),
            transport: None,
            sensor_health: Arc::new(OnceLock::new()),
        };
        let monitor = Arc::new(Mutex::new(SilenceMonitor::new()));

        let _collector = health_collector(
            &pipeline,
            Arc::clone(&monitor),
            Vec::new(),
            Arc::new(crate::host_counters::AgentHostCounters::new(
                Arc::clone(&pipeline.sink),
                crate::host_counters::WatchdogReport::default(),
                None,
            )),
        );
        monitor
            .lock()
            .unwrap()
            .register(SensorHeartbeat::new("windows-etw"), 1, 0);

        let published = pipeline.sensor_health.get().expect("cli health source");
        let names: Vec<String> = published
            .sensor_health()
            .into_iter()
            .map(|s| s.name)
            .collect();
        // The sink holds its files open, and Windows can't delete an open file.
        drop(pipeline);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(names, ["windows-etw"]);
    }

    fn finish_run_sink(name: &str) -> (Arc<DetectionSink>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("common-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sink = Arc::new(
            DetectionSink::new(
                rules::RuleState::new(),
                &dir.join("alerts.ndjson"),
                Some(&dir.join("events.jsonl")),
                None,
                None,
                &dir.join("content"),
                &dir.join("ml-registry"),
            )
            .unwrap(),
        );
        (sink, dir)
    }

    /// #147: Windows and macOS ended `cmd_run` with no flush and no shutdown, so the upload
    /// loop never made its final drain. Every registered worker must be signalled and joined.
    #[test]
    fn finish_run_signals_and_joins_every_registered_worker() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let (sink, dir) = finish_run_sink("finish-joins");
        let stop = Arc::new(AtomicBool::new(false));
        let drained = Arc::new(AtomicBool::new(false));
        let (worker_stop, worker_drained) = (Arc::clone(&stop), Arc::clone(&drained));
        let handle = std::thread::spawn(move || {
            crate::shutdown::sleep_unless_stopped(&worker_stop, std::time::Duration::from_secs(60));
            // The final drain an upload loop makes once it sees the stop.
            worker_drained.store(true, Ordering::SeqCst);
        });
        let mut plan = ShutdownPlan::default();
        let signal = Arc::clone(&stop);
        plan.register(
            "worker",
            move || signal.store(true, Ordering::SeqCst),
            handle,
        );

        let started = std::time::Instant::now();
        let stragglers = finish_run(&sink, plan);

        assert!(stragglers.is_empty(), "{stragglers:?}");
        assert!(
            drained.load(Ordering::SeqCst),
            "the worker did not finish its drain"
        );
        assert!(
            started.elapsed() < SHUTDOWN_BUDGET,
            "a cooperative worker must not use the whole budget"
        );
        drop(sink);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A worker that ignores its stop must not hold the exit hostage: it is named and
    /// detached once the budget is spent.
    #[test]
    fn finish_run_names_a_stuck_worker_and_returns_within_the_budget() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let (sink, dir) = finish_run_sink("finish-stuck");
        let release = Arc::new(AtomicBool::new(false));
        let held = Arc::clone(&release);
        let handle = std::thread::spawn(move || {
            while !held.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        });
        let mut plan = ShutdownPlan::default();
        plan.register("stuck", || {}, handle);

        let budget = std::time::Duration::from_millis(300);
        let started = std::time::Instant::now();
        let stragglers = finish_run_within(&sink, plan, budget);
        let took = started.elapsed();
        release.store(true, Ordering::SeqCst);

        assert_eq!(stragglers, ["stuck"]);
        // Flush bound (1 s, only if the queue is stalled) is not part of this: the queue is empty.
        assert!(
            took < budget + std::time::Duration::from_secs(1),
            "{took:?}"
        );
        drop(sink);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
