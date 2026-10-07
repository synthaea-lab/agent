//! Platform-independent composition of the `run` pipeline. The platform
//! modules (`linux`, `windows`) own sensor selection and platform-only wiring
//! (silence monitors, response, pollers); everything both share — transport,
//! the detection sink, the banner, the progress heartbeat — is assembled here,
//! so a new pipeline stage lands once instead of per-platform.

use std::sync::{Arc, Mutex};

use tamper::heartbeat::SilenceMonitor;

use crate::{
    health::{
        DroppedCounter, HealthCollector, HealthCollectorConfig, NoopSpoolStats, SensorHealthSource,
        SpoolStatsSource,
    },
    ipc_handler::{AgentHandler, SensorHealthSlot},
    silence::SilenceHealthSource,
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
pub(crate) fn plant_canaries(
    sink: &DetectionSink,
    deception: &config::DeceptionConfig,
    storage: &config::StorageConfig,
) {
    if let Some(tripwires) = crate::deception::start(deception, &storage.state_dir) {
        sink.set_tripwires(tripwires);
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
) -> HealthCollector {
    let spool_stats: Arc<dyn SpoolStatsSource> = match &pipeline.transport {
        Some(t) => Arc::new(crate::upload::SpoolHealth {
            events: Arc::clone(&t.spool),
            detections: Arc::clone(&t.detection_spool),
        }),
        None => Arc::new(NoopSpoolStats),
    };
    let heartbeat_client = pipeline.transport.as_ref().map(|t| Arc::clone(&t.client));
    let silence_health: Arc<dyn SensorHealthSource> =
        Arc::new(SilenceHealthSource::new(silence_monitor));
    let _ = pipeline.sensor_health.set(Arc::clone(&silence_health));
    HealthCollector::new(
        HealthCollectorConfig::default(),
        silence_health,
        spool_stats,
        Arc::new(pipeline.sink.enrich_queue().clone()) as Arc<dyn DroppedCounter>,
        move |beacon| {
            tracing::info!(
                sensors = beacon.sensors.len(),
                spool_bytes = beacon.spool_bytes,
                enrich_dropped = beacon.enrich_dropped,
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

#[cfg(test)]
mod tests {
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

        let _collector = health_collector(&pipeline, Arc::clone(&monitor));
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
}
