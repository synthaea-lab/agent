//! Platform-independent composition of the `run` pipeline. The platform
//! modules (`linux`, `windows`) own sensor selection and platform-only wiring
//! (silence monitors, response, pollers); everything both share — transport,
//! the detection sink, the banner, the progress heartbeat — is assembled here,
//! so a new pipeline stage lands once instead of per-platform.

use std::sync::Arc;

use crate::sink::DetectionSink;

/// What `run` composes before handing control to the platform's sensors.
pub(crate) struct RunPipeline {
    pub(crate) sink: Arc<DetectionSink>,
    /// `Some` when `--server` was given: the upload thread is already running
    /// and the sink is spooling — see [`crate::upload`].
    // Read back only on Linux (spool health stats + heartbeat client, see
    // `commands::linux::cmd_run`) — `windows.rs` uses `pipeline.sink` alone.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) transport: Option<crate::upload::TransportHandle>,
}

/// Builds the shared pipeline: optional transport (spool + upload thread),
/// the detection sink (spooling into it when transport is on), the operator
/// banner, and the progress-backed liveness heartbeat (#102).
pub(crate) fn wire_run_pipeline(
    rule_state: rules::RuleState,
    alerts: &std::path::Path,
    events: &std::path::Path,
    server: Option<&str>,
) -> anyhow::Result<RunPipeline> {
    // Transport first: the sink needs the spool handle at construction.
    let transport = server
        .map(|url| crate::upload::start(url, alerts))
        .transpose()?;
    let spool = transport.as_ref().map(|t| Arc::clone(&t.spool));

    let sink = Arc::new(DetectionSink::new(rule_state, alerts, events, spool)?);

    eprintln!("Synthaea agent — detection active (Ctrl-C to stop)");
    eprintln!(
        "alerts: {} · events: {}",
        alerts.display(),
        events.display()
    );
    if let Some(url) = server {
        eprintln!(
            "server: {url} · spool: {} (store-and-forward, at-least-once)",
            alerts.with_file_name("spool").display()
        );
    }

    // Progress-backed liveness (#102): started here because it only needs a
    // clone of the shared counter, not the sink itself.
    crate::heartbeat::start(
        crate::heartbeat::heartbeat_path_for(alerts),
        sink.progress_handle(),
        crate::heartbeat::WRITE_INTERVAL,
    );

    Ok(RunPipeline { sink, transport })
}
