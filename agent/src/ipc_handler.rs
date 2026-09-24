//! The agent side of the local control channel (issue #388): the real
//! `ipc::Handler` that answers `cli status` / `health` / `detections` /
//! `policy` from live agent state, and the thread that serves it.
//!
//! The IPC server is a control channel, never a detection dependency: if it
//! fails to start (endpoint busy, missing rights), the failure is logged and
//! the agent keeps detecting. Nothing here can stop the capture pipeline.

use std::sync::{Arc, OnceLock};

use ipc::{
    DetectionSummary, Handler, PolicyVersionResponse, RecentDetectionsResponse, SensorHealth,
    SensorHealthResponse, SensorState, Server, StatusResponse,
};

use crate::{
    alerts::{AlertLog, RecentAlert},
    health::SensorHealthSource,
};

/// Where a platform deposits its sensor-health source once it has built one.
/// Empty until then: `cli health` reports no sensors rather than inventing
/// any. A `OnceLock` because on Linux the silence monitor is created after the
/// shared pipeline (and therefore after this handler) is wired.
pub(crate) type SensorHealthSlot = Arc<OnceLock<Arc<dyn SensorHealthSource>>>;

/// Answers the four IPC requests from the running agent's own state.
pub(crate) struct AgentHandler {
    agent_version: String,
    started_at_ns: u64,
    alerts: Arc<AlertLog>,
    sensors: SensorHealthSlot,
}

impl AgentHandler {
    #[must_use]
    pub(crate) fn new(alerts: Arc<AlertLog>, sensors: SensorHealthSlot) -> Self {
        Self {
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            started_at_ns: schema::time::now_ns(),
            alerts,
            sensors,
        }
    }

    fn sensor_entries(&self) -> Vec<SensorHealth> {
        self.sensors
            .get()
            .map(|source| {
                source
                    .sensor_health()
                    .into_iter()
                    .map(to_ipc_health)
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Handler for AgentHandler {
    async fn status(&self) -> Result<StatusResponse, String> {
        // "Healthy" is derived from real data, not asserted: no attached
        // sensor has gone silent. With no health source wired yet, there is
        // nothing silent, so the pipeline reports healthy.
        let pipeline_healthy = self
            .sensor_entries()
            .iter()
            .all(|s| s.state == SensorState::Up);
        Ok(StatusResponse {
            agent_version: self.agent_version.clone(),
            started_at_ns: self.started_at_ns,
            pipeline_healthy,
        })
    }

    async fn sensor_health(&self) -> Result<SensorHealthResponse, String> {
        Ok(SensorHealthResponse {
            sensors: self.sensor_entries(),
        })
    }

    async fn recent_detections(&self, limit: u32) -> Result<RecentDetectionsResponse, String> {
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        Ok(RecentDetectionsResponse {
            detections: self
                .alerts
                .latest(limit)
                .into_iter()
                .map(to_summary)
                .collect(),
        })
    }

    async fn policy_version(&self) -> Result<PolicyVersionResponse, String> {
        // The agent does not load a policy document yet (out of scope for
        // #388): report "no policy applied" honestly instead of a made-up
        // version or a claimed signature check.
        Ok(PolicyVersionResponse {
            schema_version: policy::SCHEMA_VERSION,
            policy_version: None,
            signature_verified: None,
            issued_at_ns: None,
        })
    }
}

fn to_summary(alert: RecentAlert) -> DetectionSummary {
    DetectionSummary {
        emitted_at_ns: alert.emitted_at_ns,
        source: alert.technique,
        summary: alert.message,
    }
}

/// The silence monitor exposes a pulse count, not a heartbeat timestamp, so
/// `last_heartbeat_ns` stays `None` rather than being fabricated. `Failed`
/// needs a sensor registry (attach errors) and is out of scope for #388.
fn to_ipc_health(h: schema::SensorHealth) -> SensorHealth {
    SensorHealth {
        name: h.name,
        state: if h.silent {
            SensorState::Silent
        } else {
            SensorState::Up
        },
        last_heartbeat_ns: None,
    }
}

/// Serves the IPC endpoint on a dedicated thread with its own single-threaded
/// tokio runtime, detached like the heartbeat writer. Every failure path is a
/// log line, never a panic or an early return from `run`.
pub(crate) fn spawn(endpoint: String, handler: AgentHandler) {
    let spawned = std::thread::Builder::new()
        .name("ipc-server".to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::warn!(error = %e, "IPC: tokio runtime failed to start — `cli` will not reach this agent, detection continues");
                    return;
                }
            };
            tracing::info!(endpoint = %endpoint, "IPC: serving the local control channel");
            // `run` only ever returns on failure (`Ok` is `Infallible`).
            let Err(e) = runtime.block_on(Server::new(endpoint.clone(), handler).run());
            tracing::warn!(endpoint = %endpoint, error = %e, "IPC: server stopped — `cli` will not reach this agent, detection continues");
        });
    if let Err(e) = spawned {
        tracing::warn!(error = %e, "IPC: could not spawn the server thread — detection continues");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::RECENT_ALERTS_CAPACITY;

    struct FixedHealth(Vec<(&'static str, bool)>);

    impl SensorHealthSource for FixedHealth {
        fn sensor_health(&self) -> Vec<schema::SensorHealth> {
            self.0
                .iter()
                .map(|(name, silent)| schema::SensorHealth {
                    name: (*name).to_string(),
                    pulse_count: 1,
                    silent: *silent,
                })
                .collect()
        }
    }

    fn alert_log(tag: &str) -> Arc<AlertLog> {
        let dir = std::env::temp_dir().join(format!("synthaea-ipc-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Arc::new(AlertLog::open(&dir.join("alerts.ndjson"), RECENT_ALERTS_CAPACITY).unwrap())
    }

    fn handler_with(tag: &str, sensors: Option<Vec<(&'static str, bool)>>) -> AgentHandler {
        let slot: SensorHealthSlot = Arc::new(OnceLock::new());
        if let Some(list) = sensors {
            let source: Arc<dyn SensorHealthSource> = Arc::new(FixedHealth(list));
            assert!(slot.set(source).is_ok());
        }
        AgentHandler::new(alert_log(tag), slot)
    }

    #[test]
    fn buffer_capacity_matches_the_protocol_hard_limit() {
        assert_eq!(
            RECENT_ALERTS_CAPACITY,
            usize::try_from(ipc::RECENT_DETECTIONS_HARD_LIMIT).unwrap()
        );
    }

    #[tokio::test]
    async fn recent_detections_serve_recorded_alerts_oldest_first_within_limit() {
        let handler = handler_with("det", None);
        handler.alerts.record("T1", "first".to_string());
        handler.alerts.record("T2", "second".to_string());
        handler.alerts.record("T3", "third".to_string());

        let got = handler.recent_detections(2).await.unwrap().detections;
        let sources: Vec<&str> = got.iter().map(|d| d.source.as_str()).collect();
        assert_eq!(sources, vec!["T2", "T3"]);
        assert_eq!(got[1].summary, "third");
    }

    #[tokio::test]
    async fn health_is_empty_until_a_platform_fills_the_slot() {
        let handler = handler_with("empty", None);
        assert!(handler.sensor_health().await.unwrap().sensors.is_empty());
        assert!(handler.status().await.unwrap().pipeline_healthy);
    }

    #[tokio::test]
    async fn silent_sensor_maps_to_silent_and_marks_the_pipeline_unhealthy() {
        let handler = handler_with(
            "silent",
            Some(vec![("windows-etw", false), ("windows-eventlog", true)]),
        );
        let sensors = handler.sensor_health().await.unwrap().sensors;
        assert_eq!(sensors.len(), 2);
        assert_eq!(sensors[0].state, SensorState::Up);
        assert_eq!(sensors[1].state, SensorState::Silent);
        assert_eq!(sensors[1].last_heartbeat_ns, None);
        assert!(!handler.status().await.unwrap().pipeline_healthy);
    }

    #[tokio::test]
    async fn policy_reports_nothing_applied() {
        let handler = handler_with("policy", None);
        let p = handler.policy_version().await.unwrap();
        assert_eq!(p.schema_version, policy::SCHEMA_VERSION);
        assert_eq!(p.policy_version, None);
        assert_eq!(p.signature_verified, None);
        assert_eq!(p.issued_at_ns, None);
    }

    #[tokio::test]
    async fn status_reports_this_crate_version() {
        let handler = handler_with("status", None);
        assert_eq!(
            handler.status().await.unwrap().agent_version,
            env!("CARGO_PKG_VERSION")
        );
    }
}
