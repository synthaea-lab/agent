//! Cross-event correlation in the detection sink: the correlator call for every event, the
//! ML correlation scorer that feeds its belief, the one-second clock that expires its
//! windows, and how its alerts become findings. The engine is described in
//! `docs/correlation.md`, the scorer in `docs/detection/ml.md`.

use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::Duration,
};

use schema::Event;

use super::{DetectionSink, entity_key, recording::Finding, response::crosses_kill_gate};
use crate::sync::LockExt as _;

/// The ML correlation model family of this platform.
#[cfg(target_os = "linux")]
const MODEL_FAMILY: &str = "correlation-iforest-linux";
#[cfg(target_os = "windows")]
const MODEL_FAMILY: &str = "correlation-iforest-windows";
#[cfg(target_os = "macos")]
const MODEL_FAMILY: &str = "correlation-iforest-macos";

/// Why the ML correlation scorer could not be loaded.
#[derive(Debug, thiserror::Error)]
pub(super) enum ScorerLoadError {
    /// `model.onnx` is missing or unreadable.
    #[error("cannot read the model: {0}")]
    ReadModel(#[from] io::Error),
    /// The model was read but the scorer rejected it.
    #[error(transparent)]
    Scorer(#[from] ml::ScorerError),
}

/// The `case_id` of a correlator finding: `{ppid}:{comm}`, with `@{generation}` of the
/// parent appended when it is known, so two incarnations of a recycled parent pid do not
/// share one case. The server treats it as an opaque string.
pub(super) fn correlator_case_id(entity: &verdict::EntityKey) -> String {
    match entity.parent_generation {
        Some(generation) => format!("{}:{}@{generation}", entity.ppid, entity.comm),
        None => format!("{}:{}", entity.ppid, entity.comm),
    }
}

/// Where the agent looks for ML model families first: under the state directory,
/// like the content and the updater's files, not the process's working directory
/// (#559). Lab runs and source checkouts keep working through the relative
/// `ml/registry` fallback in [`load_correlation_scorer`].
pub(crate) fn model_root(state_dir: &Path) -> PathBuf {
    state_dir.join("ml").join("registry")
}

/// The version directory of `family` under the first of `roots` that holds a
/// `model.onnx`. When none does, the first root's directory: it is the one the
/// "scorer unavailable" warning should name, where an operator would put the model.
pub(super) fn locate_model_dir(roots: &[&Path], family: &str) -> PathBuf {
    let dirs: Vec<PathBuf> = roots
        .iter()
        .map(|root| root.join(family).join("0.1.0"))
        .collect();
    dirs.iter()
        .find(|dir| dir.join("model.onnx").is_file())
        .unwrap_or(&dirs[0])
        .clone()
}

/// The ML correlation scorer of this platform, or `None` (logged) when it cannot be
/// loaded: the agent then runs on the hand-calibrated features alone. Where it looks
/// and why: `docs/detection/ml.md`, "Loading and degraded mode".
pub(super) fn load_correlation_scorer(model_root: &Path) -> Option<ml::CorrelationScorer> {
    let model_dir = locate_model_dir(&[model_root, Path::new("ml/registry")], MODEL_FAMILY);
    match try_load_scorer(&model_dir) {
        Ok(scorer) => {
            tracing::info!(
                model_dir = %model_dir.display(),
                "ML correlation scorer loaded"
            );
            Some(scorer)
        }
        Err(e) => {
            tracing::warn!(
                model_dir = %model_dir.display(),
                error = %e,
                "ML correlation scorer unavailable — agent works without ML"
            );
            None
        }
    }
}

/// Loads `model.onnx` from `model_dir`, with the `model_metadata.json` next to it when
/// there is one (it is optional).
pub(super) fn try_load_scorer(model_dir: &Path) -> Result<ml::CorrelationScorer, ScorerLoadError> {
    let model_bytes = std::fs::read(model_dir.join("model.onnx"))?;
    let meta_bytes = std::fs::read(model_dir.join("model_metadata.json")).ok();
    Ok(ml::CorrelationScorer::from_onnx_bytes_with_metadata(
        &model_bytes,
        meta_bytes.as_deref(),
    )?)
}

/// The scorer's log-likelihood ratio for the pid's behavior over the correlator window,
/// or `None` when it has no evidence to give: too few events yet, a feature outside the
/// training bounds (logged), or a scorer failure (logged; fail open). `None` means "no
/// evidence", never "benign".
fn ml_evidence(
    scorer: &mut ml::CorrelationScorer,
    engine: &correlator::CorrelationEngine,
    pid: u32,
    generation: Option<u64>,
) -> Option<f32> {
    match scorer.score(engine.bus(), pid, generation) {
        Ok(score) => score.map(ml::score_to_llr),
        Err(ml::ScorerError::FeatureOutOfBounds {
            feature,
            value,
            min,
            max,
        }) => {
            tracing::warn!(
                pid = pid,
                feature = feature,
                value = value,
                min = min,
                max = max,
                "ML scorer OOD rejection"
            );
            None
        }
        Err(e) => {
            tracing::error!(pid = pid, error = %e, "ML scorer error");
            None
        }
    }
}

impl DetectionSink {
    /// Starts the one-second clock that expires pending web-shell correlations even
    /// when the sensor has stopped producing events. The worker holds only a `Weak`
    /// reference while sleeping, and releases the correlator mutex before log I/O.
    pub(crate) fn start_correlator_ticker(self: &Arc<Self>) -> io::Result<()> {
        let sink = Arc::downgrade(self);
        thread::Builder::new()
            .name("correlator-tick".into())
            .spawn(move || {
                loop {
                    thread::sleep(Duration::from_secs(1));
                    let Some(sink) = sink.upgrade() else {
                        break;
                    };
                    sink.advance_correlation_time(schema::time::now_ns());
                }
            })?;
        Ok(())
    }

    pub(super) fn advance_correlation_time(&self, now_ns: u64) {
        let alerts = {
            let mut correlator = self.correlator.lock_recovering();
            correlator.advance_time(now_ns)
        };
        // `BAYES`, the only technique that crosses the kill gate, is never raised by the
        // window expiry, so this path has no shield to pass (docs/response.md).
        self.emit_correlator_alerts(&alerts, None, None);
    }

    /// Cross-event correlation (co-occurrence rules + Bayesian belief), with the ML
    /// scorer's evidence folded into the belief when a scorer is loaded. Scoring runs
    /// inside the correlator lock: inference takes microseconds, on the capture thread.
    pub(super) fn correlate(&self, event: &Event) {
        let mut engine = self.correlator.lock_recovering();
        let alerts = engine.on_event(event.clone());

        let pid = event.meta().pid;
        let generation = event.meta().process_generation;
        if let Some(ref mut scorer) = *self.ml_scorer.lock_recovering() {
            let ml_llr = ml_evidence(scorer, &engine, pid, generation);
            // `Err` only means the pid has no behavior vector yet: normal for its first events.
            let _ = engine.update_belief_with_ml(pid, generation, ml_llr);
        }

        let shield = engine.kill_shield(pid, generation);
        drop(engine); // Unlock correlator before alert emission (log I/O).

        // The kill gate reads this event's own alerts, never the entity's sticky fused
        // verdict (docs/response.md, "What can trigger a kill").
        self.emit_correlator_alerts(&alerts, Some(event), shield);
    }

    /// Records each correlator alert as a finding, then hands the kill gate the pid of the
    /// last alert that crosses it. `shield` is the correlator's provenance verdict for the
    /// event this batch came from; it is read only for a `BAYES` alert, whose
    /// `trigger_event` is always `None`, so it always resolves to `default_event`: the
    /// pid `shield` was computed for.
    fn emit_correlator_alerts(
        &self,
        alerts: &[correlator::CorrelationAlert],
        default_event: Option<&Event>,
        shield: Option<correlator::KillShield>,
    ) {
        let mut high_confidence_pid = None;
        for alert in alerts {
            let Some(event) = alert.trigger_event.as_deref().or(default_event) else {
                continue;
            };
            let entity = entity_key(event.meta());
            let case_id = correlator_case_id(&entity);
            let source = schema::detection::DetectionSource::Correlator { case_id };
            let finding = Finding {
                entity: &entity,
                technique: alert.technique,
                message: &alert.message,
                source,
                severity: alert.severity,
            };
            self.record(finding, event, Vec::new());
            if crosses_kill_gate(alert.technique) {
                high_confidence_pid = Some(event.meta().pid);
            }
        }
        if let Some(pid) = high_confidence_pid {
            self.maybe_kill(pid, shield);
        }
    }
}
