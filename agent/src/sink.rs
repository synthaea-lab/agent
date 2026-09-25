//! The agent's concrete `EventSink`s: full detection (`DetectionSink`) and raw
//! capture (re-using `sinks::JsonlEventSink` directly). Migrated from
//! `old/agent/sinks.rs`, minus what isn't wired yet — the correlator, Sigma, and ML
//! scorer plug in here as their crates are migrated (M2), each addition a new field
//! and a few lines in `on_event`.

use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use policy::ResponsePolicy;
use schema::{Event, sensor::EventSink};
use sinks::JsonlWriter;

use crate::{
    alerts::{AlertLog, RECENT_ALERTS_CAPACITY},
    enrich_queue::EnrichQueue,
};

/// Wires issue #25's automated response into the sink once `enable_response` sets it
/// (Linux only for this pass — see `commands::linux::cmd_run`). Held behind
/// `Arc<Mutex<Option<_>>>` rather than a constructor parameter because the YARA scan
/// queue's callback closure is created inside `DetectionSink::new` itself, before a
/// caller has a `&DetectionSink` to configure — the shared cell lets both `correlate`
/// and that closure read whatever was set (or nothing, on a platform that never
/// calls `enable_response`) without restructuring construction order.
struct ResponseHooks {
    policy: ResponsePolicy,
    /// The actual OS-level kill call, injected by the caller: `response` is
    /// base-tier-only and platform dispatch belongs to the binary (CLAUDE.md).
    terminate: Box<dyn Fn(u32) -> std::io::Result<()> + Send + Sync>,
    quarantine_dir: PathBuf,
}

/// Dispatches every event to the detection engines and the output sinks. `Mutex`
/// around the mutable state (`RuleState`) rather than no synchronization: the
/// `EventSink` trait requires `Send + Sync` and only exposes `&self`, to stay correct
/// if several sensors ever share one sink.
pub(crate) struct DetectionSink {
    rule_state: Mutex<rules::RuleState>,
    correlator: Mutex<correlator::CorrelationEngine>,
    /// ML correlation scorer (issue #46 Phase 3, #47 Phase 2): scores behavior over
    /// the correlator window and feeds the Bayesian belief state. `None` when the
    /// model is unavailable (missing registry, load error) — the agent works without
    /// ML (hand-calibrated features still function).
    ml_scorer: Mutex<Option<ml::CorrelationScorer>>,
    /// Sigma rules from `rules/sigma` (next to the agent executable, falling back
    /// to the working directory) when the folder exists — otherwise the agent runs without a Sigma engine, and that is
    /// not an error (the load failure path IS an error: content present but broken).
    sigma: Option<sigma::SigmaEngine>,
    /// The single alert funnel (issue #388): alerts.ndjson + stderr + the
    /// in-memory recent-alerts buffer served to `cli detections`. Shared with
    /// the YARA scan worker and quarantine.
    alert_log: Arc<AlertLog>,
    /// Budgeted background content scanning; `None` when rules/yara is absent.
    yara: Option<yara::ScanQueue>,
    /// Enrichment (hash + signature) and the high-volume raw-event logging, off the
    /// drain thread (issue #126). The capture thread runs detection in memory and
    /// hands the event here with a non-blocking send.
    enrich_queue: EnrichQueue,
    /// Liveness counter for the watchdog's heartbeat monitor (#102): incremented
    /// once `on_event` has fully processed an event, so `agent::heartbeat`'s
    /// writer thread can sample it and expose real forward progress — not just
    /// "the process is scheduled" — to `watchdog::supervise::HeartbeatMonitor`.
    /// See `progress_handle`.
    progress: Arc<AtomicU64>,
    /// Issue #25's automated response, `None` until (if ever) `enable_response` sets
    /// it — see [`ResponseHooks`].
    response: Arc<Mutex<Option<ResponseHooks>>>,
}

impl DetectionSink {
    /// `rule_state` arrives already seeded by the caller (from /proc or the
    /// platform's process list — see `commands`). `spool` is the transport
    /// spool (`run --server`), `None` when the agent runs standalone.
    pub(crate) fn new(
        rule_state: rules::RuleState,
        alerts_path: &std::path::Path,
        events_path: &std::path::Path,
        spool: Option<Arc<Mutex<store::EventSpool>>>,
    ) -> std::io::Result<Self> {
        let alert_log = Arc::new(AlertLog::open(alerts_path, RECENT_ALERTS_CAPACITY)?);
        // The raw event log is written by the enrichment worker, not the drain
        // thread — shared behind an Arc so the worker owns a handle. The spool
        // append rides the same worker for the same #126 reason: it is file
        // I/O that must never stall the capture thread.
        let events_log = Arc::new(JsonlWriter::open(events_path)?);
        let enrich_queue = EnrichQueue::start(enrich::Enricher::new(), move |event| {
            events_log.write(&event);
            if let Some(spool) = &spool
                && let Err(e) = spool.lock().unwrap().push(&event)
            {
                // Spool full is handled inside push (shed-oldest, counted);
                // reaching here is a real I/O failure — degrade to local-only.
                tracing::warn!(error = %e, "spool append failed — event stays local-only");
            }
        });
        let response: Arc<Mutex<Option<ResponseHooks>>> = Arc::new(Mutex::new(None));
        Ok(Self {
            rule_state: Mutex::new(rule_state),
            correlator: Mutex::new(correlator::CorrelationEngine::new()),
            ml_scorer: Mutex::new(Self::load_correlation_scorer()),
            sigma: load_sigma_rules(),
            yara: start_yara(alert_log.clone(), response.clone()),
            alert_log,
            enrich_queue,
            progress: Arc::new(AtomicU64::new(0)),
            response,
        })
    }

    /// Loads the ML correlation scorer from the registry (issue #46 Phase 3, #47 Phase 2).
    ///
    /// Returns `None` when the model is unavailable (missing directory, load error) —
    /// the agent works without ML (hand-calibrated Bayesian features still function).
    /// Logs a warning on load failure so the operator sees the degradation.
    ///
    /// Model location: `ml/registry/correlation-iforest-{linux,windows}/0.1.0/`
    /// next to the agent binary (or in the current working directory as fallback).
    fn load_correlation_scorer() -> Option<ml::CorrelationScorer> {
        /// Platform-specific model family names.
        #[cfg(target_os = "linux")]
        const MODEL_FAMILY: &str = "correlation-iforest-linux";
        #[cfg(target_os = "windows")]
        const MODEL_FAMILY: &str = "correlation-iforest-windows";
        #[cfg(target_os = "macos")]
        const MODEL_FAMILY: &str = "correlation-iforest-macos";

        let model_dir = std::path::Path::new("ml/registry")
            .join(MODEL_FAMILY)
            .join("0.1.0");

        match Self::try_load_scorer(&model_dir) {
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

    fn try_load_scorer(
        model_dir: &std::path::Path,
    ) -> Result<ml::CorrelationScorer, Box<dyn std::error::Error>> {
        let model_bytes = std::fs::read(model_dir.join("model.onnx"))?;
        let meta_bytes = std::fs::read(model_dir.join("model_metadata.json")).ok();

        Ok(ml::CorrelationScorer::from_onnx_bytes_with_metadata(
            &model_bytes,
            meta_bytes.as_deref(),
        )?)
    }

    /// Activates issue #25's automated response — process kill on a high-confidence
    /// correlated (`BAYES`) verdict, quarantine on a confirmed YARA match. Not called
    /// at all on a platform that doesn't wire it (Windows, for this pass), so
    /// `response` stays `None` and every action reports
    /// [`response::KillOutcome::ObserveOnly`]/[`response::QuarantineOutcome::ObserveOnly`]
    /// regardless of `policy` — the same as if this were never called, which is
    /// deliberate: not opting in and opting in with policy fully disabled must look
    /// identical to an audit consumer.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn enable_response(
        &self,
        policy: ResponsePolicy,
        terminate: impl Fn(u32) -> std::io::Result<()> + Send + Sync + 'static,
        quarantine_dir: PathBuf,
    ) {
        *self.response.lock().unwrap() = Some(ResponseHooks {
            policy,
            terminate: Box::new(terminate),
            quarantine_dir,
        });
    }

    /// Returns a reference to the enrichment queue for health telemetry.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn enrich_queue(&self) -> &EnrichQueue {
        &self.enrich_queue
    }

    /// Hands out the shared progress counter for `agent::heartbeat::start` to
    /// sample (#102) — a clone of the `Arc`, not the sink itself, so the
    /// heartbeat writer thread needs no reference to the sink or its other
    /// state.
    pub(crate) fn progress_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.progress)
    }

    /// Cross-event correlation (co-occurrence rules + Bayesian belief).
    ///
    /// `BAYES` is today's only correlator output with a real number behind it (the
    /// belief engine's `log_odds`, gated by its own threshold before it ever fires —
    /// see `correlator::bayes`); the co-occurrence rules carry no confidence field.
    /// Issue #131 (verdict fusion) will give this a principled score to key off
    /// instead of a technique-name check.
    ///
    /// ML correlation scorer (issue #46 Phase 3, #47 Phase 2): if available, scores
    /// the pid's behavior over the correlator window and updates the belief state with
    /// the resulting log-likelihood ratio. Scoring happens in the correlator lock —
    /// ONNX inference is fast (~microseconds) and the capture thread is single-threaded.
    fn correlate(&self, event: &Event) {
        let mut engine = self.correlator.lock().unwrap();
        let alerts = engine.on_event(event.clone());

        // ML scoring: score the pid's behavior and update belief with the LLR.
        // The scorer lock is held briefly (load Option, score if present). Scoring
        // itself accesses the bus while still holding the correlator lock, which is
        // acceptable — inference is fast and this is the capture thread.
        let pid = event.meta().pid;
        if let Some(ref mut scorer) = *self.ml_scorer.lock().unwrap() {
            let ml_llr = match scorer.score(engine.bus(), pid) {
                Ok(Some(score)) => {
                    // Scored successfully: convert to log-likelihood ratio.
                    Some(ml::score_to_llr(score))
                }
                Ok(None) => {
                    // Gated: fewer than MIN_EVENT_COUNT events in the window for this pid.
                    // No score available yet, not an error.
                    None
                }
                Err(ml::ScorerError::FeatureOutOfBounds {
                    feature,
                    value,
                    min,
                    max,
                }) => {
                    // OOD rejection: feature value outside training bounds, score unreliable.
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
                    // Other error (ONNX runtime, model parse): fail open, log and continue.
                    tracing::error!(pid = pid, error = %e, "ML scorer error");
                    None
                }
            };

            // Update belief with the ML LLR (None = no ML evidence, not "benign").
            if let Err(()) = engine.update_belief_with_ml(pid, ml_llr) {
                // No behavior vector available yet for this pid — not enough events.
                // Silent: this is normal for the first few events of a new pid.
            }
        }

        // Emit alerts from co-occurrence rules and Bayesian belief.
        let is_high_confidence = alerts.iter().any(|alert| alert.technique == "BAYES");
        drop(engine); // Unlock correlator before alert emission (log I/O).
        for alert in &alerts {
            self.emit(alert.technique, &alert.message);
        }
        if is_high_confidence {
            self.maybe_kill(pid);
        }
    }

    /// Issue #25: policy-gates killing the process behind a high-confidence
    /// correlated verdict. A no-op whenever `enable_response` was never called.
    fn maybe_kill(&self, pid: u32) {
        let guard = self.response.lock().unwrap();
        let Some(hooks) = guard.as_ref() else {
            return;
        };
        let outcome = response::kill_process(pid, &hooks.policy, |p| (hooks.terminate)(p));
        drop(guard);
        let message = match outcome {
            response::KillOutcome::Killed { pid } => {
                format!("killed pid {pid} on a high-confidence correlated verdict")
            }
            response::KillOutcome::ObserveOnly { pid } => {
                format!(
                    "pid {pid} would have been killed on a high-confidence correlated verdict (observe-only)"
                )
            }
            response::KillOutcome::Failed { pid, error } => {
                format!("failed to kill pid {pid} on a high-confidence correlated verdict: {error}")
            }
        };
        self.emit("RESPONSE-KILL", &message);
    }

    /// Exec events: stateless rules, stateful rules, then Sigma.
    fn detect_exec(&self, event: &schema::ExecEvent) {
        for alert in rules::evaluate_exec(event) {
            self.emit(alert.technique, &alert.message);
        }
        for alert in self.rule_state.lock().unwrap().on_exec(event) {
            self.emit(alert.technique, &alert.message);
        }
        if let Some(sigma) = &self.sigma {
            for hit in sigma.eval_exec(event) {
                let technique = if hit.tags.is_empty() {
                    "Sigma".to_string()
                } else {
                    hit.tags.join("/")
                };
                self.emit(&technique, &hit.title);
            }
        }
    }

    /// `FileOpen` events: stateless rules, downloader-write history, and the
    /// budgeted YARA queue on write intent (off the event path).
    fn detect_file_open(&self, event: &schema::FileOpenEvent) {
        let state_alerts = self.rule_state.lock().unwrap().on_file_open(event);
        for alert in rules::evaluate_file_open(event)
            .into_iter()
            .chain(state_alerts)
        {
            self.emit(alert.technique, &alert.message);
        }
        if let Some(yara) = &self.yara
            && event.flags & 0o103 != 0
        {
            yara.enqueue(std::path::PathBuf::from(&event.path));
        }
    }

    /// `FileQuarantine` events (macOS quarantine xattr, Windows
    /// `Zone.Identifier`): recorded for the T1204.002 download→exec join, no
    /// alert on their own (#365).
    fn detect_file_quarantine(&self, event: &schema::FileQuarantineEvent) {
        self.rule_state.lock().unwrap().on_file_quarantine(event);
    }

    /// Connect events: beacon detection.
    fn detect_connect(&self, event: &schema::ConnectEvent) {
        for alert in self.rule_state.lock().unwrap().on_connect(event) {
            self.emit(alert.technique, &alert.message);
        }
    }

    /// `NetworkFlow` events (conntrack polling, issue #92): same beacon detection as
    /// `detect_connect`, deduped per-flow so a poll-based source doesn't
    /// false-positive on one ordinary long-lived connection.
    fn detect_network_flow(&self, event: &schema::NetworkFlowEvent) {
        for alert in self.rule_state.lock().unwrap().on_network_flow(event) {
            self.emit(alert.technique, &alert.message);
        }
    }

    /// `ListenPort` events (`sock_diag` polling, issue #92): LISTENER-DRIFT.
    fn detect_listen_port(&self, event: &schema::ListenPortEvent) {
        for alert in self.rule_state.lock().unwrap().on_listen_port(event) {
            self.emit(alert.technique, &alert.message);
        }
    }

    /// `Auth` events: brute-force/spray burst detection (T1110, pack #377).
    fn detect_auth(&self, event: &schema::AuthEvent) {
        for alert in self.rule_state.lock().unwrap().on_auth(event) {
            self.emit(alert.technique, &alert.message);
        }
    }

    /// `FileDelete` events: log-tamper detection (T1070.002, pack #379).
    fn detect_file_delete(&self, event: &schema::FileDeleteEvent) {
        for alert in rules::evaluate_file_delete(event) {
            self.emit(alert.technique, &alert.message);
        }
    }

    /// `Signal` events: security-process tampering (T1562.001, issue #362).
    fn detect_signal(&self, event: &schema::SignalEvent) {
        for alert in rules::evaluate_signal(event) {
            self.emit(alert.technique, &alert.message);
        }
    }

    /// `FileRename` events: mass-rename ransomware detection (T1486, issue #262).
    fn detect_file_rename(&self, event: &schema::FileRenameEvent) {
        for alert in self.rule_state.lock().unwrap().on_file_rename(event) {
            self.emit(alert.technique, &alert.message);
        }
    }

    /// Writes one alert to the shared log and highlighted stderr. `pub(crate)`
    /// rather than private: `silence::spawn_monitor` (#71) emits a sensor-silence
    /// verdict through the exact same path as a rule/correlator/Sigma finding —
    /// one alert shape, whatever detected it.
    pub(crate) fn emit(&self, technique: &str, message: &str) {
        self.alert_log.record(technique, message.to_string());
    }

    /// Handle to the alert funnel, for the IPC handler's `recent_detections`
    /// endpoint (issue #388).
    pub(crate) fn alert_log(&self) -> Arc<AlertLog> {
        Arc::clone(&self.alert_log)
    }
}

/// Resolves a content directory: next to the agent executable first, then the
/// working directory. A cwd-relative path alone breaks under service managers
/// (systemd runs with cwd=/, Windows services in System32), which silently
/// disabled Sigma and YARA exactly in production deployments (review finding).
fn content_dir(name: &str) -> Option<std::path::PathBuf> {
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join(name);
        if candidate.is_dir() {
            return Some(candidate);
        }
    }
    let cwd_relative = std::path::PathBuf::from(name);
    cwd_relative.is_dir().then_some(cwd_relative)
}

/// Loads the Sigma content directory if present. Migrated from the old agent's
/// `load_sigma_rules`.
fn load_sigma_rules() -> Option<sigma::SigmaEngine> {
    let rules_dir = content_dir("rules/sigma")?;
    match sigma::SigmaEngine::load_dir(&rules_dir) {
        Ok(engine) => {
            tracing::info!(rules = engine.rule_count(), "sigma: rules loaded");
            Some(engine)
        }
        Err(e) => {
            tracing::error!(error = %e, "sigma: load error");
            None
        }
    }
}

/// Loads rules/yara when present and starts the scan worker; matches are emitted as
/// alerts by the worker thread through the shared alert log, and — issue #25 —
/// trigger quarantine of the matched file through `response`, whenever
/// `enable_response` set it.
fn start_yara(
    alert_log: Arc<AlertLog>,
    response: Arc<Mutex<Option<ResponseHooks>>>,
) -> Option<yara::ScanQueue> {
    let dir = content_dir("rules/yara")?;
    match yara::RuleSet::load_dir(&dir) {
        Ok(rules) => {
            tracing::info!(rules = rules.rule_count(), "yara: rules loaded");
            Some(yara::ScanQueue::start(rules, move |outcome| {
                let matched = !outcome.matches.is_empty();
                for rule in &outcome.matches {
                    let message = format!("yara rule {rule} matched {}", outcome.path.display());
                    alert_log.record("YARA", message);
                }
                if matched {
                    quarantine_matched_payload(&response, &outcome.path, &alert_log);
                }
            }))
        }
        Err(e) => {
            tracing::error!(error = %e, "yara: load error");
            None
        }
    }
}

/// Issue #25: policy-gates quarantining a YARA-confirmed payload. A no-op whenever
/// `enable_response` was never called — same posture as `DetectionSink::maybe_kill`.
fn quarantine_matched_payload(
    response: &Mutex<Option<ResponseHooks>>,
    path: &std::path::Path,
    alert_log: &AlertLog,
) {
    let guard = response.lock().unwrap();
    let Some(hooks) = guard.as_ref() else {
        return;
    };
    // A quarantined file is written under `quarantine_dir` — that write is itself a
    // FileOpen the sensor sees, which would otherwise re-match and re-"quarantine"
    // the file into itself, overwriting its own `.origin` sidecar with the wrong
    // "original" path (real behavior observed on the lab VM). Once a payload is
    // already there, leave it alone.
    if path.starts_with(&hooks.quarantine_dir) {
        return;
    }
    let outcome = response::quarantine_file(path, &hooks.quarantine_dir, &hooks.policy);
    drop(guard);
    let message = match outcome {
        response::QuarantineOutcome::Quarantined {
            original,
            quarantined_at,
            sha256_hex,
        } => format!(
            "quarantined {} ({sha256_hex}) to {} on a confirmed YARA match",
            original.display(),
            quarantined_at.display()
        ),
        response::QuarantineOutcome::ObserveOnly { path } => format!(
            "{} would have been quarantined on a confirmed YARA match (observe-only)",
            path.display()
        ),
        response::QuarantineOutcome::Failed { path, error } => {
            format!(
                "failed to quarantine {} on a confirmed YARA match: {error}",
                path.display()
            )
        }
    };
    alert_log.record("RESPONSE-QUARANTINE", message);
}

impl EventSink for DetectionSink {
    fn on_event(&self, event: Event) {
        // Detection runs in memory on the capture thread — no engine needs the hash
        // or signature synchronously (issue #126).
        self.correlate(&event);
        match &event {
            Event::Exec(e) => self.detect_exec(e),
            Event::FileOpen(e) => self.detect_file_open(e),
            Event::Connect(e) => self.detect_connect(e),
            Event::NetworkFlow(e) => self.detect_network_flow(e),
            Event::ListenPort(e) => self.detect_listen_port(e),
            Event::Auth(e) => self.detect_auth(e),
            Event::FileDelete(e) => self.detect_file_delete(e),
            Event::Signal(e) => self.detect_signal(e),
            Event::FileQuarantine(e) => self.detect_file_quarantine(e),
            Event::FileRename(e) => self.detect_file_rename(e),
            // New telemetry categories reach the engines as they land; until a rule
            // consumes them, logging below is the whole treatment.
            _ => {}
        }
        // Enrichment + the high-volume raw-event write happen off this thread.
        self.enrich_queue.enqueue(event);
        // Last: only counts as "progress" once everything above has actually
        // completed for this event (#102) — a hang anywhere above (a poisoned
        // lock, a wedged Sigma/YARA call) stops the heartbeat from advancing.
        self.progress.fetch_add(1, Ordering::Relaxed);
    }
}

// ── BaselineSink ──────────────────────────────────────────────────────────────

/// Minimal sink for ML baseline capture: records the exec events that trigger NO
/// deterministic rule — the "known benign under current rules" corpus consumed by
/// `synthaea_ml` training. Migrated from the old agent's `BaselineSink`, now
/// platform-neutral (any sensor speaking the contract feeds it).
pub(crate) struct BaselineSink {
    rule_state: Mutex<rules::RuleState>,
    out: JsonlWriter,
    count: std::sync::atomic::AtomicU64,
}

/// One baseline record — the format `synthaea_ml` training consumes.
///
/// `argv` is the canonical form: the training side joins it with NUL exactly as
/// [`schema::ExecEvent::ml_cmdline`] does, so the model trains on the vectors the
/// agent will score. `cmdline` is kept alongside it for human inspection of the
/// capture and as the documented fallback when `argv` is empty (Windows/ETW).
#[derive(serde::Serialize)]
struct BaselineRecord<'a> {
    argv: &'a [String],
    cmdline: &'a str,
}

impl BaselineSink {
    pub(crate) fn new(
        rule_state: rules::RuleState,
        output: &std::path::Path,
    ) -> std::io::Result<Self> {
        Ok(Self {
            rule_state: Mutex::new(rule_state),
            out: JsonlWriter::open(output)?,
            count: std::sync::atomic::AtomicU64::new(0),
        })
    }
}

impl EventSink for BaselineSink {
    fn on_event(&self, event: Event) {
        match &event {
            Event::Exec(e) => {
                // Evaluate the deterministic rules — alerting cmdlines are excluded
                // from the baseline (they are exactly what the model must not learn
                // as normal).
                let det_alerts = rules::evaluate_exec(e);
                let state_alerts = self.rule_state.lock().unwrap().on_exec(e);
                if !det_alerts.is_empty() || !state_alerts.is_empty() {
                    return;
                }
                self.out.write(&BaselineRecord {
                    argv: &e.argv,
                    cmdline: &e.cmdline,
                });
                let n = self
                    .count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    + 1;
                if n.is_multiple_of(10) {
                    eprintln!("[baseline] {n} cmdlines captured...");
                }
            }
            // File events feed the stateful rules' history (download tracking) so
            // exclusion decisions stay accurate; connects are irrelevant here.
            Event::FileOpen(e) => {
                self.rule_state.lock().unwrap().on_file_open(e);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex, atomic::Ordering};

    use schema::{ConnectEvent, Event, EventMeta, ExecEvent, User, sensor::EventSink as _};

    use super::DetectionSink;

    fn tmp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sink-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sink_in(dir: &std::path::Path) -> Arc<DetectionSink> {
        Arc::new(
            DetectionSink::new(
                rules::RuleState::new(),
                &dir.join("alerts.ndjson"),
                &dir.join("events.jsonl"),
                None,
            )
            .unwrap(),
        )
    }

    fn alerts_in(dir: &std::path::Path) -> String {
        std::fs::read_to_string(dir.join("alerts.ndjson")).unwrap_or_default()
    }

    fn exec(pid: u32, cmdline: &str, image_path: &str) -> Event {
        Event::Exec(ExecEvent {
            meta: EventMeta {
                pid,
                ppid: 1,
                user: User::Unix {
                    uid: 1000,
                    gid: 1000,
                },
                comm: "bash".into(),
                ..schema::fixtures::meta()
            },
            image_path: image_path.into(),
            cmdline: cmdline.into(),
            ..schema::fixtures::exec()
        })
    }

    /// The BAYES recipe from `correlator`'s own tests: a suspicious-path exec
    /// plus repeated connects to a public address crosses the belief threshold.
    fn drive_bayes_crossing(sink: &DetectionSink, pid: u32) {
        sink.on_event(exec(
            pid,
            "malware.exe",
            "C:\\Users\\solka\\AppData\\Roaming\\malware.exe",
        ));
        for i in 0..25u64 {
            sink.on_event(Event::Connect(ConnectEvent {
                meta: EventMeta {
                    pid,
                    timestamp_ns: (i + 1) * 100_000_000,
                    ..schema::fixtures::meta()
                },
                daddr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(185, 220, 101, 1)),
                dport: 4444,
            }));
        }
    }

    #[test]
    fn exec_rule_alert_reaches_the_alert_log() {
        let dir = tmp("rule-alert");
        let sink = sink_in(&dir);
        sink.on_event(exec(
            42,
            "bash -c echo cGF5bG9hZAo= | base64 -d | sh",
            "/bin/bash",
        ));
        let alerts = alerts_in(&dir);
        assert!(
            alerts.contains("T1059.004"),
            "base64-decode rule must land in alerts.ndjson, got: {alerts}"
        );
    }

    #[test]
    fn progress_advances_once_per_fully_processed_event() {
        let dir = tmp("progress");
        let sink = sink_in(&dir);
        let progress = sink.progress_handle();
        assert_eq!(progress.load(Ordering::Relaxed), 0);
        for i in 0..5 {
            sink.on_event(exec(100 + i, "ls", "/bin/ls"));
        }
        assert_eq!(
            progress.load(Ordering::Relaxed),
            5,
            "#102: real progress, one per event"
        );
    }

    #[test]
    fn bayes_crossing_without_response_hooks_alerts_but_never_kills() {
        let dir = tmp("bayes-observe");
        let sink = sink_in(&dir);
        drive_bayes_crossing(&sink, 4242);
        let alerts = alerts_in(&dir);
        assert!(
            alerts.contains("BAYES"),
            "belief crossing must alert: {alerts}"
        );
        assert!(
            !alerts.contains("RESPONSE-KILL"),
            "no enable_response call means response stays entirely silent"
        );
    }

    #[test]
    fn bayes_crossing_with_kill_disabled_reports_observe_only() {
        let dir = tmp("bayes-disabled");
        let sink = sink_in(&dir);
        let killed = Arc::new(Mutex::new(Vec::new()));
        let killed_rec = Arc::clone(&killed);
        sink.enable_response(
            policy::ResponsePolicy {
                kill_enabled: false,
                quarantine_enabled: false,
            },
            move |pid| {
                killed_rec.lock().unwrap().push(pid);
                Ok(())
            },
            dir.join("quarantine"),
        );
        drive_bayes_crossing(&sink, 4243);
        let alerts = alerts_in(&dir);
        assert!(
            alerts.contains("RESPONSE-KILL"),
            "response path must report: {alerts}"
        );
        assert!(
            alerts.contains("observe-only"),
            "policy-off means observe-only: {alerts}"
        );
        assert!(
            killed.lock().unwrap().is_empty(),
            "terminate must never run with kill disabled"
        );
    }

    #[test]
    fn bayes_crossing_with_kill_enabled_calls_terminate_on_the_verdict_pid() {
        let dir = tmp("bayes-kill");
        let sink = sink_in(&dir);
        let killed = Arc::new(Mutex::new(Vec::new()));
        let killed_rec = Arc::clone(&killed);
        sink.enable_response(
            policy::ResponsePolicy {
                kill_enabled: true,
                quarantine_enabled: false,
            },
            move |pid| {
                killed_rec.lock().unwrap().push(pid);
                Ok(())
            },
            dir.join("quarantine"),
        );
        drive_bayes_crossing(&sink, 4244);
        let alerts = alerts_in(&dir);
        assert!(
            alerts.contains("killed pid 4244"),
            "kill outcome must be recorded in alerts: {alerts}"
        );
        assert_eq!(
            *killed.lock().unwrap(),
            vec![4244],
            "the injected terminate runs, exactly once"
        );
    }

    #[test]
    fn events_and_spool_receive_the_raw_event_via_the_enrich_worker() {
        let dir = tmp("spool");
        let spool_dir = dir.join("spool");
        let spool = Arc::new(Mutex::new(
            store::EventSpool::open(&spool_dir, u64::MAX).unwrap(),
        ));
        let sink = Arc::new(
            DetectionSink::new(
                rules::RuleState::new(),
                &dir.join("alerts.ndjson"),
                &dir.join("events.jsonl"),
                Some(Arc::clone(&spool)),
            )
            .unwrap(),
        );
        sink.on_event(exec(7, "ls", "/bin/ls"));

        // The raw write and the spool append run on the enrich worker — wait.
        let mut spooled: Vec<Event> = Vec::new();
        for _ in 0..200 {
            spooled = spool.lock().unwrap().drain_oldest().unwrap();
            if !spooled.is_empty() {
                break;
            }
            // Segment may be in-flight from the empty drain — put it back.
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(spooled.len(), 1, "the event must reach the transport spool");
        let events_log = std::fs::read_to_string(dir.join("events.jsonl")).unwrap_or_default();
        assert!(
            events_log.contains("/bin/ls"),
            "raw event log written off-thread"
        );
    }

    /// A counting sink for wiring tests elsewhere would go through `EventSink`;
    /// this pins that `DetectionSink` is object-safe behind the same trait the
    /// sensors use (compile-time check, the assertion is incidental).
    #[test]
    fn detection_sink_is_usable_as_a_trait_object() {
        let dir = tmp("dyn");
        let sink: Arc<dyn schema::sensor::EventSink> = sink_in(&dir);
        sink.on_event(exec(9, "true", "/bin/true"));
    }
}
