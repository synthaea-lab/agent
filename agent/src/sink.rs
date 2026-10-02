//! The agent's concrete `EventSink`s: full detection (`DetectionSink`) and raw
//! capture (re-using `sinks::JsonlEventSink` directly). Migrated from
//! `old/agent/sinks.rs`, minus what isn't wired yet — the correlator, Sigma, and ML
//! scorer plug in here as their crates are migrated (M2), each addition a new field
//! and a few lines in `on_event`.

use std::{
    path::{Path, PathBuf},
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
    /// Sigma rules from `<content_root>/rules/sigma` when the folder exists —
    /// otherwise the agent runs without a Sigma engine, and that is not an
    /// error (the load failure path IS an error: content present but
    /// broken). `Mutex`-wrapped (issue #30): `reload_content` swaps in a
    /// freshly loaded engine while the agent keeps running, the same reason
    /// every other mutable field on this struct is a `Mutex`.
    sigma: Mutex<Option<sigma::SigmaEngine>>,
    /// The single alert funnel (issue #388): alerts.ndjson + stderr + the
    /// in-memory recent-alerts buffer served to `cli detections`. Shared with
    /// the YARA scan worker and quarantine.
    alert_log: Arc<AlertLog>,
    /// Budgeted background content scanning; `None` when
    /// `<content_root>/rules/yara` is absent. `Mutex`-wrapped for the same
    /// reload reason as `sigma`.
    yara: Mutex<Option<(yara::ScanQueue, usize)>>,
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
    /// Issue #131: cross-engine verdict fusion, keyed the same way the correlator
    /// keys its own belief state (`(ppid, comm)` — see `verdict::EntityKey`). Every
    /// rule/Sigma/correlator finding folds in here alongside reaching the alert
    /// log, giving each entity a bounded, composed evidence trail — but the kill
    /// gate (`correlate`'s `maybe_kill`) deliberately does *not* read this fused,
    /// sticky state: it stays scoped to the triggering event's own evidence (PR
    /// #502 review — the entity's composed severity is a max over everything
    /// ever seen for `(ppid, comm)`, too coarse and too sticky to gate a
    /// destructive action on). YARA matches are folded in too (#614): the scan
    /// request carries the writing process's `(ppid, comm)` through the queue's
    /// settle delay ([`yara::ScanContext`]), and the match is keyed to the same
    /// entity as the rule alerts on it.
    verdict: Arc<Mutex<verdict::VerdictEngine>>,
    /// Resolved once at construction ([`resolve_content_root`]) and reused
    /// by every `reload_content` call — the exe/cwd resolution reflects
    /// where the process actually started, which does not change at
    /// runtime, so re-resolving on every reload would add nothing but a
    /// syscall.
    content_root: PathBuf,
}

/// The verdict entity an event belongs to: `(ppid, comm)` plus the incarnation of the
/// parent when the sensor stamped one, so a recycled parent pid does not join the
/// previous parent's entity (#592).
fn entity_key(meta: &schema::EventMeta) -> verdict::EntityKey {
    verdict::EntityKey::new(meta.ppid, meta.comm.clone())
        .with_parent_generation(meta.parent_process_generation)
}

/// The escalation decision (#612) as a free function so the YARA scan worker, which
/// has no `DetectionSink`, raises the same alert as every other engine (#614).
fn escalate_if_warranted(alert_log: &AlertLog, fused: &verdict::Verdict) {
    if !response::should_escalate(fused.severity) {
        return;
    }
    let message = format!(
        "escalated {}:{} at {:?} severity across {} source(s): {}",
        fused.entity.ppid,
        fused.entity.comm,
        fused.severity,
        fused.sources.len(),
        fused.techniques.join(", ")
    );
    alert_log.record("RESPONSE-ESCALATE", message);
}

/// The `case_id` of a correlator finding: `{ppid}:{comm}`, with `@{generation}` of the
/// parent appended when it is known, so two incarnations of a recycled parent pid do not
/// share one case. The server treats it as an opaque string.
fn correlator_case_id(entity: &verdict::EntityKey) -> String {
    match entity.parent_generation {
        Some(generation) => format!("{}:{}@{generation}", entity.ppid, entity.comm),
        None => format!("{}:{}", entity.ppid, entity.comm),
    }
}

/// How long a technique already recorded for an entity stays "the same finding":
/// a second engine (or the same engine again) reporting it inside this window
/// folds in silently instead of producing a second alert. Matches the
/// ransomware-detection window's order of magnitude (`crates/rules/src/
/// exclusions.rs`'s `RANSOMWARE_RENAME_WINDOW_NS`) — long enough to absorb
/// ordinary cross-engine timing skew (Sigma/rules run inline, the correlator
/// reacts to the same event a few lines later), short enough that a genuine
/// second occurrence of the same technique still gets its own finding.
const VERDICT_DEDUP_WINDOW_NS: u64 = 30_000_000_000; // 30s

/// Whether an alert raised by the correlator makes its process eligible for
/// `response`'s kill (issue #25). Deliberately its own question, not "severity is
/// `Critical`": a Sigma rule's `level: critical` is an analyst-facing ranking
/// written by a rule author, not a belief the correlator has earned, and a
/// severity that merely feeds the verdict must never widen what the agent kills
/// (issue #131 follow-up). Only the correlator's belief crossing its threshold
/// qualifies. (`BAYES` also carries `Critical` severity, but that is a coincidence
/// of the ranking, not what gates the kill.)
fn crosses_kill_gate(technique: &str) -> bool {
    technique == "BAYES"
}

/// ATT&CK technique ids folded into a [`schema::detection::Detection`] from the
/// `technique` string this crate already uses as the dedup/alert-log key.
/// Same convention `tools/attack-coverage.py` uses to build the coverage doc:
/// a single alert can carry more than one id joined with `/` (a beacon flagged
/// both C2 and exfiltration, say) — split back out here. `BAYES` (the
/// correlator's belief-crossing sentinel) and Sigma's untagged `"Sigma"`
/// fallback (`detect_exec`, when a hit carries no `attack.tXXXX` tag) are not
/// real ATT&CK ids and fold to an empty list, same as
/// `tools/attack-coverage.py`'s own `BAYES_SENTINEL` skip.
fn techniques_from(technique: &str) -> Vec<String> {
    if technique == "BAYES" || technique == "Sigma" {
        Vec::new()
    } else {
        technique.split('/').map(str::to_string).collect()
    }
}

/// Where the agent looks for ML model families first: under the state directory,
/// like the content and the updater's files, not the process's working directory
/// (#559). Lab runs and source checkouts keep working through the relative
/// `ml/registry` fallback in [`DetectionSink::load_correlation_scorer`].
pub(crate) fn model_root(state_dir: &Path) -> std::path::PathBuf {
    state_dir.join("ml").join("registry")
}

/// The version directory of `family` under the first of `roots` that holds a
/// `model.onnx`. When none does, the first root's directory: it is the one the
/// "scorer unavailable" warning should name, where an operator would put the model.
fn locate_model_dir(roots: &[&Path], family: &str) -> std::path::PathBuf {
    let dirs: Vec<std::path::PathBuf> = roots
        .iter()
        .map(|root| root.join(family).join("0.1.0"))
        .collect();
    dirs.iter()
        .find(|dir| dir.join("model.onnx").is_file())
        .unwrap_or(&dirs[0])
        .clone()
}

impl DetectionSink {
    /// `rule_state` arrives already seeded by the caller (from /proc or the
    /// platform's process list — see `commands`). `spool` is the transport
    /// spool (`run --server`), `None` when the agent runs standalone.
    /// `content_dir` is where `agent apply-content-manifest --content-dir`
    /// writes downloaded content (issue #30) — resolved once here via
    /// [`resolve_content_root`] and reused by every later `reload_content`
    /// call, so the two commands agree on one directory instead of the
    /// agent loading from a different, hardcoded location than the one
    /// content was actually applied to.
    pub(crate) fn new(
        rule_state: rules::RuleState,
        alerts_path: &std::path::Path,
        events_path: Option<&std::path::Path>,
        spool: Option<Arc<Mutex<store::EventSpool>>>,
        content_dir: &Path,
        model_root: &Path,
    ) -> std::io::Result<Self> {
        let alert_log = Arc::new(AlertLog::open(alerts_path, RECENT_ALERTS_CAPACITY)?);
        let content_root = resolve_content_root(content_dir);
        // The raw event log is written by the enrichment worker, not the drain
        // thread — shared behind an Arc so the worker owns a handle. The spool
        // append rides the same worker for the same #126 reason: it is file
        // I/O that must never stall the capture thread.
        // `None` (the default, and what the packaged service runs) writes no raw
        // capture at all: it grows without bound and only labs and ML calibration
        // want it (#559).
        let events_log = events_path
            .map(|path| JsonlWriter::open(path).map(Arc::new))
            .transpose()?;
        let enrich_queue = EnrichQueue::start(enrich::Enricher::new(), move |event| {
            if let Some(events_log) = &events_log {
                events_log.write(&event);
            }
            if let Some(spool) = &spool
                && let Err(e) = spool.lock().unwrap().push(&event)
            {
                // Spool full is handled inside push (shed-oldest, counted);
                // reaching here is a real I/O failure — degrade to local-only.
                tracing::warn!(error = %e, "spool append failed — event stays local-only");
            }
        });
        let response: Arc<Mutex<Option<ResponseHooks>>> = Arc::new(Mutex::new(None));
        let verdict = Arc::new(Mutex::new(verdict::VerdictEngine::new(
            VERDICT_DEDUP_WINDOW_NS,
        )));
        Ok(Self {
            rule_state: Mutex::new(rule_state),
            correlator: Mutex::new(correlator::CorrelationEngine::new()),
            ml_scorer: Mutex::new(Self::load_correlation_scorer(model_root)),
            sigma: Mutex::new(load_sigma_rules(&content_root).into_option()),
            yara: Mutex::new(
                start_yara(
                    &content_root,
                    alert_log.clone(),
                    response.clone(),
                    verdict.clone(),
                )
                .into_option(),
            ),
            alert_log,
            enrich_queue,
            progress: Arc::new(AtomicU64::new(0)),
            response,
            verdict,
            content_root,
        })
    }

    /// Re-reads Sigma/YARA content from [`Self::content_root`] and swaps it
    /// into the running pipeline (issue #30, IPC `ReloadContent`) — the way
    /// content `agent apply-content-manifest` just downloaded and verified
    /// takes effect without restarting the agent.
    ///
    /// An *absent* content subdirectory unloads that engine (same "not an
    /// error" posture startup has always had). A present-but-*broken* one
    /// keeps the previous engine running and is reported as failed: a bad
    /// rule file must never leave a live agent without that engine, which
    /// startup can afford (nothing was protecting yet) and a reload cannot.
    /// Note the asymmetry in the engines' own loaders: YARA fails the whole
    /// set on one bad rule, while Sigma skips (and warns about) an individual
    /// bad rule, so a partly broken Sigma set loads *fewer* rules and is only
    /// visible through the reported count.
    pub(crate) fn reload_content(&self) -> ReloadReport {
        // Parse/compile first, lock only for the swap: `on_event` takes these
        // locks on the capture thread for every exec and write-open, so loading
        // under them would stall capture for the whole load, which grows with
        // the rule set (PR #531 review).
        let sigma_loaded = load_sigma_rules(&self.content_root);
        let yara_loaded = start_yara(
            &self.content_root,
            self.alert_log.clone(),
            self.response.clone(),
            self.verdict.clone(),
        );

        // The replaced engines are dropped after the locks are released: a
        // `ScanQueue` joins its worker on drop, which must not stall capture.
        let mut sigma_slot = self.sigma.lock().unwrap();
        let (sigma_reload_failed, old_sigma) = match sigma_loaded {
            Load::Loaded(engine) => (false, sigma_slot.replace(engine)),
            Load::Absent => (false, sigma_slot.take()),
            Load::Failed => (true, None),
        };
        let sigma_rule_count = sigma_slot.as_ref().map(sigma::SigmaEngine::rule_count);
        drop(sigma_slot);
        drop(old_sigma);

        let mut yara_slot = self.yara.lock().unwrap();
        let (yara_reload_failed, old_yara) = match yara_loaded {
            Load::Loaded(loaded) => (false, yara_slot.replace(loaded)),
            Load::Absent => (false, yara_slot.take()),
            Load::Failed => (true, None),
        };
        let yara_rule_count = yara_slot.as_ref().map(|(_, count)| *count);
        drop(yara_slot);
        drop(old_yara);

        ReloadReport {
            sigma_rule_count,
            yara_rule_count,
            sigma_reload_failed,
            yara_reload_failed,
        }
    }

    /// Loads the ML correlation scorer from the registry (issue #46 Phase 3, #47 Phase 2).
    ///
    /// Returns `None` when the model is unavailable (missing directory, load error) —
    /// the agent works without ML (hand-calibrated Bayesian features still function).
    /// Logs a warning on load failure so the operator sees the degradation.
    ///
    /// Model location: `<model_root>/correlation-iforest-{linux,windows,macos}/0.1.0/`,
    /// where `model_root` is [`model_root`] (`<state_dir>/ml/registry`), then the
    /// relative `ml/registry` of the current working directory, which is where a
    /// source checkout (lab, ML calibration) keeps it. A packaged service has no
    /// useful working directory, so the first location is the one it can rely on.
    fn load_correlation_scorer(model_root: &Path) -> Option<ml::CorrelationScorer> {
        /// Platform-specific model family names.
        #[cfg(target_os = "linux")]
        const MODEL_FAMILY: &str = "correlation-iforest-linux";
        #[cfg(target_os = "windows")]
        const MODEL_FAMILY: &str = "correlation-iforest-windows";
        #[cfg(target_os = "macos")]
        const MODEL_FAMILY: &str = "correlation-iforest-macos";

        let model_dir = locate_model_dir(&[model_root, Path::new("ml/registry")], MODEL_FAMILY);

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

    /// Folds one engine's finding into the fused per-entity verdict (issue #131)
    /// and always writes it to the alert log — `alerts.ndjson` is the audit
    /// trail (`EVIDENCE_CAP`'s own doc: every finding lands there), and verdict
    /// fusion's dedup is a separate, deliberately lossy view for live triage
    /// (bounded evidence, kill-gate severity), not a substitute for it. A
    /// finding verdict fusion absorbs as a duplicate (same technique, another
    /// engine or a repeat, inside `VERDICT_DEDUP_WINDOW_NS`) still gets its own
    /// alert line, it just doesn't produce a new [`verdict::Verdict`] snapshot.
    /// Returns the fused verdict whenever one was produced, for a caller that
    /// needs the entity's overall composed state (e.g. its evidence list) —
    /// **not** for kill-gating: `correlate`'s kill gate reads this event's own
    /// detection severity instead, deliberately not the entity's sticky
    /// accumulated one (PR #502 review).
    fn record_and_emit(
        &self,
        entity: &verdict::EntityKey,
        technique: &str,
        message: &str,
        source: schema::detection::DetectionSource,
        severity: schema::detection::Severity,
        event: &Event,
    ) -> Option<verdict::Verdict> {
        let now_ns = event.meta().timestamp_ns;
        let detection = schema::detection::Detection {
            timestamp_ns: now_ns,
            severity,
            title: message.to_string(),
            source,
            score: None,
            attributions: Vec::new(),
            techniques: techniques_from(technique),
            events: vec![event.clone()],
        };
        let result =
            self.verdict
                .lock()
                .unwrap()
                .record(entity.clone(), technique, detection, now_ns);
        self.emit(technique, message);
        if let Some(fused) = &result {
            self.maybe_escalate(fused);
        }
        result
    }

    /// Issue #612: the first response decision to read the fused verdict. A new
    /// verdict snapshot (first sighting, a severity raise, or a recurrence outside
    /// the dedup window — never a silently absorbed duplicate) whose composed
    /// severity warrants it raises one `RESPONSE-ESCALATE` audit alert. Never
    /// kills or quarantines, and works with or without `enable_response`.
    fn maybe_escalate(&self, fused: &verdict::Verdict) {
        escalate_if_warranted(&self.alert_log, fused);
    }

    /// [`Self::record_and_emit`] for a batch of plain `rules::Alert`s (no Sigma/
    /// correlator-specific `DetectionSource` needed) — the common case for every
    /// `rule_state`/`rules::evaluate_*` call site.
    fn record_rule_alerts(&self, event: &Event, alerts: impl IntoIterator<Item = rules::Alert>) {
        let meta = event.meta();
        let entity = entity_key(meta);
        for alert in alerts {
            let source = schema::detection::DetectionSource::Rule {
                rule_id: alert.technique.to_string(),
            };
            self.record_and_emit(
                &entity,
                alert.technique,
                &alert.message,
                source,
                alert.severity,
                event,
            );
        }
    }

    /// Cross-event correlation (co-occurrence rules + Bayesian belief).
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
        let generation = event.meta().process_generation;
        if let Some(ref mut scorer) = *self.ml_scorer.lock().unwrap() {
            let ml_llr = match scorer.score(engine.bus(), pid, generation) {
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
            if let Err(()) = engine.update_belief_with_ml(pid, generation, ml_llr) {
                // No behavior vector available yet for this pid — not enough events.
                // Silent: this is normal for the first few events of a new pid.
            }
        }

        drop(engine); // Unlock correlator before alert emission (log I/O).

        // Fold co-occurrence rules and Bayesian belief into the entity's fused
        // verdict (issue #131) for evidence/severity bookkeeping. The kill gate
        // itself stays scoped to *this event's own* evidence — whether the alert
        // actually raised here crosses it ([`crosses_kill_gate`], the pre-#131 bare
        // `technique == "BAYES"` check) — not the entity's fused, sticky
        // severity: that's a max over everything ever seen for `(ppid, comm)`,
        // so gating kill on it would let one sibling process's Bayes crossing
        // condemn every later, unrelated sibling that merely shares the same
        // parent and `comm` (PR #502 review; pinned by
        // `a_siblings_weak_alert_never_triggers_kill_from_anothers_bayes_crossing`).
        let meta = event.meta();
        let entity = entity_key(meta);
        let case_id = correlator_case_id(&entity);
        let mut is_high_confidence = false;
        for alert in &alerts {
            let source = schema::detection::DetectionSource::Correlator {
                case_id: case_id.clone(),
            };
            self.record_and_emit(
                &entity,
                alert.technique,
                &alert.message,
                source,
                alert.severity,
                event,
            );
            if crosses_kill_gate(alert.technique) {
                is_high_confidence = true;
            }
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
            response::KillOutcome::Refused { pid, reason } => {
                format!(
                    "refused to kill pid {pid} on a high-confidence correlated verdict: {reason}"
                )
            }
        };
        self.emit("RESPONSE-KILL", &message);
    }

    /// Exec events: stateless rules, stateful rules, then Sigma.
    fn detect_exec(&self, wrapped: &Event, event: &schema::ExecEvent) {
        self.record_rule_alerts(wrapped, rules::evaluate_exec(event));
        self.record_rule_alerts(wrapped, self.rule_state.lock().unwrap().on_exec(event));
        let sigma_guard = self.sigma.lock().unwrap();
        if let Some(sigma) = sigma_guard.as_ref() {
            let entity = entity_key(&event.meta);
            for hit in sigma.eval_exec(event) {
                let technique = if hit.tags.is_empty() {
                    "Sigma".to_string()
                } else {
                    hit.tags.join("/")
                };
                let source = schema::detection::DetectionSource::Sigma {
                    rule_id: hit.title.clone(),
                };
                self.record_and_emit(
                    &entity,
                    &technique,
                    &hit.title,
                    source,
                    hit.severity,
                    wrapped,
                );
            }
        }
    }

    /// `FileOpen` events: stateless rules, downloader-write history, and the
    /// budgeted YARA queue on write intent (off the event path).
    fn detect_file_open(&self, wrapped: &Event, event: &schema::FileOpenEvent) {
        let state_alerts = self.rule_state.lock().unwrap().on_file_open(event);
        self.record_rule_alerts(
            wrapped,
            rules::evaluate_file_open(event)
                .into_iter()
                .chain(state_alerts),
        );
        if event.flags & 0o103 != 0
            && let Some((yara, _)) = self.yara.lock().unwrap().as_ref()
        {
            let meta = wrapped.meta();
            yara.enqueue_for(
                std::path::PathBuf::from(&event.path),
                yara::ScanContext {
                    ppid: meta.ppid,
                    comm: meta.comm.clone(),
                    parent_generation: meta.parent_process_generation,
                    timestamp_ns: meta.timestamp_ns,
                },
            );
        }
    }

    /// `FileQuarantine` events (macOS quarantine xattr, Windows
    /// `Zone.Identifier`): recorded for the T1204.002 download→exec join, no
    /// alert on their own (#365).
    fn detect_file_quarantine(&self, event: &schema::FileQuarantineEvent) {
        self.rule_state.lock().unwrap().on_file_quarantine(event);
    }

    /// Connect events: stateless rules (unusual outbound from a web/DB
    /// service, issue #478), then beacon detection.
    fn detect_connect(&self, wrapped: &Event, event: &schema::ConnectEvent) {
        self.record_rule_alerts(wrapped, rules::evaluate_connect(event));
        self.record_rule_alerts(wrapped, self.rule_state.lock().unwrap().on_connect(event));
    }

    /// `NetworkFlow` events (conntrack polling, issue #92): same beacon detection as
    /// `detect_connect`, deduped per-flow so a poll-based source doesn't
    /// false-positive on one ordinary long-lived connection.
    fn detect_network_flow(&self, wrapped: &Event, event: &schema::NetworkFlowEvent) {
        self.record_rule_alerts(
            wrapped,
            self.rule_state.lock().unwrap().on_network_flow(event),
        );
    }

    /// `ListenPort` events (`sock_diag` polling, issue #92): LISTENER-DRIFT.
    fn detect_listen_port(&self, wrapped: &Event, event: &schema::ListenPortEvent) {
        self.record_rule_alerts(
            wrapped,
            self.rule_state.lock().unwrap().on_listen_port(event),
        );
    }

    /// `Auth` events: brute-force/spray burst detection (T1110, pack #377).
    fn detect_auth(&self, wrapped: &Event, event: &schema::AuthEvent) {
        self.record_rule_alerts(wrapped, self.rule_state.lock().unwrap().on_auth(event));
    }

    /// `FileDelete` events: log-tamper detection (T1070.001/.002, pack #379), then the
    /// unlink half of the write-new-then-unlink T1486 shape (#512 part B), which needs
    /// the creation history `on_file_open` keeps.
    fn detect_file_delete(&self, wrapped: &Event, event: &schema::FileDeleteEvent) {
        self.record_rule_alerts(wrapped, rules::evaluate_file_delete(event));
        self.record_rule_alerts(
            wrapped,
            self.rule_state.lock().unwrap().on_file_delete(event),
        );
    }

    /// `Signal` events: security-process tampering (T1562.001, issue #362).
    fn detect_signal(&self, wrapped: &Event, event: &schema::SignalEvent) {
        self.record_rule_alerts(wrapped, rules::evaluate_signal(event));
    }

    /// `FileRename` events: mass-rename ransomware detection (T1486, issue #262) +
    /// write-volume corroboration (issue #82).
    fn detect_file_rename(&self, wrapped: &Event, event: &schema::FileRenameEvent) {
        self.record_rule_alerts(
            wrapped,
            self.rule_state.lock().unwrap().on_file_rename(event),
        );
    }

    /// `FileWrite` events: no alert on their own — tracks per-pid write volume for
    /// the ransomware write-volume corroboration signal (T1486, issue #82),
    /// consumed on the next `FileRename`.
    fn detect_file_write(&self, event: &schema::FileWriteEvent) {
        self.rule_state.lock().unwrap().on_file_write(event);
    }

    /// `MemfdCreate` events (Linux, issue #265): usually no alert on its own —
    /// tracks per-pid memfd-creation history consumed by the memfd-exec
    /// signal (T1620, issue #497) on a later `Exec`. Can still emit directly
    /// when a matching `/proc/.../fd/<n>` exec was already seen and is
    /// waiting on this corroborating evidence (#503 review: the two ring
    /// buffers can deliver out of order even though the kernel always
    /// creates the memfd before executing it).
    fn detect_memfd_create(&self, event: &schema::MemfdCreateEvent) {
        for alert in self.rule_state.lock().unwrap().on_memfd_create(event) {
            self.emit(alert.technique, &alert.message);
        }
    }

    /// `AmsiContent` events (Windows, #282): the de-obfuscated buffer a
    /// runtime hands to AMSI — download cradles, AMSI tampering, reflective
    /// loads, credential-dumping modules, script hosts launching interpreters.
    fn detect_amsi_content(&self, wrapped: &Event, event: &schema::AmsiContentEvent) {
        self.record_rule_alerts(wrapped, rules::evaluate_amsi_content(event));
    }

    /// `LdapSearch` events (Windows, #364): roasting / privilege / trust /
    /// stored-password searches, then the enumeration-sweep burst.
    fn detect_ldap_search(&self, wrapped: &Event, event: &schema::LdapSearchEvent) {
        self.record_rule_alerts(wrapped, rules::evaluate_ldap_search(event));
        self.record_rule_alerts(
            wrapped,
            self.rule_state.lock().unwrap().on_ldap_search(event),
        );
    }

    /// Writes one alert to the shared log and highlighted stderr. `pub(crate)`
    /// rather than private: `silence::spawn_monitor` (#71) emits a sensor-silence
    /// verdict through the exact same path as a rule/correlator/Sigma finding —
    /// one alert shape, whatever detected it.
    pub(crate) fn emit(&self, technique: &str, message: &str) {
        self.alert_log.record(technique, message.to_string());
    }

    /// Issue #613: an operator's request to silence `technique` on the entity
    /// `(ppid, comm)` in the fused verdict. Returns whether the mark is new.
    /// Audited as `VERDICT-SUPPRESS` in the alert log, which itself keeps every
    /// finding: this only changes what the fused view (and so escalation) sees.
    ///
    /// # Errors
    ///
    /// An empty `comm` or `technique` (it could never match a finding), or the
    /// suppression list being full ([`verdict::MAX_SUPPRESSIONS`]).
    pub(crate) fn suppress_verdict(
        &self,
        ppid: u32,
        comm: &str,
        technique: &str,
    ) -> Result<bool, String> {
        if comm.is_empty() || technique.is_empty() {
            return Err("comm and technique must not be empty".to_string());
        }
        let outcome = self
            .verdict
            .lock()
            .unwrap()
            .suppress(verdict::EntityKey::new(ppid, comm), technique);
        match outcome {
            verdict::SuppressOutcome::Added => {
                self.emit(
                    "VERDICT-SUPPRESS",
                    &format!("suppressed {technique} on {ppid}:{comm} by operator request"),
                );
                Ok(true)
            }
            verdict::SuppressOutcome::AlreadySuppressed => Ok(false),
            verdict::SuppressOutcome::Full => Err(format!(
                "suppression list is full ({} entries): lift one first",
                verdict::MAX_SUPPRESSIONS
            )),
        }
    }

    /// Issue #613: lifts a suppression made with [`Self::suppress_verdict`].
    /// Returns whether one was removed; audited as `VERDICT-UNSUPPRESS`.
    pub(crate) fn unsuppress_verdict(&self, ppid: u32, comm: &str, technique: &str) -> bool {
        let removed = self
            .verdict
            .lock()
            .unwrap()
            .unsuppress(&verdict::EntityKey::new(ppid, comm), technique);
        if removed {
            self.emit(
                "VERDICT-UNSUPPRESS",
                &format!("lifted suppression of {technique} on {ppid}:{comm} by operator request"),
            );
        }
        removed
    }

    /// Every active verdict suppression as `(ppid, comm, technique)`, for the
    /// agent status (issue #613).
    pub(crate) fn suppressions(&self) -> Vec<(u32, String, String)> {
        self.verdict
            .lock()
            .unwrap()
            .suppressions()
            .into_iter()
            .map(|(entity, technique)| (entity.ppid, entity.comm, technique))
            .collect()
    }

    /// Handle to the alert funnel, for the IPC handler's `recent_detections`
    /// endpoint (issue #388).
    pub(crate) fn alert_log(&self) -> Arc<AlertLog> {
        Arc::clone(&self.alert_log)
    }
}

/// What [`DetectionSink::reload_content`] (and, indirectly, [`DetectionSink::new`])
/// reports about what's loaded after a (re)load.
pub(crate) struct ReloadReport {
    /// Rules loaded *after* the reload (the previous set if the reload failed).
    pub(crate) sigma_rule_count: Option<usize>,
    pub(crate) yara_rule_count: Option<usize>,
    /// The content was present but failed to load; the previous engine kept running.
    pub(crate) sigma_reload_failed: bool,
    pub(crate) yara_reload_failed: bool,
}

/// Outcome of loading one content directory.
enum Load<T> {
    /// The directory does not exist — not an error.
    Absent,
    Loaded(T),
    /// The directory exists but its content did not load (already logged).
    Failed,
}

impl<T> Load<T> {
    /// Startup posture: a broken directory leaves the engine unloaded.
    fn into_option(self) -> Option<T> {
        match self {
            Self::Loaded(value) => Some(value),
            Self::Absent | Self::Failed => None,
        }
    }
}

/// Resolves `content_dir` to an actual directory to load content from: next
/// to the agent executable first, then the current working directory, same
/// fallback order the old hardcoded `rules/sigma`/`rules/yara` convention
/// used. A cwd-relative path alone breaks under service managers (systemd
/// runs with cwd=/, Windows services in System32), which silently disabled
/// Sigma and YARA exactly in production deployments (review finding this
/// preserves). An absolute `content_dir` is used as-is — no fallback search
/// needed when the caller already gave an unambiguous path.
fn resolve_content_root(content_dir: &Path) -> PathBuf {
    if content_dir.is_absolute() {
        return content_dir.to_path_buf();
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join(content_dir);
        if candidate.is_dir() {
            return candidate;
        }
    }
    content_dir.to_path_buf()
}

/// Loads the Sigma content directory if present, under `content_root`.
fn load_sigma_rules(content_root: &Path) -> Load<sigma::SigmaEngine> {
    let rules_dir = content_root.join("rules/sigma");
    if !rules_dir.is_dir() {
        return Load::Absent;
    }
    match sigma::SigmaEngine::load_dir(&rules_dir) {
        Ok(engine) => {
            tracing::info!(rules = engine.rule_count(), "sigma: rules loaded");
            Load::Loaded(engine)
        }
        Err(e) => {
            tracing::error!(error = %e, "sigma: load error");
            Load::Failed
        }
    }
}

/// Loads `rules/yara` under `content_root` when present and starts the scan
/// worker, alongside the rule count for [`DetectionSink::reload_content`]'s
/// report (the count is only available before [`yara::RuleSet`] is consumed
/// by [`yara::ScanQueue::start`], so it has to travel out with the queue
/// rather than be queried from it afterward). Matches are emitted as alerts
/// by the worker thread through the shared alert log, and — issue #25 —
/// trigger quarantine of the matched file through `response`, whenever
/// `enable_response` set it.
fn start_yara(
    content_root: &Path,
    alert_log: Arc<AlertLog>,
    response: Arc<Mutex<Option<ResponseHooks>>>,
    verdict: Arc<Mutex<verdict::VerdictEngine>>,
) -> Load<(yara::ScanQueue, usize)> {
    let dir = content_root.join("rules/yara");
    if !dir.is_dir() {
        return Load::Absent;
    }
    match yara::RuleSet::load_dir(&dir) {
        Ok(rules) => {
            let rule_count = rules.rule_count();
            tracing::info!(rules = rule_count, "yara: rules loaded");
            let queue = yara::ScanQueue::start(rules, move |outcome| {
                let matched = !outcome.matches.is_empty();
                // Fuse before the alert lines below: the verdict is the state they
                // report on, and a reader waiting for the `YARA` line may look at it.
                let fused: Vec<verdict::Verdict> = outcome
                    .context
                    .iter()
                    .flat_map(|context| {
                        outcome
                            .matches
                            .iter()
                            .filter_map(|rule| fuse_yara_match(&verdict, context, rule))
                    })
                    .collect();
                for rule in &outcome.matches {
                    let message = format!(
                        "yara rule {} matched {}",
                        rule.identifier,
                        outcome.path.display()
                    );
                    alert_log.record("YARA", message);
                }
                for verdict in &fused {
                    escalate_if_warranted(&alert_log, verdict);
                }
                if matched {
                    quarantine_matched_payload(&response, &outcome.path, &alert_log);
                }
            });
            Load::Loaded((queue, rule_count))
        }
        Err(e) => {
            tracing::error!(error = %e, "yara: load error");
            Load::Failed
        }
    }
}

/// Issue #614: folds a YARA match into the verdict of the process that wrote the
/// scanned file, keyed by the rule's ATT&CK technique so the same behavior flagged
/// by a native rule or Sigma on that entity inside the dedup window stays one
/// finding. The match still gets its own `YARA` line in the alert log (the audit
/// trail); this is the fused, bounded view only. The detection is stamped with the
/// triggering event's timestamp, the clock the entity's other findings use.
fn fuse_yara_match(
    verdict: &Mutex<verdict::VerdictEngine>,
    context: &yara::ScanContext,
    rule: &yara::YaraMatch,
) -> Option<verdict::Verdict> {
    let detection = schema::detection::Detection {
        timestamp_ns: context.timestamp_ns,
        severity: rule.severity,
        title: format!("yara rule {} matched", rule.identifier),
        source: schema::detection::DetectionSource::Yara {
            rule_name: rule.identifier.clone(),
        },
        score: None,
        attributions: Vec::new(),
        techniques: techniques_from(&rule.technique),
        events: Vec::new(),
    };
    let entity = verdict::EntityKey::new(context.ppid, context.comm.clone())
        .with_parent_generation(context.parent_generation);
    verdict
        .lock()
        .unwrap()
        .record(entity, &rule.technique, detection, context.timestamp_ns)
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
            Event::Exec(e) => self.detect_exec(&event, e),
            Event::FileOpen(e) => self.detect_file_open(&event, e),
            Event::Connect(e) => self.detect_connect(&event, e),
            Event::NetworkFlow(e) => self.detect_network_flow(&event, e),
            Event::ListenPort(e) => self.detect_listen_port(&event, e),
            Event::Auth(e) => self.detect_auth(&event, e),
            Event::FileDelete(e) => self.detect_file_delete(&event, e),
            Event::Signal(e) => self.detect_signal(&event, e),
            Event::FileQuarantine(e) => self.detect_file_quarantine(e),
            Event::FileRename(e) => self.detect_file_rename(&event, e),
            Event::FileWrite(e) => self.detect_file_write(e),
            Event::MemfdCreate(e) => self.detect_memfd_create(e),
            Event::AmsiContent(e) => self.detect_amsi_content(&event, e),
            Event::LdapSearch(e) => self.detect_ldap_search(&event, e),
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

    use super::{DetectionSink, correlator_case_id, entity_key};

    #[test]
    fn the_verdict_entity_carries_the_parents_incarnation_when_stamped() {
        let mut meta = schema::fixtures::meta();
        meta.ppid = 50;
        meta.comm = "evil".into();
        assert_eq!(entity_key(&meta).parent_generation, None);
        meta.parent_process_generation = Some(7);
        let entity = entity_key(&meta);
        assert_eq!(entity.parent_generation, Some(7));
        assert_eq!((entity.ppid, entity.comm.as_str()), (50, "evil"));
    }

    #[test]
    fn the_correlator_case_id_names_the_parent_incarnation_only_when_known() {
        let plain = verdict::EntityKey::new(50, "evil");
        assert_eq!(correlator_case_id(&plain), "50:evil");
        let stamped = plain.with_parent_generation(Some(7));
        assert_eq!(correlator_case_id(&stamped), "50:evil@7");
    }

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
                Some(&dir.join("events.jsonl")),
                None,
                &dir.join("content"),
                &dir.join("ml-registry"),
            )
            .unwrap(),
        )
    }

    fn alerts_in(dir: &std::path::Path) -> String {
        std::fs::read_to_string(dir.join("alerts.ndjson")).unwrap_or_default()
    }

    /// Quarantine hooks + the alert log they audit into, over a real directory
    /// holding one payload. `terminate` is never reached on this path.
    fn quarantine_fixture(
        name: &str,
        quarantine_enabled: bool,
    ) -> (
        std::path::PathBuf,
        Mutex<Option<super::ResponseHooks>>,
        crate::alerts::AlertLog,
        std::path::PathBuf,
    ) {
        let dir = tmp(name);
        let payload = dir.join("payload.bin");
        std::fs::write(&payload, b"marker payload").unwrap();
        let hooks = super::ResponseHooks {
            policy: policy::ResponsePolicy {
                kill_enabled: false,
                quarantine_enabled,
            },
            terminate: Box::new(|_| panic!("quarantine never terminates")),
            quarantine_dir: dir.join("quarantine"),
        };
        let log = crate::alerts::AlertLog::open(&dir.join("alerts.ndjson"), 8).unwrap();
        (dir, Mutex::new(Some(hooks)), log, payload)
    }

    #[test]
    fn a_yara_match_with_quarantine_disabled_leaves_the_payload_and_says_observe_only() {
        let (dir, hooks, log, payload) = quarantine_fixture("quarantine-off", false);
        super::quarantine_matched_payload(&hooks, &payload, &log);
        assert!(payload.exists(), "policy off must never move the file");
        assert!(
            !dir.join("quarantine").exists(),
            "policy off must not even create the quarantine directory"
        );
        let alerts = alerts_in(&dir);
        assert!(alerts.contains("RESPONSE-QUARANTINE"), "{alerts}");
        assert!(alerts.contains("observe-only"), "{alerts}");
    }

    #[test]
    fn a_yara_match_with_quarantine_enabled_moves_the_payload_and_audits_it() {
        let (dir, hooks, log, payload) = quarantine_fixture("quarantine-on", true);
        super::quarantine_matched_payload(&hooks, &payload, &log);
        assert!(!payload.exists(), "the payload must be moved out of place");
        let moved: Vec<_> = std::fs::read_dir(dir.join("quarantine"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            moved.iter().any(|n| n.ends_with(".origin")),
            "the restore sidecar must exist: {moved:?}"
        );
        let alerts = alerts_in(&dir);
        assert!(alerts.contains("RESPONSE-QUARANTINE"), "{alerts}");
        assert!(alerts.contains("quarantined"), "{alerts}");
        // `alerts.ndjson` is JSON: a Windows path is written with doubled
        // backslashes, so compare the decoded message, not the raw text.
        let message = alerts
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find(|record| record["technique"] == "RESPONSE-QUARANTINE")
            .and_then(|record| record["message"].as_str().map(str::to_owned))
            .unwrap_or_else(|| panic!("no RESPONSE-QUARANTINE record: {alerts}"));
        assert!(
            message.contains(&payload.display().to_string()),
            "the audit line names the original path: {message}"
        );
    }

    /// The response chain through the real detection path, in-process: real
    /// correlator, real YARA queue and rule set, real filesystem; only the
    /// kernel-level `terminate` call is a recorder. The stream is the shape of
    /// `lab/scenarios/response.sh`: an implant that connects out quickly and keeps
    /// beaconing, while a payload carrying a YARA marker is written to disk.
    const RESPONSE_MARKER_RULE: &str = r#"
rule response_marker {
    meta:
        technique = "T1105"
        severity = "low"
        falsepositives = "none, test-only rule"
    strings:
        $m = "RESPONSE-SCENARIO-MARKER"
    condition:
        $m
}
"#;

    /// An implant execs and reaches an external address (TEST-NET-1, never
    /// routed) within a second, then repeats: the beacon shape.
    fn drive_linux_beacon(sink: &DetectionSink, pid: u32) {
        sink.on_event(exec(pid, "/tmp/implant", "/tmp/implant"));
        for i in 0..4u64 {
            sink.on_event(Event::Connect(ConnectEvent {
                meta: EventMeta {
                    pid,
                    timestamp_ns: (i + 1) * 500_000_000,
                    ..schema::fixtures::meta()
                },
                daddr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
                dport: 4444,
            }));
        }
    }

    /// Writes the marker payload, loads the YARA rule into the sink, enables
    /// response with `policy`, then drives the beacon and reports the write
    /// to the sensor path so YARA scans the payload. Returns the payload path
    /// and the pids `terminate` was asked to kill.
    fn run_response_scenario(
        dir: &std::path::Path,
        policy: policy::ResponsePolicy,
    ) -> (std::path::PathBuf, Arc<Mutex<Vec<u32>>>) {
        let yara_dir = dir.join("content").join("rules").join("yara");
        std::fs::create_dir_all(&yara_dir).unwrap();
        std::fs::write(yara_dir.join("marker.yar"), RESPONSE_MARKER_RULE).unwrap();
        let payload = dir.join("payload.bin");
        std::fs::write(&payload, b"dropped payload RESPONSE-SCENARIO-MARKER").unwrap();

        let sink = sink_in(dir);
        assert_eq!(sink.reload_content().yara_rule_count, Some(1));
        let killed = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&killed);
        sink.enable_response(
            policy,
            move |pid| {
                recorder.lock().unwrap().push(pid);
                Ok(())
            },
            dir.join("quarantine"),
        );

        sink.on_event(Event::FileOpen(schema::FileOpenEvent {
            path: payload.display().to_string(),
            flags: 0o101, // O_WRONLY | O_CREAT: write intent, what queues a scan
            ..schema::fixtures::file_open()
        }));
        drive_linux_beacon(&sink, 6262);
        (payload, killed)
    }

    /// The YARA scan runs on its own thread; wait for its response line.
    fn wait_for_alert(dir: &std::path::Path, technique: &str) -> String {
        for _ in 0..200 {
            let alerts = alerts_in(dir);
            if alerts.contains(technique) {
                return alerts;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("no {technique} within 10s: {}", alerts_in(dir));
    }

    #[test]
    fn a_beacon_with_a_dropped_payload_is_killed_and_quarantined_and_both_are_audited() {
        let dir = tmp("response-enforce");
        let (payload, killed) = run_response_scenario(
            &dir,
            policy::ResponsePolicy {
                kill_enabled: true,
                quarantine_enabled: true,
            },
        );
        let alerts = wait_for_alert(&dir, "RESPONSE-QUARANTINE");

        // Killed, audited.
        assert_eq!(*killed.lock().unwrap(), vec![6262]);
        assert!(alerts.contains("RESPONSE-KILL"), "{alerts}");
        assert!(alerts.contains("killed pid 6262"), "{alerts}");
        // Quarantined, audited.
        assert!(!payload.exists(), "the payload must have been moved");
        assert!(alerts.contains("quarantined"), "{alerts}");
        assert!(!alerts.contains("observe-only"), "policy is on: {alerts}");

        // And reversible from what the audit trail and the directory record.
        let listed = response::list_quarantined(&dir.join("quarantine")).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].original, payload);
        response::unquarantine(&dir.join("quarantine"), &listed[0].sha256_hex).unwrap();
        assert_eq!(
            std::fs::read(&payload).unwrap(),
            b"dropped payload RESPONSE-SCENARIO-MARKER"
        );
    }

    #[test]
    fn the_same_beacon_and_payload_with_policy_off_kill_nothing_and_move_nothing() {
        let dir = tmp("response-observe");
        let (payload, killed) = run_response_scenario(&dir, policy::ResponsePolicy::default());
        let alerts = wait_for_alert(&dir, "RESPONSE-QUARANTINE");

        assert!(
            killed.lock().unwrap().is_empty(),
            "terminate must never run"
        );
        assert!(payload.exists(), "the payload must stay where it was");
        assert!(
            !dir.join("quarantine").exists(),
            "nothing may be quarantined"
        );
        // Both would-have-acted decisions are still audited, as observe-only.
        let observe_only: Vec<_> = alerts
            .lines()
            .filter(|l| l.contains("RESPONSE-") && l.contains("observe-only"))
            .collect();
        assert_eq!(observe_only.len(), 2, "one per action: {alerts}");
        assert!(alerts.contains("RESPONSE-KILL"), "{alerts}");
    }

    #[test]
    fn a_payload_already_in_quarantine_is_left_alone() {
        // The quarantine write is itself a file event the sensor sees; matching it
        // again must not quarantine the file into itself.
        let (dir, hooks, log, payload) = quarantine_fixture("quarantine-loop", true);
        super::quarantine_matched_payload(&hooks, &payload, &log);
        let before = std::fs::read_dir(dir.join("quarantine")).unwrap().count();
        let quarantined = std::fs::read_dir(dir.join("quarantine"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_none())
            .unwrap();
        super::quarantine_matched_payload(&hooks, &quarantined, &log);
        assert!(quarantined.exists());
        assert_eq!(
            std::fs::read_dir(dir.join("quarantine")).unwrap().count(),
            before
        );
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

    /// Issue #131/PR #502 review point 3: verdict fusion's own dedup (bounded
    /// evidence, one composed severity per entity — see `crates/verdict`'s own
    /// tests, e.g. `the_same_technique_from_a_second_engine_within_the_window_is_one_finding`)
    /// must never mean a finding disappears from `alerts.ndjson` — that file is
    /// the audit trail, and every finding lands there regardless of whether
    /// fusion also folded it into the entity's already-live verdict.
    #[test]
    fn repeated_identical_exec_alerts_each_still_reach_the_alert_log() {
        let dir = tmp("verdict-dedup");
        let sink = sink_in(&dir);
        let ev = exec(
            50,
            "bash -c echo cGF5bG9hZAo= | base64 -d | sh",
            "/bin/bash",
        );
        sink.on_event(ev.clone());
        sink.on_event(ev);
        let alerts = alerts_in(&dir);
        assert_eq!(
            alerts.matches("T1059.004").count(),
            2,
            "verdict fusion dedups its own entity state, but alerts.ndjson is \
             the audit trail — every occurrence must still land there: {alerts}"
        );
    }

    /// The flip side of the dedup test: fusion is scoped per entity
    /// (`(ppid, comm)`) — a different entity raising the identical technique
    /// must still get its own finding, not be silently absorbed by the first
    /// entity's state.
    #[test]
    fn the_same_technique_on_a_different_entity_still_alerts() {
        let dir = tmp("verdict-cross-entity");
        let sink = sink_in(&dir);
        sink.on_event(exec(
            60,
            "bash -c echo cGF5bG9hZAo= | base64 -d | sh",
            "/bin/bash",
        ));
        let mut other = exec(
            61,
            "bash -c echo cGF5bG9hZAo= | base64 -d | sh",
            "/bin/bash",
        );
        if let Event::Exec(e) = &mut other {
            e.meta.ppid = 2;
            e.meta.comm = "sh".into();
        }
        sink.on_event(other);
        let alerts = alerts_in(&dir);
        assert_eq!(
            alerts.matches("T1059.004").count(),
            2,
            "a distinct entity must get its own finding: {alerts}"
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

    /// PR #502 review: `maybe_kill`'s gate must read *this event's own*
    /// evidence, not the entity's fused, sticky severity. `drive_bayes_crossing`'s
    /// connect events all carry the fixture's neutral, unmodified
    /// `(ppid, comm)` (`(0, "")`), so a second, unrelated pid's own connect
    /// lands in the *same* verdict entity as the first pid's Bayes crossing —
    /// exactly the "sibling process" collision the review found: a plain
    /// `T1059/T1071` co-occurrence alert (`Medium`) on its own must never
    /// trigger a kill just because that shared entity was earlier raised to
    /// `Critical` by someone else's Bayes crossing.
    #[test]
    fn a_siblings_weak_alert_never_triggers_kill_from_anothers_bayes_crossing() {
        let dir = tmp("bayes-sibling");
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

        // pid 5001 crosses Bayes — raises the shared `(0, "")` verdict entity
        // to `Critical` and gets killed, exactly as before.
        drive_bayes_crossing(&sink, 5001);

        // pid 5002: one exec, one connect 40s later — outside
        // VERDICT_DEDUP_WINDOW_NS (30s), so this produces a genuine fresh
        // verdict for the shared entity, not a silently-absorbed duplicate.
        // Correlator's own window is 60s, so the co-occurrence rule still
        // fires: a plain, weak `T1059/T1071` finding, nothing Bayesian.
        sink.on_event(exec(5002, "bash -c true", "/bin/bash"));
        sink.on_event(Event::Connect(ConnectEvent {
            meta: EventMeta {
                pid: 5002,
                timestamp_ns: 40_000_000_000,
                ..schema::fixtures::meta()
            },
            daddr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34)),
            dport: 443,
        }));

        let alerts = alerts_in(&dir);
        assert!(
            alerts.contains("T1059/T1071"),
            "the sibling's weak co-occurrence finding must still alert: {alerts}"
        );
        assert_eq!(
            *killed.lock().unwrap(),
            vec![5001],
            "only the pid that actually crossed Bayes may be killed — the \
             sibling's own weak finding must not ride the shared entity's \
             sticky severity to a kill: {alerts}"
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
                Some(&dir.join("events.jsonl")),
                Some(Arc::clone(&spool)),
                &dir.join("content"),
                &dir.join("ml-registry"),
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

    #[test]
    fn without_an_events_path_no_raw_event_log_is_written_but_the_spool_still_is() {
        let dir = tmp("no-events-log");
        let spool = Arc::new(Mutex::new(
            store::EventSpool::open(&dir.join("spool"), u64::MAX).unwrap(),
        ));
        let sink = Arc::new(
            DetectionSink::new(
                rules::RuleState::new(),
                &dir.join("alerts.ndjson"),
                None,
                Some(Arc::clone(&spool)),
                &dir.join("content"),
                &dir.join("ml-registry"),
            )
            .unwrap(),
        );
        sink.on_event(exec(7, "ls", "/bin/ls"));

        // The enrich worker is what appends to the spool: once the event is there,
        // it has also gone past the (absent) raw-log step.
        let mut spooled: Vec<Event> = Vec::new();
        for _ in 0..200 {
            spooled = spool.lock().unwrap().drain_oldest().unwrap();
            if !spooled.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(spooled.len(), 1, "the event must still reach the spool");
        assert!(
            !dir.join("events.jsonl").exists(),
            "no events path means no raw event log, not a file at a default path"
        );
    }

    #[test]
    fn the_model_is_found_under_the_state_directory_before_the_working_directory() {
        let state = tmp("model-root");
        let under_state = super::model_root(&state).join("fam").join("0.1.0");
        std::fs::create_dir_all(&under_state).unwrap();
        std::fs::write(under_state.join("model.onnx"), b"x").unwrap();
        let cwd_root = tmp("model-cwd");
        let under_cwd = cwd_root.join("fam").join("0.1.0");
        std::fs::create_dir_all(&under_cwd).unwrap();
        std::fs::write(under_cwd.join("model.onnx"), b"y").unwrap();

        let found = super::locate_model_dir(&[&super::model_root(&state), &cwd_root], "fam");
        assert_eq!(found, under_state);
    }

    #[test]
    fn the_working_directory_registry_is_the_fallback_for_a_source_checkout() {
        let state = tmp("model-root-empty");
        let cwd_root = tmp("model-cwd-only");
        let under_cwd = cwd_root.join("fam").join("0.1.0");
        std::fs::create_dir_all(&under_cwd).unwrap();
        std::fs::write(under_cwd.join("model.onnx"), b"y").unwrap();

        let found = super::locate_model_dir(&[&super::model_root(&state), &cwd_root], "fam");
        assert_eq!(found, under_cwd);
    }

    #[test]
    fn with_no_model_anywhere_the_state_directory_is_the_one_named() {
        let state = tmp("model-none");
        let cwd_root = tmp("model-none-cwd");
        let found = super::locate_model_dir(&[&super::model_root(&state), &cwd_root], "fam");
        assert_eq!(found, super::model_root(&state).join("fam").join("0.1.0"));
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

    // ── reload_content (issue #30) ──────────────────────────────────────

    /// A minimal, valid Sigma rule (issue #73's required metadata: `level`,
    /// `falsepositives`, an ATT&CK tag, and a recognized platform directory
    /// — the last one is why the test writes it under a `.../linux/` path,
    /// not just any temp dir) matching on an image path no other rule in
    /// this crate's tests, or `crates/rules`' deterministic checks, would
    /// ever incidentally match.
    const RELOAD_TEST_SIGMA_RULE: &str = r#"
title: reload-content test marker rule
tags:
  - attack.t1059
level: low
falsepositives:
  - none, test-only rule
detection:
  selection:
    Image|endswith:
      - '/reload-content-marker'
  condition: selection
"#;

    #[test]
    fn reload_content_picks_up_a_sigma_rule_added_after_construction() {
        let dir = tmp("reload-sigma");
        let sink = sink_in(&dir);

        // Before reload: no Sigma engine loaded yet (content dir is empty),
        // so this exec produces no Sigma-sourced alert.
        sink.on_event(exec(900, "run", "/opt/reload-content-marker"));
        assert!(
            !alerts_in(&dir).contains("reload-content test marker rule"),
            "no sigma engine should be loaded before the first reload"
        );

        let sigma_dir = dir
            .join("content")
            .join("rules")
            .join("sigma")
            .join("linux");
        std::fs::create_dir_all(&sigma_dir).unwrap();
        std::fs::write(sigma_dir.join("marker.yml"), RELOAD_TEST_SIGMA_RULE).unwrap();

        let report = sink.reload_content();
        assert_eq!(
            report.sigma_rule_count,
            Some(1),
            "the one rule just written must load"
        );
        assert_eq!(
            report.yara_rule_count, None,
            "no rules/yara directory exists in this test's content dir"
        );

        sink.on_event(exec(901, "run", "/opt/reload-content-marker"));
        assert!(
            alerts_in(&dir).contains("reload-content test marker rule"),
            "the reloaded rule must now fire: {}",
            alerts_in(&dir)
        );
    }

    /// A rule author's `level:` is data on the finding, not a kill decision
    /// (#131): the rule below is `critical` and must still never terminate anything.
    fn critical_sigma_sink(name: &str) -> (std::path::PathBuf, Arc<DetectionSink>) {
        let dir = tmp(name);
        let sigma_dir = dir
            .join("content")
            .join("rules")
            .join("sigma")
            .join("linux");
        std::fs::create_dir_all(&sigma_dir).unwrap();
        std::fs::write(
            sigma_dir.join("critical.yml"),
            RELOAD_TEST_SIGMA_RULE.replace("level: low", "level: critical"),
        )
        .unwrap();
        let sink = sink_in(&dir);
        assert_eq!(sink.reload_content().sigma_rule_count, Some(1));
        (dir, sink)
    }

    #[test]
    fn a_sigma_rules_severity_reaches_the_fused_verdict() {
        let (_dir, sink) = critical_sigma_sink("sigma-severity-verdict");
        sink.on_event(exec(910, "run", "/opt/reload-content-marker"));
        let verdict = sink
            .verdict
            .lock()
            .unwrap()
            .peek(&verdict::EntityKey::new(1, "bash"))
            .expect("the Sigma hit is folded into the entity's verdict");
        assert_eq!(verdict.severity, schema::detection::Severity::Critical);
    }

    fn yara_match(technique: &str, severity: schema::detection::Severity) -> yara::YaraMatch {
        yara::YaraMatch {
            identifier: "response_marker".into(),
            severity,
            technique: technique.into(),
        }
    }

    fn yara_context(meta: &EventMeta) -> yara::ScanContext {
        yara::ScanContext {
            ppid: meta.ppid,
            comm: meta.comm.clone(),
            parent_generation: meta.parent_process_generation,
            timestamp_ns: meta.timestamp_ns,
        }
    }

    /// #614: a native rule and a YARA rule flagging the same technique on the same
    /// entity are one finding, whichever engine reports first.
    #[test]
    fn a_yara_match_and_a_rule_alert_on_the_same_entity_and_technique_are_one_verdict() {
        let dir = tmp("yara-fusion-dedup");
        let sink = sink_in(&dir);
        let meta = schema::fixtures::meta();
        let entity = verdict::EntityKey::new(meta.ppid, meta.comm.clone());
        let event = Event::FileOpen(schema::FileOpenEvent {
            meta: meta.clone(),
            ..schema::fixtures::file_open()
        });
        sink.record_and_emit(
            &entity,
            "T1105",
            "downloader wrote then ran a binary",
            schema::detection::DetectionSource::Rule {
                rule_id: "T1105".into(),
            },
            schema::detection::Severity::Medium,
            &event,
        );

        let absorbed = super::fuse_yara_match(
            &sink.verdict,
            &yara_context(&meta),
            &yara_match("T1105", schema::detection::Severity::Low),
        );
        assert_eq!(absorbed, None, "same technique, same entity: a duplicate");

        let fused = sink.verdict.lock().unwrap().peek(&entity).unwrap();
        assert_eq!(fused.techniques, vec!["T1105"], "one finding, not two");
        assert_eq!(fused.sources.len(), 2, "both engines are on the evidence");
        assert_eq!(fused.severity, schema::detection::Severity::Medium);
    }

    #[test]
    fn a_yara_match_on_a_different_entity_is_its_own_verdict() {
        let dir = tmp("yara-fusion-entity");
        let sink = sink_in(&dir);
        let meta = EventMeta {
            ppid: 900,
            comm: "dropper".into(),
            ..schema::fixtures::meta()
        };
        let fused = super::fuse_yara_match(
            &sink.verdict,
            &yara_context(&meta),
            &yara_match("T1105", schema::detection::Severity::High),
        )
        .expect("first sighting on this entity");
        assert_eq!(fused.entity, verdict::EntityKey::new(900, "dropper"));
        assert_eq!(fused.severity, schema::detection::Severity::High);
        assert_eq!(
            fused.sources,
            vec![schema::detection::DetectionSource::Yara {
                rule_name: "response_marker".into()
            }]
        );
    }

    /// End to end: the scan runs on its own thread after the settle delay, and the
    /// match must still land on the process that wrote the file.
    #[test]
    fn a_scanned_payloads_match_reaches_the_verdict_of_the_process_that_wrote_it() {
        let dir = tmp("yara-fusion-e2e");
        let yara_dir = dir.join("content").join("rules").join("yara");
        std::fs::create_dir_all(&yara_dir).unwrap();
        std::fs::write(yara_dir.join("marker.yar"), RESPONSE_MARKER_RULE).unwrap();
        let payload = dir.join("payload.bin");
        std::fs::write(&payload, b"dropped payload RESPONSE-SCENARIO-MARKER").unwrap();
        let sink = sink_in(&dir);
        assert_eq!(sink.reload_content().yara_rule_count, Some(1));

        let meta = EventMeta {
            ppid: 777,
            comm: "dropper".into(),
            ..schema::fixtures::meta()
        };
        sink.on_event(Event::FileOpen(schema::FileOpenEvent {
            meta,
            path: payload.display().to_string(),
            flags: 0o101,
        }));
        wait_for_alert(&dir, "YARA");

        let fused = sink
            .verdict
            .lock()
            .unwrap()
            .peek(&verdict::EntityKey::new(777, "dropper"))
            .expect("the match is folded into the writer's verdict");
        assert_eq!(fused.techniques, vec!["T1105"]);
    }

    #[test]
    fn a_critical_fused_verdict_raises_an_escalation_alert_without_killing() {
        let (dir, sink) = critical_sigma_sink("sigma-critical-escalates");
        let killed = Arc::new(Mutex::new(Vec::new()));
        let killed_rec = Arc::clone(&killed);
        sink.enable_response(
            policy::ResponsePolicy {
                kill_enabled: true,
                quarantine_enabled: true,
            },
            move |pid| {
                killed_rec.lock().unwrap().push(pid);
                Ok(())
            },
            dir.join("quarantine"),
        );
        sink.on_event(exec(912, "run", "/opt/reload-content-marker"));
        assert!(
            alerts_in(&dir).contains("RESPONSE-ESCALATE"),
            "{}",
            alerts_in(&dir)
        );
        assert!(killed.lock().unwrap().is_empty());
    }

    #[test]
    fn a_medium_fused_verdict_does_not_escalate() {
        let dir = tmp("medium-no-escalate");
        let sink = sink_in(&dir);
        sink.on_event(exec(
            913,
            "bash -c echo cGF5bG9hZAo= | base64 -d | sh",
            "/bin/bash",
        ));
        let alerts = alerts_in(&dir);
        assert!(alerts.contains("T1059.004"), "{alerts}");
        assert!(!alerts.contains("RESPONSE-ESCALATE"), "{alerts}");
    }

    /// A built-in rule that fires on a plain exec: `T1490`, severity `High`.
    const SHADOW_DELETE: &str = "vssadmin.exe Delete Shadows /All /Quiet";

    /// #615: a built-in rule's own severity reaches the fused verdict, instead of
    /// the flat placeholder every non-`BAYES` finding used to get.
    #[test]
    fn a_built_in_rules_own_severity_reaches_the_fused_verdict() {
        let dir = tmp("builtin-severity");
        let sink = sink_in(&dir);
        sink.on_event(exec(920, SHADOW_DELETE, "/usr/bin/vssadmin"));
        let fused = sink
            .verdict
            .lock()
            .unwrap()
            .peek(&verdict::EntityKey::new(1, "bash"))
            .expect("the built-in alert is folded into the entity's verdict");
        assert!(fused.techniques.contains(&"T1490".to_string()), "{fused:?}");
        assert_eq!(fused.severity, schema::detection::Severity::High);
    }

    /// #615: a high-severity built-in alert must never terminate a process by
    /// severity alone: only the correlator's `BAYES` crossing gates kill.
    #[test]
    fn a_high_severity_built_in_alert_never_triggers_a_kill() {
        let dir = tmp("builtin-high-no-kill");
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
        sink.on_event(exec(921, SHADOW_DELETE, "/usr/bin/vssadmin"));
        assert!(alerts_in(&dir).contains("T1490"), "{}", alerts_in(&dir));
        assert!(
            killed.lock().unwrap().is_empty(),
            "severity alone must never gate a kill"
        );
        assert!(
            !alerts_in(&dir).contains("killed pid"),
            "{}",
            alerts_in(&dir)
        );
    }

    /// #613: a suppression drops the finding from the fused verdict, never from
    /// the audit trail.
    #[test]
    fn a_suppressed_technique_leaves_the_verdict_but_stays_in_the_alert_log() {
        let dir = tmp("suppress-verdict");
        let sink = sink_in(&dir);
        let meta = EventMeta {
            comm: "dropper".into(),
            ..schema::fixtures::meta()
        };
        let entity = verdict::EntityKey::new(meta.ppid, meta.comm.clone());
        let event = Event::FileOpen(schema::FileOpenEvent {
            meta: meta.clone(),
            ..schema::fixtures::file_open()
        });
        let record = || {
            sink.record_and_emit(
                &entity,
                "T1105",
                "downloader wrote then ran a binary",
                schema::detection::DetectionSource::Rule {
                    rule_id: "T1105".into(),
                },
                schema::detection::Severity::Medium,
                &event,
            )
        };

        assert_eq!(
            sink.suppress_verdict(meta.ppid, &meta.comm, "T1105"),
            Ok(true)
        );
        assert_eq!(record(), None, "a suppressed finding yields no verdict");
        assert!(
            alerts_in(&dir).contains("T1105"),
            "the audit trail keeps it"
        );

        assert!(sink.unsuppress_verdict(meta.ppid, &meta.comm, "T1105"));
        assert!(record().is_some(), "lifting the mark restores fusion");
    }

    /// #592 applied to YARA: a match from a recycled parent pid is a new entity and
    /// must not inherit the previous parent's evidence or severity.
    #[test]
    fn a_yara_match_from_a_recycled_parent_does_not_inherit_the_previous_parents_verdict() {
        let dir = tmp("yara-fusion-recycled-parent");
        let sink = sink_in(&dir);
        let first = EventMeta {
            ppid: 500,
            comm: "dropper".into(),
            parent_process_generation: Some(1),
            ..schema::fixtures::meta()
        };
        super::fuse_yara_match(
            &sink.verdict,
            &yara_context(&first),
            &yara_match("T1105", schema::detection::Severity::Critical),
        )
        .unwrap();

        let recycled = EventMeta {
            parent_process_generation: Some(2),
            ..first
        };
        let fused = super::fuse_yara_match(
            &sink.verdict,
            &yara_context(&recycled),
            &yara_match("T1071", schema::detection::Severity::Low),
        )
        .unwrap();
        assert_eq!(fused.severity, schema::detection::Severity::Low);
        assert_eq!(fused.techniques, vec!["T1071"]);
    }

    /// #614 + #612: a High-or-above YARA match escalates like any other engine's
    /// finding; the low-severity marker rule used elsewhere does not.
    #[test]
    fn a_high_severity_yara_match_raises_an_escalation_alert() {
        let dir = tmp("yara-fusion-escalate");
        let yara_dir = dir.join("content").join("rules").join("yara");
        std::fs::create_dir_all(&yara_dir).unwrap();
        std::fs::write(
            yara_dir.join("marker.yar"),
            RESPONSE_MARKER_RULE.replace("severity = \"low\"", "severity = \"high\""),
        )
        .unwrap();
        let payload = dir.join("payload.bin");
        std::fs::write(&payload, b"dropped payload RESPONSE-SCENARIO-MARKER").unwrap();
        let sink = sink_in(&dir);
        assert_eq!(sink.reload_content().yara_rule_count, Some(1));

        let meta = EventMeta {
            ppid: 778,
            comm: "dropper".into(),
            ..schema::fixtures::meta()
        };
        sink.on_event(Event::FileOpen(schema::FileOpenEvent {
            meta,
            path: payload.display().to_string(),
            flags: 0o101,
        }));
        let alerts = wait_for_alert(&dir, "RESPONSE-ESCALATE");
        assert!(alerts.contains("778:dropper"), "{alerts}");
    }

    #[test]
    fn a_critical_sigma_hit_never_triggers_a_kill() {
        let (dir, sink) = critical_sigma_sink("sigma-critical-no-kill");
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
        sink.on_event(exec(911, "run", "/opt/reload-content-marker"));
        assert!(
            alerts_in(&dir).contains("reload-content test marker rule"),
            "the critical rule must fire: {}",
            alerts_in(&dir)
        );
        assert!(
            killed.lock().unwrap().is_empty(),
            "only a correlator belief crossing its threshold may terminate a process"
        );
        assert!(
            !alerts_in(&dir).contains("killed pid"),
            "{}",
            alerts_in(&dir)
        );
    }

    #[test]
    fn reload_content_with_no_content_dir_present_unloads_cleanly() {
        let dir = tmp("reload-empty");
        let sink = sink_in(&dir);
        let report = sink.reload_content();
        assert_eq!(report.sigma_rule_count, None);
        assert_eq!(report.yara_rule_count, None);
        // Still safe to process events after a no-op reload.
        sink.on_event(exec(902, "ls", "/bin/ls"));
    }

    const RELOAD_TEST_YARA_RULE: &str = r#"
rule reload_content_test_marker {
    meta:
        technique = "T1105"
        severity = "low"
        falsepositives = "none, test-only rule"
    strings:
        $m = "RELOAD-CONTENT-YARA-MARKER"
    condition:
        $m
}
"#;

    #[test]
    fn reload_content_keeps_the_previous_yara_rules_when_the_new_set_is_broken() {
        // YARA's `load_dir` is all-or-nothing (a rule that doesn't compile is a
        // hard error), which is the case a reload must survive: an applied,
        // signed-but-broken rule set must not switch scanning off.
        let dir = tmp("reload-broken-keeps-old");
        let sink = sink_in(&dir);
        let yara_dir = dir.join("content").join("rules").join("yara");
        std::fs::create_dir_all(&yara_dir).unwrap();
        std::fs::write(yara_dir.join("marker.yar"), RELOAD_TEST_YARA_RULE).unwrap();
        let report = sink.reload_content();
        assert_eq!(report.yara_rule_count, Some(1));
        assert!(!report.yara_reload_failed);

        std::fs::write(yara_dir.join("broken.yar"), "rule nope { condition: \n").unwrap();
        let report = sink.reload_content();
        assert!(report.yara_reload_failed, "a rule that fails to compile");
        assert_eq!(
            report.yara_rule_count,
            Some(1),
            "the previous scan queue must keep running"
        );

        // Fixing the content recovers on the next reload.
        std::fs::remove_file(yara_dir.join("broken.yar")).unwrap();
        let report = sink.reload_content();
        assert!(!report.yara_reload_failed);
        assert_eq!(report.yara_rule_count, Some(1));
    }

    #[test]
    fn reload_content_drops_a_rule_whose_file_was_removed() {
        let dir = tmp("reload-remove");
        let sink = sink_in(&dir);
        let sigma_dir = dir
            .join("content")
            .join("rules")
            .join("sigma")
            .join("linux");
        std::fs::create_dir_all(&sigma_dir).unwrap();
        std::fs::write(sigma_dir.join("marker.yml"), RELOAD_TEST_SIGMA_RULE).unwrap();
        assert_eq!(sink.reload_content().sigma_rule_count, Some(1));

        std::fs::remove_dir_all(dir.join("content")).unwrap();
        let report = sink.reload_content();
        assert_eq!(
            report.sigma_rule_count, None,
            "removing the content dir must unload the engine, not error"
        );

        sink.on_event(exec(903, "run", "/opt/reload-content-marker"));
        assert!(
            !alerts_in(&dir).contains("reload-content test marker rule"),
            "the removed rule must no longer fire"
        );
    }
}
