//! The agent's concrete `EventSink`s: full detection (`DetectionSink`) and raw
//! capture (re-using `sinks::JsonlEventSink` directly). Migrated from
//! `old/agent/sinks.rs`, minus what isn't wired yet — the correlator, Sigma, and ML
//! scorer plug in here as their crates are migrated (M2), each addition a new field
//! and a few lines in `on_event`.

use std::sync::{Arc, Mutex};

use schema::{Event, sensor::EventSink};
use sinks::{AlertRecord, JsonlWriter};

/// Dispatches every event to the detection engines and the output sinks. `Mutex`
/// around the mutable state (`RuleState`) rather than no synchronization: the
/// `EventSink` trait requires `Send + Sync` and only exposes `&self`, to stay correct
/// if several sensors ever share one sink.
pub(crate) struct DetectionSink {
    rule_state: Mutex<rules::RuleState>,
    correlator: Mutex<correlator::CorrelationEngine>,
    /// Sigma rules from `rules/sigma` (relative to the working directory) when the
    /// folder exists — otherwise the agent runs without a Sigma engine, and that is
    /// not an error (the load failure path IS an error: content present but broken).
    sigma: Option<sigma::SigmaEngine>,
    /// Hash + code-signature enrichment, cached by (path, mtime, size).
    enricher: Mutex<enrich::Enricher>,
    /// One alert per line in alerts.ndjson (shared with the YARA scan worker).
    alert_log: Arc<JsonlWriter>,
    /// Budgeted background content scanning; `None` when rules/yara is absent.
    yara: Option<yara::ScanQueue>,
    /// Raw event log (one normalized event per line) for calibration/ML training.
    events_log: JsonlWriter,
}

impl DetectionSink {
    /// `rule_state` arrives already seeded by the caller (from /proc or the
    /// platform's process list — see `commands`).
    pub(crate) fn new(
        rule_state: rules::RuleState,
        alerts_path: &std::path::Path,
        events_path: &std::path::Path,
    ) -> std::io::Result<Self> {
        let alert_log = Arc::new(JsonlWriter::open(alerts_path)?);
        Ok(Self {
            rule_state: Mutex::new(rule_state),
            correlator: Mutex::new(correlator::CorrelationEngine::new()),
            sigma: load_sigma_rules(),
            enricher: Mutex::new(enrich::Enricher::new()),
            yara: start_yara(alert_log.clone()),
            alert_log,
            events_log: JsonlWriter::open(events_path)?,
        })
    }

    fn emit(&self, technique: &str, message: &str) {
        // Alerts go to stderr (stdout carries nothing in run mode; the raw stream
        // lives in events.jsonl) and are highlighted — an alert must not get lost in
        // terminal noise.
        eprintln!("\x1b[1;31m[ALERT] {technique} — {message}\x1b[0m");
        self.alert_log.write(&AlertRecord {
            timestamp_ns: now_epoch_ns(),
            technique: technique.to_string(),
            message: message.to_string(),
        });
    }
}

/// Loads the Sigma content directory if present. Migrated from the old agent's
/// load_sigma_rules.
fn load_sigma_rules() -> Option<sigma::SigmaEngine> {
    let rules_dir = std::path::Path::new("rules/sigma");
    if !rules_dir.is_dir() {
        return None;
    }
    match sigma::SigmaEngine::load_dir(rules_dir) {
        Ok(engine) => {
            log::info!("sigma: {} rules loaded", engine.rule_count());
            Some(engine)
        }
        Err(e) => {
            log::error!("sigma: load error: {e}");
            None
        }
    }
}

/// Loads rules/yara when present and starts the scan worker; matches are emitted as
/// alerts by the worker thread through the shared alert log.
fn start_yara(alert_log: Arc<JsonlWriter>) -> Option<yara::ScanQueue> {
    let dir = std::path::Path::new("rules/yara");
    if !dir.is_dir() {
        return None;
    }
    match yara::RuleSet::load_dir(dir) {
        Ok(rules) => {
            log::info!("yara: {} rule files loaded", rules.rule_file_count());
            Some(yara::ScanQueue::start(rules, move |outcome| {
                for rule in &outcome.matches {
                    let message = format!("yara rule {rule} matched {}", outcome.path.display());
                    eprintln!("\x1b[1;31m[ALERT] YARA — {message}\x1b[0m");
                    alert_log.write(&AlertRecord {
                        timestamp_ns: now_epoch_ns(),
                        technique: "YARA".to_string(),
                        message,
                    });
                }
            }))
        }
        Err(e) => {
            log::error!("yara: load error: {e}");
            None
        }
    }
}

fn now_epoch_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

impl EventSink for DetectionSink {
    fn on_event(&self, mut event: Event) {
        // Enrichment first, so the logged event and every engine see hash+signature.
        // Budgeted: cache hit is a stat; miss is one bounded hash + one offline
        // signature check (see crates/enrich docs).
        if let Event::Exec(e) = &mut event
            && !e.image_path.is_empty()
            && e.sha256.is_none()
        {
            let enrichment = self
                .enricher
                .lock()
                .unwrap()
                .enrich(std::path::Path::new(&e.image_path));
            e.sha256 = enrichment.sha256;
            e.signature = Some(enrichment.signature);
        }
        self.events_log.write(&event);
        let mut alerts = Vec::new();
        for alert in self.correlator.lock().unwrap().on_event(event.clone()) {
            self.emit(alert.technique, &alert.message);
        }
        match &event {
            Event::Exec(e) => {
                alerts.extend(rules::evaluate_exec(e));
                alerts.extend(self.rule_state.lock().unwrap().on_exec(e));
                if let Some(sigma) = &self.sigma {
                    for hit in sigma.eval_exec(e) {
                        let technique = if hit.tags.is_empty() {
                            "Sigma".to_string()
                        } else {
                            hit.tags.join("/")
                        };
                        self.emit(&technique, &hit.title);
                    }
                }
            }
            Event::FileOpen(e) => {
                alerts.extend(rules::evaluate_file_open(e));
                self.rule_state.lock().unwrap().on_file_open(e);
                // Content scan on write intent, off the event path (budgeted queue).
                if let Some(yara) = &self.yara
                    && e.flags & 0o103 != 0
                {
                    yara.enqueue(std::path::PathBuf::from(&e.path));
                }
            }
            Event::Connect(e) => {
                alerts.extend(self.rule_state.lock().unwrap().on_connect(e));
            }
            // New telemetry categories reach the engines as they land; until a rule
            // consumes them, logging above is the whole treatment.
            _ => {}
        }
        for alert in alerts {
            self.emit(alert.technique, &alert.message);
        }
    }
}

// ── BaselineSink ──────────────────────────────────────────────────────────────

/// Minimal sink for ML baseline capture: records only the cmdlines of exec events
/// that trigger NO deterministic rule — the "known benign under current rules"
/// corpus consumed by `synthaea_ml` training. Migrated from the old agent's
/// BaselineSink, now platform-neutral (any sensor speaking the contract feeds it).
pub(crate) struct BaselineSink {
    rule_state: Mutex<rules::RuleState>,
    out: JsonlWriter,
    count: std::sync::atomic::AtomicU64,
}

/// One baseline record — the format `synthaea_ml/training` consumes.
#[derive(serde::Serialize)]
struct BaselineRecord<'a> {
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
            Event::FileOpen(e) => self.rule_state.lock().unwrap().on_file_open(e),
            _ => {}
        }
    }
}
