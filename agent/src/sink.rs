//! The agent's concrete `EventSink`s: full detection (`DetectionSink`) and raw
//! capture (re-using `sinks::JsonlEventSink` directly). Migrated from
//! `old/agent/sinks.rs`, minus what isn't wired yet — the correlator, Sigma, and ML
//! scorer plug in here as their crates are migrated (M2), each addition a new field
//! and a few lines in `on_event`.

use std::sync::Mutex;

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
    /// One alert per line in alerts.ndjson.
    alert_log: JsonlWriter,
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
        Ok(Self {
            rule_state: Mutex::new(rule_state),
            correlator: Mutex::new(correlator::CorrelationEngine::new()),
            sigma: load_sigma_rules(),
            alert_log: JsonlWriter::open(alerts_path)?,
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

fn now_epoch_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

impl EventSink for DetectionSink {
    fn on_event(&self, event: Event) {
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
