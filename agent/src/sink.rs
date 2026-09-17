//! The agent's concrete `EventSink`s: full detection (`DetectionSink`) and raw
//! capture (re-using `sinks::JsonlEventSink` directly). Migrated from
//! `old/agent/sinks.rs`, minus what isn't wired yet — the correlator, Sigma, and ML
//! scorer plug in here as their crates are migrated (M2), each addition a new field
//! and a few lines in `on_event`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use schema::{Event, sensor::EventSink};
use sinks::{AlertRecord, JsonlWriter};

use crate::enrich_queue::EnrichQueue;

/// Dispatches every event to the detection engines and the output sinks. `Mutex`
/// around the mutable state (`RuleState`) rather than no synchronization: the
/// `EventSink` trait requires `Send + Sync` and only exposes `&self`, to stay correct
/// if several sensors ever share one sink.
pub(crate) struct DetectionSink {
    rule_state: Mutex<rules::RuleState>,
    correlator: Mutex<correlator::CorrelationEngine>,
    /// Sigma rules from `rules/sigma` (next to the agent executable, falling back
    /// to the working directory) when the folder exists — otherwise the agent runs without a Sigma engine, and that is
    /// not an error (the load failure path IS an error: content present but broken).
    sigma: Option<sigma::SigmaEngine>,
    /// One alert per line in alerts.ndjson (shared with the YARA scan worker).
    alert_log: Arc<JsonlWriter>,
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
        // The raw event log is written by the enrichment worker, not the drain
        // thread — shared behind an Arc so the worker owns a handle.
        let events_log = Arc::new(JsonlWriter::open(events_path)?);
        let enrich_queue = EnrichQueue::start(enrich::Enricher::new(), move |event| {
            events_log.write(&event);
        });
        Ok(Self {
            rule_state: Mutex::new(rule_state),
            correlator: Mutex::new(correlator::CorrelationEngine::new()),
            sigma: load_sigma_rules(),
            yara: start_yara(alert_log.clone()),
            alert_log,
            enrich_queue,
            progress: Arc::new(AtomicU64::new(0)),
        })
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
    fn correlate(&self, event: &Event) {
        for alert in self.correlator.lock().unwrap().on_event(event.clone()) {
            self.emit(alert.technique, &alert.message);
        }
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
        for alert in rules::evaluate_file_open(event) {
            self.emit(alert.technique, &alert.message);
        }
        self.rule_state.lock().unwrap().on_file_open(event);
        if let Some(yara) = &self.yara
            && event.flags & 0o103 != 0
        {
            yara.enqueue(std::path::PathBuf::from(&event.path));
        }
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

    fn emit(&self, technique: &str, message: &str) {
        // Alerts go to stderr (stdout carries nothing in run mode; the raw stream
        // lives in events.jsonl) and are highlighted — an alert must not get lost in
        // terminal noise.
        eprintln!("\x1b[1;31m[ALERT] {technique} — {message}\x1b[0m");
        self.alert_log.write(&AlertRecord {
            timestamp_ns: crate::time::now_ns(),
            technique: technique.to_string(),
            message: message.to_string(),
        });
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
    let dir = content_dir("rules/yara")?;
    match yara::RuleSet::load_dir(&dir) {
        Ok(rules) => {
            log::info!("yara: {} rules loaded", rules.rule_count());
            Some(yara::ScanQueue::start(rules, move |outcome| {
                for rule in &outcome.matches {
                    let message = format!("yara rule {rule} matched {}", outcome.path.display());
                    eprintln!("\x1b[1;31m[ALERT] YARA — {message}\x1b[0m");
                    alert_log.write(&AlertRecord {
                        timestamp_ns: crate::time::now_ns(),
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
            Event::FileOpen(e) => self.rule_state.lock().unwrap().on_file_open(e),
            _ => {}
        }
    }
}
