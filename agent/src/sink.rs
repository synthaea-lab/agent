//! The agent's concrete `EventSink`s: full detection (`DetectionSink`) and raw
//! capture (re-using `sinks::JsonlEventSink` directly). Migrated from
//! `old/agent/sinks.rs`, minus what isn't wired yet — the correlator, Sigma, and ML
//! scorer plug in here as their crates are migrated (M2), each addition a new field
//! and a few lines in `on_event`.

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
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
    correlator: Arc<Mutex<correlator::CorrelationEngine>>,
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
    /// The fleet's common-set snapshot (ADR-0020, issue #76) from
    /// `<content_root>/snapshots/common-set.bin`, or `None` while there is none: the
    /// "not in the common set" evidence is withheld without one. Swapped whole on
    /// `reload_content`, like the engines above, so a reader never sees a half-loaded
    /// filter; nothing reads it on the capture path yet (the lookup is the next slice).
    common_set: Arc<Mutex<Option<Arc<ml::features::common_set::CommonSetSnapshot>>>>,
    /// On-device IOC matching (#60, ADR-0038) over `<content_root>/ioc/`: exec image hashes on the
    /// enrichment worker, connect destinations on the capture thread. Shared with the worker,
    /// which is the only place an exec's hash is known.
    ioc: Arc<crate::ioc::IocMatcher>,
    /// What became of the rarity judgements, for the health beacon.
    rarity_stats: Arc<RarityStats>,
    /// Tamper-class alerts raised since the agent started (a sensor confirmed silent, a shipped
    /// binary or its manifest that no longer verifies), for the health beacon (#863).
    tamper_events: AtomicU64,
    /// The single alert funnel (issue #388): alerts.ndjson + stderr + the
    /// in-memory recent-alerts buffer served to `cli detections`. Shared with
    /// the YARA scan worker and quarantine.
    alert_log: Arc<AlertLog>,
    /// Budgeted background content scanning; `None` when
    /// `<content_root>/rules/yara` is absent. `Mutex`-wrapped for the same
    /// reload reason as `sigma`.
    yara: Mutex<Option<(yara::ScanQueue, usize)>>,
    /// Budgeted YARA scanning of one process's memory (#85, ADR-0023), requested by a
    /// detection about that process (today the memfd-exec rule, T1620), never swept.
    /// `None` when `<content_root>/rules/yara` is absent, and on every platform but
    /// Linux. `Mutex`-wrapped for the same reload reason as `yara`.
    memscan: Mutex<Option<yara::MemoryScanQueue>>,
    /// Enrichment (hash + signature) and the high-volume raw-event logging, off the
    /// drain thread (issue #126). The capture thread runs detection in memory and
    /// hands the event here with a non-blocking send.
    enrich_queue: EnrichQueue,
    /// Structured findings are persisted on the enrichment worker. A full
    /// queue falls back to a direct append so overload does not silently drop
    /// a detection.
    detection_spool: Option<Arc<Mutex<store::EventSpool>>>,
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
    /// The planted canary files (#81), set once at start by [`Self::set_tripwires`]; empty
    /// of effect when the operator configured no `[deception]` directories.
    tripwires: std::sync::OnceLock<deception::Tripwires>,
    /// Executables allowed to touch a canary without a detection (`[deception] allow_exe`),
    /// set once with the tripwires.
    canary_allow: std::sync::OnceLock<crate::deception::CanaryAllow>,
    /// The image each process was seen to execute, so `canary_allow` need not read `/proc`.
    exec_images: Mutex<crate::deception::ExecImages>,
    /// Canary touches by a process whose `Exec` was not recorded yet, waiting for it (#81),
    /// oldest first. Only filled when `canary_allow` lists an executable.
    held_canary: Mutex<VecDeque<HeldTouch>>,
    /// Length of `held_canary`, so the common empty case costs no lock per event.
    held_canary_len: AtomicUsize,
    /// When each `(canary, pid, incarnation of pid)` last raised a detection (event time,
    /// ns), so a tool that reads the same canary again and again raises one finding per
    /// cooldown, not one per open. Only read opens are absorbed (see [`absorbable`]);
    /// bounded; the hits it absorbs are counted in `canary_hits_absorbed`.
    canary_last_hit: Mutex<store::BoundedMap<CanaryKey, u64>>,
    canary_hits_absorbed: AtomicU64,
    /// Touches judged at once because the hold queue was full, and touches raised after a hold
    /// that ended with no allowed exec: the two outcomes of the hold that bring the false
    /// positive back, counted and logged like `canary_hits_absorbed` (#81 review).
    canary_hold_overflow: AtomicU64,
    canary_hold_expired: AtomicU64,
    /// The ransomware reflex's trigger (#82): a process that raised the burst rule and
    /// touched a canary inside one window. See [`crate::ransomware_join`].
    ransomware_join: Mutex<crate::ransomware_join::RansomwareJoin>,
}

/// The verdict entity an event belongs to: `(ppid, comm)` plus the incarnation of the
/// parent when the sensor stamped one, so a recycled parent pid does not join the
/// previous parent's entity (#592).
fn entity_key(meta: &schema::EventMeta) -> verdict::EntityKey {
    verdict::EntityKey::new(meta.ppid, meta.comm.clone())
        .with_parent_generation(meta.parent_process_generation)
}

/// The ATT&CK technique the memfd-exec rule reports (`rules`, T1620 reflective code
/// loading): the trigger for a memory scan of that process (#85).
const MEMFD_EXEC_TECHNIQUE: &str = "T1620";

/// The ATT&CK technique the ransomware rules report (T1486): its detection carries a
/// damage manifest of the process's recent renames and deletions (#82).
const RANSOMWARE_TECHNIQUE: &str = "T1486";

/// The ATT&CK technique a canary hit reports: someone looked through files nothing
/// legitimate reads (T1083 file and directory discovery). The rule id names the provenance.
const CANARY_TECHNIQUE: &str = "T1083";

/// `(canary path, pid, process incarnation)`: the incarnation, when the sensor stamps one,
/// keeps a process that reuses the pid inside the cooldown from being absorbed as its
/// predecessor.
type CanaryKey = (PathBuf, u32, Option<u64>);

/// Open flags that mean write intent on Linux (`O_WRONLY | O_RDWR | O_CREAT`), the same
/// mask the YARA trigger uses. On a platform whose flags mean something else the mask can
/// only let more opens through, never absorb more.
const WRITE_INTENT_FLAGS: u32 = 0o103;

/// Whether a repeat of this touch may be absorbed by the cooldown. Only a read open may: a
/// delete, a rename or a write-intent open is the destructive touch an encryptor makes after
/// reading, and absorbing it behind the first open would hide the one finding an analyst
/// needs. Those always raise a detection (bounded by the number of canaries).
fn absorbable(touch: &deception::Touch) -> bool {
    matches!(touch, deception::Touch::Open { flags } if flags & WRITE_INTENT_FLAGS == 0)
}

/// How long one process's repeat touches of one canary are absorbed after a detection.
const CANARY_COOLDOWN_NS: u64 = 60 * 1_000_000_000;

/// How long (event time) a canary touch by a process whose `Exec` the sink has not recorded
/// waits for it before it is judged on what is known. The sensor stamps an `exec` before the
/// open that follows it, but the merged stream can deliver the open first: on the lab VM the
/// open of a cron-started `tar` came about 80 events before its own `exec`, and the process had
/// already exited, so `/proc` said nothing and the allow list refused it (#81). Half a second
/// is far longer than that lag and short for a detection that is not corroborated by anything.
const CANARY_EXEC_HOLD_NS: u64 = 500_000_000;

/// Most touches held at once. A host with an allow list under an open flood must not grow
/// this without bound, and a flood must not be a way to delay findings: past the bound a
/// touch is judged at once, as it was before the hold existed.
const MAX_HELD_CANARY_TOUCHES: usize = 256;

/// Most `(canary, pid)` pairs the cooldown remembers; the oldest are evicted first, which
/// at worst lets one more detection through.
const CANARY_COOLDOWN_KEYS: usize = 1024;

/// The reason the audit line gives when the ransomware reflex kills (#82). A trigger of its
/// own, never severity or the Bayes gate: it needs both the burst rule and a canary touch
/// from the same process (`crate::ransomware_join`).
const RANSOMWARE_REFLEX_REASON: &str =
    "a corroborated ransomware signal (burst rule + canary touch)";

/// `DetectionSource::Rule` id of a canary hit. `DetectionSource` is part of the
/// semi-frozen schema, so deception provenance rides in the rule id until a dedicated
/// variant is decided (#81).
const CANARY_RULE_ID: &str = "DECEPTION-CANARY";

/// What the allow list makes of a canary touch.
enum CanaryVerdict {
    /// The toucher runs an allowed executable.
    Allowed,
    /// Not allowed by what the sink knows, and `/proc` names no executable (the process already
    /// exited): an `Exec` may still be on its way, either the first (none recorded) or the last of
    /// several. A process `/proc` shows running something else is not unknown, it is not allowed:
    /// `/proc` is read after the touch, so it shows the image the touch was made by or a later one.
    Unknown,
    /// Not allowed, and nothing more to wait for.
    Raise,
}

/// A canary touch waiting for the `Exec` of its process (#81).
struct HeldTouch {
    event: Event,
    /// Event time of the touch, ns: the hold runs from it, and only an `exec` at or before it
    /// can excuse the touch.
    since_ns: u64,
    /// The latest image of this incarnation exec'd at or before the touch, as far as the sink has
    /// seen one. The final verdict is taken on it, not on the table's newest entry, which a
    /// later `exec` (one the touch cannot have been made by) may have replaced.
    image: Option<crate::deception::ExecImage>,
}

/// Most renames and deletions a ransomware detection carries beyond its triggering event.
/// A bound on the size of one detection: the correlator window is 60 s, and a fast
/// encryptor renames far more than this in it.
const DAMAGE_MANIFEST_MAX: usize = 100;

/// The escalation decision (#612) as a free function so the YARA scan worker, which
/// has no `DetectionSink`, raises the same alert as every other engine (#614). A new
/// verdict snapshot (first sighting, a severity raise, or a recurrence outside the
/// dedup window — never a silently absorbed duplicate) whose composed severity
/// warrants it raises one `RESPONSE-ESCALATE` audit alert. Never kills or
/// quarantines, and works with or without `enable_response`.
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

/// Records one finding: fused into the verdict, written to the alert log, and
/// escalated when the fused severity warrants it, then handed to `persist` (the
/// durable detection spool, when one is configured). A free function so the
/// enrichment worker, which has no `DetectionSink`, records the signature-gated
/// findings the same way (#441).
///
/// The worker records a gated finding when it reaches the event, so it can enter
/// the verdict after findings the capture thread already recorded for later
/// events of the same entity. Fusion keys on the event's own timestamp and its
/// dedup check saturates, so a late arrival can at most be absorbed as a
/// duplicate, never reopen a window; only the order of the evidence list differs.
fn record_detection(
    verdict: &Mutex<verdict::VerdictEngine>,
    alert_log: &AlertLog,
    finding: Finding<'_>,
    event: &Event,
    evidence: Vec<Event>,
    persist: Option<&dyn Fn(schema::detection::Detection)>,
) -> Option<verdict::Verdict> {
    let now_ns = event.meta().timestamp_ns;
    // Rules and Sigma have already evaluated the raw event/message. Redact only
    // the copy that enters the verdict, alert log, and durable detection spool.
    let safe_message = if let Some(Event::Exec(exec)) = std::iter::once(event)
        .chain(evidence.iter())
        .find(|e| matches!(e, Event::Exec(_)))
    {
        let mut safe_exec = Event::Exec(exec.clone());
        crate::redact::redact_event(&mut safe_exec);
        let Event::Exec(safe_exec) = safe_exec else {
            unreachable!()
        };
        redact_detection_message(&exec.cmdline, &safe_exec.cmdline, finding.message)
    } else {
        finding.message.to_owned()
    };
    let mut safe_events: Vec<Event> = std::iter::once(event.clone()).chain(evidence).collect();
    for event in &mut safe_events {
        crate::redact::redact_event(event);
    }
    let detection = schema::detection::Detection {
        timestamp_ns: now_ns,
        severity: finding.severity,
        title: safe_message.clone(),
        source: finding.source,
        score: None,
        attributions: Vec::new(),
        techniques: techniques_from(finding.technique),
        events: safe_events,
    };
    let spooled = persist.map(|_| detection.clone());
    let result = verdict.lock().unwrap().record(
        finding.entity.clone(),
        finding.technique,
        detection,
        now_ns,
    );
    alert_log.record(finding.technique, safe_message);
    if let Some(fused) = &result {
        escalate_if_warranted(alert_log, fused);
    }
    if let (Some(persist), Some(detection)) = (persist, spooled) {
        persist(detection);
    }
    result
}

fn redact_detection_message(raw_cmdline: &str, safe_cmdline: &str, message: &str) -> String {
    if raw_cmdline.is_empty() {
        message.to_owned()
    } else {
        message.replace(raw_cmdline, safe_cmdline)
    }
}

/// One engine's finding, as [`record_detection`] takes it.
struct Finding<'a> {
    entity: &'a verdict::EntityKey,
    technique: &'a str,
    message: &'a str,
    source: schema::detection::DetectionSource,
    severity: schema::detection::Severity,
}

/// [`record_detection`] for one `rules::Alert`.
fn record_rule_alert(
    verdict: &Mutex<verdict::VerdictEngine>,
    alert_log: &AlertLog,
    event: &Event,
    alert: &rules::Alert,
    persist: Option<&dyn Fn(schema::detection::Detection)>,
) {
    let finding = Finding {
        entity: &entity_key(event.meta()),
        technique: alert.technique,
        message: &alert.message,
        source: schema::detection::DetectionSource::Rule {
            rule_id: alert.technique.to_string(),
        },
        severity: alert.severity,
    };
    record_detection(verdict, alert_log, finding, event, Vec::new(), persist);
}

/// [`record_detection`] for one IOC match (#60). The worker records it for an exec image, the
/// capture thread through [`DetectionSink::record_ioc`] for a connect.
fn record_ioc_hit(
    verdict: &Mutex<verdict::VerdictEngine>,
    alert_log: &AlertLog,
    event: &Event,
    hit: crate::ioc::IocHit,
    persist: Option<&dyn Fn(schema::detection::Detection)>,
) {
    let message = hit.message(&event.meta().comm);
    let severity = hit.severity();
    let finding = Finding {
        entity: &entity_key(event.meta()),
        technique: crate::ioc::IOC_TECHNIQUE,
        message: &message,
        source: ioc_source(hit),
        severity,
    };
    record_detection(verdict, alert_log, finding, event, Vec::new(), persist);
}

fn ioc_source(hit: crate::ioc::IocHit) -> schema::detection::DetectionSource {
    schema::detection::DetectionSource::Ioc {
        kind: hit.kind,
        indicator: hit.indicator,
        feed: hit.feed,
        feed_version: hit.feed_version,
        reference: None,
    }
}

/// The enrichment worker's append to the durable detection spool. A failure
/// loses only the upload copy: the finding is already in the alert log.
fn spool_on_worker(
    spool: Option<&Mutex<store::EventSpool>>,
    detection: schema::detection::Detection,
) {
    if let Some(spool) = spool
        && let Err(e) = crate::upload::persist_detection(spool, detection)
    {
        tracing::warn!(error = %e, "detection spool append failed");
    }
}

/// What the enrichment learnt about an exec's image. `chain_verified`: the
/// verdict is Authenticode, whose `Valid` is a chain to a trusted root; macOS
/// `codesign` and the ES flags call ad-hoc signatures valid too.
fn image_signature(event: &Event) -> rules::ImageSignature {
    rules::ImageSignature {
        verdict: match event {
            Event::Exec(e) => e.signature,
            _ => None,
        },
        chain_verified: cfg!(windows),
    }
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

/// Why the kill gate refuses a system service's main process (#652, ADR-0028).
// Review of #755 (SherlockOmss, 2026-10-19): the old wording ("package-owned
// binary") claimed more than `service_main_path_is_trusted` checks — nothing
// here asks whether a package actually owns the file, only where it lives and
// who started it. An analyst reading `alerts.ndjson` would otherwise take
// "package-owned" as verified.
const SERVICE_MAIN_REFUSAL: &str = "main process of a system service (image under a system path, started by init); escalated, not killed";

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
    if technique == "BAYES" || technique == "Sigma" || technique == crate::ioc::IOC_TECHNIQUE {
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
    /// Starts the one-second clock that expires pending web-shell correlations even
    /// when the sensor has stopped producing events. The worker holds only a `Weak`
    /// reference while sleeping, and releases the correlator mutex before log I/O.
    pub(crate) fn start_correlator_ticker(self: &Arc<Self>) -> std::io::Result<()> {
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

    fn advance_correlation_time(&self, now_ns: u64) {
        let alerts = {
            let mut correlator = self.correlator.lock().unwrap();
            correlator.advance_time(now_ns)
        };
        // BAYES is the only technique `crosses_kill_gate` recognizes, and it is raised
        // only from the per-event path below (`CorrelationEngine::bayes_alert`'s one call
        // site), never from `advance_time`'s window-expiry alerts — so `service_main`
        // is never read on this path, and `false` is a placeholder, not a real claim
        // about any pid here (issue #652).
        self.emit_correlator_alerts(&alerts, None, false);
    }

    /// `service_main` is the correlator's provenance verdict for the event this batch of
    /// alerts was produced from (issue #652) — meaningful only when a `BAYES` alert is
    /// among them, since that is the only technique [`crosses_kill_gate`] recognizes, and
    /// `CorrelationAlert::trigger_event` is always `None` for it (so it always resolves to
    /// `default_event`, never to a different pid than the one `service_main` was computed
    /// for).
    fn emit_correlator_alerts(
        &self,
        alerts: &[correlator::CorrelationAlert],
        default_event: Option<&Event>,
        service_main: bool,
    ) {
        let mut high_confidence_pid = None;
        for alert in alerts {
            let Some(event) = alert.trigger_event.as_deref().or(default_event) else {
                continue;
            };
            let entity = entity_key(event.meta());
            let case_id = correlator_case_id(&entity);
            let source = schema::detection::DetectionSource::Correlator { case_id };
            self.record_and_emit(
                &entity,
                alert.technique,
                &alert.message,
                source,
                alert.severity,
                event,
            );
            if crosses_kill_gate(alert.technique) {
                high_confidence_pid = Some(event.meta().pid);
            }
        }
        if let Some(pid) = high_confidence_pid {
            self.maybe_kill(pid, service_main);
        }
    }

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
        detection_spool: Option<Arc<Mutex<store::EventSpool>>>,
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
        let verdict = Arc::new(Mutex::new(verdict::VerdictEngine::new(
            VERDICT_DEDUP_WINDOW_NS,
        )));
        // Shared with the enrichment worker, which learns an exec's hash after it was correlated
        // and feeds the rarity evidence back (ADR-0020, #76).
        let correlator = Arc::new(Mutex::new(correlator::CorrelationEngine::new()));
        let common_set = Arc::new(Mutex::new(
            load_common_set(&content_root).into_option().map(Arc::new),
        ));
        let rarity_stats = Arc::new(RarityStats::default());
        let (rarity_correlator, rarity_common_set, worker_rarity_stats) =
            (correlator.clone(), common_set.clone(), rarity_stats.clone());
        let ioc = Arc::new(crate::ioc::IocMatcher::new(&content_root));
        let worker_ioc = ioc.clone();
        let (gate_verdict, gate_alert_log) = (verdict.clone(), alert_log.clone());
        let (gate_spool, worker_spool) = (detection_spool.clone(), detection_spool.clone());
        let enrich_queue = EnrichQueue::start_with_detections(
            enrich::Enricher::new(),
            move |event, gated| {
                if let Some(alert) = gated.and_then(|gated| gated.resolve(image_signature(&event)))
                {
                    // Already on the worker: append directly, no trip through the queue.
                    let persist = |detection| spool_on_worker(gate_spool.as_deref(), detection);
                    let persist = gate_spool.as_ref().map(|_| &persist as &dyn Fn(_));
                    record_rule_alert(&gate_verdict, &gate_alert_log, &event, &alert, persist);
                }
                if let Event::Exec(exec) = &event
                    && let Some(hit) =
                        worker_ioc.check_exec_image(exec.sha256.as_deref(), exec.meta.timestamp_ns)
                {
                    let persist = |detection| spool_on_worker(gate_spool.as_deref(), detection);
                    let persist = gate_spool.as_ref().map(|_| &persist as &dyn Fn(_));
                    record_ioc_hit(&gate_verdict, &gate_alert_log, &event, hit, persist);
                }
                if let Event::Exec(exec) = &event {
                    note_image_rarity(
                        &rarity_correlator,
                        &rarity_common_set,
                        &worker_rarity_stats,
                        exec,
                        unix_now_secs(),
                    );
                }
                let mut safe_event = event.clone();
                crate::redact::redact_event(&mut safe_event);
                if let Some(events_log) = &events_log {
                    events_log.write(&safe_event);
                }
                if let Some(spool) = &spool
                    && let Err(e) = spool.lock().unwrap().push(&safe_event)
                {
                    // Spool full is handled inside push (shed-oldest, counted);
                    // reaching here is a real I/O failure — degrade to local-only.
                    tracing::warn!(error = %e, "spool append failed — event stays local-only");
                }
            },
            move |detection| spool_on_worker(worker_spool.as_deref(), detection),
        );
        let response: Arc<Mutex<Option<ResponseHooks>>> = Arc::new(Mutex::new(None));
        Ok(Self {
            rule_state: Mutex::new(rule_state),
            correlator,
            ml_scorer: Mutex::new(Self::load_correlation_scorer(model_root)),
            sigma: Mutex::new(load_sigma_rules(&content_root).into_option()),
            common_set,
            ioc,
            rarity_stats,
            tamper_events: AtomicU64::new(0),
            yara: Mutex::new(
                start_yara(
                    &content_root,
                    alert_log.clone(),
                    response.clone(),
                    verdict.clone(),
                )
                .into_option(),
            ),
            memscan: Mutex::new(
                start_memscan(&content_root, alert_log.clone(), verdict.clone()).into_option(),
            ),
            alert_log,
            enrich_queue,
            detection_spool,
            progress: Arc::new(AtomicU64::new(0)),
            response,
            verdict,
            content_root,
            tripwires: std::sync::OnceLock::new(),
            canary_allow: std::sync::OnceLock::new(),
            exec_images: Mutex::new(crate::deception::ExecImages::new()),
            held_canary: Mutex::new(VecDeque::new()),
            held_canary_len: AtomicUsize::new(0),
            canary_last_hit: Mutex::new(store::BoundedMap::new(CANARY_COOLDOWN_KEYS)),
            canary_hits_absorbed: AtomicU64::new(0),
            canary_hold_overflow: AtomicU64::new(0),
            canary_hold_expired: AtomicU64::new(0),
            ransomware_join: Mutex::new(crate::ransomware_join::RansomwareJoin::new()),
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
        let memscan_loaded = start_memscan(
            &self.content_root,
            self.alert_log.clone(),
            self.verdict.clone(),
        );

        let common_set_loaded = load_common_set(&self.content_root);

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

        self.swap_common_set(common_set_loaded);
        self.ioc.reload(&self.content_root);

        // Same rules, same posture as the file scanner: absent unloads, broken keeps
        // the previous queue (its failure is already reported through `yara`).
        let mut memscan_slot = self.memscan.lock().unwrap();
        let old_memscan = match memscan_loaded {
            Load::Loaded(queue) => memscan_slot.replace(queue),
            Load::Absent => memscan_slot.take(),
            Load::Failed => None,
        };
        drop(memscan_slot);
        drop(old_memscan);

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
        self.record_and_emit_with(
            entity,
            technique,
            message,
            source,
            severity,
            event,
            Vec::new(),
        )
    }

    /// [`Self::record_and_emit`] with further evidence events after the triggering one.
    #[allow(
        clippy::too_many_arguments,
        reason = "one more than the plain call: the extra evidence, appended after the trigger"
    )]
    fn record_and_emit_with(
        &self,
        entity: &verdict::EntityKey,
        technique: &str,
        message: &str,
        source: schema::detection::DetectionSource,
        severity: schema::detection::Severity,
        event: &Event,
        evidence: Vec<Event>,
    ) -> Option<verdict::Verdict> {
        let finding = Finding {
            entity,
            technique,
            message,
            source,
            severity,
        };
        let persist = |detection| self.spool_detection(detection);
        let persist = self
            .detection_spool
            .as_ref()
            .map(|_| &persist as &dyn Fn(_));
        record_detection(
            &self.verdict,
            &self.alert_log,
            finding,
            event,
            evidence,
            persist,
        )
    }

    /// Hands a finding to the worker for the durable detection spool.
    fn spool_detection(&self, detection: schema::detection::Detection) {
        if let Err(detection) = self.enrich_queue.enqueue_detection(detection) {
            // The queue is full, so the capture thread does this file append
            // itself, which the #126 design otherwise keeps off it. Under sustained
            // overload every finding takes this path; accepted on purpose (a finding
            // is never lost), and only reached once the queue is already shedding.
            tracing::warn!("detection queue full; persisting on capture thread");
            if let Some(spool) = &self.detection_spool
                && let Err(e) = crate::upload::persist_detection(spool, *detection)
            {
                tracing::error!(error = %e, "detection spool append failed on fallback");
            }
        }
    }

    /// Asks for a budgeted YARA scan of the memory of the process behind `event` (#85):
    /// the payload of a fileless exec exists only there. The scan queue applies the
    /// cooldown, the global cap and the per-scan budget; a shed request is counted there.
    fn request_memory_scan(&self, event: &Event) {
        let guard = self.memscan.lock().unwrap();
        let Some(queue) = guard.as_ref() else {
            return;
        };
        let meta = event.meta();
        queue.enqueue(
            meta.pid,
            meta.process_generation,
            meta.timestamp_ns,
            Some(yara::ScanContext {
                ppid: meta.ppid,
                comm: meta.comm.clone(),
                parent_generation: meta.parent_process_generation,
                timestamp_ns: meta.timestamp_ns,
                // The #594 gate is about reading a path the requester named, as the agent
                // with `CAP_DAC_READ_SEARCH`. A memory scan reads no named path: it reads
                // `/proc/<pid>/mem`, which the kernel gates by `ptrace_may_access` (ADR-0023).
                requester: None,
            }),
        );
    }

    /// Installs the planted canaries (#81). Called once, before the sensor starts; a second
    /// call is ignored.
    pub(crate) fn set_tripwires(&self, tripwires: deception::Tripwires) {
        let _ = self.tripwires.set(tripwires);
    }

    /// Installs the executables allowed to touch a canary (#81). Called once, with the
    /// tripwires.
    pub(crate) fn set_canary_allow(&self, allow: crate::deception::CanaryAllow) {
        let _ = self.canary_allow.set(allow);
    }

    /// A touch of a planted canary by any process but the agent itself is a detection:
    /// nothing legitimate reads these files. The agent's own pid is skipped because it
    /// writes them at start and verifies them later.
    ///
    /// When the process is unknown (no `Exec` recorded for this incarnation) and an
    /// executable is allowed, the decision waits up to [`CANARY_EXEC_HOLD_NS`] for its `Exec`
    /// ([`Self::hold_canary`]): the stream can deliver the open before the exec it follows.
    fn detect_canary(&self, event: &Event) {
        let Some(tripwires) = self.tripwires.get() else {
            return;
        };
        let Some(hit) = tripwires.matches(event) else {
            return;
        };
        if hit.pid == std::process::id() {
            return;
        }
        let seen = self.image_before(hit.pid, event);
        match self.canary_verdict(hit.pid, seen.as_ref()) {
            CanaryVerdict::Allowed => {
                tracing::debug!(
                    pid = hit.pid,
                    "deception: canary touch by an allowed executable"
                );
                return;
            }
            CanaryVerdict::Unknown if self.hold_canary(event, seen) => return,
            CanaryVerdict::Unknown | CanaryVerdict::Raise => {}
        }
        self.raise_canary(event, false);
    }

    /// The image the table holds for the process that made `event`, when it exec'd at or before
    /// the touch: a later `exec` of the same process (an allowed `tar` run after an open by
    /// something else) must not excuse a touch it did not make.
    fn image_before(&self, pid: u32, event: &Event) -> Option<crate::deception::ExecImage> {
        let meta = event.meta();
        // Cloned out so the lock is not held across the `/proc` fallback inside `allows`:
        // `detect_exec` takes it for every exec event.
        self.exec_images
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .image_of_not_after(pid, meta.process_generation, meta.timestamp_ns)
    }

    /// What the allow list says about the process `pid`, given the image it was seen to exec.
    fn canary_verdict(
        &self,
        pid: u32,
        seen: Option<&crate::deception::ExecImage>,
    ) -> CanaryVerdict {
        let Some(allow) = self.canary_allow.get() else {
            return CanaryVerdict::Raise;
        };
        if allow.allows(pid, seen) {
            CanaryVerdict::Allowed
        } else if !allow.is_empty()
            && !allow.refuses_outright(pid, seen)
            && !allow.proc_names_an_exe(pid)
        {
            CanaryVerdict::Unknown
        } else {
            CanaryVerdict::Raise
        }
    }

    /// Holds `event` until the hold runs out, for the `Exec` of its process to be recorded.
    /// False when the queue is full: the caller then judges the touch at once, and the
    /// overflow is counted (it brings the false positive back without a trace otherwise).
    fn hold_canary(&self, event: &Event, image: Option<crate::deception::ExecImage>) -> bool {
        let mut held = self
            .held_canary
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if held.len() >= MAX_HELD_CANARY_TOUCHES {
            let overflowed = self.canary_hold_overflow.fetch_add(1, Ordering::Relaxed) + 1;
            if overflowed.is_power_of_two() {
                tracing::warn!(
                    overflowed_total = overflowed,
                    "deception: canary hold queue full, touch judged without waiting for its exec"
                );
            }
            return false;
        }
        held.push_back(HeldTouch {
            event: event.clone(),
            since_ns: event.meta().timestamp_ns,
            image,
        });
        self.held_canary_len.store(held.len(), Ordering::Relaxed);
        true
    }

    /// Records, on the held touches of the incarnation that has just exec'd, the image of this
    /// exec when it happened at or before the touch (the latest such one wins: a process may exec
    /// more than once, `bash -c "tar ..."` is `bash`, then `tar` in one pid). An exec after the
    /// touch says nothing about who made it and is ignored. The decision itself is taken when
    /// the hold ends ([`Self::judge_held`]).
    ///
    /// An exec without a generation never counts: a pid reused within the hold would match the
    /// touch of its previous life.
    fn record_exec_on_held(&self, exec: &schema::ExecEvent) {
        let generation = exec.meta.process_generation;
        if generation.is_none() || self.held_canary_len.load(Ordering::Relaxed) == 0 {
            return;
        }
        let image = crate::deception::ExecImage::from_exec(exec);
        let mut held = self
            .held_canary
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for touch in held.iter_mut() {
            let meta = touch.event.meta();
            if meta.pid == exec.meta.pid
                && meta.process_generation == generation
                && image.precedes(touch.since_ns)
                && touch
                    .image
                    .as_ref()
                    .is_none_or(|previous| previous.precedes(image.timestamp_ns()))
            {
                touch.image = Some(image.clone());
            }
        }
    }

    /// Judges the held touches older than the hold, at event time `now_ns`.
    fn expire_held_canary(&self, now_ns: u64) {
        if self.held_canary_len.load(Ordering::Relaxed) == 0 {
            return;
        }
        let due =
            self.take_held(|held| now_ns.saturating_sub(held.since_ns) >= CANARY_EXEC_HOLD_NS);
        self.judge_held(due);
    }

    /// Removes and returns the held touches `pick` selects, oldest first.
    fn take_held(&self, pick: impl Fn(&HeldTouch) -> bool) -> Vec<HeldTouch> {
        let mut held = self
            .held_canary
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut taken = Vec::new();
        let mut kept = VecDeque::new();
        for touch in held.drain(..) {
            if pick(&touch) {
                taken.push(touch);
            } else {
                kept.push_back(touch);
            }
        }
        *held = kept;
        self.held_canary_len.store(held.len(), Ordering::Relaxed);
        taken
    }

    /// The final decision on touches that waited: allowed ones are dropped, every other is
    /// raised (and counted as expired), whether its exec arrived or not.
    fn judge_held(&self, touches: Vec<HeldTouch>) {
        for held in touches {
            let pid = held.event.meta().pid;
            if matches!(
                self.canary_verdict(pid, held.image.as_ref()),
                CanaryVerdict::Allowed
            ) {
                tracing::debug!(pid, "deception: held canary touch by an allowed executable");
                continue;
            }
            let expired = self.canary_hold_expired.fetch_add(1, Ordering::Relaxed) + 1;
            if expired.is_power_of_two() {
                tracing::info!(
                    expired_total = expired,
                    "deception: held canary touch raised, no allowed exec before it"
                );
            }
            self.raise_canary(&held.event, true);
        }
    }

    /// Records the detection for a canary touch that no allow-list entry excuses, and the
    /// ransomware reflex when the same process also burst.
    ///
    /// `late` is a touch that waited out the hold. The ransomware reflex does not kill from it:
    /// `/proc` named nothing for the process when it was held, so by now it is gone or its pid
    /// is someone else's, and the reflex kills by pid.
    fn raise_canary(&self, event: &Event, late: bool) {
        let Some(tripwires) = self.tripwires.get() else {
            return;
        };
        let Some(hit) = tripwires.matches(event) else {
            return;
        };
        let meta = event.meta();
        let corroborated = self.ransomware_join.lock().unwrap().note_canary(
            hit.pid,
            meta.process_generation,
            meta.timestamp_ns,
        );
        if absorbable(&hit.touch)
            && self.canary_in_cooldown(
                (hit.canary.path.clone(), hit.pid, meta.process_generation),
                meta.timestamp_ns,
            )
        {
            let absorbed = self.canary_hits_absorbed.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::debug!(
                pid = hit.pid,
                absorbed,
                "deception: repeat canary touch absorbed"
            );
            // The finding was raised by the touch that started the cooldown; the reflex
            // does not wait for a new one.
            if corroborated && !late {
                self.ransomware_reflex(hit.pid);
            }
            return;
        }
        let message = format!(
            "canary file touched: {} ({:?}) by pid {} ({})",
            hit.canary.path.display(),
            hit.touch,
            hit.pid,
            meta.comm
        );
        self.record_and_emit_with(
            &entity_key(meta),
            CANARY_TECHNIQUE,
            &message,
            schema::detection::DetectionSource::Rule {
                rule_id: CANARY_RULE_ID.to_string(),
            },
            schema::detection::Severity::High,
            event,
            Vec::new(),
        );
        if corroborated && !late {
            self.ransomware_reflex(hit.pid);
        } else if corroborated {
            tracing::info!(
                pid = hit.pid,
                "deception: ransomware reflex skipped for a canary touch judged after the hold"
            );
        }
    }

    /// True when `key` already raised a detection within the cooldown; otherwise records
    /// this touch as the one that did.
    fn canary_in_cooldown(&self, key: CanaryKey, now_ns: u64) -> bool {
        let mut last = self.canary_last_hit.lock().unwrap();
        if let Some(&at) = last.peek(&key)
            && now_ns.saturating_sub(at) < CANARY_COOLDOWN_NS
        {
            return true;
        }
        last.insert(key, now_ns);
        false
    }

    /// An IOC match found on the capture thread (a connect's destination, #60).
    fn record_ioc(&self, event: &Event, hit: crate::ioc::IocHit) {
        let message = hit.message(&event.meta().comm);
        let severity = hit.severity();
        self.record_and_emit_with(
            &entity_key(event.meta()),
            crate::ioc::IOC_TECHNIQUE,
            &message,
            ioc_source(hit),
            severity,
            event,
            Vec::new(),
        );
    }

    /// [`Self::record_and_emit`] for a batch of plain `rules::Alert`s (no Sigma/
    /// correlator-specific `DetectionSource` needed) — the common case for every
    /// `rule_state`/`rules::evaluate_*` call site.
    fn record_rule_alerts(&self, event: &Event, alerts: impl IntoIterator<Item = rules::Alert>) {
        let entity = entity_key(event.meta());
        for alert in alerts {
            if alert.technique == MEMFD_EXEC_TECHNIQUE {
                self.request_memory_scan(event);
            }
            let source = schema::detection::DetectionSource::Rule {
                rule_id: alert.technique.to_string(),
            };
            let is_burst = alert.technique == RANSOMWARE_TECHNIQUE;
            let corroborated = is_burst && self.note_ransomware_burst(event);
            let manifest = if is_burst {
                self.damage_manifest(event)
            } else {
                Vec::new()
            };
            self.record_and_emit_with(
                &entity,
                alert.technique,
                &alert.message,
                source,
                alert.severity,
                event,
                manifest,
            );
            if corroborated {
                self.ransomware_reflex(event.meta().pid);
            }
        }
    }

    /// The damage manifest of a ransomware alert (issue #82): the file renames and
    /// deletions of the alerting process incarnation that the rule state remembers (the
    /// newest `DAMAGE_MANIFEST_MAX`), oldest first, without the triggering event (which is
    /// the detection's first event already). It rides in `Detection::events`, so no schema
    /// change: the control plane keeps events after the first as the detection's further
    /// triggering events, and a restoration tool reads the scope from them.
    ///
    /// Takes the rule-state lock: callers must not hold it (see `detect_file_rename`).
    fn damage_manifest(&self, trigger: &Event) -> Vec<Event> {
        let meta = trigger.meta();
        let mut touched = self
            .rule_state
            .lock()
            .unwrap()
            .touched_files(meta.pid, meta.process_generation);
        touched.retain(|e| e != trigger);
        let excess = touched.len().saturating_sub(DAMAGE_MANIFEST_MAX);
        touched.drain(..excess);
        touched
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

        let service_main = engine.is_service_main_process(pid, generation);
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
        self.emit_correlator_alerts(&alerts, Some(event), service_main);
    }

    /// Issue #25: policy-gates killing the process behind a high-confidence
    /// correlated verdict. A no-op whenever `enable_response` was never called.
    ///
    /// Issue #652: `service_main` is the correlator's provenance verdict for `pid` (its
    /// image under a system path, started by init — see the comment above
    /// `SERVICE_MAIN_REFUSAL`'s definition for why this is not phrased as "package-owned").
    /// A Bayesian crossing alone does not
    /// justify killing a system service, so it is refused, in observe mode too, and the
    /// verdict still escalates. Corroborating evidence does not lift it: the refusal is
    /// about what the process is, not how much evidence there is (ADR-0028).
    fn maybe_kill(&self, pid: u32, service_main: bool) {
        self.kill_for(pid, "a high-confidence correlated verdict", service_main);
    }

    /// The policy-gated kill behind every automated trigger; `reason` names which one, in
    /// the audit line (`RESPONSE-KILL`). `service_main` makes it refuse (ADR-0028); only the
    /// correlator's verdict sets it, a trigger with its own evidence (the ransomware reflex)
    /// passes `false`.
    fn kill_for(&self, pid: u32, reason: &str, service_main: bool) {
        let guard = self.response.lock().unwrap();
        let Some(hooks) = guard.as_ref() else {
            return;
        };
        let outcome = if service_main {
            response::KillOutcome::Refused {
                pid,
                reason: SERVICE_MAIN_REFUSAL,
            }
        } else {
            response::kill_process(pid, &hooks.policy, |p| (hooks.terminate)(p))
        };
        drop(guard);
        let message = match outcome {
            response::KillOutcome::Killed { pid } => format!("killed pid {pid} on {reason}"),
            response::KillOutcome::ObserveOnly { pid } => {
                format!("pid {pid} would have been killed on {reason} (observe-only)")
            }
            response::KillOutcome::Failed { pid, error } => {
                format!("failed to kill pid {pid} on {reason}: {error}")
            }
            response::KillOutcome::Refused { pid, reason: why } => {
                format!("refused to kill pid {pid} on {reason}: {why}")
            }
        };
        self.emit("RESPONSE-KILL", &message);
    }

    /// The process behind `event` raised the ransomware burst rule (#82). True when it also
    /// touched a canary in the window: the corroborated signal. The caller records the
    /// detection first and then calls [`Self::ransomware_reflex`].
    fn note_ransomware_burst(&self, event: &Event) -> bool {
        let meta = event.meta();
        self.ransomware_join.lock().unwrap().note_burst(
            meta.pid,
            meta.process_generation,
            meta.timestamp_ns,
        )
    }

    /// The reflex: the policy-gated kill of the corroborated process. Observe-only unless
    /// kill is enabled, like every other automated kill.
    fn ransomware_reflex(&self, pid: u32) {
        self.kill_for(pid, RANSOMWARE_REFLEX_REASON, false);
    }

    /// Exec events: stateless rules, stateful rules, then Sigma.
    fn detect_exec(&self, wrapped: &Event, event: &schema::ExecEvent) {
        // The table is read only when an executable may be allowed: recording every exec of a
        // host that allows none would take a lock and clone a path for nothing.
        if self
            .canary_allow
            .get()
            .is_some_and(|allow| !allow.is_empty())
        {
            self.exec_images
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .record(event);
            self.record_exec_on_held(event);
        }
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
            let requester = match meta.user {
                schema::User::Unix { uid, gid } => Some(yara::Requester { uid, gid }),
                // No uid to check on this platform: scanned as before.
                _ if !cfg!(unix) => None,
                // On unix a user the sensor could not resolve must not fall through to
                // the unrestricted read, which runs with `CAP_DAC_READ_SEARCH` (#594).
                _ => {
                    tracing::warn!(
                        pid = meta.pid,
                        path = %event.path,
                        "yara: not scanning a path opened by a user the sensor could not resolve"
                    );
                    return;
                }
            };
            yara.enqueue_for(
                std::path::PathBuf::from(&event.path),
                yara::ScanContext {
                    ppid: meta.ppid,
                    comm: meta.comm.clone(),
                    parent_generation: meta.parent_process_generation,
                    timestamp_ns: meta.timestamp_ns,
                    // The path is whatever the process named, even when the kernel
                    // refused the open: scan it only if that user could read it (#594).
                    requester,
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

    /// `BitsJob` events (Windows BITS-Client): recorded for the T1197
    /// download→exec join, no alert on their own (#284).
    fn detect_bits_job(&self, event: &schema::BitsJobEvent) {
        self.rule_state.lock().unwrap().on_bits_job(event);
    }

    /// Connect events: stateless rules (unusual outbound from a web/DB
    /// service, issue #478), then beacon detection.
    fn detect_connect(&self, wrapped: &Event, event: &schema::ConnectEvent) {
        if let Some(hit) = self.ioc.check_connect(event.daddr, event.meta.timestamp_ns) {
            self.record_ioc(wrapped, hit);
        }
        self.record_rule_alerts(wrapped, rules::evaluate_connect(event));
        self.record_rule_alerts(wrapped, self.rule_state.lock().unwrap().on_connect(event));
    }

    /// `DnsQuery` events: the egress-domain join (it never alerts) and, on a listed domain or
    /// one of its subdomains, an IOC finding (#60).
    fn detect_dns_query(&self, wrapped: &Event, event: &schema::DnsQueryEvent) {
        if let Some(hit) = self
            .ioc
            .check_dns_query(&event.query, event.meta.timestamp_ns)
        {
            self.record_ioc(wrapped, hit);
        }
        self.rule_state.lock().unwrap().on_dns_query(event);
    }

    /// `NetworkFlow` events (conntrack polling, issue #92): same beacon detection as
    /// `detect_connect`, deduped per-flow so a poll-based source doesn't
    /// false-positive on one ordinary long-lived connection. The peer address is also checked
    /// against the IOC set (#60); every poll of one live flow repeats it, which the per-indicator
    /// cooldown absorbs.
    fn detect_network_flow(&self, wrapped: &Event, event: &schema::NetworkFlowEvent) {
        if let Some(hit) = self.ioc.check_connect(event.daddr, event.meta.timestamp_ns) {
            self.record_ioc(wrapped, hit);
        }
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

    /// `PolicyDenial` events (`SELinux` AVC #297, AppLocker/WDAC #283):
    /// POLICY-DENIAL-DRIFT (issue #774).
    fn detect_policy_denial(&self, wrapped: &Event, event: &schema::PolicyDenialEvent) {
        self.record_rule_alerts(
            wrapped,
            self.rule_state.lock().unwrap().on_policy_denial(event),
        );
    }

    /// `Auth` events: brute-force/spray burst detection (T1110, pack #377).
    fn detect_auth(&self, wrapped: &Event, event: &schema::AuthEvent) {
        self.record_rule_alerts(wrapped, self.rule_state.lock().unwrap().on_auth(event));
    }

    /// `Session` events: a disconnected session reconnected from another client
    /// (T1563.002, #285).
    fn detect_session(&self, wrapped: &Event, event: &schema::SessionEvent) {
        self.record_rule_alerts(wrapped, self.rule_state.lock().unwrap().on_session(event));
    }

    /// `FileDelete` events: log-tamper detection (T1070.001/.002, pack #379), then the
    /// unlink half of the write-new-then-unlink T1486 shape (#512 part B), which needs
    /// the creation history `on_file_open` keeps.
    fn detect_file_delete(&self, wrapped: &Event, event: &schema::FileDeleteEvent) {
        self.record_rule_alerts(wrapped, rules::evaluate_file_delete(event));
        let alerts = self.rule_state.lock().unwrap().on_file_delete(event);
        self.record_rule_alerts(wrapped, alerts);
    }

    /// `Signal` events: security-process tampering (T1562.001, issue #362).
    fn detect_signal(&self, wrapped: &Event, event: &schema::SignalEvent) {
        self.record_rule_alerts(wrapped, rules::evaluate_signal(event));
    }

    /// `FileRename` events: mass-rename ransomware detection (T1486, issue #262) +
    /// write-volume corroboration (issue #82).
    fn detect_file_rename(&self, wrapped: &Event, event: &schema::FileRenameEvent) {
        // Bound first: `record_rule_alerts` takes the lock again for the damage manifest.
        let alerts = self.rule_state.lock().unwrap().on_file_rename(event);
        self.record_rule_alerts(wrapped, alerts);
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

    /// [`Self::emit`] for an alert that says the agent itself is being impaired or no longer
    /// matches what was shipped (a silent sensor, a failed integrity or signature check), which
    /// the health beacon counts so the control plane can show a host where that happened (#863).
    pub(crate) fn emit_tamper(&self, technique: &str, message: &str) {
        self.tamper_events.fetch_add(1, Ordering::Relaxed);
        self.emit(technique, message);
    }

    /// Tamper-class alerts raised since the agent started, for the health beacon.
    pub(crate) fn tamper_events(&self) -> u64 {
        self.tamper_events.load(Ordering::Relaxed)
    }

    /// IOC engine figures for the health beacon: indicators in force, findings raised, matches
    /// the cooldown absorbed (#60).
    pub(crate) fn ioc_counts(&self) -> (u64, u64, u64) {
        let stats = self.ioc.stats();
        (
            self.ioc.indicator_count() as u64,
            stats.raised.load(Ordering::Relaxed),
            stats.cooled_down.load(Ordering::Relaxed),
        )
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

    /// Same posture as the rule directories for the snapshot: absent unloads (the evidence is
    /// withheld), broken keeps the previous one (its failure is logged by the loader).
    fn swap_common_set(&self, loaded: Load<ml::features::common_set::CommonSetSnapshot>) {
        let mut slot = self.common_set.lock().unwrap();
        let old = match loaded {
            Load::Loaded(snapshot) => slot.replace(Arc::new(snapshot)),
            Load::Absent => slot.take(),
            Load::Failed => None,
        };
        drop(slot);
        drop(old);
    }

    /// Re-reads only the snapshot file, after the fetch loop wrote a new one (ADR-0033): the
    /// rule directories and models are untouched, so a daily snapshot does not rebuild the
    /// detection engines.
    pub(crate) fn reload_common_set(&self) {
        self.swap_common_set(load_common_set(&self.content_root));
    }

    /// The snapshot in force. Tests read it until the evidence lookup does (next slice of
    /// #76), which is why it is not compiled otherwise.
    #[cfg(test)]
    fn common_set(&self) -> Option<Arc<ml::features::common_set::CommonSetSnapshot>> {
        self.common_set.lock().unwrap().clone()
    }

    /// The rarity evidence counters, for the health beacon (ADR-0020, #76).
    pub(crate) fn rarity_stats(&self) -> Arc<RarityStats> {
        Arc::clone(&self.rarity_stats)
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

/// Loads the Sigma content of the platform this agent is built for, if the content directory
/// is present under `content_root`: only `rules/sigma/<platform>/`, so a rule written for
/// another platform never runs on this host (#980).
fn load_sigma_rules(content_root: &Path) -> Load<sigma::SigmaEngine> {
    let rules_dir = content_root.join("rules/sigma");
    if !rules_dir.is_dir() {
        return Load::Absent;
    }
    let Some(platform) = sigma::Platform::host() else {
        tracing::warn!("sigma: no rules directory for this operating system, none loaded");
        return Load::Absent;
    };
    match sigma::SigmaEngine::load_dir_for(&rules_dir, platform) {
        Ok(engine) => {
            tracing::info!(
                rules = engine.rule_count(),
                platform = platform.dir_name(),
                "sigma: rules loaded"
            );
            Load::Loaded(engine)
        }
        Err(e) => {
            tracing::error!(error = %e, "sigma: load error");
            Load::Failed
        }
    }
}

/// How many hosts a snapshot must cover before "not in the common set" counts as evidence
/// (ADR-0020): on a fleet that has just enrolled the snapshot is empty or thin, and every
/// binary would look rare. **Provisional**: ADR-0020 leaves it to calibration on lab data
/// (slice 6 of `docs/detection/fleet-prevalence-snapshot-plan.md`).
const RARITY_MIN_HOSTS_COVERED: u64 = 10;

/// How old a snapshot may be before it is treated as absent. **Provisional**, see
/// [`updater::snapshot::DEFAULT_MAX_AGE_SECS`].
const MAX_SNAPSHOT_AGE_SECS: u64 = updater::snapshot::DEFAULT_MAX_AGE_SECS;

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// What became of the rarity judgements since start, for the health beacon (ADR-0020, #76).
/// Plain atomics: bumped on the enrichment worker, read by the beacon thread.
#[derive(Default)]
pub(crate) struct RarityStats {
    applied: AtomicU64,
    withheld: AtomicU64,
    unapplied: AtomicU64,
}

impl crate::health::RarityStatsSource for RarityStats {
    fn rarity_counts(&self) -> crate::health::RarityCounts {
        crate::health::RarityCounts {
            applied: self.applied.load(Ordering::Relaxed),
            withheld: self.withheld.load(Ordering::Relaxed),
            unapplied: self.unapplied.load(Ordering::Relaxed),
        }
    }
}

/// What the fleet's common set says about one executed image.
#[derive(Debug, PartialEq, Eq)]
enum Rarity {
    /// The snapshot covers enough hosts and does not contain the image's hash.
    NotInCommonSet,
    /// The snapshot covers enough hosts and contains the hash.
    InCommonSet,
    /// No basis to say: no snapshot, too few hosts covered, or no usable hash. Never read as
    /// "rare" (the `rarity_known` of the ML feature, `ml::features::rarity`).
    Withheld,
}

/// The rarity of an image given the snapshot in force, the exec's hash and the minimum
/// coverage. A pure function over the same inputs as the ML rarity feature, so the two
/// cannot disagree about what is known.
fn rarity_evidence(
    sha256: Option<&str>,
    snapshot: Option<&ml::features::common_set::CommonSetSnapshot>,
    min_hosts: u64,
) -> Rarity {
    use ml::features::rarity::{CommonSet, extract_features};

    let [known, in_common_set] =
        extract_features(sha256, snapshot.map(|s| s as &dyn CommonSet), min_hosts);
    if known < 0.5 {
        Rarity::Withheld
    } else if in_common_set > 0.5 {
        Rarity::InCommonSet
    } else {
        Rarity::NotInCommonSet
    }
}

/// Feeds "this exec's image is not in the fleet's common set" to the correlator, when that is
/// what the snapshot in force says. Runs on the enrichment worker, off the capture path,
/// because only the worker knows the hash, and after the capture thread already correlated the
/// exec (so the process has a belief to add to). The snapshot lock is released before the
/// correlator lock is taken: no nested locking.
fn note_image_rarity(
    correlator: &Mutex<correlator::CorrelationEngine>,
    common_set: &Mutex<Option<Arc<ml::features::common_set::CommonSetSnapshot>>>,
    stats: &RarityStats,
    exec: &schema::ExecEvent,
    now_secs: u64,
) {
    // A snapshot past its maximum age counts as absent: the evidence is withheld, so a server
    // that stopped publishing cannot keep a stale set in force (ADR-0033 decision 3).
    let snapshot = common_set.lock().unwrap().clone().filter(|s| {
        !updater::snapshot::is_expired(s.header().built_at, now_secs, MAX_SNAPSHOT_AGE_SECS)
    });
    match rarity_evidence(
        exec.sha256.as_deref(),
        snapshot.as_deref(),
        RARITY_MIN_HOSTS_COVERED,
    ) {
        Rarity::InCommonSet => {}
        Rarity::Withheld => {
            stats.withheld.fetch_add(1, Ordering::Relaxed);
        }
        Rarity::NotInCommonSet => {
            let applied = correlator
                .lock()
                .unwrap()
                .apply_rarity_evidence(exec.meta.pid, exec.meta.process_generation);
            let counter = if applied {
                &stats.applied
            } else {
                &stats.unapplied
            };
            counter.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                pid = exec.meta.pid,
                applied,
                "rarity: image not in the common set"
            );
        }
    }
}

/// The largest snapshot file the agent reads. The content manifest allows an artifact of up to
/// 100 MiB; a snapshot is a Bloom filter whose size the server caps when it builds it, so
/// anything near this is a malformed or hostile file, refused before it is read.
pub(crate) const MAX_COMMON_SET_BYTES: u64 = 64 * 1024 * 1024;

/// Loads `<content_root>/snapshots/common-set.bin`, the file the signed content manifest
/// delivers (ADR-0020). Absent is "no snapshot yet", not an error; unreadable, too large or
/// not a snapshot is [`Load::Failed`] (logged with the reason, never the bytes).
fn load_common_set(content_root: &Path) -> Load<ml::features::common_set::CommonSetSnapshot> {
    load_common_set_capped(content_root, MAX_COMMON_SET_BYTES)
}

fn load_common_set_capped(
    content_root: &Path,
    max_bytes: u64,
) -> Load<ml::features::common_set::CommonSetSnapshot> {
    use std::io::Read as _;

    let path = content_root.join("snapshots").join("common-set.bin");
    let file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Load::Absent,
        Err(e) => {
            tracing::error!(error = %e, "common set: cannot open the snapshot file");
            return Load::Failed;
        }
    };
    // Read at most one byte past the cap: a file that grows between a size check and the read
    // still cannot make this allocate more than the cap.
    let mut bytes = Vec::new();
    if let Err(e) = file.take(max_bytes + 1).read_to_end(&mut bytes) {
        tracing::error!(error = %e, "common set: cannot read the snapshot file");
        return Load::Failed;
    }
    if bytes.len() as u64 > max_bytes {
        tracing::error!(max_bytes, "common set: snapshot file is over the size cap");
        return Load::Failed;
    }
    match ml::features::common_set::CommonSetSnapshot::parse(&bytes) {
        Ok(snapshot) => {
            let header = snapshot.header();
            tracing::info!(
                entries = header.entry_count,
                hosts_covered = header.hosts_covered,
                min_hosts = header.min_hosts,
                built_at = header.built_at,
                "common set: snapshot loaded"
            );
            Load::Loaded(snapshot)
        }
        Err(e) => {
            tracing::error!(error = %e, "common set: not a usable snapshot");
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

/// Starts the memory scanner over the same `rules/yara` content as the file scanner
/// (#85, ADR-0023). The rule set is compiled a second time because the file queue owns
/// its copy; memory and file scanning share rules, not state. Linux only: reading
/// another process's memory is the `sensor-linux-procmem` mechanism.
#[cfg(target_os = "linux")]
fn start_memscan(
    content_root: &Path,
    alert_log: Arc<AlertLog>,
    verdict: Arc<Mutex<verdict::VerdictEngine>>,
) -> Load<yara::MemoryScanQueue> {
    let dir = content_root.join("rules/yara");
    if !dir.is_dir() {
        return Load::Absent;
    }
    match yara::RuleSet::load_dir(&dir) {
        Ok(rules) => Load::Loaded(yara::MemoryScanQueue::start(
            rules,
            Arc::new(crate::memscan::ProcMemSource),
            yara::MemoryBudget::default(),
            move |outcome| report_memory_matches(&alert_log, &verdict, &outcome),
        )),
        // The file scanner reports the same load failure; this one only follows it.
        Err(_) => Load::Failed,
    }
}

/// No memory scanner off Linux (ADR-0023: Windows and macOS need their own mechanism).
#[cfg(not(target_os = "linux"))]
fn start_memscan(
    _content_root: &Path,
    _alert_log: Arc<AlertLog>,
    _verdict: Arc<Mutex<verdict::VerdictEngine>>,
) -> Load<yara::MemoryScanQueue> {
    Load::Absent
}

/// What a memory scan that matched produces: the match fused into the verdict of the
/// process that was scanned (the same path as a file match), a `YARA-MEM` audit line per
/// rule, and the escalation the fused severity warrants. A memory match does not
/// quarantine anything: there is no file to move.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn report_memory_matches(
    alert_log: &AlertLog,
    verdict: &Mutex<verdict::VerdictEngine>,
    outcome: &yara::MemoryScanOutcome,
) {
    let fused: Vec<verdict::Verdict> = outcome
        .context
        .iter()
        .flat_map(|context| {
            outcome
                .report
                .matches
                .iter()
                .filter_map(|rule| fuse_yara_match(verdict, context, rule))
        })
        .collect();
    for rule in &outcome.report.matches {
        alert_log.record(
            "YARA-MEM",
            format!(
                "yara rule {} matched in the memory of pid {} ({} region(s) scanned, {} skipped by budget)",
                rule.identifier,
                outcome.pid,
                outcome.report.regions_scanned,
                outcome.report.regions_skipped,
            ),
        );
    }
    for verdict in &fused {
        escalate_if_warranted(alert_log, verdict);
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

impl Drop for DetectionSink {
    /// Touches still held when the sink goes away are not judged (the hold runs on event time and
    /// nothing flushes it); say how many, so the loss is not silent.
    fn drop(&mut self) {
        let held = self
            .held_canary
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        if held > 0 {
            tracing::warn!(
                held,
                "deception: canary touches still held at shutdown are not reported"
            );
        }
    }
}

impl EventSink for DetectionSink {
    fn on_event(&self, event: Event) {
        // Detection runs in memory on the capture thread — no engine needs the hash
        // or signature synchronously (issue #126).
        self.correlate(&event);
        // The hold runs on the clock of the stream that carries both the exec and the touch. The
        // netlink poller, uprobes and log sources call this from their own threads with their own
        // clocks: letting them expire the hold would end it before the exec had a chance to come.
        if matches!(
            event,
            Event::Exec(_)
                | Event::FileOpen(_)
                | Event::FileDelete(_)
                | Event::FileRename(_)
                | Event::FileSetTime(_)
        ) {
            self.expire_held_canary(event.meta().timestamp_ns);
        }
        self.detect_canary(&event);
        match &event {
            Event::Exec(e) => self.detect_exec(&event, e),
            Event::FileOpen(e) => self.detect_file_open(&event, e),
            Event::Connect(e) => self.detect_connect(&event, e),
            Event::NetworkFlow(e) => self.detect_network_flow(&event, e),
            Event::DnsQuery(e) => self.detect_dns_query(&event, e),
            Event::ListenPort(e) => self.detect_listen_port(&event, e),
            Event::Auth(e) => self.detect_auth(&event, e),
            Event::Session(e) => self.detect_session(&event, e),
            Event::FileDelete(e) => self.detect_file_delete(&event, e),
            Event::Signal(e) => self.detect_signal(&event, e),
            Event::FileQuarantine(e) => self.detect_file_quarantine(e),
            Event::BitsJob(e) => self.detect_bits_job(e),
            Event::FileRename(e) => self.detect_file_rename(&event, e),
            Event::FileSetTime(e) => {
                self.record_rule_alerts(&event, rules::evaluate_file_set_time(e));
            }
            Event::FileWrite(e) => self.detect_file_write(e),
            Event::MemfdCreate(e) => self.detect_memfd_create(e),
            Event::AmsiContent(e) => self.detect_amsi_content(&event, e),
            Event::Defender(e) => {
                self.record_rule_alerts(&event, rules::evaluate_defender_event(e));
            }
            Event::LdapSearch(e) => self.detect_ldap_search(&event, e),
            Event::NtlmAuth(e) => self.record_rule_alerts(&event, rules::evaluate_ntlm_auth(e)),
            Event::LogCleared(e) => {
                self.record_rule_alerts(&event, rules::evaluate_log_cleared(e));
            }
            Event::KerberosDelegationFailure(e) => {
                self.record_rule_alerts(&event, rules::evaluate_kerberos_delegation_failure(e));
            }
            Event::PolicyDenial(e) => self.detect_policy_denial(&event, e),
            Event::PackageChange(e) => {
                self.record_rule_alerts(&event, rules::evaluate_package_change(e));
            }
            // New telemetry categories reach the engines as they land; until a rule
            // consumes them, logging below is the whole treatment.
            _ => {}
        }
        // Enrichment + the high-volume raw-event write happen off this thread, and
        // with them the findings that wait for the image's signature (#441).
        let gated = match &event {
            Event::Exec(e) => self.rule_state.lock().unwrap().on_exec_signature_gated(e),
            _ => None,
        };
        if let Some((event, gated)) = self.enrich_queue.enqueue(event, gated) {
            self.record_rule_alerts(&event, [gated.unverified()]);
        }
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
                let mut rule_state = self.rule_state.lock().unwrap();
                // Conservative: a gated finding excludes the cmdline whatever the
                // signature would have said.
                let gated = rule_state.on_exec_signature_gated(e);
                let state_alerts = rule_state.on_exec(e);
                drop(rule_state);
                if !det_alerts.is_empty() || !state_alerts.is_empty() || gated.is_some() {
                    return;
                }
                // Baselines leave the process and are used as a training corpus;
                // store the same redacted canonical argv that inference can derive.
                let safe = e.clone();
                let mut safe_event = Event::Exec(safe);
                crate::redact::redact_event(&mut safe_event);
                let Event::Exec(safe) = safe_event else {
                    unreachable!()
                };
                self.out.write(&BaselineRecord {
                    argv: &safe.argv,
                    cmdline: &safe.cmdline,
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
    use std::{
        sync::{Arc, Mutex, atomic::Ordering},
        thread,
        time::Duration,
    };

    use schema::{ConnectEvent, Event, EventMeta, ExecEvent, User, sensor::EventSink as _};

    use super::{
        CANARY_EXEC_HOLD_NS, DetectionSink, Load, MAX_HELD_CANARY_TOUCHES, correlator_case_id,
        entity_key, load_sigma_rules,
    };

    /// A content root with one Sigma rule per platform directory, each titled after it.
    fn sigma_content_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        for platform in ["linux", "windows", "macos"] {
            let dir = root.path().join("rules/sigma").join(platform);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("rule.yml"),
                format!(
                    "title: {platform}-rule\ndescription: d\ntags:\n  - attack.t1059\nlevel: low\n\
                     falsepositives:\n  - none\ndetection:\n  selection:\n    Image|endswith: '/x'\n  \
                     condition: selection\n"
                ),
            )
            .unwrap();
        }
        root
    }

    #[test]
    fn the_agent_loads_only_the_sigma_rules_of_its_own_platform() {
        let root = sigma_content_root();
        let Load::Loaded(engine) = load_sigma_rules(root.path()) else {
            panic!("the content directory is present and readable");
        };
        // macOS also runs the Unix-family rules of `linux/` (#980); the others only their own.
        let mut titles = engine.rule_titles();
        titles.sort_unstable();
        let expected: &[&str] = if cfg!(target_os = "linux") {
            &["linux-rule"]
        } else if cfg!(target_os = "windows") {
            &["windows-rule"]
        } else {
            &["linux-rule", "macos-rule"]
        };
        assert_eq!(titles, expected);
    }

    #[test]
    fn a_content_root_named_after_another_platform_does_not_change_which_rules_load() {
        // `<tmp>/windows/linux/...`: read from the full path, every rule would look like
        // every platform's.
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("windows").join("linux");
        std::fs::create_dir_all(&root).unwrap();
        let inner = sigma_content_root();
        let from = inner.path().join("rules");
        let to = root.join("rules");
        std::fs::create_dir_all(to.join("sigma")).unwrap();
        for platform in ["linux", "windows", "macos"] {
            std::fs::create_dir_all(to.join("sigma").join(platform)).unwrap();
            std::fs::copy(
                from.join("sigma").join(platform).join("rule.yml"),
                to.join("sigma").join(platform).join("rule.yml"),
            )
            .unwrap();
        }
        let Load::Loaded(engine) = load_sigma_rules(&root) else {
            panic!("the content directory is present and readable");
        };
        let expected = if cfg!(target_os = "macos") { 2 } else { 1 };
        assert_eq!(engine.rule_count(), expected, "{:?}", engine.rule_titles());
    }

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

    #[test]
    fn ordinary_file_write_does_not_enter_the_timestomp_rule_route() {
        let dir = tmp("file-write-not-timestomp");
        let sink = sink_in(&dir);
        sink.on_event(Event::FileWrite(schema::FileWriteEvent {
            meta: schema::fixtures::meta(),
            fd: 12,
            bytes_requested: 4096,
        }));
        assert!(!alerts_in(&dir).contains("T1070.006"));
    }

    #[test]
    fn set_time_event_reaches_the_timestomp_rule_through_the_real_sink() {
        let dir = tmp("file-set-time-route");
        let sink = sink_in(&dir);
        sink.on_event(Event::FileSetTime(schema::FileSetTimeEvent {
            meta: schema::fixtures::meta(),
            path: r"C:\Users\u\invoice.docx".into(),
            last_write_time: Some(132_537_600_000_000_000),
            ..schema::fixtures::file_set_time()
        }));
        let alerts = alerts_in(&dir);
        assert!(alerts.contains("T1070.006"), "{alerts}");
        assert!(alerts.contains("invoice.docx"), "{alerts}");
    }

    #[test]
    fn sigma_sees_raw_exec_but_alert_and_event_outputs_are_redacted() {
        let dir = tmp("cmdline-redaction-e2e");
        // The engine only loads the running host's own platform directory (#980) -- write the
        // rule there, not a hardcoded "linux", so this test exercises the real load path on
        // whichever platform runs it instead of silently loading zero rules on Windows/macOS.
        let platform_dir = sigma::Platform::host()
            .expect("supported CI platform")
            .dir_name();
        let sigma_dir = dir.join("content/rules/sigma").join(platform_dir);
        std::fs::create_dir_all(&sigma_dir).unwrap();
        std::fs::write(
            sigma_dir.join("raw-secret.yml"),
            "title: Password flag on a command line\ndescription: test\ntags:\n  - attack.t1059\nlevel: high\nfalsepositives:\n  - none\ndetection:\n  selection:\n    CommandLine|contains: '--password='\n  condition: selection\n",
        )
        .unwrap();
        let spool = Arc::new(Mutex::new(
            store::EventSpool::open(&dir.join("detection-spool"), u64::MAX).unwrap(),
        ));
        let sink = Arc::new(
            DetectionSink::new(
                rules::RuleState::new(),
                &dir.join("alerts.ndjson"),
                Some(&dir.join("events.jsonl")),
                None,
                Some(Arc::clone(&spool)),
                &dir.join("content"),
                &dir.join("ml-registry"),
            )
            .unwrap(),
        );
        for (pid, comm) in [(101, "it's"), (102, "a\"b")] {
            let mut exec = schema::fixtures::exec();
            exec.meta.pid = pid;
            exec.meta.comm = comm.into();
            exec.image_path = "/usr/bin/curl".into();
            exec.cmdline = "curl -u a:S3cret h; base64 -d --password=S3cret".into();
            exec.argv = Vec::new();
            sink.on_event(Event::Exec(exec));
        }
        assert!(sink.enrich_queue.flush(std::time::Duration::from_secs(2)));

        let alerts = alerts_in(&dir);
        assert!(alerts.contains("REDACTED"), "{alerts}");
        assert!(!alerts.contains("S3cret"), "{alerts}");
        let recent = sink.alert_log.latest(crate::alerts::RECENT_ALERTS_CAPACITY);
        assert!(
            recent
                .iter()
                .any(|alert| alert.message.contains("base64 -d --password=REDACTED")),
            "{recent:?}"
        );
        assert!(
            recent.iter().all(|alert| !alert.message.contains("S3cret")),
            "{recent:?}"
        );
        let terminal_alert =
            crate::alerts::format_alert_line(&recent[0].technique, &recent[0].message);
        assert!(
            terminal_alert.contains("[ALERT]") && terminal_alert.contains("REDACTED"),
            "{terminal_alert}"
        );
        assert!(!terminal_alert.contains("S3cret"), "{terminal_alert}");
        let events = std::fs::read_to_string(dir.join("events.jsonl")).unwrap();
        assert!(events.contains("--password=REDACTED"), "{events}");
        assert!(!events.contains("S3cret"), "{events}");
        let detections: Vec<transport::QueuedDetection> =
            spool.lock().unwrap().drain_oldest().unwrap();
        assert!(
            detections.len() >= 2,
            "Sigma and base64 rule should both detect: {detections:?}"
        );
        assert!(
            detections
                .iter()
                .any(|queued| queued.detection.title == "Password flag on a command line"),
            "{detections:?}"
        );
        assert!(
            detections.iter().any(|queued| queued
                .detection
                .title
                .contains("base64 -d --password=REDACTED")),
            "{detections:?}"
        );
        for queued in &detections {
            let serialized = serde_json::to_string(&queued.detection).unwrap();
            assert!(!serialized.contains("S3cret"), "{serialized}");
        }
    }

    #[test]
    fn redacted_detection_message_keeps_messages_with_an_empty_command_line_intact() {
        assert_eq!(
            super::redact_detection_message("", "", "process comm=it's"),
            "process comm=it's"
        );
    }

    #[test]
    fn baseline_corpus_stores_redacted_command_line_and_argv() {
        let dir = tmp("baseline-cmdline-redaction");
        let path = dir.join("baseline.jsonl");
        let sink = super::BaselineSink::new(rules::RuleState::new(), &path).unwrap();
        let mut exec = schema::fixtures::exec();
        exec.image_path = "/usr/bin/mysql".into();
        exec.cmdline = "mysql --password=S3cret".into();
        exec.argv = vec!["mysql".into(), "--password=S3cret".into()];
        sink.on_event(Event::Exec(exec));

        let record = std::fs::read_to_string(path).unwrap();
        assert!(record.contains("--password=REDACTED"), "{record}");
        assert!(!record.contains("S3cret"), "{record}");
    }

    #[test]
    fn advancing_the_correlator_clock_emits_a_silent_shell_alert() {
        let dir = tmp("correlator-tick");
        let sink = sink_in(&dir);
        let now = schema::time::now_ns();
        let mut meta = schema::fixtures::meta();
        meta.pid = 9_031;
        meta.ppid = 500;
        meta.comm = "sh".into();
        meta.timestamp_ns = now.saturating_sub(10_000_000_000);
        let shell = Event::Exec(ExecEvent {
            meta,
            image_path: "/usr/bin/sh".into(),
            parent_comm: Some("nginx".into()),
            ..schema::fixtures::exec()
        });

        sink.on_event(shell);
        assert!(!alerts_in(&dir).contains("T1505.003"));
        sink.advance_correlation_time(now);
        let alerts = alerts_in(&dir);
        assert!(alerts.contains("T1505.003"), "{alerts}");
        assert!(alerts.contains("no matching"), "{alerts}");
    }

    #[test]
    fn the_correlator_ticker_emits_without_a_following_event() {
        let dir = tmp("correlator-ticker-thread");
        let sink = sink_in(&dir);
        let now = schema::time::now_ns();
        let mut meta = schema::fixtures::meta();
        meta.pid = 9_032;
        meta.ppid = 500;
        meta.comm = "sh".into();
        meta.timestamp_ns = now.saturating_sub(10_000_000_000);
        let shell = Event::Exec(ExecEvent {
            meta,
            image_path: "/usr/bin/sh".into(),
            parent_comm: Some("nginx".into()),
            ..schema::fixtures::exec()
        });

        sink.on_event(shell);
        sink.start_correlator_ticker().unwrap();
        for _ in 0..30 {
            if alerts_in(&dir).contains("T1505.003") {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
        panic!("the one-second ticker did not emit the idle shell alert");
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
                isolate_enabled: false,
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
            meta: EventMeta {
                // Root: unrestricted, the payload is the test's own file.
                user: schema::User::Unix { uid: 0, gid: 0 },
                ..schema::fixtures::meta()
            },
        }));
        drive_linux_beacon(&sink, 6262);
        (payload, killed)
    }

    /// A sink watching the one canary a plant into `dir/canaries` produced.
    fn sink_watching_canary(dir: &std::path::Path) -> (Arc<DetectionSink>, String) {
        let planted = dir.join("canaries");
        std::fs::create_dir_all(&planted).unwrap();
        let tripwires = crate::deception::start(
            &config::DeceptionConfig {
                canary_dirs: vec![planted.clone()],
                ..Default::default()
            },
            &dir.join("state"),
        )
        .unwrap();
        let canary = std::fs::read_dir(&planted)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path()
            .display()
            .to_string();
        let sink = sink_in(dir);
        sink.set_tripwires(tripwires);
        (sink, canary)
    }

    fn open_event(path: &str, pid: u32) -> Event {
        Event::FileOpen(schema::FileOpenEvent {
            path: path.to_string(),
            meta: EventMeta {
                pid,
                ..schema::fixtures::meta()
            },
            ..schema::fixtures::file_open()
        })
    }

    #[test]
    fn another_process_opening_a_canary_raises_a_deception_detection() {
        let dir = tmp("canary-hit");
        let (sink, canary) = sink_watching_canary(&dir);
        sink.on_event(open_event(&canary, std::process::id() + 1));
        let alerts = alerts_in(&dir);
        assert!(alerts.contains("T1083"), "{alerts}");
        assert!(alerts.contains("canary file touched"), "{alerts}");
    }

    fn open_event_at(path: &str, pid: u32, timestamp_ns: u64) -> Event {
        let Event::FileOpen(mut e) = open_event(path, pid) else {
            unreachable!()
        };
        e.meta.timestamp_ns = timestamp_ns;
        Event::FileOpen(e)
    }

    fn canary_alert_count(dir: &std::path::Path) -> usize {
        alerts_in(dir).matches("canary file touched").count()
    }

    #[test]
    fn a_process_reopening_a_canary_raises_one_detection_per_cooldown() {
        let dir = tmp("canary-cooldown");
        let (sink, canary) = sink_watching_canary(&dir);
        let pid = std::process::id() + 1;
        let t0 = 1_000_000_000_000;
        for i in 0..5 {
            sink.on_event(open_event_at(&canary, pid, t0 + i * 1_000_000_000));
        }
        assert_eq!(canary_alert_count(&dir), 1);
        assert_eq!(sink.canary_hits_absorbed.load(Ordering::Relaxed), 4);
        sink.on_event(open_event_at(
            &canary,
            pid,
            t0 + super::CANARY_COOLDOWN_NS + 1,
        ));
        assert_eq!(canary_alert_count(&dir), 2);
    }

    fn event_by(
        canary: &str,
        pid: u32,
        generation: Option<u64>,
        timestamp_ns: u64,
        kind: &str,
    ) -> Event {
        let meta = EventMeta {
            pid,
            process_generation: generation,
            timestamp_ns,
            ..schema::fixtures::meta()
        };
        match kind {
            "read" | "write" => {
                let mut e = schema::fixtures::file_open();
                e.path = canary.into();
                e.flags = if kind == "write" { 0o102 } else { 0 };
                e.meta = meta;
                Event::FileOpen(e)
            }
            "delete" => {
                let mut e = schema::fixtures::file_delete();
                e.path = canary.into();
                e.meta = meta;
                Event::FileDelete(e)
            }
            "rename" => Event::FileRename(schema::FileRenameEvent {
                old_path: canary.into(),
                new_path: format!("{canary}.locked"),
                meta,
                ..schema::fixtures::file_rename()
            }),
            other => panic!("unknown touch {other}"),
        }
    }

    #[test]
    fn a_delete_rename_or_write_open_after_a_read_open_is_not_absorbed() {
        for destructive in ["delete", "rename", "write"] {
            let dir = tmp(&format!("canary-destructive-{destructive}"));
            let (sink, canary) = sink_watching_canary(&dir);
            let pid = std::process::id() + 1;
            sink.on_event(event_by(&canary, pid, None, 5, "read"));
            sink.on_event(event_by(&canary, pid, None, 6, destructive));
            assert_eq!(
                canary_alert_count(&dir),
                2,
                "{destructive} must not hide behind the read open"
            );
            assert_eq!(sink.canary_hits_absorbed.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn repeated_destructive_touches_each_raise_a_detection() {
        let dir = tmp("canary-repeat-delete");
        let (sink, canary) = sink_watching_canary(&dir);
        let pid = std::process::id() + 1;
        for t in 0..3 {
            sink.on_event(event_by(&canary, pid, None, 5 + t, "rename"));
        }
        assert_eq!(canary_alert_count(&dir), 3);
    }

    #[test]
    fn a_process_that_reuses_the_pid_is_not_absorbed_as_its_predecessor() {
        let dir = tmp("canary-pid-reuse");
        let (sink, canary) = sink_watching_canary(&dir);
        let pid = std::process::id() + 1;
        sink.on_event(event_by(&canary, pid, Some(7), 5, "read"));
        sink.on_event(event_by(&canary, pid, Some(7), 6, "read"));
        assert_eq!(canary_alert_count(&dir), 1, "same incarnation: absorbed");
        sink.on_event(event_by(&canary, pid, Some(8), 7, "read"));
        assert_eq!(canary_alert_count(&dir), 2, "new incarnation: reported");
    }

    #[test]
    fn a_second_process_touching_the_same_canary_is_not_absorbed() {
        let dir = tmp("canary-two-pids");
        let (sink, canary) = sink_watching_canary(&dir);
        let pid = std::process::id() + 1;
        sink.on_event(open_event_at(&canary, pid, 5));
        sink.on_event(open_event_at(&canary, pid + 1, 6));
        assert_eq!(canary_alert_count(&dir), 2);
    }

    #[test]
    fn an_allowed_executable_touching_a_canary_is_not_a_detection() {
        let dir = tmp("canary-allowed");
        let (sink, canary) = sink_watching_canary(&dir);
        sink.set_canary_allow(crate::deception::CanaryAllow::for_test(
            "/usr/bin/updatedb",
            |_| Some("/usr/bin/updatedb".into()),
        ));
        sink.on_event(open_event(&canary, std::process::id() + 1));
        assert_eq!(canary_alert_count(&dir), 0);
    }

    #[test]
    fn an_exec_is_recorded_only_when_an_executable_may_be_allowed() {
        let pid = std::process::id() + 1;
        let record = |sink: &DetectionSink| {
            let mut exec = schema::fixtures::exec();
            exec.meta.pid = pid;
            exec.meta.process_generation = Some(3);
            exec.image_path = "/usr/bin/updatedb".into();
            sink.on_event(Event::Exec(exec));
            sink.exec_images.lock().unwrap().image_of(pid, Some(3))
        };
        let dir = tmp("exec-record-none");
        let (sink, _canary) = sink_watching_canary(&dir);
        assert!(record(&sink).is_none(), "no allow list: nothing recorded");
        let dir = tmp("exec-record-empty");
        let (sink, _canary) = sink_watching_canary(&dir);
        // What a host with `[deception]` but no `allow_exe` has: an allow list, empty.
        sink.set_canary_allow(crate::deception::CanaryAllow::new(
            &config::DeceptionConfig::default(),
        ));
        assert!(
            record(&sink).is_none(),
            "an empty allow list: nothing recorded"
        );
        let dir = tmp("exec-record-listed");
        let (sink, _canary) = sink_watching_canary(&dir);
        sink.set_canary_allow(crate::deception::CanaryAllow::for_test(
            "/usr/bin/updatedb",
            |_| None,
        ));
        assert!(record(&sink).is_some(), "an allow list: recorded");
    }

    #[test]
    fn a_process_seen_to_exec_an_allowed_image_may_touch_a_canary_without_proc() {
        let dir = tmp("canary-exec-image");
        let (sink, canary) = sink_watching_canary(&dir);
        // The /proc fallback resolves nothing: only the Exec the sink saw can allow.
        sink.set_canary_allow(crate::deception::CanaryAllow::for_test(
            "/usr/bin/updatedb",
            |_| None,
        ));
        let pid = std::process::id() + 1;
        let mut exec = schema::fixtures::exec();
        exec.meta.pid = pid;
        exec.meta.process_generation = Some(3);
        exec.image_path = "/usr/bin/updatedb".into();
        sink.on_event(Event::Exec(exec));
        let mut open = schema::fixtures::file_open();
        open.path = canary.clone();
        open.meta.pid = pid;
        open.meta.process_generation = Some(3);
        sink.on_event(Event::FileOpen(open));
        assert_eq!(
            canary_alert_count(&dir),
            0,
            "an allowed image raises no hit"
        );

        // The same pid, another incarnation that never exec'd: not allowed.
        let mut other = schema::fixtures::file_open();
        other.path = canary;
        other.meta.pid = pid;
        other.meta.process_generation = Some(4);
        let other_ts = other.meta.timestamp_ns;
        sink.on_event(Event::FileOpen(other));
        // No Exec was seen for this incarnation: the touch is held, then raised.
        sink.on_event(tick_at(other_ts + CANARY_EXEC_HOLD_NS));
        assert_eq!(canary_alert_count(&dir), 1, "a recycled pid raises the hit");
    }

    /// A canary open by `pid` (incarnation `generation`) at event time `ts`.
    fn canary_touch(canary: &str, pid: u32, generation: u64, ts: u64) -> Event {
        let Event::FileOpen(mut e) = open_event_at(canary, pid, ts) else {
            unreachable!()
        };
        e.meta.process_generation = Some(generation);
        Event::FileOpen(e)
    }

    fn exec_of(image: &str, pid: u32, generation: u64, ts: u64) -> Event {
        let mut exec = schema::fixtures::exec();
        exec.meta.pid = pid;
        exec.meta.process_generation = Some(generation);
        exec.meta.timestamp_ns = ts;
        exec.image_path = image.into();
        Event::Exec(exec)
    }

    /// Any event that is not a canary touch, at event time `ts`: it moves the sink's clock.
    fn tick_at(ts: u64) -> Event {
        open_event_at("/not/a/canary", 1, ts)
    }

    fn sink_allowing_tar(name: &str) -> (Arc<DetectionSink>, String, std::path::PathBuf) {
        let dir = tmp(name);
        let (sink, canary) = sink_watching_canary(&dir);
        // The `/proc` fallback resolves nothing, as for a process that already exited.
        sink.set_canary_allow(crate::deception::CanaryAllow::for_test(
            "/usr/bin/tar",
            |_| None,
        ));
        (sink, canary, dir)
    }

    #[test]
    fn a_touch_that_arrives_before_the_exec_of_an_allowed_image_is_not_a_detection() {
        // The sensor stamps the exec before the open, but the merged stream can deliver the
        // open first (cron's `bash` then `tar`, #81): the decision waits for the exec.
        let (sink, canary, dir) = sink_allowing_tar("canary-before-exec-allowed");
        let pid = std::process::id() + 1;
        sink.on_event(canary_touch(&canary, pid, 3, 10_000));
        assert_eq!(canary_alert_count(&dir), 0, "held, not raised yet");
        sink.on_event(exec_of("/usr/bin/tar", pid, 3, 9_000));
        assert_eq!(
            canary_alert_count(&dir),
            0,
            "the exec shows an allowed image"
        );
        sink.on_event(tick_at(10_000 + 2 * CANARY_EXEC_HOLD_NS));
        assert_eq!(
            canary_alert_count(&dir),
            0,
            "and it is not raised later either"
        );
    }

    #[test]
    fn a_touch_that_arrives_before_the_exec_of_another_image_is_raised_when_the_hold_ends() {
        let (sink, canary, dir) = sink_allowing_tar("canary-before-exec-other");
        let pid = std::process::id() + 1;
        sink.on_event(canary_touch(&canary, pid, 3, 10_000));
        sink.on_event(exec_of("/usr/bin/cat", pid, 3, 9_000));
        assert_eq!(
            canary_alert_count(&dir),
            0,
            "a later exec may still be the allowed one"
        );
        sink.on_event(tick_at(10_000 + CANARY_EXEC_HOLD_NS));
        assert_eq!(
            canary_alert_count(&dir),
            1,
            "a listed name on another image is no excuse"
        );
    }

    #[test]
    fn a_touch_before_a_two_step_exec_is_judged_by_the_last_image() {
        // `bash -c "tar ..."` is one pid that execs `bash`, then `tar`: the first image must
        // not settle the touch (the lab run of cron's job, #81).
        let (sink, canary, dir) = sink_allowing_tar("canary-before-two-step-exec");
        let pid = std::process::id() + 1;
        sink.on_event(canary_touch(&canary, pid, 3, 10_000));
        sink.on_event(exec_of("/usr/bin/bash", pid, 3, 8_000));
        sink.on_event(exec_of("/usr/bin/tar", pid, 3, 9_000));
        sink.on_event(tick_at(10_000 + 2 * CANARY_EXEC_HOLD_NS));
        assert_eq!(canary_alert_count(&dir), 0);
    }

    #[test]
    fn a_touch_between_the_two_execs_of_one_pid_is_judged_by_the_last_image() {
        // The first exec is recorded when the touch arrives, the second is still on its way.
        let (sink, canary, dir) = sink_allowing_tar("canary-between-two-execs");
        let pid = std::process::id() + 1;
        sink.on_event(exec_of("/usr/bin/bash", pid, 3, 8_000));
        sink.on_event(canary_touch(&canary, pid, 3, 10_000));
        assert_eq!(
            canary_alert_count(&dir),
            0,
            "held, not raised on the first image"
        );
        sink.on_event(exec_of("/usr/bin/tar", pid, 3, 9_000));
        sink.on_event(tick_at(10_000 + 2 * CANARY_EXEC_HOLD_NS));
        assert_eq!(canary_alert_count(&dir), 0);
    }

    #[test]
    fn a_touch_whose_exec_never_comes_is_raised_once_the_hold_has_passed() {
        let (sink, canary, dir) = sink_allowing_tar("canary-hold-expires");
        let pid = std::process::id() + 1;
        sink.on_event(canary_touch(&canary, pid, 3, 10_000));
        sink.on_event(tick_at(10_000 + CANARY_EXEC_HOLD_NS - 1));
        assert_eq!(canary_alert_count(&dir), 0, "inside the hold");
        sink.on_event(tick_at(10_000 + CANARY_EXEC_HOLD_NS));
        assert_eq!(canary_alert_count(&dir), 1, "the hold is bounded");
        assert_eq!(
            sink.canary_hold_expired.load(Ordering::Relaxed),
            1,
            "a hold that ended with no exec is counted"
        );
        sink.on_event(tick_at(10_000 + 3 * CANARY_EXEC_HOLD_NS));
        assert_eq!(canary_alert_count(&dir), 1, "raised once");
    }

    #[test]
    fn an_exec_without_a_generation_does_not_resolve_a_held_touch() {
        // A sensor that does not stamp the generation: the touch and the exec both carry
        // `None`; `None == None` must not let the exec excuse the touch (a recycled pid).
        let (sink, canary, dir) = sink_allowing_tar("canary-hold-no-generation");
        let pid = std::process::id() + 1;
        let Event::FileOpen(mut open) = canary_touch(&canary, pid, 3, 10_000) else {
            unreachable!()
        };
        open.meta.process_generation = None;
        sink.on_event(Event::FileOpen(open));
        let Event::Exec(mut exec) = exec_of("/usr/bin/tar", pid, 3, 10_500) else {
            unreachable!()
        };
        exec.meta.process_generation = None;
        sink.on_event(Event::Exec(exec));
        sink.on_event(tick_at(10_000 + CANARY_EXEC_HOLD_NS));
        assert_eq!(
            canary_alert_count(&dir),
            1,
            "no generation on the exec: the touch is judged when the hold ends"
        );
    }

    #[test]
    fn an_allowed_exec_after_the_touch_does_not_excuse_it() {
        // `/tmp/evil` opens a canary, then execs an allowed `tar` that exits at once: the touch
        // was made by the first image, not by `tar` (#81 review).
        for prior in [None, Some("/usr/bin/cat")] {
            let (sink, canary, dir) = sink_allowing_tar("canary-exec-after-touch");
            let pid = std::process::id() + 1;
            if let Some(image) = prior {
                sink.on_event(exec_of(image, pid, 3, 8_000));
            }
            sink.on_event(canary_touch(&canary, pid, 3, 10_000));
            sink.on_event(exec_of("/usr/bin/tar", pid, 3, 11_000));
            sink.on_event(tick_at(10_000 + 2 * CANARY_EXEC_HOLD_NS));
            assert_eq!(
                canary_alert_count(&dir),
                1,
                "an exec after the touch excuses nothing (prior exec: {prior:?})"
            );
        }
    }

    #[test]
    fn an_allowed_exec_delivered_before_a_touch_it_follows_in_time_does_not_excuse_it() {
        // The merged stream can deliver the exec first, too: its time is what counts.
        let (sink, canary, dir) = sink_allowing_tar("canary-exec-after-touch-early");
        let pid = std::process::id() + 1;
        sink.on_event(exec_of("/usr/bin/tar", pid, 3, 11_000));
        sink.on_event(canary_touch(&canary, pid, 3, 10_000));
        sink.on_event(tick_at(10_000 + 2 * CANARY_EXEC_HOLD_NS));
        assert_eq!(canary_alert_count(&dir), 1);
    }

    #[test]
    fn an_exec_at_the_time_of_the_touch_may_excuse_it() {
        let (sink, canary, dir) = sink_allowing_tar("canary-exec-same-time");
        let pid = std::process::id() + 1;
        sink.on_event(canary_touch(&canary, pid, 3, 10_000));
        sink.on_event(exec_of("/usr/bin/tar", pid, 3, 10_000));
        sink.on_event(tick_at(10_000 + 2 * CANARY_EXEC_HOLD_NS));
        assert_eq!(canary_alert_count(&dir), 0);
    }

    #[test]
    fn a_held_touch_is_judged_on_the_last_exec_before_it_not_on_a_later_one() {
        // bash, then tar, both before the touch's time; a later `cat` is not what touched.
        let (sink, canary, dir) = sink_allowing_tar("canary-hold-latest-qualifying");
        let pid = std::process::id() + 1;
        sink.on_event(canary_touch(&canary, pid, 3, 10_000));
        sink.on_event(exec_of("/usr/bin/bash", pid, 3, 8_000));
        sink.on_event(exec_of("/usr/bin/tar", pid, 3, 9_000));
        sink.on_event(exec_of("/usr/bin/cat", pid, 3, 11_000));
        sink.on_event(tick_at(10_000 + 2 * CANARY_EXEC_HOLD_NS));
        assert_eq!(canary_alert_count(&dir), 0);
    }

    #[test]
    fn an_empty_allow_list_raises_a_touch_at_once() {
        let dir = tmp("canary-empty-allow");
        let (sink, canary) = sink_watching_canary(&dir);
        sink.set_canary_allow(crate::deception::CanaryAllow::new(
            &config::DeceptionConfig::default(),
        ));
        sink.on_event(canary_touch(&canary, std::process::id() + 1, 3, 10_000));
        assert_eq!(canary_alert_count(&dir), 1, "nothing to wait for");
    }

    #[test]
    fn a_process_in_another_mount_namespace_is_raised_at_once() {
        // `allows` refuses it whatever exec arrives, so holding it only delays the finding.
        let dir = tmp("canary-foreign-ns");
        let (sink, canary) = sink_watching_canary(&dir);
        sink.set_canary_allow(
            crate::deception::CanaryAllow::for_test("/usr/bin/tar", |_| None)
                .in_foreign_mount_ns_for_test(),
        );
        sink.on_event(canary_touch(&canary, std::process::id() + 1, 3, 10_000));
        assert_eq!(canary_alert_count(&dir), 1, "not held");
    }

    #[test]
    fn only_the_touch_stream_expires_the_hold() {
        // A poller on its own thread and clock must not end the hold before the exec can arrive.
        let (sink, canary, dir) = sink_allowing_tar("canary-hold-other-streams");
        let pid = std::process::id() + 1;
        sink.on_event(canary_touch(&canary, pid, 3, 10_000));
        let mut connect = schema::fixtures::connect();
        connect.meta.timestamp_ns = 10_000 + 2 * CANARY_EXEC_HOLD_NS;
        sink.on_event(Event::Connect(connect));
        assert_eq!(canary_alert_count(&dir), 0, "still held");
        sink.on_event(exec_of("/usr/bin/tar", pid, 3, 9_000));
        sink.on_event(tick_at(10_000 + 2 * CANARY_EXEC_HOLD_NS));
        assert_eq!(canary_alert_count(&dir), 0, "the exec arrived in time");
    }

    #[test]
    fn the_reflex_does_not_kill_from_a_touch_judged_after_the_hold() {
        // `/proc` was empty when the touch was held: by now the pid may be someone else's.
        let dir = tmp("reflex-held-touch");
        let (sink, canary, killed) = reflex_sink(&dir, true);
        sink.set_canary_allow(crate::deception::CanaryAllow::for_test(
            "/usr/bin/tar",
            |_| None,
        ));
        burst(&sink, 900);
        let touch_at = BURST_END_NS + 1_000_000;
        sink.on_event(canary_open_at(&canary, 900, touch_at));
        sink.on_event(tick_at(touch_at + CANARY_EXEC_HOLD_NS));
        assert!(
            alerts_in(&dir).contains("canary file touched"),
            "the touch is still a finding"
        );
        assert!(killed.lock().unwrap().is_empty(), "but nothing is killed");
    }

    #[test]
    fn the_exec_of_another_incarnation_does_not_resolve_a_held_touch() {
        let (sink, canary, dir) = sink_allowing_tar("canary-hold-other-incarnation");
        let pid = std::process::id() + 1;
        sink.on_event(canary_touch(&canary, pid, 3, 10_000));
        // A recycled pid's later life exec'ing an allowed image says nothing about the toucher.
        sink.on_event(exec_of("/usr/bin/tar", pid, 4, 10_500));
        sink.on_event(tick_at(10_000 + CANARY_EXEC_HOLD_NS));
        assert_eq!(canary_alert_count(&dir), 1);
    }

    #[test]
    fn a_full_hold_queue_raises_the_touch_instead_of_holding_it() {
        let (sink, canary, dir) = sink_allowing_tar("canary-hold-full");
        let first = std::process::id() + 1;
        for i in 0..MAX_HELD_CANARY_TOUCHES as u32 {
            sink.on_event(canary_touch(&canary, first + i, 3, 10_000));
        }
        assert_eq!(
            canary_alert_count(&dir),
            0,
            "every touch within the bound is held"
        );
        let overflow = first + MAX_HELD_CANARY_TOUCHES as u32;
        sink.on_event(canary_touch(&canary, overflow, 3, 10_000));
        assert_eq!(
            canary_alert_count(&dir),
            1,
            "beyond the bound it is raised at once"
        );
        assert_eq!(
            sink.canary_hold_overflow.load(Ordering::Relaxed),
            1,
            "and the overflow is counted"
        );
    }

    #[test]
    fn a_process_that_proc_shows_running_another_image_is_raised_at_once() {
        // `/proc` is an answer, not a gap: nothing to wait for.
        let dir = tmp("canary-proc-other-image");
        let (sink, canary) = sink_watching_canary(&dir);
        sink.set_canary_allow(crate::deception::CanaryAllow::for_test(
            "/usr/bin/tar",
            |_| Some("/usr/bin/cat".into()),
        ));
        sink.on_event(canary_touch(&canary, std::process::id() + 1, 3, 10_000));
        assert_eq!(canary_alert_count(&dir), 1);
    }

    #[test]
    fn without_an_allow_list_a_touch_is_raised_at_once() {
        let dir = tmp("canary-no-allow-no-hold");
        let (sink, canary) = sink_watching_canary(&dir);
        sink.on_event(canary_touch(&canary, std::process::id() + 1, 3, 10_000));
        assert_eq!(canary_alert_count(&dir), 1);
    }

    #[test]
    fn planting_canary_mtime_does_not_trip_the_agent_or_hide_a_real_touch() {
        let dir = tmp("canary-own-pid");
        let (sink, canary) = sink_watching_canary(&dir);
        let modified = std::fs::metadata(&canary).unwrap().modified().unwrap();
        assert!(modified < std::time::SystemTime::now());

        sink.on_event(open_event(&canary, std::process::id()));
        assert!(!alerts_in(&dir).contains("canary file touched"));

        sink.on_event(open_event(&canary, std::process::id() + 1));
        assert!(alerts_in(&dir).contains("canary file touched"));
    }

    #[test]
    fn an_ordinary_path_is_not_a_canary_hit() {
        let dir = tmp("canary-miss");
        let (sink, _canary) = sink_watching_canary(&dir);
        sink.on_event(open_event("/etc/hostname", std::process::id() + 1));
        assert!(!alerts_in(&dir).contains("canary file touched"));
    }

    #[test]
    fn without_tripwires_a_canary_looking_path_is_ordinary() {
        let dir = tmp("canary-off");
        let sink = sink_in(&dir);
        sink.on_event(open_event("/srv/passwords_00000000.txt", 1));
        assert!(!alerts_in(&dir).contains("canary file touched"));
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
                isolate_enabled: false,
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

    /// #594: a write whose user the sensor could not resolve is not scanned at all, not
    /// read with the agent's own privileges. The control event after it proves the
    /// queue and the rule work, so the single scan is the root one.
    #[cfg(unix)]
    #[test]
    fn a_write_by_an_unresolved_user_is_not_scanned_on_unix() {
        let dir = tmp("yara-unknown-user");
        let yara_dir = dir.join("content").join("rules").join("yara");
        std::fs::create_dir_all(&yara_dir).unwrap();
        std::fs::write(yara_dir.join("marker.yar"), RESPONSE_MARKER_RULE).unwrap();
        let payload = dir.join("payload.bin");
        std::fs::write(&payload, b"dropped payload RESPONSE-SCENARIO-MARKER").unwrap();
        let sink = sink_in(&dir);
        assert_eq!(sink.reload_content().yara_rule_count, Some(1));
        let write_as = |user: schema::User| {
            sink.on_event(Event::FileOpen(schema::FileOpenEvent {
                meta: EventMeta {
                    user,
                    ..schema::fixtures::meta()
                },
                path: payload.display().to_string(),
                flags: 0o101,
            }));
        };

        write_as(schema::User::Unknown);
        write_as(schema::User::Unix { uid: 0, gid: 0 });
        wait_for_alert(&dir, "YARA");
        std::thread::sleep(std::time::Duration::from_millis(600));
        let stats = sink.yara.lock().unwrap().as_ref().unwrap().0.stats();
        assert_eq!(
            stats.scanned, 1,
            "only the root write is scanned, the unresolved one never reaches the queue"
        );
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
        drive_bayes_crossing_from(sink, pid, "C:\\Users\\solka\\AppData\\Roaming\\malware.exe");
    }

    /// [`drive_bayes_crossing`] for an exec of `image_path`: the same connects to a
    /// public address, so what differs between two runs is only where the binary lives.
    fn drive_bayes_crossing_from(sink: &DetectionSink, pid: u32, image_path: &str) {
        sink.on_event(exec(pid, "malware.exe", image_path));
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

    /// EGRESS-DOMAIN (#380) crosses two event kinds: the lookup is a `DnsQuery`, which the sink
    /// must hand to the rule state (it did not before), and the volume is a `NetworkFlow`.
    #[test]
    fn a_dns_lookup_and_the_flow_that_follows_raise_egress_domain_in_the_alert_log() {
        let dir = tmp("egress-domain");
        let sink = sink_in(&dir);
        let pid = 4242;
        let meta_at = |ns: u64| EventMeta {
            pid,
            comm: "curl".to_string(),
            timestamp_ns: ns,
            ..schema::fixtures::meta()
        };
        sink.on_event(Event::DnsQuery(schema::DnsQueryEvent {
            meta: meta_at(0),
            query: "pastebin.com".to_string(),
            result: Some("203.0.113.9".to_string()),
            status: 0,
            ..schema::fixtures::dns_query()
        }));
        for (i, sent) in [0u64, 30 * 1024 * 1024].into_iter().enumerate() {
            sink.on_event(Event::NetworkFlow(schema::NetworkFlowEvent {
                meta: meta_at((i as u64 + 1) * 1_000_000_000),
                local_port: 50000,
                daddr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 9)),
                dport: 443,
                protocol: 6,
                bytes_sent: Some(sent),
                ..schema::fixtures::network_flow()
            }));
        }
        let alerts = alerts_in(&dir);
        assert!(
            alerts.contains("T1567.003"),
            "the lookup must reach the rule state and join the flow, got: {alerts}"
        );
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
                isolate_enabled: false,
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
                isolate_enabled: false,
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

    fn enable_recording_kill(sink: &DetectionSink, dir: &std::path::Path) -> Arc<Mutex<Vec<u32>>> {
        let killed = Arc::new(Mutex::new(Vec::new()));
        let killed_rec = Arc::clone(&killed);
        sink.enable_response(
            policy::ResponsePolicy {
                kill_enabled: true,
                quarantine_enabled: false,
                isolate_enabled: false,
            },
            move |pid| {
                killed_rec.lock().unwrap().push(pid);
                Ok(())
            },
            dir.join("quarantine"),
        );
        killed
    }

    /// Issue #652: `NetworkManager` crossed `BAYES` on a stock Fedora host with no rule or
    /// YARA hit and was killed. A package binary started by init is a system service's
    /// main process: the crossing still raises its alert, but the kill is refused.
    #[test]
    fn a_system_service_crossing_bayes_is_refused_not_killed() {
        let dir = tmp("bayes-service");
        let sink = sink_in(&dir);
        let killed = enable_recording_kill(&sink, &dir);
        drive_bayes_crossing_from(&sink, 6001, "/usr/sbin/NetworkManager");
        let alerts = alerts_in(&dir);
        assert!(
            alerts.contains("BAYES"),
            "the recipe must still cross the belief threshold: {alerts}"
        );
        assert!(
            alerts.contains("refused to kill pid 6001"),
            "the refusal must be audited: {alerts}"
        );
        assert!(
            killed.lock().unwrap().is_empty(),
            "a service's main process must never reach terminate on BAYES alone"
        );
    }

    /// The control for the test above: identical behaviour from a binary in `/tmp`
    /// (the implant's provenance) is killed, as before.
    #[test]
    fn the_same_crossing_from_a_tmp_binary_is_still_killed() {
        let dir = tmp("bayes-tmp");
        let sink = sink_in(&dir);
        let killed = enable_recording_kill(&sink, &dir);
        drive_bayes_crossing_from(&sink, 6002, "/tmp/NetworkManager");
        assert_eq!(*killed.lock().unwrap(), vec![6002]);
    }

    /// Observe-only mode says the truth too: a service is "refused", not "would have
    /// been killed" (the line the issue's reporter saw on the Fedora VM).
    #[test]
    fn observe_mode_reports_a_service_as_refused_not_as_would_be_killed() {
        let dir = tmp("bayes-service-observe");
        let sink = sink_in(&dir);
        sink.enable_response(
            policy::ResponsePolicy {
                kill_enabled: false,
                quarantine_enabled: false,
                isolate_enabled: false,
            },
            |_| panic!("terminate must not be called in observe mode"),
            dir.join("quarantine"),
        );
        drive_bayes_crossing_from(&sink, 6003, "/usr/sbin/NetworkManager");
        let alerts = alerts_in(&dir);
        assert!(alerts.contains("refused to kill pid 6003"), "{alerts}");
        assert!(!alerts.contains("would have been killed"), "{alerts}");
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
                isolate_enabled: false,
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
                None,
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

    // --- tamper-class alerts are counted for the health beacon (#863) ---

    fn sink_for_counting(dir: &std::path::Path) -> DetectionSink {
        DetectionSink::new(
            rules::RuleState::new(),
            &dir.join("alerts.ndjson"),
            None,
            None,
            None,
            &dir.join("content"),
            &dir.join("ml-registry"),
        )
        .unwrap()
    }

    #[test]
    fn a_tamper_alert_is_recorded_like_any_alert_and_counted() {
        let dir = tmp("tamper-count");
        let sink = sink_for_counting(&dir);
        assert_eq!(sink.tamper_events(), 0);

        sink.emit_tamper("T1562", "sensor linux-journal went silent");
        sink.emit_tamper("T1601", "binary swapped");

        assert_eq!(sink.tamper_events(), 2);
        let alerts = std::fs::read_to_string(dir.join("alerts.ndjson")).unwrap();
        assert!(alerts.contains("T1562") && alerts.contains("sensor linux-journal went silent"));
        assert!(alerts.contains("T1601") && alerts.contains("binary swapped"));
    }

    #[test]
    fn an_ordinary_alert_is_not_a_tamper_event() {
        let dir = tmp("tamper-not-counted");
        let sink = sink_for_counting(&dir);

        sink.emit("T1059", "command line contains a base64 decode");

        assert_eq!(sink.tamper_events(), 0);
    }

    #[test]
    fn emitted_finding_reaches_the_durable_detection_spool() {
        let dir = tmp("detection-spool");
        let spool = Arc::new(Mutex::new(
            store::EventSpool::open(&dir.join("detection-spool"), u64::MAX).unwrap(),
        ));
        let sink = DetectionSink::new(
            rules::RuleState::new(),
            &dir.join("alerts.ndjson"),
            Some(&dir.join("events.jsonl")),
            None,
            Some(Arc::clone(&spool)),
            &dir.join("content"),
            &dir.join("ml-registry"),
        )
        .unwrap();
        let event = exec(7, "test", "/bin/test");
        sink.record_and_emit(
            &verdict::EntityKey::new(1, "test"),
            "T1059",
            "test finding",
            schema::detection::DetectionSource::Rule {
                rule_id: "T1059".into(),
            },
            schema::detection::Severity::Medium,
            &event,
        );
        assert!(sink.enrich_queue().flush(std::time::Duration::from_secs(2)));
        let records: Vec<transport::QueuedDetection> =
            spool.lock().unwrap().drain_oldest().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].detection.title, "test finding");
        assert_eq!(
            records[0].detection.events,
            vec![with_its_enrichment(&event, &records[0].detection.events)]
        );
        assert_eq!(records[0].key.len(), 36);
    }

    /// `event` as the spooled detection carries it: the enrichment worker adds the image's hash and
    /// signature before the detection is stored (#62), so that the control plane can join hosts
    /// on the hash. Everything else of the event must be as it was captured. The hash is asserted
    /// present for an image that exists on this machine, and compared as given otherwise.
    fn with_its_enrichment(event: &Event, spooled: &[Event]) -> Event {
        let (Event::Exec(captured), Some(Event::Exec(stored))) = (event, spooled.first()) else {
            return event.clone();
        };
        assert!(
            captured.sha256.is_some()
                || stored.sha256.is_some()
                || !std::path::Path::new(&captured.image_path).is_file(),
            "the detection's exec should carry the hash of {}",
            captured.image_path
        );
        let mut expected = captured.clone();
        expected.sha256.clone_from(&stored.sha256);
        expected.signature = stored.signature;
        Event::Exec(expected)
    }

    fn rename_of(pid: u32, i: u64, to: &str) -> Event {
        Event::FileRename(schema::FileRenameEvent {
            meta: EventMeta {
                pid,
                timestamp_ns: 1_000_000_000 + i * 50_000_000,
                comm: "encryptor".into(),
                ..schema::fixtures::meta()
            },
            old_path: format!("/home/u/doc{i}.txt"),
            new_path: format!("/home/u/doc{i}.txt{to}"),
            ..schema::fixtures::file_rename()
        })
    }

    fn canary_open_at(path: &str, pid: u32, timestamp_ns: u64) -> Event {
        Event::FileOpen(schema::FileOpenEvent {
            path: path.to_string(),
            meta: EventMeta {
                pid,
                timestamp_ns,
                comm: "encryptor".into(),
                ..schema::fixtures::meta()
            },
            ..schema::fixtures::file_open()
        })
    }

    /// A sink watching one canary, with kill wired to a recorder.
    fn reflex_sink(
        dir: &std::path::Path,
        kill_enabled: bool,
    ) -> (Arc<DetectionSink>, String, Arc<Mutex<Vec<u32>>>) {
        let (sink, canary) = sink_watching_canary(dir);
        let killed = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&killed);
        sink.enable_response(
            policy::ResponsePolicy {
                kill_enabled,
                quarantine_enabled: false,
                isolate_enabled: false,
            },
            move |pid| {
                recorder.lock().unwrap().push(pid);
                Ok(())
            },
            dir.join("quarantine"),
        );
        (sink, canary, killed)
    }

    fn burst(sink: &DetectionSink, pid: u32) {
        for i in 0..30 {
            sink.on_event(rename_of(pid, i, ".locked"));
        }
    }

    const BURST_END_NS: u64 = 1_000_000_000 + 30 * 50_000_000;

    #[test]
    fn a_burst_then_a_canary_touch_by_the_same_process_kills_it() {
        let dir = tmp("reflex-burst-first");
        let (sink, canary, killed) = reflex_sink(&dir, true);
        burst(&sink, 900);
        assert!(
            killed.lock().unwrap().is_empty(),
            "a burst alone never kills"
        );
        sink.on_event(canary_open_at(&canary, 900, BURST_END_NS + 1_000_000));
        assert_eq!(*killed.lock().unwrap(), vec![900]);
        let alerts = alerts_in(&dir);
        assert!(
            alerts.contains("killed pid 900 on a corroborated ransomware signal"),
            "{alerts}"
        );
        assert!(
            alerts.find("canary file touched").unwrap() < alerts.find("RESPONSE-KILL").unwrap(),
            "the finding is recorded before the kill"
        );
    }

    #[test]
    fn a_canary_touch_then_a_burst_by_the_same_process_kills_it_once() {
        let dir = tmp("reflex-canary-first");
        let (sink, canary, killed) = reflex_sink(&dir, true);
        sink.on_event(canary_open_at(&canary, 900, 1_000_000_000));
        assert!(
            killed.lock().unwrap().is_empty(),
            "a canary touch alone never kills"
        );
        burst(&sink, 900);
        assert_eq!(
            *killed.lock().unwrap(),
            vec![900],
            "the burst keeps raising alerts but the process is killed once"
        );
    }

    #[test]
    fn a_burst_and_a_canary_touch_from_two_processes_kill_neither() {
        let dir = tmp("reflex-two-processes");
        let (sink, canary, killed) = reflex_sink(&dir, true);
        burst(&sink, 900);
        sink.on_event(canary_open_at(&canary, 901, BURST_END_NS + 1_000_000));
        assert!(killed.lock().unwrap().is_empty());
    }

    #[test]
    fn a_canary_touch_long_before_the_burst_does_not_corroborate() {
        let dir = tmp("reflex-stale");
        let (sink, canary, killed) = reflex_sink(&dir, true);
        sink.on_event(canary_open_at(&canary, 900, 1_000_000_000));
        // The same process starts its burst two minutes later.
        for i in 0..30 {
            let Event::FileRename(mut e) = rename_of(900, i, ".locked") else {
                unreachable!()
            };
            e.meta.timestamp_ns += 120_000_000_000;
            sink.on_event(Event::FileRename(e));
        }
        assert!(killed.lock().unwrap().is_empty());
    }

    #[test]
    fn an_allowed_executable_that_also_bursts_is_not_killed_by_the_reflex() {
        let dir = tmp("reflex-allowed");
        let (sink, canary, killed) = reflex_sink(&dir, true);
        // A backup tool: it reads the canaries and rotates archives (a burst of renames).
        sink.set_canary_allow(crate::deception::CanaryAllow::for_test(
            "/usr/bin/backup-tool",
            |_| Some("/usr/bin/backup-tool".into()),
        ));
        burst(&sink, 900);
        sink.on_event(canary_open_at(&canary, 900, BURST_END_NS + 1_000_000));
        assert!(
            killed.lock().unwrap().is_empty(),
            "an allowed process never notes a canary signal"
        );
        assert!(!alerts_in(&dir).contains("RESPONSE-KILL"));
    }

    /// #731 with #722: an allow-listed image recognised from the process's own `Exec` (no
    /// `/proc` read) is not killed by the reflex either, even when it bursts and reads a canary.
    #[test]
    fn a_process_allowed_from_its_exec_that_also_bursts_is_not_killed_by_the_reflex() {
        let dir = tmp("reflex-allowed-by-exec");
        let (sink, canary, killed) = reflex_sink(&dir, true);
        sink.set_canary_allow(crate::deception::CanaryAllow::for_test(
            "/usr/bin/backup-tool",
            |_| None,
        ));
        let mut exec = schema::fixtures::exec();
        exec.meta.pid = 900;
        exec.meta.process_generation = Some(5);
        exec.image_path = "/usr/bin/backup-tool".into();
        sink.on_event(Event::Exec(exec));
        for i in 0..30 {
            let Event::FileRename(mut e) = rename_of(900, i, ".locked") else {
                unreachable!()
            };
            e.meta.process_generation = Some(5);
            sink.on_event(Event::FileRename(e));
        }
        let Event::FileOpen(mut open) = canary_open_at(&canary, 900, BURST_END_NS + 1_000_000)
        else {
            unreachable!()
        };
        open.meta.process_generation = Some(5);
        sink.on_event(Event::FileOpen(open));
        assert!(killed.lock().unwrap().is_empty());
        assert!(!alerts_in(&dir).contains("RESPONSE-KILL"));
    }

    #[test]
    fn a_process_that_is_not_on_the_allow_list_is_still_killed_when_a_list_exists() {
        let dir = tmp("reflex-not-allowed");
        let (sink, canary, killed) = reflex_sink(&dir, true);
        sink.set_canary_allow(crate::deception::CanaryAllow::for_test(
            "/usr/bin/backup-tool",
            |_| Some("/tmp/encryptor".into()),
        ));
        burst(&sink, 900);
        sink.on_event(canary_open_at(&canary, 900, BURST_END_NS + 1_000_000));
        assert_eq!(*killed.lock().unwrap(), vec![900]);
    }

    #[test]
    fn with_kill_disabled_the_reflex_is_observe_only() {
        let dir = tmp("reflex-observe");
        let (sink, canary, killed) = reflex_sink(&dir, false);
        burst(&sink, 900);
        sink.on_event(canary_open_at(&canary, 900, BURST_END_NS + 1_000_000));
        assert!(killed.lock().unwrap().is_empty());
        let alerts = alerts_in(&dir);
        assert!(
            alerts.contains("pid 900 would have been killed on a corroborated ransomware signal"),
            "{alerts}"
        );
    }

    /// The ransomware detection (T1486, issue #82) carries the files the process touched
    /// in the window, so the case records the scope of the damage.
    #[test]
    fn a_ransomware_detection_carries_the_files_the_process_renamed_as_a_damage_manifest() {
        let dir = tmp("damage-manifest");
        let spool = Arc::new(Mutex::new(
            store::EventSpool::open(&dir.join("detection-spool"), u64::MAX).unwrap(),
        ));
        let sink = DetectionSink::new(
            rules::RuleState::new(),
            &dir.join("alerts.ndjson"),
            None,
            None,
            Some(Arc::clone(&spool)),
            &dir.join("content"),
            &dir.join("ml-registry"),
        )
        .unwrap();

        // 30 renames to an encrypted extension by one process, then a different process's
        // rename that must not appear in the manifest.
        for i in 0..30 {
            sink.on_event(rename_of(900, i, ".locked"));
        }
        sink.on_event(rename_of(901, 99, ".bak"));

        assert!(sink.enrich_queue().flush(std::time::Duration::from_secs(2)));
        let records: Vec<transport::QueuedDetection> =
            spool.lock().unwrap().drain_oldest().unwrap();
        let ransomware: Vec<_> = records
            .iter()
            .filter(|r| r.detection.techniques.iter().any(|t| t == "T1486"))
            .collect();
        assert!(
            !ransomware.is_empty(),
            "the burst must raise a T1486 detection"
        );
        let detection = &ransomware[0].detection;

        // First the triggering event, then the earlier renames of the same process.
        assert!(detection.events.len() > 1, "the manifest is attached");
        for event in &detection.events {
            let Event::FileRename(rename) = event else {
                panic!("only renames expected, got {event:?}");
            };
            assert_eq!(
                rename.meta.pid, 900,
                "another process's files are not this one's damage"
            );
        }
        let triggering = detection.events[0].clone();
        assert!(
            !detection.events[1..].contains(&triggering),
            "the triggering event is not repeated in the manifest"
        );
        // Oldest first.
        let stamps: Vec<u64> = detection.events[1..]
            .iter()
            .map(|e| e.meta().timestamp_ns)
            .collect();
        assert!(stamps.windows(2).all(|w| w[0] <= w[1]));
        assert!(detection.events.len() <= 1 + super::DAMAGE_MANIFEST_MAX);
    }

    #[test]
    fn a_detection_that_is_not_ransomware_carries_only_its_triggering_event() {
        let dir = tmp("no-manifest");
        let spool = Arc::new(Mutex::new(
            store::EventSpool::open(&dir.join("detection-spool"), u64::MAX).unwrap(),
        ));
        let sink = DetectionSink::new(
            rules::RuleState::new(),
            &dir.join("alerts.ndjson"),
            None,
            None,
            Some(Arc::clone(&spool)),
            &dir.join("content"),
            &dir.join("ml-registry"),
        )
        .unwrap();
        sink.on_event(rename_of(900, 0, ".bak"));
        let event = exec(7, "test", "/bin/test");
        sink.record_and_emit(
            &verdict::EntityKey::new(1, "test"),
            "T1059",
            "test finding",
            schema::detection::DetectionSource::Rule {
                rule_id: "T1059".into(),
            },
            schema::detection::Severity::Medium,
            &event,
        );
        assert!(sink.enrich_queue().flush(std::time::Duration::from_secs(2)));
        let records: Vec<transport::QueuedDetection> =
            spool.lock().unwrap().drain_oldest().unwrap();
        assert_eq!(
            records[0].detection.events,
            vec![with_its_enrichment(&event, &records[0].detection.events)]
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
                None,
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
    /// The directory a test writes its Sigma rule to: the one the agent reads on the host it
    /// runs on (`Platform::rule_dirs`, #980), not a fixed `linux/`: a Windows host loads only
    /// `windows/`, so a rule written elsewhere is never loaded. The rule below matches the
    /// image path of a synthetic exec event (`/opt/reload-content-marker`), so it fires on
    /// any host once it is loaded.
    fn host_sigma_dir(dir: &std::path::Path) -> std::path::PathBuf {
        let platform = sigma::Platform::host().expect("tests run on a platform with rules");
        dir.join("content")
            .join("rules")
            .join("sigma")
            .join(platform.rule_dirs()[0])
    }

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

        let sigma_dir = host_sigma_dir(&dir);
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
        let sigma_dir = host_sigma_dir(&dir);
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
            requester: None,
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
            // Root: unrestricted, the payload is the test's own file (#594).
            user: schema::User::Unix { uid: 0, gid: 0 },
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
                isolate_enabled: false,
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
                isolate_enabled: false,
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
            // Root: unrestricted, the payload is the test's own file (#594).
            user: schema::User::Unix { uid: 0, gid: 0 },
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

    /// Maps one page of anonymous read-write-execute memory holding `payload`: the shape
    /// of shellcode or a reflectively loaded image. `None` when the host refuses RWX
    /// mappings (`SELinux` `execmem` denial, a hardened kernel), so the test can skip.
    #[cfg(target_os = "linux")]
    fn plant_in_executable_memory(payload: &[u8]) -> Option<*mut libc::c_void> {
        assert!(payload.len() <= 4096);
        // SAFETY: a fresh private anonymous page, checked against MAP_FAILED before use,
        // and `payload` fits inside it (asserted above).
        unsafe {
            let page = libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if page == libc::MAP_FAILED {
                return None;
            }
            std::ptr::copy_nonoverlapping(payload.as_ptr(), page.cast::<u8>(), payload.len());
            Some(page)
        }
    }

    /// A fileless exec: the process image is a `/dev/fd/N` path and the comm says memfd,
    /// which is what the T1620 rule keys on. `pid` is a real, readable process so the
    /// memory scan it triggers is a real one.
    #[cfg(target_os = "linux")]
    fn memfd_exec_of(pid: u32) -> Event {
        Event::Exec(ExecEvent {
            meta: EventMeta {
                pid,
                ppid: 1,
                comm: "memfd:implant".into(),
                ..schema::fixtures::meta()
            },
            image_path: "/dev/fd/3".into(),
            argv: vec!["/dev/fd/3".into()],
            ..schema::fixtures::exec()
        })
    }

    /// Held by every test that scans this test process's own memory. The tests run in
    /// parallel in one process, so a marker one of them plants in an executable page is
    /// visible to a scan another one requests: the "clean" test then failed 17 times out
    /// of 30 on a `YARA-MEM` it never planted.
    #[cfg(target_os = "linux")]
    static OWN_PROCESS_MEMORY: Mutex<()> = Mutex::new(());

    /// Serializes the tests that scan `std::process::id()`. Poison-tolerant: one test's
    /// failed assertion must not fail the others on a poisoned lock.
    #[cfg(target_os = "linux")]
    fn own_process_memory() -> std::sync::MutexGuard<'static, ()> {
        OWN_PROCESS_MEMORY
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// #85 end to end, no mocks: a payload that exists only in executable anonymous
    /// memory of a real process is found by the scan the memfd-exec alert triggers.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_payload_present_only_in_executable_memory_is_found_after_a_memfd_exec_alert() {
        let _own_memory = own_process_memory();
        let dir = tmp("memscan-e2e");
        let yara_dir = dir.join("content").join("rules").join("yara");
        std::fs::create_dir_all(&yara_dir).unwrap();
        std::fs::write(
            yara_dir.join("marker.yar"),
            RESPONSE_MARKER_RULE.replace("severity = \"low\"", "severity = \"high\""),
        )
        .unwrap();
        let sink = sink_in(&dir);
        assert_eq!(sink.reload_content().yara_rule_count, Some(1));

        let Some(page) = plant_in_executable_memory(b"..RESPONSE-SCENARIO-MARKER..") else {
            eprintln!("skipped: this host refuses RWX anonymous mappings");
            return;
        };
        sink.on_event(memfd_exec_of(std::process::id()));
        let alerts = wait_for_alert(&dir, "YARA-MEM");
        // SAFETY: `page` is the one-page mapping created above and is not used again.
        unsafe { libc::munmap(page, 4096) };

        assert!(alerts.contains("T1620"), "the trigger is audited: {alerts}");
        assert!(
            alerts.contains("matched in the memory of pid"),
            "the memory match is audited: {alerts}"
        );
        assert!(
            alerts.contains("RESPONSE-ESCALATE"),
            "a High memory match escalates like any other finding: {alerts}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn a_memfd_exec_of_a_clean_process_triggers_a_scan_that_finds_nothing() {
        let _own_memory = own_process_memory();
        let dir = tmp("memscan-clean");
        let yara_dir = dir.join("content").join("rules").join("yara");
        std::fs::create_dir_all(&yara_dir).unwrap();
        std::fs::write(yara_dir.join("marker.yar"), RESPONSE_MARKER_RULE).unwrap();
        let sink = sink_in(&dir);
        assert_eq!(sink.reload_content().yara_rule_count, Some(1));

        sink.on_event(memfd_exec_of(std::process::id()));
        let stats_done = || {
            sink.memscan
                .lock()
                .unwrap()
                .as_ref()
                .map(|q| q.wait_for_completed(1, std::time::Duration::from_secs(10)))
        };
        assert_eq!(stats_done(), Some(true), "the scan ran");
        assert!(
            !alerts_in(&dir).contains("YARA-MEM"),
            "no marker in executable memory: {}",
            alerts_in(&dir)
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn without_yara_content_a_memfd_exec_requests_no_scan() {
        let dir = tmp("memscan-no-content");
        let sink = sink_in(&dir);
        sink.on_event(memfd_exec_of(std::process::id()));
        assert!(sink.memscan.lock().unwrap().is_none());
        assert!(
            alerts_in(&dir).contains("T1620"),
            "the rule itself still fires"
        );
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
                isolate_enabled: false,
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
        let sigma_dir = host_sigma_dir(&dir);
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

    /// A download-provenance mark on `image`, then `image` run inside the
    /// window, then the enrichment worker drained (#441).
    fn mark_then_run(sink: &DetectionSink, image: &str) {
        sink.on_event(Event::FileQuarantine(schema::FileQuarantineEvent {
            path: image.into(),
            ..schema::fixtures::file_quarantine()
        }));
        sink.on_event(Event::Exec(schema::ExecEvent {
            image_path: image.into(),
            ..schema::fixtures::exec()
        }));
        assert!(
            sink.enrich_queue()
                .flush(std::time::Duration::from_secs(30)),
            "the enrichment worker must drain"
        );
    }

    // ── the common-set snapshot (ADR-0020, issue #76) ───────────────────────

    /// A reference snapshot from the shared golden file (the same bytes the server's builder
    /// and the `ml` reader are tested against), with some hashes it contains.
    fn golden_common_set(case: &str) -> (Vec<u8>, Vec<String>, u32) {
        let doc: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../ml/tests/fixtures/common_set_snapshot_golden.json"
        )))
        .unwrap();
        let case = doc["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == case)
            .unwrap();
        let hex = case["bytes_hex"].as_str().unwrap();
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let members = case["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m.as_str().unwrap().to_owned())
            .collect();
        let hosts = u32::try_from(case["params"]["hosts_covered"].as_u64().unwrap()).unwrap();
        (bytes, members, hosts)
    }

    fn write_common_set(dir: &std::path::Path, bytes: &[u8]) {
        let snapshots = dir.join("content").join("snapshots");
        std::fs::create_dir_all(&snapshots).unwrap();
        std::fs::write(snapshots.join("common-set.bin"), bytes).unwrap();
    }

    #[test]
    fn a_common_set_snapshot_in_the_content_dir_is_loaded_at_startup() {
        use ml::features::rarity::CommonSet as _;
        let dir = tmp("common-set-startup");
        let (bytes, members, hosts) = golden_common_set("fifty_hashes_one_percent");
        write_common_set(&dir, &bytes);

        let sink = sink_in(&dir);

        let loaded = sink.common_set().expect("the snapshot must be loaded");
        assert_eq!(loaded.hosts_covered(), u64::from(hosts));
        assert!(members.iter().all(|m| loaded.contains(m)));
    }

    #[test]
    fn no_snapshot_file_means_no_common_set_and_no_failure() {
        let dir = tmp("common-set-absent");
        let sink = sink_in(&dir);
        assert!(sink.common_set().is_none());
        sink.reload_content();
        assert!(sink.common_set().is_none());
    }

    #[test]
    fn reload_content_picks_up_a_common_set_snapshot_added_after_construction() {
        let dir = tmp("common-set-reload");
        let sink = sink_in(&dir);
        assert!(sink.common_set().is_none());
        let (bytes, _, _) = golden_common_set("one_hash");
        write_common_set(&dir, &bytes);

        sink.reload_content();

        assert!(sink.common_set().is_some());
    }

    #[test]
    fn reload_content_unloads_the_common_set_when_its_file_is_removed() {
        // Same posture as the rule directories: an absent file is "no content", not an error,
        // and the evidence that depends on it is withheld rather than judged on a stale set.
        let dir = tmp("common-set-removed");
        let (bytes, _, _) = golden_common_set("one_hash");
        write_common_set(&dir, &bytes);
        let sink = sink_in(&dir);
        assert!(sink.common_set().is_some());
        std::fs::remove_file(dir.join("content/snapshots/common-set.bin")).unwrap();

        sink.reload_content();

        assert!(sink.common_set().is_none());
    }

    #[test]
    fn reload_content_keeps_the_previous_common_set_when_the_new_file_is_corrupt() {
        use ml::features::rarity::CommonSet as _;
        let dir = tmp("common-set-corrupt");
        let (bytes, members, _) = golden_common_set("fifty_hashes_one_percent");
        write_common_set(&dir, &bytes);
        let sink = sink_in(&dir);
        let mut broken = bytes.clone();
        broken.truncate(bytes.len() - 1);
        write_common_set(&dir, &broken);

        sink.reload_content();

        let kept = sink.common_set().expect("a broken file must not unload it");
        assert!(members.iter().all(|m| kept.contains(m)));
    }

    #[test]
    fn a_corrupt_common_set_at_startup_leaves_it_unloaded_not_the_agent_down() {
        let dir = tmp("common-set-corrupt-startup");
        write_common_set(&dir, b"not a snapshot");
        let sink = sink_in(&dir);
        assert!(sink.common_set().is_none());
    }

    #[test]
    fn a_common_set_file_over_the_size_cap_is_refused_unread() {
        let dir = tmp("common-set-cap");
        let (bytes, _, _) = golden_common_set("two_hundred_hashes_one_in_a_thousand");
        write_common_set(&dir, &bytes);
        let root = dir.join("content");

        assert!(matches!(
            super::load_common_set_capped(&root, u64::try_from(bytes.len()).unwrap()),
            super::Load::Loaded(_)
        ));
        assert!(matches!(
            super::load_common_set_capped(&root, u64::try_from(bytes.len()).unwrap() - 1),
            super::Load::Failed
        ));
    }

    #[test]
    fn a_directory_where_the_common_set_file_belongs_is_a_failure_not_a_crash() {
        let dir = tmp("common-set-dir");
        std::fs::create_dir_all(dir.join("content/snapshots/common-set.bin")).unwrap();
        let sink = sink_in(&dir);
        assert!(sink.common_set().is_none());
    }

    // ── rarity evidence (ADR-0020, issue #76) ───────────────────────────────

    /// A hash the snapshot built in a golden case does not contain.
    fn golden_non_member(case: &str) -> String {
        let doc: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../ml/tests/fixtures/common_set_snapshot_golden.json"
        )))
        .unwrap();
        let case = doc["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == case)
            .unwrap();
        case["non_members"][0].as_str().unwrap().to_owned()
    }

    #[test]
    fn rarity_evidence_follows_the_snapshot_the_hash_and_the_coverage() {
        use ml::features::common_set::CommonSetSnapshot;
        let load = |case: &str| CommonSetSnapshot::parse(&golden_common_set(case).0).unwrap();
        let wide = load("fifty_hashes_one_percent"); // 12 hosts covered
        let member = golden_common_set("fifty_hashes_one_percent").1[0].clone();
        let absent = golden_non_member("fifty_hashes_one_percent");

        assert_eq!(
            super::rarity_evidence(Some(&member), Some(&wide), 10),
            super::Rarity::InCommonSet
        );
        assert_eq!(
            super::rarity_evidence(Some(&absent), Some(&wide), 10),
            super::Rarity::NotInCommonSet
        );
        // Coverage exactly at the minimum counts, one below withholds.
        assert_eq!(
            super::rarity_evidence(Some(&absent), Some(&wide), 12),
            super::Rarity::NotInCommonSet
        );
        assert_eq!(
            super::rarity_evidence(Some(&absent), Some(&wide), 13),
            super::Rarity::Withheld
        );
        // A snapshot built from 4 hosts is too thin to call anything rare.
        let thin = load("one_hash");
        assert_eq!(
            super::rarity_evidence(Some(&absent), Some(&thin), 10),
            super::Rarity::Withheld
        );
        // No snapshot, no hash, or something that is not a hash: nothing to say.
        assert_eq!(
            super::rarity_evidence(Some(&absent), None, 10),
            super::Rarity::Withheld
        );
        assert_eq!(
            super::rarity_evidence(None, Some(&wide), 10),
            super::Rarity::Withheld
        );
        assert_eq!(
            super::rarity_evidence(Some("not-a-hash"), Some(&wide), 10),
            super::Rarity::Withheld
        );
    }

    /// An exec whose hash is `sha256`, for [`note_image_rarity`].
    fn exec_hashed(pid: u32, sha256: Option<&str>) -> ExecEvent {
        ExecEvent {
            meta: EventMeta {
                pid,
                ..schema::fixtures::meta()
            },
            sha256: sha256.map(str::to_owned),
            ..schema::fixtures::exec()
        }
    }

    /// The counts after one exec, against an engine that has (or has not) correlated it.
    fn rarity_counts_after(
        case: &str,
        sha256: Option<String>,
        correlated: bool,
    ) -> crate::health::RarityCounts {
        use ml::features::common_set::CommonSetSnapshot;

        use crate::health::RarityStatsSource as _;

        let snapshot = CommonSetSnapshot::parse(&golden_common_set(case).0).unwrap();
        // "Now" is the instant the snapshot was built: its age is not what these cases are about.
        let now = snapshot.header().built_at;
        let exec = exec_hashed(7_001, sha256.as_deref());
        let mut engine = correlator::CorrelationEngine::new();
        if correlated {
            engine.on_event(Event::Exec(exec.clone()));
        }
        let stats = super::RarityStats::default();
        super::note_image_rarity(
            &Mutex::new(engine),
            &Mutex::new(Some(Arc::new(snapshot))),
            &stats,
            &exec,
            now,
        );
        stats.rarity_counts()
    }

    #[test]
    fn rarity_counts_an_applied_evidence() {
        let absent = golden_non_member("fifty_hashes_one_percent");
        let counts = rarity_counts_after("fifty_hashes_one_percent", Some(absent), true);
        assert_eq!(
            (counts.applied, counts.withheld, counts.unapplied),
            (1, 0, 0)
        );
    }

    #[test]
    fn rarity_counts_evidence_that_found_no_belief_to_land_on() {
        // The correlator evicted (or never created) the process's belief: the loss is
        // counted, not silent.
        let absent = golden_non_member("fifty_hashes_one_percent");
        let counts = rarity_counts_after("fifty_hashes_one_percent", Some(absent), false);
        assert_eq!(
            (counts.applied, counts.withheld, counts.unapplied),
            (0, 0, 1)
        );
    }

    #[test]
    fn rarity_counts_a_withheld_judgement_whatever_the_reason() {
        let absent = golden_non_member("fifty_hashes_one_percent");
        // A snapshot too thin to judge by, then an exec with no hash.
        let thin = rarity_counts_after("one_hash", Some(absent), true);
        let no_hash = rarity_counts_after("fifty_hashes_one_percent", None, true);
        assert_eq!((thin.applied, thin.withheld, thin.unapplied), (0, 1, 0));
        assert_eq!(
            (no_hash.applied, no_hash.withheld, no_hash.unapplied),
            (0, 1, 0)
        );
    }

    #[test]
    fn rarity_counts_nothing_for_an_image_the_fleet_knows() {
        let member = golden_common_set("fifty_hashes_one_percent").1[0].clone();
        let counts = rarity_counts_after("fifty_hashes_one_percent", Some(member), true);
        assert_eq!(
            (counts.applied, counts.withheld, counts.unapplied),
            (0, 0, 0)
        );
    }

    #[test]
    fn rarity_counts_withheld_with_no_snapshot_at_all() {
        use crate::health::RarityStatsSource as _;
        let stats = super::RarityStats::default();
        super::note_image_rarity(
            &Mutex::new(correlator::CorrelationEngine::new()),
            &Mutex::new(None),
            &stats,
            &exec_hashed(7_002, Some(&"ab".repeat(32))),
            0,
        );
        assert_eq!(stats.rarity_counts().withheld, 1);
    }

    /// The same non-member judged at two instants: inside the maximum age it is evidence, past
    /// it the snapshot counts as absent and the judgement is withheld (ADR-0033 decision 3).
    #[test]
    fn a_snapshot_past_its_maximum_age_withholds_the_evidence() {
        use crate::health::RarityStatsSource as _;
        let case = "fifty_hashes_one_percent";
        let absent = golden_non_member(case);
        let built_at =
            ml::features::common_set::CommonSetSnapshot::parse(&golden_common_set(case).0)
                .unwrap()
                .header()
                .built_at;
        let counts_at = |now: u64| {
            let mut engine = correlator::CorrelationEngine::new();
            let exec = exec_hashed(7_003, Some(&absent));
            engine.on_event(Event::Exec(exec.clone()));
            let stats = super::RarityStats::default();
            super::note_image_rarity(
                &Mutex::new(engine),
                &Mutex::new(Some(Arc::new(
                    ml::features::common_set::CommonSetSnapshot::parse(&golden_common_set(case).0)
                        .unwrap(),
                ))),
                &stats,
                &exec,
                now,
            );
            stats.rarity_counts()
        };
        let max = super::MAX_SNAPSHOT_AGE_SECS;
        assert_eq!(
            counts_at(built_at + max).applied,
            1,
            "at the maximum age it is still in force"
        );
        let past = counts_at(built_at + max + 1);
        assert_eq!((past.applied, past.withheld), (0, 1));
    }

    /// A version-1 snapshot built here (the layout in
    /// `docs/detection/common-set-snapshot-format.md`): a fixed 4096-bit, 7-hash filter holding
    /// `hashes`, claiming `hosts_covered` hosts.
    fn snapshot_holding(hashes: &[&str], hosts_covered: u32) -> Vec<u8> {
        const BITS: u32 = 4096;
        const HASHES: u16 = 7;
        let mut body = vec![0u8; (BITS / 8) as usize];
        for hash in hashes {
            let raw: Vec<u8> = (0..32)
                .map(|i| u8::from_str_radix(&hash[i * 2..i * 2 + 2], 16).unwrap())
                .collect();
            let h1 = u64::from_le_bytes(raw[0..8].try_into().unwrap());
            let h2 = u64::from_le_bytes(raw[8..16].try_into().unwrap()) | 1;
            for i in 0..u64::from(HASHES) {
                let bit = h1.wrapping_add(i.wrapping_mul(h2)) % u64::from(BITS);
                body[(bit >> 3) as usize] |= 1 << (bit & 7);
            }
        }
        let mut out = b"SYCS".to_vec();
        out.extend(1u16.to_le_bytes());
        out.extend(HASHES.to_le_bytes());
        out.extend(3u32.to_le_bytes());
        out.extend(hosts_covered.to_le_bytes());
        out.extend(u32::try_from(hashes.len()).unwrap().to_le_bytes());
        out.extend(BITS.to_le_bytes());
        // Built just now: the worker judges against the real clock, and a snapshot past its
        // maximum age is withheld (ADR-0033).
        out.extend(super::unix_now_secs().to_le_bytes());
        out.extend(body);
        out
    }

    /// What the snapshot holds, for [`belief_after_exec`].
    enum Snapshot {
        None,
        /// Holds the executed image's own hash.
        HoldingTheImage {
            hosts_covered: u32,
        },
        /// Holds only an unrelated hash.
        HoldingOthers {
            hosts_covered: u32,
        },
    }

    /// Runs one exec of a file through a sink, lets the enrichment worker finish, and returns
    /// the belief the correlator holds for the process.
    fn belief_after_exec(name: &str, snapshot: &Snapshot, image_exists: bool) -> f32 {
        let dir = tmp(name);
        let image = dir.join("image.bin");
        if image_exists {
            std::fs::write(&image, b"an executable nobody on the fleet has run").unwrap();
        }
        let image_hash = enrich::Enricher::new()
            .enrich(&image)
            .sha256
            .unwrap_or_else(|| "cd".repeat(32));
        let unrelated = "ab".repeat(32);
        match snapshot {
            Snapshot::None => {}
            Snapshot::HoldingTheImage { hosts_covered } => {
                write_common_set(&dir, &snapshot_holding(&[&image_hash], *hosts_covered));
            }
            Snapshot::HoldingOthers { hosts_covered } => {
                write_common_set(&dir, &snapshot_holding(&[&unrelated], *hosts_covered));
            }
        }
        let sink = sink_in(&dir);

        sink.on_event(exec(9_100, "run", image.to_str().unwrap()));
        assert!(sink.enrich_queue().flush(std::time::Duration::from_secs(2)));

        let engine = sink.correlator.lock().unwrap();
        engine
            .belief_for_pid(9_100)
            .expect("the exec created a belief")
            .log_odds
    }

    #[test]
    fn an_image_the_fleet_has_not_seen_raises_the_belief_a_little() {
        let baseline = belief_after_exec("rarity-baseline", &Snapshot::None, true);

        let rare = belief_after_exec(
            "rarity-rare",
            &Snapshot::HoldingOthers { hosts_covered: 50 },
            true,
        );

        let gained = rare - baseline;
        assert!(gained > 0.0, "rarity evidence must apply, gained {gained}");
        assert!(
            gained <= 1.0,
            "and stay within its allowance, gained {gained}"
        );
    }

    #[test]
    fn an_image_in_the_common_set_adds_nothing() {
        let baseline = belief_after_exec("rarity-common-baseline", &Snapshot::None, true);
        let common = belief_after_exec(
            "rarity-common",
            &Snapshot::HoldingTheImage { hosts_covered: 50 },
            true,
        );
        assert!((common - baseline).abs() < 1e-6);
    }

    #[test]
    fn a_snapshot_covering_too_few_hosts_adds_nothing() {
        // A freshly enrolled fleet has a thin snapshot: without this every binary on it
        // would look rare.
        let baseline = belief_after_exec("rarity-thin-baseline", &Snapshot::None, true);
        let thin = belief_after_exec(
            "rarity-thin",
            &Snapshot::HoldingOthers { hosts_covered: 3 },
            true,
        );
        assert!((thin - baseline).abs() < 1e-6);
    }

    #[test]
    fn an_exec_with_no_readable_image_adds_nothing() {
        let baseline = belief_after_exec("rarity-nohash-baseline", &Snapshot::None, false);
        let unreadable = belief_after_exec(
            "rarity-nohash",
            &Snapshot::HoldingOthers { hosts_covered: 50 },
            false,
        );
        assert!((unreadable - baseline).abs() < 1e-6);
    }

    #[test]
    fn a_marked_unsigned_file_run_alerts_after_enrichment() {
        let dir = tmp("gate-unsigned");
        let image = dir.join("invoice.exe");
        // A real unsigned PE: this test binary. Bytes that are not a PE verify
        // as `Unsupported` on Windows, not `Unsigned`.
        std::fs::copy(std::env::current_exe().unwrap(), &image).unwrap();
        let sink = sink_in(&dir);
        mark_then_run(&sink, &image.to_string_lossy());
        let alerts = alerts_in(&dir);
        assert!(alerts.contains("T1204.002"), "{alerts}");
        #[cfg(windows)]
        assert!(alerts.contains("[unsigned]"), "{alerts}");
        drop(sink);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The issue's done-when: a signed installer run does not alert. notepad.exe
    /// is catalog-signed, so it verifies `Valid` (the enrich crate's own test).
    #[cfg(windows)]
    #[test]
    fn a_marked_signed_file_run_does_not_alert() {
        let image = r"C:\Windows\System32\notepad.exe";
        if !std::path::Path::new(image).exists() {
            eprintln!("skipping: {image} not present on this host");
            return;
        }
        let dir = tmp("gate-signed");
        let sink = sink_in(&dir);
        mark_then_run(&sink, image);
        let alerts = alerts_in(&dir);
        assert!(!alerts.contains("T1204.002"), "{alerts}");
    }

    /// #655 review: a signed file runs once (its `Valid` verdict cached), then an
    /// unsigned file of the same size takes its path with the mtime restored. The
    /// Windows cache key has no file identity, so only an uncached verification
    /// keeps the gate from reading the old file's verdict.
    #[cfg(windows)]
    #[test]
    fn a_cached_valid_verdict_for_a_replaced_file_does_not_silence_t1204_002() {
        let signed = std::path::Path::new(r"C:\Windows\System32\notepad.exe");
        let Ok(bytes) = std::fs::read(signed) else {
            eprintln!("skipping: {} not readable on this host", signed.display());
            return;
        };
        let dir = tmp("gate-replaced");
        let image = dir.join("setup.exe");
        std::fs::write(&image, &bytes).unwrap();
        // Catalog-signed: a copy verifies by its hash, so it is `Valid` too.
        if enrich::Enricher::new().enrich(&image).signature != schema::Signature::Valid {
            eprintln!("skipping: the notepad.exe copy does not verify on this host");
            return;
        }
        let sink = sink_in(&dir);
        let path = image.to_string_lossy().into_owned();
        sink.on_event(Event::Exec(schema::ExecEvent {
            image_path: path.clone(),
            ..schema::fixtures::exec()
        }));
        assert!(
            sink.enrich_queue()
                .flush(std::time::Duration::from_secs(30))
        );

        let mtime = std::fs::metadata(&image).unwrap().modified().unwrap();
        let mut tampered = bytes;
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0xFF;
        std::fs::write(&image, &tampered).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&image)
            .unwrap()
            .set_modified(mtime)
            .unwrap();

        mark_then_run(&sink, &path);
        let alerts = alerts_in(&dir);
        assert!(alerts.contains("T1204.002"), "{alerts}");
        drop(sink);
        std::fs::remove_dir_all(&dir).ok();
    }

    const IOC_HASH: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    fn write_ioc_feed(dir: &std::path::Path, text: &str) {
        let feeds = dir.join("content").join("ioc");
        std::fs::create_dir_all(&feeds).unwrap();
        std::fs::write(feeds.join("test-feed.txt"), text).unwrap();
        std::fs::write(feeds.join("VERSION"), "2026-10-26.1\n").unwrap();
    }

    fn connect_to(addr: &str, timestamp_ns: u64) -> Event {
        Event::Connect(schema::ConnectEvent {
            meta: EventMeta {
                timestamp_ns,
                ..schema::fixtures::meta()
            },
            daddr: addr.parse().unwrap(),
            dport: 443,
        })
    }

    #[test]
    fn a_connect_to_a_listed_address_raises_one_ioc_finding_and_the_repeat_is_absorbed() {
        let dir = tmp("ioc-connect");
        write_ioc_feed(&dir, "ip:203.0.113.9\n");
        let spool = Arc::new(Mutex::new(
            store::EventSpool::open(&dir.join("detection-spool"), u64::MAX).unwrap(),
        ));
        let sink = DetectionSink::new(
            rules::RuleState::new(),
            &dir.join("alerts.ndjson"),
            Some(&dir.join("events.jsonl")),
            None,
            Some(Arc::clone(&spool)),
            &dir.join("content"),
            &dir.join("ml-registry"),
        )
        .unwrap();

        sink.on_event(connect_to("203.0.113.10", 1_000));
        assert!(
            !alerts_in(&dir).contains("IOC"),
            "an unlisted address is silent"
        );
        sink.on_event(connect_to("203.0.113.9", 2_000));
        sink.on_event(connect_to("203.0.113.9", 3_000));
        assert!(sink.enrich_queue().flush(std::time::Duration::from_secs(2)));

        let alerts = alerts_in(&dir);
        assert_eq!(alerts.matches("203.0.113.9").count(), 1, "{alerts}");
        assert!(
            alerts.contains("test-feed") && alerts.contains("2026-10-26.1"),
            "{alerts}"
        );
        // The repeated connects may also move the correlator's belief; only IOC findings count.
        let drained: Vec<transport::QueuedDetection> =
            spool.lock().unwrap().drain_oldest().unwrap();
        let records: Vec<_> = drained
            .into_iter()
            .filter(|r| {
                matches!(
                    r.detection.source,
                    schema::detection::DetectionSource::Ioc { .. }
                )
            })
            .collect();
        assert_eq!(records.len(), 1);
        let detection = &records[0].detection;
        assert_eq!(detection.severity, schema::detection::Severity::Medium);
        assert!(
            detection.techniques.is_empty(),
            "IOC is not an ATT&CK technique"
        );
        assert_eq!(
            detection.source,
            schema::detection::DetectionSource::Ioc {
                kind: schema::detection::IocKind::Ip,
                indicator: "203.0.113.9".into(),
                feed: "test-feed".into(),
                feed_version: "2026-10-26.1".into(),
                reference: None,
            }
        );
        drop(sink);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_polled_flow_to_a_listed_address_raises_one_ioc_finding() {
        let dir = tmp("ioc-flow");
        write_ioc_feed(&dir, "ip:203.0.113.9\n");
        let sink = DetectionSink::new(
            rules::RuleState::new(),
            &dir.join("alerts.ndjson"),
            Some(&dir.join("events.jsonl")),
            None,
            None,
            &dir.join("content"),
            &dir.join("ml-registry"),
        )
        .unwrap();

        let flow = |addr: &str, timestamp_ns: u64| {
            Event::NetworkFlow(schema::NetworkFlowEvent {
                meta: EventMeta {
                    timestamp_ns,
                    ..schema::fixtures::meta()
                },
                daddr: addr.parse().unwrap(),
                ..schema::fixtures::network_flow()
            })
        };
        sink.on_event(flow("203.0.113.10", 1_000));
        assert!(
            !alerts_in(&dir).contains("IOC"),
            "an unlisted peer is silent"
        );
        for poll in 0..3 {
            sink.on_event(flow("203.0.113.9", 2_000 + poll));
        }
        assert!(sink.enrich_queue().flush(std::time::Duration::from_secs(2)));

        let alerts = alerts_in(&dir);
        assert_eq!(alerts.matches("203.0.113.9").count(), 1, "{alerts}");
        drop(sink);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_exec_whose_image_hash_is_listed_raises_a_high_ioc_finding_from_the_worker() {
        let dir = tmp("ioc-exec");
        write_ioc_feed(&dir, &format!("sha256:{IOC_HASH}\n"));
        let spool = Arc::new(Mutex::new(
            store::EventSpool::open(&dir.join("detection-spool"), u64::MAX).unwrap(),
        ));
        let sink = DetectionSink::new(
            rules::RuleState::new(),
            &dir.join("alerts.ndjson"),
            Some(&dir.join("events.jsonl")),
            None,
            Some(Arc::clone(&spool)),
            &dir.join("content"),
            &dir.join("ml-registry"),
        )
        .unwrap();
        // The hash is set on the event, as enrichment leaves it: the worker looks it up.
        let listed = Event::Exec(ExecEvent {
            sha256: Some(IOC_HASH.to_uppercase()),
            image_path: String::new(),
            ..schema::fixtures::exec()
        });
        let other = Event::Exec(ExecEvent {
            sha256: Some("0".repeat(64)),
            image_path: String::new(),
            ..schema::fixtures::exec()
        });

        sink.on_event(other);
        sink.on_event(listed);
        assert!(sink.enrich_queue().flush(std::time::Duration::from_secs(2)));

        let alerts = alerts_in(&dir);
        assert!(alerts.contains(IOC_HASH), "{alerts}");
        let records: Vec<transport::QueuedDetection> =
            spool.lock().unwrap().drain_oldest().unwrap();
        let [record] = records.as_slice() else {
            panic!("exactly one IOC detection expected, got {}", records.len());
        };
        assert_eq!(record.detection.severity, schema::detection::Severity::High);
        assert!(matches!(
            record.detection.source,
            schema::detection::DetectionSource::Ioc {
                kind: schema::detection::IocKind::Sha256,
                ..
            }
        ));
        drop(sink);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reload_content_picks_up_a_feed_added_after_construction_and_unloads_a_removed_one() {
        let dir = tmp("ioc-reload");
        let sink = sink_in(&dir);
        sink.on_event(connect_to("203.0.113.9", 1_000));
        assert!(!alerts_in(&dir).contains("IOC"));

        write_ioc_feed(&dir, "ip:203.0.113.9\n");
        sink.reload_content();
        sink.on_event(connect_to("203.0.113.9", 2_000));
        assert!(alerts_in(&dir).contains("203.0.113.9"));

        std::fs::remove_dir_all(dir.join("content").join("ioc")).unwrap();
        sink.reload_content();
        let before = alerts_in(&dir).matches("203.0.113.9").count();
        sink.on_event(connect_to("203.0.113.9", 2 * 60 * 60 * 1_000_000_000));
        assert_eq!(alerts_in(&dir).matches("203.0.113.9").count(), before);
        drop(sink);
        std::fs::remove_dir_all(&dir).ok();
    }

    fn dns_query_of(name: &str, timestamp_ns: u64) -> Event {
        Event::DnsQuery(schema::DnsQueryEvent {
            meta: EventMeta {
                timestamp_ns,
                ..schema::fixtures::meta()
            },
            query: name.into(),
            ..schema::fixtures::dns_query()
        })
    }

    #[test]
    fn a_dns_query_under_a_listed_domain_names_the_listed_domain_not_the_subdomain() {
        let dir = tmp("ioc-dns");
        write_ioc_feed(&dir, "domain:evil.example\n");
        let spool = Arc::new(Mutex::new(
            store::EventSpool::open(&dir.join("detection-spool"), u64::MAX).unwrap(),
        ));
        let sink = DetectionSink::new(
            rules::RuleState::new(),
            &dir.join("alerts.ndjson"),
            Some(&dir.join("events.jsonl")),
            None,
            Some(Arc::clone(&spool)),
            &dir.join("content"),
            &dir.join("ml-registry"),
        )
        .unwrap();

        sink.on_event(dns_query_of("good.example", 1_000));
        sink.on_event(dns_query_of("notevil.example", 2_000));
        sink.on_event(dns_query_of("Cdn.Evil.Example.", 3_000));
        assert!(sink.enrich_queue().flush(std::time::Duration::from_secs(2)));

        let drained: Vec<transport::QueuedDetection> =
            spool.lock().unwrap().drain_oldest().unwrap();
        let records: Vec<_> = drained
            .into_iter()
            .filter(|r| {
                matches!(
                    r.detection.source,
                    schema::detection::DetectionSource::Ioc { .. }
                )
            })
            .collect();
        let [record] = records.as_slice() else {
            panic!("exactly one IOC detection expected, got {}", records.len());
        };
        assert_eq!(
            record.detection.severity,
            schema::detection::Severity::Medium
        );
        assert_eq!(
            record.detection.source,
            schema::detection::DetectionSource::Ioc {
                kind: schema::detection::IocKind::Domain,
                indicator: "evil.example".into(),
                feed: "test-feed".into(),
                feed_version: "2026-10-26.1".into(),
                reference: None,
            }
        );
        drop(sink);
        std::fs::remove_dir_all(&dir).ok();
    }
}
