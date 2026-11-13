//! The agent's own `EventSink`s: `DetectionSink`, which runs every event through the
//! detection engines (rules, Sigma, IOC, YARA, deception canaries, the correlator and
//! the ML correlation scorer), fuses verdicts and records alerts, detections and
//! responses; and [`BaselineSink`] (in `baseline`), which stores the redacted exec
//! corpus used for ML training. Raw capture needs no sink of its own: it uses
//! `sinks::JsonlEventSink` directly.

// Production locks go through `LockExt::lock_recovering` (the agent's poisoned-lock policy,
// `crate::sync`); a bare `unwrap` here would bring the panic-on-poison back.
#![cfg_attr(not(test), warn(clippy::unwrap_used))]

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use schema::{Event, sensor::EventSink};
use sinks::JsonlWriter;

use crate::{
    alerts::{AlertLog, RECENT_ALERTS_CAPACITY},
    enrich_queue::EnrichQueue,
    sync::LockExt as _,
};

mod baseline;
mod canary;
mod correlation;
mod recording;
mod response;

pub(crate) use baseline::BaselineSink;
pub(crate) use correlation::{correlator_case_id, model_root};
use recording::{Finding, record_ioc_hit, record_rule_alert, spool_on_worker};
use response::{DAMAGE_MANIFEST_MAX, ResponseCell};

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
    /// What tells the agent's own control-plane traffic from everything else (<https://github.com/synthaea-lab/agent/issues/47>).
    own_traffic: Arc<crate::own_traffic::OwnTraffic>,
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
    /// Issue #25's automated response, empty until (if ever) `enable_response` sets it.
    /// Shared with the YARA worker, which quarantines through it.
    response: Arc<ResponseCell>,
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
    /// Which canary touches become findings (#81).
    canary: canary::CanaryGate,
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

/// The events the server keeps per detection (`MAX_EVENTS`, server/lib/detection-payload.ts,
/// #1060); a server unit test reads this line, in this file, and fails when the two differ.
const SERVER_MAX_EVENTS: usize = 128;
// The trigger plus the manifest: `1 + DAMAGE_MANIFEST_MAX <= SERVER_MAX_EVENTS`.
const _: () = assert!(DAMAGE_MANIFEST_MAX < SERVER_MAX_EVENTS);

/// The escalation decision (#612) as a free function so the YARA scan worker, which
/// has no `DetectionSink`, raises the same alert as every other engine (#614). A new
/// verdict snapshot (first sighting, a severity raise, or a recurrence outside the
/// dedup window — never a silently absorbed duplicate) whose composed severity
/// warrants it raises one `RESPONSE-ESCALATE` audit alert. Never kills or
/// quarantines, and works with or without `enable_response`.
fn escalate_if_warranted(alert_log: &AlertLog, fused: &verdict::Verdict) {
    if !::response::should_escalate(fused.severity) {
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

/// How long a technique already recorded for an entity stays "the same finding":
/// a second engine (or the same engine again) reporting it inside this window
/// folds in silently instead of producing a second alert. Matches the
/// ransomware-detection window's order of magnitude (`crates/rules/src/
/// exclusions.rs`'s `RANSOMWARE_RENAME_WINDOW_NS`) — long enough to absorb
/// ordinary cross-engine timing skew (Sigma/rules run inline, the correlator
/// reacts to the same event a few lines later), short enough that a genuine
/// second occurrence of the same technique still gets its own finding.
const VERDICT_DEDUP_WINDOW_NS: u64 = 30_000_000_000; // 30s

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
                    && let Err(e) = spool.lock_recovering().push(&safe_event)
                {
                    // Spool full is handled inside push (shed-oldest, counted);
                    // reaching here is a real I/O failure — degrade to local-only.
                    tracing::warn!(error = %e, "spool append failed — event stays local-only");
                }
            },
            move |detection| spool_on_worker(worker_spool.as_deref(), detection),
        )?;
        let response = Arc::new(ResponseCell::new());
        Ok(Self {
            rule_state: Mutex::new(rule_state),
            correlator,
            ml_scorer: Mutex::new(correlation::load_correlation_scorer(model_root)),
            sigma: Mutex::new(load_sigma_rules(&content_root).into_option()),
            common_set,
            ioc,
            own_traffic: Arc::new(crate::own_traffic::OwnTraffic::new()),
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
            canary: canary::CanaryGate::new(),
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
        let mut sigma_slot = self.sigma.lock_recovering();
        let (sigma_reload_failed, old_sigma) = match sigma_loaded {
            Load::Loaded(engine) => (false, sigma_slot.replace(engine)),
            Load::Absent => (false, sigma_slot.take()),
            Load::Failed => (true, None),
        };
        let sigma_rule_count = sigma_slot.as_ref().map(sigma::SigmaEngine::rule_count);
        drop(sigma_slot);
        drop(old_sigma);

        let mut yara_slot = self.yara.lock_recovering();
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
        let mut memscan_slot = self.memscan.lock_recovering();
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

    /// Returns a reference to the enrichment queue for health telemetry.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn enrich_queue(&self) -> &EnrichQueue {
        &self.enrich_queue
    }

    /// The fused verdict of the entity `meta` belongs to, or `None` while no finding was
    /// recorded for it. `agent replay` reads it to write one case per entity.
    pub(crate) fn verdict_for(&self, meta: &schema::EventMeta) -> Option<verdict::Verdict> {
        self.verdict.lock_recovering().peek(&entity_key(meta))
    }

    /// Stops the YARA file and memory scanners. A replay must not scan anything: the pids
    /// and paths in a recorded trace name processes and files of the host that captured
    /// it, not of the one replaying it.
    pub(crate) fn stop_host_scans(&self) {
        let yara = self.yara.lock_recovering().take();
        let memscan = self.memscan.lock_recovering().take();
        // Dropped after the locks are released, like `reload_content` does.
        drop((yara, memscan));
    }

    /// Hands out the shared progress counter for `agent::heartbeat::start` to
    /// sample (#102) — a clone of the `Arc`, not the sink itself, so the
    /// heartbeat writer thread needs no reference to the sink or its other
    /// state.
    pub(crate) fn progress_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.progress)
    }

    /// Asks for a budgeted YARA scan of the memory of the process behind `event` (#85):
    /// the payload of a fileless exec exists only there. The scan queue applies the
    /// cooldown, the global cap and the per-scan budget; a shed request is counted there.
    fn request_memory_scan(&self, event: &Event) {
        let guard = self.memscan.lock_recovering();
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
        self.canary.set_tripwires(tripwires);
    }

    /// Tells the rules the host's UTC offset in minutes (<https://github.com/synthaea-lab/agent/issues/17>); false when it is not a real one.
    pub(crate) fn set_local_utc_offset_minutes(&self, minutes: i32) -> bool {
        self.rule_state
            .lock_recovering()
            .set_local_utc_offset_minutes(minutes)
    }

    /// Declares the ordinary local hours (<https://github.com/synthaea-lab/agent/issues/64>); false when they are not a window.
    pub(crate) fn set_work_hours(&self, start: u32, end: u32) -> bool {
        self.rule_state.lock_recovering().set_work_hours(start, end)
    }

    /// Declares the accounts whose odd-hour logons are expected (<https://github.com/synthaea-lab/agent/issues/64>).
    pub(crate) fn set_odd_hour_exempt_accounts(&self, accounts: &[String]) -> usize {
        self.rule_state
            .lock_recovering()
            .set_odd_hour_exempt_accounts(accounts)
    }

    /// Gives the rules the platform's time zone (<https://github.com/synthaea-lab/agent/issues/15>); false when it has no answer for `now_secs`.
    pub(crate) fn set_local_zone(&self, zone: rules::LocalOffsetAt, now_secs: i64) -> bool {
        self.rule_state
            .lock_recovering()
            .set_local_zone(zone, now_secs)
    }

    /// Installs the executables allowed to touch a canary (#81). Called once, with the
    /// tripwires.
    pub(crate) fn set_canary_allow(&self, allow: crate::deception::CanaryAllow) {
        self.canary.set_allow(allow);
    }

    /// Records a canary touch the gate did not excuse, and runs the ransomware join on it: the
    /// reflex kills when the same process also burst, unless the touch was judged late.
    fn record_canary_touch(&self, touch: canary::CanaryTouch<'_>) {
        let meta = touch.event.meta();
        let corroborated = self.ransomware_join.lock_recovering().note_canary(
            touch.pid,
            meta.process_generation,
            meta.timestamp_ns,
        );
        let raised = match &touch.outcome {
            canary::TouchOutcome::Raise { message } => {
                let entity = entity_key(meta);
                self.record(Finding::canary(&entity, message), &touch.event, Vec::new());
                true
            }
            // The finding was raised by the touch that started the cooldown; the reflex
            // does not wait for a new one.
            canary::TouchOutcome::Absorbed => false,
        };
        if corroborated && !touch.late {
            self.ransomware_reflex(touch.pid);
        } else if corroborated && raised {
            tracing::info!(
                pid = touch.pid,
                "deception: ransomware reflex skipped for a canary touch judged after the hold"
            );
        }
    }

    /// An IOC match found on the capture thread (a connect's destination, #60).
    fn record_ioc(&self, event: &Event, hit: crate::ioc::IocHit) {
        let message = hit.message(&event.meta().comm);
        let entity = entity_key(event.meta());
        self.record(Finding::ioc(&entity, &message, hit), event, Vec::new());
    }

    /// [`Self::record`] for a batch of plain `rules::Alert`s (no Sigma/
    /// correlator-specific `DetectionSource` needed) — the common case for every
    /// `rule_state`/`rules::evaluate_*` call site.
    fn record_rule_alerts(&self, event: &Event, alerts: impl IntoIterator<Item = rules::Alert>) {
        let entity = entity_key(event.meta());
        for alert in alerts {
            if alert.technique == MEMFD_EXEC_TECHNIQUE {
                self.request_memory_scan(event);
            }
            let is_burst = alert.technique == RANSOMWARE_TECHNIQUE;
            let corroborated = is_burst && self.note_ransomware_burst(event);
            let manifest = if is_burst {
                self.damage_manifest(event)
            } else {
                Vec::new()
            };
            self.record(Finding::rule(&entity, &alert), event, manifest);
            if corroborated {
                self.ransomware_reflex(event.meta().pid);
            }
        }
    }

    /// Exec events: stateless rules, stateful rules, then Sigma.
    fn detect_exec(&self, wrapped: &Event, event: &schema::ExecEvent) {
        self.own_traffic.record_exec(event);
        self.canary.on_exec(event);
        self.record_rule_alerts(wrapped, rules::evaluate_exec(event));
        self.record_rule_alerts(wrapped, self.rule_state.lock_recovering().on_exec(event));
        // This exec moved the stream clock: identity requests waiting for it may be due (#1041).
        self.record_due_identity_alerts(
            self.rule_state.lock_recovering().take_due_identity_alerts(),
        );
        self.record_due_unit_stops();
        let sigma_guard = self.sigma.lock_recovering();
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
                let finding = Finding {
                    entity: &entity,
                    technique: &technique,
                    message: &hit.title,
                    source,
                    severity: hit.severity,
                };
                self.record(finding, wrapped, Vec::new());
            }
        }
    }

    /// `FileOpen` events: stateless rules, downloader-write history, and the
    /// budgeted YARA queue on write intent (off the event path).
    fn detect_file_open(&self, wrapped: &Event, event: &schema::FileOpenEvent) {
        let state_alerts = self.rule_state.lock_recovering().on_file_open(event);
        self.record_rule_alerts(
            wrapped,
            rules::evaluate_file_open(event)
                .into_iter()
                .chain(state_alerts),
        );
        // This event moved the stream clock: a queued unit stop may be due (#1085).
        self.record_due_unit_stops();
        if rules::has_write_intent(event.flags)
            && let Some((yara, _)) = self.yara.lock_recovering().as_ref()
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
        self.rule_state.lock_recovering().on_file_quarantine(event);
    }

    /// `BitsJob` events (Windows BITS-Client): recorded for the T1197
    /// download→exec join, no alert on their own (#284).
    fn detect_bits_job(&self, event: &schema::BitsJobEvent) {
        self.rule_state.lock_recovering().on_bits_job(event);
    }

    /// Connect events: stateless rules (unusual outbound from a web/DB
    /// service, issue #478), then beacon detection.
    fn detect_connect(&self, wrapped: &Event, event: &schema::ConnectEvent) {
        if let Some(hit) = self
            .ioc
            .check_connect(event.daddr, event.meta.timestamp_ns, || {
                self.own_connect(&event.meta, event.daddr)
            })
        {
            self.record_ioc(wrapped, hit);
        }
        self.record_rule_alerts(wrapped, rules::evaluate_connect(event));
        self.record_rule_alerts(wrapped, self.rule_state.lock_recovering().on_connect(event));
    }

    /// `DnsQuery` events: the egress-domain join (it never alerts) and, on a listed domain or
    /// one of its subdomains, an IOC finding (#60).
    fn detect_dns_query(&self, wrapped: &Event, event: &schema::DnsQueryEvent) {
        if let Some(hit) = self
            .ioc
            .check_dns_query(&event.query, event.meta.timestamp_ns, || {
                self.own_dns_query(&event.meta, &event.query)
            })
        {
            self.record_ioc(wrapped, hit);
        }
        self.rule_state.lock_recovering().on_dns_query(event);
    }

    /// `NetworkFlow` events (conntrack polling, issue #92): same beacon detection as
    /// `detect_connect`, deduped per-flow so a poll-based source doesn't
    /// false-positive on one ordinary long-lived connection. The peer address is also checked
    /// against the IOC set (#60); every poll of one live flow repeats it, which the per-indicator
    /// cooldown absorbs.
    fn detect_network_flow(&self, wrapped: &Event, event: &schema::NetworkFlowEvent) {
        if let Some(hit) = self
            .ioc
            .check_connect(event.daddr, event.meta.timestamp_ns, || {
                self.own_connect(&event.meta, event.daddr)
            })
        {
            self.record_ioc(wrapped, hit);
        }
        self.record_rule_alerts(
            wrapped,
            self.rule_state.lock_recovering().on_network_flow(event),
        );
    }

    /// `ListenPort` events (`sock_diag` polling, issue #92): LISTENER-DRIFT.
    fn detect_listen_port(&self, wrapped: &Event, event: &schema::ListenPortEvent) {
        self.record_rule_alerts(
            wrapped,
            self.rule_state.lock_recovering().on_listen_port(event),
        );
    }

    /// `PolicyDenial` events (`SELinux` AVC #297, AppLocker/WDAC #283):
    /// POLICY-DENIAL-DRIFT (issue #774).
    fn detect_policy_denial(&self, wrapped: &Event, event: &schema::PolicyDenialEvent) {
        self.record_rule_alerts(
            wrapped,
            self.rule_state.lock_recovering().on_policy_denial(event),
        );
    }

    /// `Auth` events: brute-force/spray burst detection (T1110, pack #377).
    fn detect_auth(&self, wrapped: &Event, event: &schema::AuthEvent) {
        self.record_rule_alerts(wrapped, self.rule_state.lock_recovering().on_auth(event));
    }

    /// `Session` events: a disconnected session reconnected from another client
    /// (T1563.002, #285).
    fn detect_session(&self, wrapped: &Event, event: &schema::SessionEvent) {
        self.record_rule_alerts(wrapped, self.rule_state.lock_recovering().on_session(event));
    }

    /// `FileDelete` events: log-tamper detection (T1070.001/.002, pack #379), then the
    /// unlink half of the write-new-then-unlink T1486 shape (#512 part B), which needs
    /// the creation history `on_file_open` keeps.
    fn detect_file_delete(&self, wrapped: &Event, event: &schema::FileDeleteEvent) {
        self.record_rule_alerts(wrapped, rules::evaluate_file_delete(event));
        let alerts = self.rule_state.lock_recovering().on_file_delete(event);
        self.record_rule_alerts(wrapped, alerts);
    }

    /// `Signal` events: security-process tampering (T1562.001, issue #362).
    fn detect_signal(&self, wrapped: &Event, event: &schema::SignalEvent) {
        self.record_rule_alerts(wrapped, rules::evaluate_signal(event));
    }

    /// `IdentityChange` events (Linux, #266): SETUID-ROOT-REQUEST (T1548.001, #1041). A request
    /// is judged once its process's exec has had time to arrive, so the alerts returned here are
    /// those of earlier events, each attributed to its own.
    fn detect_identity_change(&self, event: &schema::IdentityChangeEvent) {
        let due = self.rule_state.lock_recovering().on_identity_change(event);
        self.record_due_identity_alerts(due);
    }

    /// Records the identity-request alerts that came due, each against the event it is about.
    fn record_due_identity_alerts(&self, due: Vec<(schema::IdentityChangeEvent, rules::Alert)>) {
        for (event, alert) in due {
            self.record_rule_alerts(&Event::IdentityChange(event), [alert]);
        }
    }

    /// Security-unit stops whose wait is over (UNEXPLAINED-UNIT-STOP, #1085), each attributed to
    /// its own journal event.
    fn record_due_unit_stops(&self) {
        let due = self.rule_state.lock_recovering().take_due_unit_stops();
        for (event, alert) in due {
            self.record_rule_alerts(&Event::UnitStop(event), [alert]);
        }
    }

    /// `FileRename` events: mass-rename ransomware detection (T1486, issue #262) +
    /// write-volume corroboration (issue #82).
    fn detect_file_rename(&self, wrapped: &Event, event: &schema::FileRenameEvent) {
        // Bound first: `record_rule_alerts` takes the lock again for the damage manifest.
        let alerts = self.rule_state.lock_recovering().on_file_rename(event);
        self.record_rule_alerts(wrapped, alerts);
    }

    /// `FileWrite` events: no alert on their own — tracks per-pid write volume for
    /// the ransomware write-volume corroboration signal (T1486, issue #82),
    /// consumed on the next `FileRename`.
    fn detect_file_write(&self, event: &schema::FileWriteEvent) {
        self.rule_state.lock_recovering().on_file_write(event);
    }

    /// `MemfdCreate` events (Linux, issue #265): usually no alert on its own —
    /// tracks per-pid memfd-creation history consumed by the memfd-exec
    /// signal (T1620, issue #497) on a later `Exec`. Can still emit directly
    /// when a matching `/proc/.../fd/<n>` exec was already seen and is
    /// waiting on this corroborating evidence (#503 review: the two ring
    /// buffers can deliver out of order even though the kernel always
    /// creates the memfd before executing it).
    fn detect_memfd_create(&self, event: &schema::MemfdCreateEvent) {
        for alert in self.rule_state.lock_recovering().on_memfd_create(event) {
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
            self.rule_state.lock_recovering().on_ldap_search(event),
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

    /// IOC matches skipped as the agent's own control-plane traffic: made by this process, and by
    /// a second process on the agent's executable (<https://github.com/synthaea-lab/agent/issues/47>).
    pub(crate) fn ioc_own_skips(&self) -> (u64, u64) {
        let stats = self.ioc.stats();
        (
            stats.own_skipped.load(Ordering::Relaxed),
            stats.sibling_skipped.load(Ordering::Relaxed),
        )
    }

    /// Names the control plane whose traffic, from the agent, an IOC match skips (<https://github.com/synthaea-lab/agent/issues/47>), and
    /// starts following the addresses its host resolves to. `false` when the URL names no host.
    pub(crate) fn set_control_plane(&self, url: &str) -> bool {
        let set = self.own_traffic.set_control_plane(url);
        if set {
            self.own_traffic.spawn_refresh();
        }
        set
    }

    /// Whether a connection to `address` is the agent's own control-plane traffic.
    fn own_connect(
        &self,
        meta: &schema::EventMeta,
        address: std::net::IpAddr,
    ) -> crate::ioc::OwnMatch {
        if !self.own_traffic.is_control_plane_address(address) {
            return None;
        }
        self.own_traffic
            .origin(meta)
            .map(|origin| (origin, meta.pid))
    }

    /// Whether a lookup of `name` is the agent's own control-plane traffic.
    fn own_dns_query(&self, meta: &schema::EventMeta, name: &str) -> crate::ioc::OwnMatch {
        if !self.own_traffic.is_control_plane_name(name) {
            return None;
        }
        self.own_traffic
            .origin(meta)
            .map(|origin| (origin, meta.pid))
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
            .lock_recovering()
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
            .lock_recovering()
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
            .lock_recovering()
            .suppressions()
            .into_iter()
            .map(|(entity, technique)| (entity.ppid, entity.comm, technique))
            .collect()
    }

    /// Same posture as the rule directories for the snapshot: absent unloads (the evidence is
    /// withheld), broken keeps the previous one (its failure is logged by the loader).
    fn swap_common_set(&self, loaded: Load<ml::features::common_set::CommonSetSnapshot>) {
        let mut slot = self.common_set.lock_recovering();
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
        self.common_set.lock_recovering().clone()
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
    let snapshot = common_set.lock_recovering().clone().filter(|s| {
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
                .lock_recovering()
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
    response: Arc<ResponseCell>,
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
            let started = yara::ScanQueue::start(rules, move |outcome| {
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
            match started {
                Ok(queue) => Load::Loaded((queue, rule_count)),
                // A host that cannot start the scan worker runs without file scanning, like a
                // rule directory that does not load; a reload keeps the previous engine.
                Err(e) => {
                    tracing::error!(error = %e, "yara: file scanning not started");
                    Load::Failed
                }
            }
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
        Ok(rules) => match yara::MemoryScanQueue::start(
            rules,
            Arc::new(crate::memscan::ProcMemSource),
            yara::MemoryBudget::default(),
            move |outcome| report_memory_matches(&alert_log, &verdict, &outcome),
        ) {
            Ok(queue) => Load::Loaded(queue),
            Err(e) => {
                tracing::error!(error = %e, "yara: memory scanning not started");
                Load::Failed
            }
        },
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
        .lock_recovering()
        .record(entity, &rule.technique, detection, context.timestamp_ns)
}

/// Issue #25: policy-gates quarantining a YARA-confirmed payload. A no-op whenever
/// `enable_response` was never called — same posture as `DetectionSink::maybe_kill`.
fn quarantine_matched_payload(
    response: &ResponseCell,
    path: &std::path::Path,
    alert_log: &AlertLog,
) {
    let Some(hooks) = response.get() else {
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
    let outcome = ::response::quarantine_file(path, &hooks.quarantine_dir, &hooks.policy);
    let message = match outcome {
        ::response::QuarantineOutcome::Quarantined {
            original,
            quarantined_at,
            sha256_hex,
        } => format!(
            "quarantined {} ({sha256_hex}) to {} on a confirmed YARA match",
            original.display(),
            quarantined_at.display()
        ),
        ::response::QuarantineOutcome::ObserveOnly { path } => format!(
            "{} would have been quarantined on a confirmed YARA match (observe-only)",
            path.display()
        ),
        ::response::QuarantineOutcome::Failed { path, error } => {
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
        for touch in self.canary.on_event(&event) {
            self.record_canary_touch(touch);
        }
        match &event {
            Event::Exec(e) => self.detect_exec(&event, e),
            Event::FileOpen(e) => self.detect_file_open(&event, e),
            Event::UnitStop(e) => {
                self.rule_state.lock_recovering().on_unit_stop(e);
                self.record_due_unit_stops();
            }
            Event::Connect(e) => self.detect_connect(&event, e),
            Event::NetworkFlow(e) => self.detect_network_flow(&event, e),
            Event::DnsQuery(e) => self.detect_dns_query(&event, e),
            Event::ListenPort(e) => self.detect_listen_port(&event, e),
            Event::Auth(e) => self.detect_auth(&event, e),
            Event::Session(e) => self.detect_session(&event, e),
            Event::IdentityChange(e) => self.detect_identity_change(e),
            Event::FileDelete(e) => self.detect_file_delete(&event, e),
            Event::Signal(e) => self.detect_signal(&event, e),
            Event::FileQuarantine(e) => self.detect_file_quarantine(e),
            Event::BitsJob(e) => self.detect_bits_job(e),
            Event::FileRename(e) => self.detect_file_rename(&event, e),
            Event::FileSetTime(e) => {
                // Bound first: `record_rule_alerts` takes the lock again.
                let alerts = self.rule_state.lock_recovering().on_file_set_time(e);
                self.record_rule_alerts(&event, alerts);
            }
            Event::RawVolumeOpen(e) => {
                self.record_rule_alerts(&event, rules::evaluate_raw_volume_open(e));
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
            Event::ProcessAccess(e) => {
                // Bound first: `record_rule_alerts` takes the lock again.
                let alerts = self.rule_state.lock_recovering().on_process_access(e);
                self.record_rule_alerts(&event, alerts);
            }
            Event::RemoteThread(e) => {
                // Bound first: `record_rule_alerts` takes the lock again.
                let alerts = self.rule_state.lock_recovering().on_remote_thread(e);
                self.record_rule_alerts(&event, alerts);
            }
            // New telemetry categories reach the engines as they land; until a rule
            // consumes them, logging below is the whole treatment.
            _ => {}
        }
        // Enrichment + the high-volume raw-event write happen off this thread, and
        // with them the findings that wait for the image's signature (#441).
        let gated = match &event {
            Event::Exec(e) => self.rule_state.lock_recovering().on_exec_signature_gated(e),
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

#[cfg(test)]
mod tests;
