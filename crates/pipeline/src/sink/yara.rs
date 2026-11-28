//! YARA wiring of the [`DetectionSink`]: starting the file and the memory
//! scan workers over `rules/yara`, folding a match into the verdict of the entity behind it, and
//! quarantining a confirmed payload. The scan engines themselves live in the `yara` crate.

use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use schema::Event;
use sinks::alert_log::AlertLog;
use workers::sync::LockExt as _;

use super::{DetectionSink, Load, ResponseCell, escalate_if_warranted, techniques_from};

impl DetectionSink {
    /// Turns on YARA scanning of process memory (#85), reading processes through `source`,
    /// and starts the scanner if `rules/yara` content is present. Until it is called a
    /// fileless exec is alerted on but not scanned. The first call wins: the mechanism
    /// cannot change under a running agent.
    pub fn enable_memory_scanning(&self, source: Arc<dyn yara::MemorySource>) {
        if self.memory_source.set(source).is_err() {
            tracing::warn!(
                "yara: memory scanning is already enabled; the second source is ignored"
            );
            return;
        }
        let started = start_memscan(
            &self.content_root,
            self.memory_source.get().cloned(),
            self.alert_log.clone(),
            self.verdict.clone(),
        );
        *self.memscan.lock_recovering() = started.into_option();
    }

    /// Asks for a budgeted YARA scan of the memory of the process behind `event` (#85):
    /// the payload of a fileless exec exists only there. The scan queue applies the
    /// cooldown, the global cap and the per-scan budget; a shed request is counted there.
    pub(super) fn request_memory_scan(&self, event: &Event) {
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
}

/// Loads `rules/yara` under `content_root` when present and starts the scan
/// worker, alongside the rule count for [`DetectionSink::reload_content`]'s
/// report (the count is only available before [`yara::RuleSet`] is consumed
/// by [`yara::ScanQueue::start`], so it has to travel out with the queue
/// rather than be queried from it afterward). Matches are emitted as alerts
/// by the worker thread through the shared alert log, and — issue #25 —
/// trigger quarantine of the matched file through `response`, whenever
/// `enable_response` set it.
pub(super) fn start_yara(
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
/// (#85, ADR-0023), reading processes through `source`. The rule set is compiled a second
/// time because the file queue owns its copy; memory and file scanning share rules, not
/// state. Without a `source` there is no scanner: reading another process's memory is a
/// platform mechanism the caller provides (`sensor-linux-procmem` on Linux, none elsewhere).
pub(super) fn start_memscan(
    content_root: &Path,
    source: Option<Arc<dyn yara::MemorySource>>,
    alert_log: Arc<AlertLog>,
    verdict: Arc<Mutex<verdict::VerdictEngine>>,
) -> Load<yara::MemoryScanQueue> {
    let Some(source) = source else {
        return Load::Absent;
    };
    let dir = content_root.join("rules/yara");
    if !dir.is_dir() {
        return Load::Absent;
    }
    match yara::RuleSet::load_dir(&dir) {
        Ok(rules) => match yara::MemoryScanQueue::start(
            rules,
            source,
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

/// What a memory scan that matched produces: the match fused into the verdict of the
/// process that was scanned (the same path as a file match), a `YARA-MEM` audit line per
/// rule, and the escalation the fused severity warrants. A memory match does not
/// quarantine anything: there is no file to move.
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
pub(super) fn fuse_yara_match(
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
pub(super) fn quarantine_matched_payload(
    response: &ResponseCell,
    path: &Path,
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
