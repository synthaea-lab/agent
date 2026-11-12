//! `agent replay`: run a recorded `events.jsonl` through the detection pipeline offline
//! and write one case per entity (ml#3).
//!
//! A learned case scorer (T2) trains on cases, not traces: the fused verdict the agent
//! builds per entity from every engine's findings. This command is the trace-to-case step.
//! It builds the same [`DetectionSink`] `agent run` does, so the cases come from the
//! shipped rules, Sigma content, correlator and verdict fusion, not from a copy of them.
//!
//! What differs from a live run, on purpose:
//! - **Event time drives the clocks.** The correlator advances to each event's timestamp
//!   instead of a one-second wall-clock ticker, and verdict fusion already stamps findings
//!   with event time, so a replay of the same file gives the same cases.
//! - **Nothing touches the host.** No response is armed, and the YARA file and memory
//!   scanners are stopped ([`DetectionSink::stop_host_scans`]): a recorded pid or path
//!   names the capture host's process or file, not this one's.
//! - **No event is shed.** The enrichment queue is drained every [`FLUSH_EVERY`] events,
//!   and a run that still dropped one fails instead of writing incomplete cases.
//! - **No case is lost to a newer one.** Verdict fusion keeps one state per `(ppid, comm)`
//!   and replaces it when the parent pid is recycled, and it evicts the least recently
//!   used entity past its cap. A live run has already emitted the replaced verdict by
//!   then; the replay keeps a snapshot of every case after each of its events instead of
//!   reading the engine once at the end.
//!
//! Known limits: a recorded trace is already redacted, so a rule that matched on a
//! redacted value does not fire again; an exec recorded without a hash (the live hash
//! failed) is hashed from this host's file at that path, if one exists; and the image
//! rarity evidence reads this host's wall clock for the age of its snapshot.

use std::{
    collections::HashMap,
    io::{BufRead, BufReader, BufWriter, Write},
    path::Path,
    time::Duration,
};

use anyhow::Context as _;
use schema::{
    Event,
    detection::{Detection, DetectionSource, Severity},
    sensor::EventSink,
};

use crate::sink::{DetectionSink, correlator_case_id};

/// Events between two drains of the enrichment queue: well under its 4096-slot depth, so a
/// replay that feeds events as fast as it can parse them never sheds one.
const FLUSH_EVERY: usize = 1_024;

/// How long one drain may take before the replay gives up on the worker.
const FLUSH_TIMEOUT: Duration = Duration::from_secs(60);

/// How far past the last event the correlator is advanced at the end, so every pending
/// window expires and raises what it would have raised live.
const DRAIN_HORIZON_NS: u64 = 3_600 * 1_000_000_000;

/// One line of the cases file: an entity's fused verdict at the end of the replay.
#[derive(serde::Serialize)]
struct CaseRecord<'a> {
    case_id: String,
    ppid: u32,
    comm: &'a str,
    parent_generation: Option<u64>,
    severity: Severity,
    score: Option<f64>,
    /// Every distinct technique, oldest first.
    techniques: &'a [String],
    /// Every distinct engine, oldest first.
    sources: &'a [DetectionSource],
    /// The most recent findings the verdict keeps, each with its triggering events.
    detections: &'a [Detection],
}

/// What a replay read and wrote, printed on stderr at the end.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ReplaySummary {
    pub(crate) events: usize,
    pub(crate) skipped_lines: usize,
    pub(crate) cases: usize,
}

/// Replays `events` (one `schema::Event` per line) through a fresh [`DetectionSink`],
/// appending alerts to `alerts` like `agent run` and writing one case per entity to
/// `cases`. A line that is not an event is skipped and counted: a capture cut while the
/// agent was writing ends with a torn line.
///
/// # Errors
///
/// Returns an error if a file cannot be opened, read or written, if the sink cannot be
/// built, or if the enrichment worker stalls or sheds an event.
pub(crate) fn cmd_replay(
    events: &Path,
    alerts: &Path,
    cases: &Path,
    content_dir: &Path,
    model_root: &Path,
) -> anyhow::Result<ReplaySummary> {
    let input = std::fs::File::open(events)
        .with_context(|| format!("cannot open the events file {}", events.display()))?;
    let sink = DetectionSink::new(
        rules::RuleState::new(),
        alerts,
        None,
        None,
        None,
        content_dir,
        model_root,
    )
    .context("cannot build the detection pipeline")?;
    sink.stop_host_scans();

    let mut summary = ReplaySummary::default();
    let mut entities: HashMap<String, schema::EventMeta> = HashMap::new();
    let mut cases_seen: HashMap<String, Case> = HashMap::new();
    let mut clock_ns = 0_u64;
    for line in BufReader::new(input).lines() {
        let line = line.with_context(|| format!("cannot read {}", events.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(event) = serde_json::from_str::<Event>(&line) else {
            summary.skipped_lines += 1;
            continue;
        };
        let meta = event.meta().clone();
        clock_ns = clock_ns.max(meta.timestamp_ns);
        sink.on_event(event);
        sink.advance_correlation_time(clock_ns);
        let key = case_key(&meta);
        snapshot(&sink, &mut cases_seen, &key, &meta);
        entities.insert(key, meta);
        summary.events += 1;
        if summary.events % FLUSH_EVERY == 0 {
            drain(&sink)?;
            snapshot_all(&sink, &mut cases_seen, &entities);
        }
    }
    drain(&sink)?;
    sink.advance_correlation_time(clock_ns.saturating_add(DRAIN_HORIZON_NS));
    drain(&sink)?;
    snapshot_all(&sink, &mut cases_seen, &entities);

    summary.cases = write_cases(cases_seen, cases)?;
    Ok(summary)
}

/// One case as last seen: the entity's verdict, and when its first finding was made.
struct Case {
    first_finding_ns: u64,
    verdict: verdict::Verdict,
}

/// Records the current verdict of the entity `meta` belongs to, if it has one. The first
/// snapshot of a case fixes its first-finding time: the verdict keeps only its most recent
/// detections, so a later snapshot may no longer hold the first one.
fn snapshot(
    sink: &DetectionSink,
    cases: &mut HashMap<String, Case>,
    key: &str,
    meta: &schema::EventMeta,
) {
    let Some(verdict) = sink.verdict_for(meta) else {
        return;
    };
    match cases.get_mut(key) {
        Some(case) => case.verdict = verdict,
        None => {
            let first_finding_ns = verdict
                .detections
                .iter()
                .map(|d| d.timestamp_ns)
                .min()
                .unwrap_or(meta.timestamp_ns);
            cases.insert(
                key.to_owned(),
                Case {
                    first_finding_ns,
                    verdict,
                },
            );
        }
    }
}

/// Snapshots every entity seen so far: picks up the findings the enrichment worker
/// recorded after the entity's own last event. An entity whose state the engine has
/// since replaced or evicted keeps its earlier snapshot.
fn snapshot_all(
    sink: &DetectionSink,
    cases: &mut HashMap<String, Case>,
    entities: &HashMap<String, schema::EventMeta>,
) {
    for (key, meta) in entities {
        snapshot(sink, cases, key, meta);
    }
}

/// The entity key as the case id the agent reports for it.
fn case_key(meta: &schema::EventMeta) -> String {
    correlator_case_id(
        &verdict::EntityKey::new(meta.ppid, meta.comm.clone())
            .with_parent_generation(meta.parent_process_generation),
    )
}

/// Waits for the enrichment worker to finish every queued event, and fails if it shed any.
fn drain(sink: &DetectionSink) -> anyhow::Result<()> {
    anyhow::ensure!(
        sink.enrich_queue().flush(FLUSH_TIMEOUT),
        "the enrichment worker did not drain within {FLUSH_TIMEOUT:?}"
    );
    let dropped = sink.enrich_queue().dropped();
    anyhow::ensure!(
        dropped == 0,
        "the enrichment queue shed {dropped} events; the cases would be incomplete"
    );
    Ok(())
}

/// Writes every case, ordered by first finding then case id so two replays of one file
/// write the same bytes. Returns the number of cases.
fn write_cases(cases_seen: HashMap<String, Case>, cases: &Path) -> anyhow::Result<usize> {
    let mut verdicts: Vec<(String, Case)> = cases_seen.into_iter().collect();
    verdicts.sort_by(|(a_id, a), (b_id, b)| {
        a.first_finding_ns
            .cmp(&b.first_finding_ns)
            .then_with(|| a_id.cmp(b_id))
    });

    let file = std::fs::File::create(cases)
        .with_context(|| format!("cannot create the cases file {}", cases.display()))?;
    let mut out = BufWriter::new(file);
    for (case_id, Case { verdict, .. }) in &verdicts {
        let record = CaseRecord {
            case_id: case_id.clone(),
            ppid: verdict.entity.ppid,
            comm: &verdict.entity.comm,
            parent_generation: verdict.entity.parent_generation,
            severity: verdict.severity,
            score: verdict.score,
            techniques: &verdict.techniques,
            sources: &verdict.sources,
            detections: &verdict.detections,
        };
        serde_json::to_writer(&mut out, &record)?;
        out.write_all(b"\n")?;
    }
    out.flush()
        .with_context(|| format!("cannot write {}", cases.display()))?;
    Ok(verdicts.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An exec the base64-decode rule flags, as `agent run --events` records it.
    fn base64_exec(pid: u32, ppid: u32, comm: &str, timestamp_ns: u64) -> Event {
        let mut exec = schema::fixtures::exec();
        exec.meta.pid = pid;
        exec.meta.ppid = ppid;
        exec.meta.comm = comm.into();
        exec.meta.timestamp_ns = timestamp_ns;
        exec.image_path = "/usr/bin/base64".into();
        exec.cmdline = "base64 -d".into();
        Event::Exec(exec)
    }

    fn quiet_exec(pid: u32, ppid: u32, comm: &str, timestamp_ns: u64) -> Event {
        let mut exec = schema::fixtures::exec();
        exec.meta.pid = pid;
        exec.meta.ppid = ppid;
        exec.meta.comm = comm.into();
        exec.meta.timestamp_ns = timestamp_ns;
        exec.image_path = "/usr/bin/true".into();
        exec.cmdline = "true".into();
        Event::Exec(exec)
    }

    fn replay(dir: &Path, lines: &[String]) -> (ReplaySummary, Vec<serde_json::Value>) {
        let events = dir.join("events.jsonl");
        std::fs::write(&events, lines.join("\n")).unwrap();
        let cases = dir.join("cases.jsonl");
        let summary = cmd_replay(
            &events,
            &dir.join("alerts.ndjson"),
            &cases,
            &dir.join("content"),
            &dir.join("ml-registry"),
        )
        .unwrap();
        let written = std::fs::read_to_string(&cases)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        (summary, written)
    }

    fn line(event: &Event) -> String {
        serde_json::to_string(event).unwrap()
    }

    #[test]
    fn a_flagged_entity_becomes_one_case_and_a_quiet_one_none() {
        let dir = tempfile::tempdir().unwrap();
        let lines = [
            line(&base64_exec(200, 100, "sh", 1_000)),
            line(&quiet_exec(300, 101, "bash", 2_000)),
        ];
        let (summary, cases) = replay(dir.path(), &lines);
        assert_eq!(summary.events, 2);
        assert_eq!(summary.cases, 1, "{cases:?}");
        assert_eq!(cases[0]["case_id"], "100:sh");
        assert!(
            !cases[0]["techniques"].as_array().unwrap().is_empty(),
            "{cases:?}"
        );
        assert!(
            !cases[0]["detections"][0]["events"]
                .as_array()
                .unwrap()
                .is_empty(),
            "a case keeps the events its findings were raised on: {cases:?}"
        );
    }

    #[test]
    fn both_incarnations_of_a_recycled_parent_keep_their_case() {
        // Same ppid and comm, two parent incarnations: verdict fusion replaces the first
        // state when the second one records a finding, as a live run does after it has
        // already emitted the first verdict. The replay must still write both cases.
        let stamped = |pid, generation, timestamp_ns| {
            let Event::Exec(mut exec) = base64_exec(pid, 100, "sh", timestamp_ns) else {
                unreachable!("base64_exec builds an exec")
            };
            exec.meta.parent_process_generation = Some(generation);
            Event::Exec(exec)
        };
        let dir = tempfile::tempdir().unwrap();
        let lines = [
            line(&stamped(200, 1, 1_000)),
            line(&stamped(201, 2, 5_000_000_000)),
        ];
        let (summary, cases) = replay(dir.path(), &lines);
        let ids: Vec<&str> = cases
            .iter()
            .map(|c| c["case_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["100:sh@1", "100:sh@2"]);
        assert_eq!(summary.cases, 2);
    }

    #[test]
    fn a_torn_line_is_counted_and_the_rest_still_replays() {
        let dir = tempfile::tempdir().unwrap();
        let whole = line(&base64_exec(200, 100, "sh", 1_000));
        let torn = whole[..whole.len() / 2].to_owned();
        let (summary, cases) = replay(dir.path(), &[whole, torn]);
        assert_eq!(summary.events, 1);
        assert_eq!(summary.skipped_lines, 1);
        assert_eq!(cases.len(), 1);
    }

    #[test]
    fn replaying_one_file_twice_writes_the_same_cases() {
        let lines = [
            line(&base64_exec(200, 100, "sh", 1_000)),
            line(&base64_exec(201, 110, "dash", 1_500)),
            line(&base64_exec(202, 100, "sh", 3_000)),
        ];
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        replay(first.path(), &lines);
        replay(second.path(), &lines);
        assert_eq!(
            std::fs::read(first.path().join("cases.jsonl")).unwrap(),
            std::fs::read(second.path().join("cases.jsonl")).unwrap()
        );
    }
}
