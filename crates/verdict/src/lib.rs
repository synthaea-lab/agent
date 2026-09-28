//! Verdict fusion (issue #131): the `engines → correlator → verdict → response`
//! node.
//!
//! Every detection engine (rules, Sigma, YARA, correlator) raises its own
//! independent finding today — `agent::sink::DetectionSink` fans them all
//! straight into one alert log with no cross-engine view, and `response`'s kill
//! gate only ever sees the correlator's own Bayesian belief, not anything from
//! rules/Sigma/YARA. This crate is the seam that turns "N engines each raising a
//! hand" into one scored verdict per entity, keyed by the same `(ppid, comm)`
//! join `correlator` already uses (the logical identity of a respawned
//! process — see `crates/correlator/src/bus.rs`).
//!
//! Findings are folded in as real [`schema::detection::Detection`] values, not
//! bare strings — the schema's own severity/score/source/evidence fields are
//! what fusion composes, so a caller downstream of a [`Verdict`] (a case store,
//! a future console) gets the same self-contained evidence a `Detection`
//! already promises, not a re-derived summary.
//!
//! Scope for this pass: per-entity severity/score composition across sources,
//! same-technique-across-engines dedup within a window, and an explicit
//! suppression list above the per-engine dated FP exclusions. Deliberately
//! **not** here: ML/T2 input (issue #132 has no trained scorer yet), response's
//! own kill/quarantine decision logic (unchanged — it now reads a better
//! signal, but still decides the same way), and any inline-blocking/enforcement
//! wiring (future issues).

use std::collections::HashSet;

use schema::detection::{Detection, DetectionSource, Severity};
use store::BoundedMap;

/// The logical identity of a process across respawns — the correlator's own join
/// key, reused here so a verdict and the correlator's belief state key
/// identically. `ppid` rather than `pid`: the same reasoning as `correlator`'s
/// own choice — a respawned process (crash-restart, a loop) keeps one identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntityKey {
    pub ppid: u32,
    pub comm: String,
}

impl EntityKey {
    #[must_use]
    pub fn new(ppid: u32, comm: impl Into<String>) -> Self {
        Self {
            ppid,
            comm: comm.into(),
        }
    }
}

/// One technique folded into an entity's verdict, with when its current dedup
/// window started. Measured from the *first* sighting that opened the window,
/// not the most recent one (PR #502 review): under steady recurring activity
/// (a webshell spawning a new `sh` for every command, say), refreshing this on
/// every duplicate would make the window slide forever and the technique would
/// never produce a fresh verdict — logged once, then silently absorbed for as
/// long as the activity continues. A fixed window from the first sighting
/// guarantees a fresh verdict at least once per [`VerdictEngine::dedup_window_ns`].
struct TechniqueRecord {
    technique: String,
    window_start_ns: u64,
}

/// Evidence kept per entity is bounded: fusion is a live-triage aid, not the
/// audit trail (`alerts.ndjson` is — every finding lands there regardless of
/// whether it also makes the bounded evidence list here). Sized to hold a
/// real multi-engine confirmation chain without growing unbounded under a
/// noisy, long-lived entity re-triggering the same handful of techniques.
const EVIDENCE_CAP: usize = 16;

/// One entity's fused state: every technique/source/detection folded in so far.
struct EntityState {
    severity: Severity,
    score: Option<f64>,
    techniques: Vec<TechniqueRecord>,
    sources: Vec<DetectionSource>,
    detections: Vec<Detection>,
}

impl EntityState {
    fn new() -> Self {
        Self {
            severity: Severity::Low,
            score: None,
            techniques: Vec::new(),
            sources: Vec::new(),
            detections: Vec::new(),
        }
    }

    fn push_evidence(&mut self, detection: Detection) {
        self.detections.push(detection);
        if self.detections.len() > EVIDENCE_CAP {
            self.detections.remove(0);
        }
    }
}

/// The fused, per-entity verdict — what `response` and the sinks gate on instead
/// of a single engine's raw output. A complete snapshot, not a delta: every
/// technique, source and (bounded) piece of evidence folded into this entity
/// so far.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub entity: EntityKey,
    pub severity: Severity,
    /// The highest-confidence score seen across every contributing source, when
    /// any source carried one. Simple max composition, not a weighted blend: a
    /// well-calibrated high-confidence engine must not be diluted by folding in
    /// an uncalibrated weak one. A principled weighted composition needs
    /// calibration work of its own — tracked against issue #132's T2 scorer,
    /// out of scope here.
    pub score: Option<f64>,
    /// Every distinct technique folded into this entity so far, oldest first.
    pub techniques: Vec<String>,
    /// Every distinct contributing source so far, oldest first.
    pub sources: Vec<DetectionSource>,
    /// The most recent [`EVIDENCE_CAP`] detections folded into this entity —
    /// the self-contained evidence a case store or console would show, not the
    /// full history (that's `alerts.ndjson`).
    pub detections: Vec<Detection>,
}

/// Bound on distinct entities tracked — same order of magnitude as
/// `correlator`'s own state maps (`crates/correlator/src/engine.rs`).
const ENTITY_CAP: usize = 16_384;

/// Folds per-engine findings into one scored verdict per entity.
pub struct VerdictEngine {
    entities: BoundedMap<EntityKey, EntityState>,
    /// Explicit, operator-applied overrides: (entity, technique) pairs to drop
    /// silently. Above and independent of the per-engine dated FP exclusions
    /// (`policy::name_exclusion_applies` and its callers): those live inside
    /// each engine's own rule code, gated on evidence at build time; this is a
    /// runtime override an operator applies after the fact, to one entity, not
    /// a rule change. No expiry in this pass — an operator who wants it back
    /// removes the mark explicitly (`unsuppress`).
    suppressed: HashSet<(EntityKey, String)>,
    dedup_window_ns: u64,
}

impl VerdictEngine {
    #[must_use]
    pub fn new(dedup_window_ns: u64) -> Self {
        Self {
            entities: BoundedMap::new(ENTITY_CAP),
            suppressed: HashSet::new(),
            dedup_window_ns,
        }
    }

    /// Folds one engine's finding into the entity's fused verdict.
    ///
    /// `technique` is the dedup/composition key (a bare ATT&CK id, a
    /// technique-tag join, or `"BAYES"` for the correlator's belief-crossing
    /// signal — whatever the caller already uses as its alert-log key);
    /// `detection` is the schema-native evidence — its `severity`/`score`
    /// drive arbitration, its `source` identifies the engine, and it is
    /// itself folded into the entity's bounded evidence list.
    ///
    /// Returns `None` when the finding was absorbed silently: suppressed, or
    /// the same technique already recorded for this entity within the dedup
    /// window with no new severity/score information (the same behavior
    /// flagged by rules *and* Sigma is one finding, not two). Returns `Some` —
    /// a complete, current snapshot of the entity's verdict — the first time a
    /// technique is recorded for an entity, whenever it raises the entity's
    /// severity or score, or when it recurs outside the dedup window (a
    /// genuine re-occurrence, not a duplicate of the live finding).
    pub fn record(
        &mut self,
        entity: EntityKey,
        technique: &str,
        detection: Detection,
        now_ns: u64,
    ) -> Option<Verdict> {
        if self
            .suppressed
            .contains(&(entity.clone(), technique.to_owned()))
        {
            return None;
        }

        let state = self
            .entities
            .get_or_insert_with(entity.clone(), EntityState::new);

        let is_dup = match state
            .techniques
            .iter_mut()
            .find(|t| t.technique == technique)
        {
            Some(t) => {
                let dup = now_ns.saturating_sub(t.window_start_ns) <= self.dedup_window_ns;
                // Only a genuine re-occurrence (outside the window) opens a new
                // one; a duplicate must not slide the window it's inside of.
                if !dup {
                    t.window_start_ns = now_ns;
                }
                dup
            }
            None => {
                state.techniques.push(TechniqueRecord {
                    technique: technique.to_owned(),
                    window_start_ns: now_ns,
                });
                false
            }
        };

        let severity_raised = detection.severity > state.severity;
        if severity_raised {
            state.severity = detection.severity;
        }
        let score_raised = match (detection.score, state.score) {
            (Some(new), Some(cur)) => new > cur,
            (Some(_), None) => true,
            _ => false,
        };
        if score_raised {
            state.score = detection.score;
        }
        if !state.sources.contains(&detection.source) {
            state.sources.push(detection.source.clone());
        }
        state.push_evidence(detection);

        if is_dup && !severity_raised && !score_raised {
            return None;
        }

        Some(Verdict {
            entity,
            severity: state.severity,
            score: state.score,
            techniques: state
                .techniques
                .iter()
                .map(|t| t.technique.clone())
                .collect(),
            sources: state.sources.clone(),
            detections: state.detections.clone(),
        })
    }

    /// Marks `technique` suppressed for `entity`: every future `record` call for
    /// that exact pair returns `None`. See the `suppressed` field doc for how
    /// this differs from the per-engine FP exclusions.
    pub fn suppress(&mut self, entity: EntityKey, technique: impl Into<String>) {
        self.suppressed.insert((entity, technique.into()));
    }

    /// Reverses a previous [`Self::suppress`] call. A no-op if the pair was
    /// never suppressed.
    pub fn unsuppress(&mut self, entity: &EntityKey, technique: &str) {
        self.suppressed
            .retain(|(e, t)| !(e == entity && t == technique));
    }

    /// The current verdict for `entity`, without folding in a new finding —
    /// for a caller that needs to read state without producing one (e.g. a
    /// health/status surface). `None` if the entity has never been recorded.
    #[must_use]
    pub fn peek(&self, entity: &EntityKey) -> Option<Verdict> {
        let state = self.entities.peek(entity)?;
        Some(Verdict {
            entity: entity.clone(),
            severity: state.severity,
            score: state.score,
            techniques: state
                .techniques
                .iter()
                .map(|t| t.technique.clone())
                .collect(),
            sources: state.sources.clone(),
            detections: state.detections.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use schema::detection::DetectionSource;

    use super::*;

    fn rule(id: &str) -> DetectionSource {
        DetectionSource::Rule {
            rule_id: id.to_string(),
        }
    }

    fn sigma(id: &str) -> DetectionSource {
        DetectionSource::Sigma {
            rule_id: id.to_string(),
        }
    }

    fn entity() -> EntityKey {
        EntityKey::new(1337, "bash")
    }

    fn detection(severity: Severity, score: Option<f64>, source: DetectionSource) -> Detection {
        Detection {
            timestamp_ns: 0,
            severity,
            title: "test finding".to_string(),
            source,
            score,
            attributions: Vec::new(),
            techniques: Vec::new(),
            events: Vec::new(),
        }
    }

    fn at(mut d: Detection, timestamp_ns: u64) -> Detection {
        d.timestamp_ns = timestamp_ns;
        d
    }

    #[test]
    fn a_first_sighting_of_a_technique_always_produces_a_verdict() {
        let mut engine = VerdictEngine::new(60_000_000_000);
        let d = detection(Severity::Medium, None, rule("r1"));
        let verdict = engine
            .record(entity(), "T1059.004", d.clone(), 0)
            .expect("first sighting must produce a verdict");
        assert_eq!(verdict.severity, Severity::Medium);
        assert_eq!(verdict.techniques, vec!["T1059.004"]);
        assert_eq!(verdict.sources, vec![rule("r1")]);
        assert_eq!(verdict.detections, vec![d]);
    }

    #[test]
    fn the_same_technique_from_a_second_engine_within_the_window_is_one_finding() {
        let mut engine = VerdictEngine::new(60_000_000_000);
        engine
            .record(
                entity(),
                "T1059.004",
                detection(Severity::Medium, None, rule("r1")),
                0,
            )
            .unwrap();
        let second = engine.record(
            entity(),
            "T1059.004",
            detection(Severity::Medium, None, sigma("s1")),
            1_000_000_000,
        );
        assert!(
            second.is_none(),
            "rules and Sigma agreeing on the same technique, same entity, same window \
             must fold into one finding, not two"
        );
        // But the fold is still tracked: a later, distinguishing call sees both sources
        // and both pieces of evidence.
        let peeked = engine.peek(&entity()).unwrap();
        assert_eq!(peeked.sources, vec![rule("r1"), sigma("s1")]);
        assert_eq!(peeked.detections.len(), 2);
    }

    #[test]
    fn a_higher_severity_from_a_second_engine_still_produces_a_verdict() {
        let mut engine = VerdictEngine::new(60_000_000_000);
        engine
            .record(
                entity(),
                "T1059.004",
                detection(Severity::Medium, None, rule("r1")),
                0,
            )
            .unwrap();
        let verdict = engine
            .record(
                entity(),
                "T1059.004",
                detection(Severity::Critical, None, sigma("s1")),
                1_000_000_000,
            )
            .expect("a severity raise must still surface, even within the dedup window");
        assert_eq!(verdict.severity, Severity::Critical);
    }

    #[test]
    fn steady_duplicates_do_not_slide_the_dedup_window_forever() {
        // PR #502 review: measuring the window from the *last* sighting let a
        // technique recurring more often than the window kept the window open
        // indefinitely — logged once, then never again for as long as the
        // activity continued. Duplicates inside the window here must not
        // extend it; a fresh verdict must still land once the window elapses
        // from the *first* sighting, even though duplicates kept arriving.
        let mut engine = VerdictEngine::new(10_000_000_000); // 10s window
        engine
            .record(
                entity(),
                "T1059.004",
                detection(Severity::Medium, None, rule("r1")),
                0,
            )
            .unwrap();
        // Two duplicates, each well inside 10s of the window's start.
        assert!(
            engine
                .record(
                    entity(),
                    "T1059.004",
                    detection(Severity::Medium, None, rule("r1")),
                    5_000_000_000,
                )
                .is_none()
        );
        assert!(
            engine
                .record(
                    entity(),
                    "T1059.004",
                    detection(Severity::Medium, None, rule("r1")),
                    9_000_000_000,
                )
                .is_none()
        );
        // 11s after the *first* sighting (only 2s after the last duplicate) —
        // with the window measured from the last sighting this would still be
        // a duplicate; measured from the first, it's a genuine re-occurrence.
        let verdict = engine.record(
            entity(),
            "T1059.004",
            detection(Severity::Medium, None, rule("r1")),
            11_000_000_000,
        );
        assert!(
            verdict.is_some(),
            "the window must expire from the first sighting, not keep sliding \
             on every duplicate"
        );
    }

    #[test]
    fn a_recurrence_outside_the_dedup_window_produces_a_fresh_verdict() {
        let mut engine = VerdictEngine::new(1_000_000_000);
        engine
            .record(
                entity(),
                "T1059.004",
                detection(Severity::Medium, None, rule("r1")),
                0,
            )
            .unwrap();
        let verdict = engine.record(
            entity(),
            "T1059.004",
            detection(Severity::Medium, None, rule("r1")),
            2_000_000_000,
        );
        assert!(
            verdict.is_some(),
            "outside the dedup window this is a genuine re-occurrence, not a duplicate"
        );
    }

    #[test]
    fn severity_composes_across_distinct_techniques_as_the_max() {
        let mut engine = VerdictEngine::new(60_000_000_000);
        engine
            .record(
                entity(),
                "T1059.004",
                detection(Severity::Medium, None, rule("r1")),
                0,
            )
            .unwrap();
        let verdict = engine
            .record(
                entity(),
                "T1071.001",
                detection(Severity::Critical, None, rule("r2")),
                0,
            )
            .unwrap();
        assert_eq!(verdict.severity, Severity::Critical);
        assert_eq!(verdict.techniques, vec!["T1059.004", "T1071.001"]);
    }

    #[test]
    fn score_composes_as_the_max_across_sources() {
        let mut engine = VerdictEngine::new(60_000_000_000);
        let case = DetectionSource::Correlator {
            case_id: "c1".into(),
        };
        engine
            .record(
                entity(),
                "BAYES",
                detection(Severity::High, Some(0.6), case.clone()),
                0,
            )
            .unwrap();
        let verdict = engine
            .record(
                entity(),
                "BAYES",
                detection(Severity::High, Some(0.9), case.clone()),
                1_000_000_000,
            )
            .expect("a higher score must still surface, even within the dedup window");
        assert_eq!(verdict.score, Some(0.9));

        // A lower score than what's already recorded must not regress the verdict.
        let regressed = engine.record(
            entity(),
            "BAYES",
            detection(Severity::High, Some(0.3), case),
            2_000_000_000,
        );
        assert!(
            regressed.is_none(),
            "a lower score within the window is a duplicate, not a new finding"
        );
        assert_eq!(engine.peek(&entity()).unwrap().score, Some(0.9));
    }

    #[test]
    fn a_suppressed_technique_never_produces_a_verdict() {
        let mut engine = VerdictEngine::new(60_000_000_000);
        engine.suppress(entity(), "T1059.004");
        let verdict = engine.record(
            entity(),
            "T1059.004",
            detection(Severity::Critical, None, rule("r1")),
            0,
        );
        assert!(verdict.is_none(), "a suppressed pair must stay silent");
        assert!(
            engine.peek(&entity()).is_none(),
            "suppression must not even create entity state"
        );
    }

    #[test]
    fn suppression_is_scoped_to_the_exact_technique() {
        let mut engine = VerdictEngine::new(60_000_000_000);
        engine.suppress(entity(), "T1059.004");
        let verdict = engine.record(
            entity(),
            "T1071.001",
            detection(Severity::Medium, None, rule("r1")),
            0,
        );
        assert!(
            verdict.is_some(),
            "a different technique on the same entity must not be suppressed"
        );
    }

    #[test]
    fn unsuppress_restores_normal_recording() {
        let mut engine = VerdictEngine::new(60_000_000_000);
        engine.suppress(entity(), "T1059.004");
        engine.unsuppress(&entity(), "T1059.004");
        let verdict = engine.record(
            entity(),
            "T1059.004",
            detection(Severity::Medium, None, rule("r1")),
            0,
        );
        assert!(
            verdict.is_some(),
            "unsuppress must restore normal recording"
        );
    }

    #[test]
    fn distinct_entities_never_share_state() {
        let mut engine = VerdictEngine::new(60_000_000_000);
        engine
            .record(
                entity(),
                "T1059.004",
                detection(Severity::Critical, None, rule("r1")),
                0,
            )
            .unwrap();
        let other = EntityKey::new(9999, "python3");
        let verdict = engine
            .record(
                other.clone(),
                "T1059.004",
                detection(Severity::Low, None, rule("r1")),
                0,
            )
            .expect("a different entity's first sighting must still produce a verdict");
        assert_eq!(verdict.severity, Severity::Low);
        assert_eq!(engine.peek(&entity()).unwrap().severity, Severity::Critical);
    }

    #[test]
    fn peek_never_folds_in_a_finding() {
        let mut engine = VerdictEngine::new(60_000_000_000);
        assert!(engine.peek(&entity()).is_none());
        engine
            .record(
                entity(),
                "T1059.004",
                detection(Severity::Medium, None, rule("r1")),
                0,
            )
            .unwrap();
        let before = engine.peek(&entity());
        let after = engine.peek(&entity());
        assert_eq!(
            before, after,
            "peek must be idempotent, no hidden state change"
        );
    }

    #[test]
    fn evidence_is_bounded_per_entity() {
        let mut engine = VerdictEngine::new(0); // no dedup: every call is a fresh technique
        for i in 0..(EVIDENCE_CAP + 10) {
            engine
                .record(
                    entity(),
                    &format!("T{i}"),
                    at(detection(Severity::Low, None, rule("r1")), i as u64),
                    i as u64,
                )
                .unwrap();
        }
        let verdict = engine.peek(&entity()).unwrap();
        assert_eq!(verdict.detections.len(), EVIDENCE_CAP);
        // The oldest evidence was evicted; the most recent EVIDENCE_CAP survive.
        let newest = verdict.detections.last().unwrap();
        assert_eq!(newest.timestamp_ns, (EVIDENCE_CAP + 9) as u64);
    }
}
