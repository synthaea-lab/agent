//! Naive Bayes filter — per-entity (ppid, comm) compromise belief.
//!
//! The belief is the prior plus three kinds of evidence, each counted once:
//!
//! - the **behaviour** evidence: the per-feature log-likelihood ratios (LLRs) of a
//!   [`crate::behavior::BehaviorVector`], summed under the naive independence assumption;
//! - the **ML** evidence, when a correlation model scored the entity;
//! - the **rarity** evidence, for images absent from the fleet's common set.
//!
//! A vector is a statement about a process, so its LLRs are the evidence that process
//! gives, not something to add again at each of its events: the belief does not grow with
//! the number of events an entity produces. An entity is `(ppid, comm)`, so several
//! processes can share one belief (a respawned beacon, or unrelated siblings of the same
//! name). The entity keeps the strongest evidence any of them gave: a quiet sibling cannot
//! cancel what a suspicious one did. Every term decays toward zero while nothing renews it.
//!
//! The LLRs are calibrated empirically by the ML pipeline's LLR calibration (which
//! regenerates the body of `log_likelihood_ratio`).

use crate::behavior::BehaviorVector;

/// Prior at ~1% compromise probability: log(0.01 / 0.99).
pub(crate) const PRIOR_LOG_ODDS: f32 = -4.6;
/// Decay toward the prior over ~5 min of inactivity.
const DECAY_TAU_S: f32 = 300.0;
/// Alert threshold: `log_odds` > 2.0 → P(compromised) ≈ 88%.
pub(crate) const BAYES_THRESHOLD: f32 = 2.0;

/// Weight of one "this image is not in the fleet's common set" observation (#76).
/// Deliberately weak: the weakest hand-calibrated feature above is ~0.1 and the strongest
/// 3.6, and rarity alone says "new here", not "malicious". **Provisional**: slice 6 of the
/// plan (`docs/detection/fleet-prevalence-snapshot-plan.md`) sets it on lab data, and the
/// snapshot's false-positive rate bounds how much it can be worth.
pub(crate) const RARITY_LLR: f32 = 0.35;
/// The most rarity can contribute to one belief at a time, however many rare images the
/// entity runs (a build host runs thousands of freshly compiled binaries, every one of them
/// absent from the common set). Together with the prior it keeps rarity alone ~7 log-odds
/// under [`BAYES_THRESHOLD`]: it can only ever tip a belief other evidence already raised.
pub(crate) const RARITY_MAX_TOTAL_LLR: f32 = 1.0;

/// Bayesian belief state for an entity (ppid, comm).
/// Keyed by (ppid, comm) rather than pid so it survives respawns:
/// fork+exec = new pid, same (ppid, comm) → belief preserved.
#[derive(Debug, Clone)]
pub struct BeliefState {
    /// Log of the odds ratio P(malicious) / P(benign).
    /// Initial value: `PRIOR_LOG_ODDS` (~1%).
    pub log_odds: f32,
    /// Timestamp of the last update — used to compute the decay.
    pub last_update_ns: u64,
    /// true if an alert has already been emitted for this threshold crossing.
    /// Reset to false when `log_odds` drops back below `BAYES_THRESHOLD` (decay).
    pub(crate) alerted: bool,
    /// How much of `log_odds` is rarity evidence (<= [`RARITY_MAX_TOTAL_LLR`]), decayed with
    /// the belief so the allowance returns as the evidence fades.
    pub(crate) rarity_llr: f32,
    /// The strongest behaviour evidence a process of this entity gave, decayed since.
    /// `None` until a first vector was judged: an entity nothing was said about sits at the
    /// prior, and a first vector that argues for "benign" is kept as such.
    behavior_llr: Option<f32>,
    /// The strongest ML evidence a scoring of this entity gave, decayed since.
    ml_llr: Option<f32>,
}

impl BeliefState {
    pub(crate) fn new(now_ns: u64) -> Self {
        Self {
            log_odds: PRIOR_LOG_ODDS,
            last_update_ns: now_ns,
            alerted: false,
            rarity_llr: 0.0,
            behavior_llr: None,
            ml_llr: None,
        }
    }

    /// Lets every term fade toward "no evidence" for the time since the last update.
    fn decay_to(&mut self, now_ns: u64) {
        let dt_s = (now_ns.saturating_sub(self.last_update_ns)) as f32 / 1e9;
        let kept = (-dt_s / DECAY_TAU_S).exp();
        self.rarity_llr *= kept;
        self.behavior_llr = self.behavior_llr.map(|llr| llr * kept);
        self.ml_llr = self.ml_llr.map(|llr| llr * kept);
        self.last_update_ns = now_ns;
    }

    /// The prior plus each kind of evidence, once.
    fn recompute(&mut self) {
        self.log_odds = PRIOR_LOG_ODDS
            + self.behavior_llr.unwrap_or(0.0)
            + self.ml_llr.unwrap_or(0.0)
            + self.rarity_llr;
    }

    /// Current compromise probability (0.0–1.0).
    #[must_use]
    pub fn probability(&self) -> f32 {
        let odds = self.log_odds.exp();
        odds / (1.0 + odds)
    }
}

/// Log-likelihood ratio for the feature at index `idx`.
/// Calibrated empirically on the `NjRAT` capture (`n_benign=97`, `n_malicious=23`) on
/// 2026-08-28. Naive independence assumption: the LLRs are summed.
fn log_likelihood_ratio(idx: usize, value: f32) -> f32 {
    match idx {
        // 0 — has_exec: neutral — data artifact (PIDs seeded without an Exec in the window)
        0 => 0.0,
        // 1 — has_connect: moderate signal — malware almost always connects
        1 => {
            if value > 0.5 {
                1.19
            } else {
                -0.93
            }
        }
        // 2 — has_filewrite: no empirical signal (few FileOpen events captured)
        2 => 0.0,
        // 3 — time_exec_to_connect_ms: quick connection after spawn → highly suspicious
        3 => {
            if value > 0.0 && value < 2_000.0 {
                1.90
            } else if value > 0.0 {
                -0.22
            } else {
                -0.09
            } // absent
        }
        // 4 — time_exec_to_filewrite_ms: no empirical signal
        4 => 0.0,
        // 5 — is_suspicious_path: AppData/Temp/Desktop → very strong signal
        5 => {
            if value > 0.5 {
                3.60
            } else {
                -0.20
            }
        }
        // 6 — connect_count: repeated beaconing → signal grows in steps
        6 => {
            if value == 0.0 {
                -0.96
            } else if value < 5.0 {
                0.41
            } else if value < 15.0 {
                2.22
            } else {
                0.87
            }
        }
        // 7 — distinct_dports: empirically not very discriminating
        7 => {
            if value <= 1.0 {
                0.02
            } else if value <= 3.0 {
                -0.54
            } else {
                0.0
            }
        }
        // 8 — dest_is_external: connection to a public IP → strong signal
        8 => {
            if value > 0.5 {
                1.23
            } else {
                -0.44
            }
        }
        _ => 0.0,
    }
}

/// The behaviour evidence of one vector: the sum of its per-feature LLRs.
fn behavior_evidence(v: &BehaviorVector) -> f32 {
    v.to_vec()
        .iter()
        .enumerate()
        .map(|(i, &value)| log_likelihood_ratio(i, value))
        .sum()
}

/// The stronger of what is remembered and what was just observed.
fn strongest(remembered: Option<f32>, observed: f32) -> f32 {
    remembered.map_or(observed, |llr| llr.max(observed))
}

/// Judges an entity's belief on the `BehaviorVector` of one of its processes, and on an ML
/// score when there is one.
///
/// Every term first decays for the time since the last update. The vector's evidence then
/// replaces the remembered behaviour evidence only if it is stronger: the same vector seen
/// again adds nothing, and a sibling process with a quieter vector takes nothing away.
///
/// # ML LLR semantics
///
/// - `ml_llr = Some(llr)`: the model's evidence, kept if stronger than what is remembered.
/// - `ml_llr = None`: no evidence (gated, out of bounds, or no scorer), not "benign".
pub(crate) fn update_belief(
    state: &mut BeliefState,
    v: &BehaviorVector,
    ml_llr: Option<f32>,
    now_ns: u64,
) {
    state.decay_to(now_ns);
    state.behavior_llr = Some(strongest(state.behavior_llr, behavior_evidence(v)));
    if let Some(llr) = ml_llr {
        state.ml_llr = Some(strongest(state.ml_llr, llr));
    }
    state.recompute();
}

/// Records an ML log-likelihood ratio on an already-updated belief state.
///
/// It does not re-run the behaviour update: `CorrelationEngine::on_event` already judged
/// the vector for this cycle, before the ML scorer could run (scoring needs the event on
/// the bus first). Like the behaviour evidence, the score is kept only if it is stronger
/// than the one remembered, so scoring an entity at each of its events does not add the
/// model's opinion to itself.
pub(crate) fn apply_ml_llr(state: &mut BeliefState, llr: f32) {
    state.ml_llr = Some(strongest(state.ml_llr, llr));
    state.recompute();
}

/// Adds the "image not in the common set" term to a belief, within its allowance
/// ([`RARITY_MAX_TOTAL_LLR`] less what is still counted). Like [`apply_ml_llr`], it adds one
/// term on top of an already-updated belief and does not re-run the feature update.
pub(crate) fn apply_rarity_llr(state: &mut BeliefState) {
    let room = (RARITY_MAX_TOTAL_LLR - state.rarity_llr).max(0.0);
    state.rarity_llr += RARITY_LLR.min(room);
    state.recompute();
}
