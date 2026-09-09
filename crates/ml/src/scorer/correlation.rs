//! On-device behaviour scoring (T2): runs the correlation Isolation Forest (ONNX)
//! over a pid's [`features::correlation`] vector and turns the anomaly score into a
//! log-odds term for the correlator's Bayesian belief state.
//!
//! Distinct from [`super::CmdlineScorer`] (T0) in every axis that matters
//! (2026-08-27 decision, `docs/detection/correlation.md`):
//!
//! - **temporal** — a cmdline is ready the instant an `Exec` arrives; this vector
//!   only once the correlator window holds several events for the pid;
//! - **statistical** — counts and spans, not text shape, so a separate model;
//! - **output** — T0 alerts on its own budget; T2 has *no standalone threshold in
//!   v1*. [`CorrelationScorer::score`] produces a number, [`score_to_llr`] turns it
//!   into evidence, and the correlator fuses that evidence into
//!   `BeliefState::log_odds` alongside the hand-calibrated per-feature LLRs. The two
//!   scorers still alert independently (OR) — T2 just makes T1 quicker to believe.
//!
//! The correlator cannot call this crate (`ml` already depends on `correlator` for
//! [`EventBus`]; the reverse edge would be a cycle). The wiring is therefore
//! "compute here, inject there": the agent runs the scorer against the engine's bus
//! and hands the LLR back through the correlator's public API. That seam is not in
//! this crate yet — see `docs/detection/correlation.md`.

use correlator::EventBus;
use ort::session::Session;
use ort::value::Tensor;

use super::{Score, ScorerError};
use crate::features::correlation::{self, FEATURE_NAMES};
use crate::forest::Forest;

/// Index of `event_count` in [`FEATURE_NAMES`] — the gate feature.
const EVENT_COUNT_IDX: usize = 7;

/// Below this many events in the window the vector is almost all zeros and carries
/// no signal — [`CorrelationScorer::score`] returns `None` rather than feed the model
/// a point it was told at training time to ignore (`train_correlation.py`,
/// `MIN_EVENT_COUNT_GATE`).
pub const MIN_EVENT_COUNT: f32 = 3.0;

/// Scores a pid's recent behaviour against one correlation Isolation Forest.
pub struct CorrelationScorer {
    session: Session,
    forest: Forest,
}

impl CorrelationScorer {
    /// Loads a model from ONNX bytes (as delivered by the update channel).
    ///
    /// Parses the tree structure up front so attribution needs no per-score reparse,
    /// and checks the model's feature arity against the correlation extractor so a
    /// mismatched model (e.g. a cmdline model) fails loudly at load, not silently at
    /// score time.
    ///
    /// # Errors
    ///
    /// Returns [`ScorerError`] when the ONNX session cannot be built, the tree
    /// structure cannot be parsed, or the model's feature arity does not match the
    /// correlation extractor.
    pub fn from_onnx_bytes(model: &[u8]) -> Result<Self, ScorerError> {
        let session = Session::builder()?.commit_from_memory(model)?;
        let forest = Forest::from_onnx_bytes(model)?;
        if forest.n_features() != FEATURE_NAMES.len() {
            return Err(ScorerError::FeatureArity {
                model: forest.n_features(),
                extractor: FEATURE_NAMES.len(),
            });
        }
        Ok(Self { session, forest })
    }

    fn run(&mut self, features: &[f32; 8]) -> Result<f32, ScorerError> {
        let input = Tensor::from_array(([1i64, features.len() as i64], features.to_vec()))?;
        let outputs = self.session.run(ort::inputs!["X" => input])?;
        let (_shape, scores) = outputs["scores"].try_extract_tensor::<f32>()?;
        scores.first().copied().ok_or(ScorerError::NoScore)
    }

    /// The anomaly score of `pid`'s behaviour over the bus's current window, or
    /// `None` when the window holds fewer than [`MIN_EVENT_COUNT`] events for the pid
    /// (nothing to score yet).
    ///
    /// `IsolationForest.decision_function`: negative = anomalous, positive = normal.
    /// No threshold is imposed here — T2 feeds the belief state, it does not alert.
    ///
    /// # Errors
    ///
    /// Returns [`ScorerError`] when ONNX inference fails or produces no score.
    pub fn score(&mut self, bus: &EventBus, pid: u32) -> Result<Option<f32>, ScorerError> {
        let features = correlation::extract_features(bus, pid);
        if features[EVENT_COUNT_IDX] < MIN_EVENT_COUNT {
            return Ok(None);
        }
        self.run(&features).map(Some)
    }

    /// The anomaly score plus its top-`k` feature attributions — for a pid whose
    /// belief crossed the alert threshold and is becoming a detection. `None` under
    /// the same gate as [`CorrelationScorer::score`].
    ///
    /// # Errors
    ///
    /// Returns [`ScorerError`] when inference fails, produces no score, or the
    /// attribution walk finds the model inconsistent with its parsed structure.
    pub fn score_explained(
        &mut self,
        bus: &EventBus,
        pid: u32,
        k: usize,
    ) -> Result<Option<Score>, ScorerError> {
        let features = correlation::extract_features(bus, pid);
        if features[EVENT_COUNT_IDX] < MIN_EVENT_COUNT {
            return Ok(None);
        }
        let value = self.run(&features)?;
        let attribution = self.forest.attribute(&features)?;
        let names: Vec<&str> = FEATURE_NAMES.to_vec();
        Ok(Some(Score {
            value,
            attributions: crate::forest::top_attributions(&attribution, &features, &names, k),
        }))
    }
}

// ── score → log-odds ─────────────────────────────────────────────────────────

/// Upper bound on the log-odds a single T2 update may add. `+3.0` moves an entity
/// from the ~1% prior to ~29% on its own — enough to matter next to the per-feature
/// LLRs, not enough to alert without corroboration (`BAYES_THRESHOLD` is `+2.0` from
/// a `-4.6` prior, so T2 alone stays well short).
const LLR_MAX: f32 = 3.0;
/// Lower bound. A confidently-normal window should pull the belief down, but a
/// behaviour model exonerates far more weakly than it accuses — hence the asymmetry.
const LLR_MIN: f32 = -1.0;
/// Slope of the linear map from `decision_function` to log-odds. **Provisional**:
/// `decision_function ≈ -0.15` is "clearly anomalous" for this model, and `0.15 * GAIN
/// ≈ LLR_MAX`. The real value comes from the pipeline's LLR calibration on a benign
/// multi-event baseline (#44), the same step that regenerates
/// `correlator::bayes::log_likelihood_ratio` — until then this is a placeholder that
/// only ever contributes to a belief, never alerts alone.
const GAIN: f32 = 20.0;

/// Maps a [`CorrelationScorer::score`] value to the log-odds term the correlator adds
/// to `BeliefState::log_odds`.
///
/// `decision_function` is positive for normal points and negative for anomalies, so
/// the term is `-score * GAIN`, clamped to `[LLR_MIN, LLR_MAX]`. `score = 0` (the
/// model's own boundary) contributes nothing.
#[must_use]
pub fn score_to_llr(score: f32) -> f32 {
    (-score * GAIN).clamp(LLR_MIN, LLR_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn llr_boundary_is_neutral() {
        assert_eq!(score_to_llr(0.0), 0.0);
    }

    #[test]
    fn llr_is_monotone_decreasing_in_score() {
        let xs = [-0.4, -0.2, -0.05, 0.0, 0.05, 0.2, 0.4];
        for w in xs.windows(2) {
            assert!(
                score_to_llr(w[0]) >= score_to_llr(w[1]),
                "score_to_llr must not increase as the score rises: {} -> {}",
                w[0],
                w[1],
            );
        }
    }

    #[test]
    fn llr_is_clamped_both_ways() {
        assert_eq!(score_to_llr(-10.0), LLR_MAX);
        assert_eq!(score_to_llr(10.0), LLR_MIN);
    }

    #[test]
    fn anomalous_side_outweighs_normal_side() {
        // Symmetric scores, asymmetric evidence: accusation is stronger than
        // exoneration.
        assert!(score_to_llr(-0.1).abs() > score_to_llr(0.1).abs());
    }
}
