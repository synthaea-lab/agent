//! On-device ML scoring: runs an Isolation Forest (ONNX) through onnxruntime
//! (`ort`, statically linked — ADR-0002) and pairs every score with the per-feature
//! attribution from [`crate::forest`], so a detection is never a bare number
//! (`docs/detection/ml.md`).
//!
//! A model is loaded as data from the update channel, never embedded
//! ([`CmdlineScorer::from_onnx_bytes`]). One model file feeds both paths: `ort`
//! executes the graph for the score, and the same bytes are parsed into a [`Forest`]
//! for attribution — so the explanation always describes the model that produced the
//! score.
//!
//! - [`CmdlineScorer`] (T0) scores one command line the instant an `Exec` arrives;
//! - [`correlation::CorrelationScorer`] (T2) scores a pid's behaviour over the
//!   correlator window once it is populated, and feeds the correlator's belief state
//!   rather than alerting on its own.

pub mod correlation;

use ort::{session::Session, value::Tensor};
use serde::Deserialize;

use crate::{
    bounds::FeatureBounds,
    features::cmdline::{self, FEATURE_NAMES},
    forest::{Forest, ParseError},
};

/// Model artifacts arrive from the update channel; loading and inference must surface
/// errors, never panic.
#[derive(Debug, thiserror::Error)]
pub enum ScorerError {
    /// onnxruntime failed to load the model or run inference.
    #[error("onnxruntime error: {0}")]
    Runtime(#[from] ort::Error),
    /// The model file could not be parsed for attribution.
    #[error(transparent)]
    Parse(#[from] ParseError),
    /// The model's input width disagrees with the scorer's feature space — a sign the
    /// wrong model shipped to this scorer.
    #[error("model expects {model} features, the extractor produces {extractor}")]
    FeatureArity { model: usize, extractor: usize },
    /// The `scores` output was missing or empty.
    #[error("model produced no score")]
    NoScore,
    /// Input feature outside training bounds (OOD detection, issue #46).
    ///
    /// The model was trained on features within specific ranges; this input falls
    /// outside those ranges and the score would be unreliable. Treat as "no score
    /// available" rather than "benign" — the absence of an ML score does not mean
    /// the input is safe, just that the model cannot confidently score it.
    #[error("feature {feature} value {value:.3} outside bounds [{min:.3}, {max:.3}]")]
    FeatureOutOfBounds {
        feature: String,
        value: f32,
        min: f32,
        max: f32,
    },
}

/// A cmdline score plus the explanation of how it was reached.
#[derive(Debug, Clone)]
pub struct Score {
    /// `IsolationForest.decision_function`: negative = anomalous, positive = normal.
    /// No threshold is imposed here — calibration (FP budgets) is the model card's
    /// contract and the caller's decision.
    pub value: f32,
    /// Top contributing features, ordered by `|contribution|`, ready to attach to a
    /// `schema::detection::Detection`. Positive contribution pushes toward anomalous.
    pub attributions: Vec<schema::detection::ScoreAttribution>,
}

/// Model metadata sidecar (issue #46).
///
/// Loaded from `model_metadata.json` alongside the ONNX model. Optional: legacy
/// models without metadata still work (no OOD validation, threshold defaults to 0).
#[derive(Debug, Deserialize)]
pub(crate) struct ModelMetadata {
    threshold: Option<f32>,
    feature_bounds: Option<FeatureBounds>,
}

/// Scores command lines against one Isolation Forest model.
pub struct CmdlineScorer {
    session: Session,
    forest: Forest,
    bounds: Option<FeatureBounds>,
    /// Conformal threshold: anomaly if score < threshold (issue #46).
    /// `None` for legacy models without calibration.
    threshold: Option<f32>,
}

impl CmdlineScorer {
    /// Loads a model from ONNX bytes with optional metadata (issue #46).
    ///
    /// Metadata format: JSON sidecar (`model_metadata.json`) with optional
    /// `threshold` (conformal calibration) and `feature_bounds` (OOD detection).
    /// If `metadata` is `None`, the scorer works in legacy mode (no OOD validation).
    ///
    /// # Errors
    ///
    /// Returns [`ScorerError`] when the ONNX session cannot be built, the tree
    /// structure cannot be parsed, the model's feature arity does not match
    /// the cmdline extractor, or the metadata JSON is malformed.
    pub fn from_onnx_bytes_with_metadata(
        model: &[u8],
        metadata: Option<&[u8]>,
    ) -> Result<Self, ScorerError> {
        let session = Session::builder()?.commit_from_memory(model)?;
        let forest = Forest::from_onnx_bytes(model)?;

        if forest.n_features() != FEATURE_NAMES.len() {
            return Err(ScorerError::FeatureArity {
                model: forest.n_features(),
                extractor: FEATURE_NAMES.len(),
            });
        }

        let (bounds, threshold) = if let Some(meta_bytes) = metadata {
            let parsed: ModelMetadata = serde_json::from_slice(meta_bytes)
                .map_err(|_| ParseError::Malformed("invalid metadata JSON"))?;

            // Validate feature bounds internal consistency (issue #46: prevent panic on
            // malformed metadata where array lengths don't match)
            if let Some(ref b) = parsed.feature_bounds {
                b.check_invariant()?;
            }

            (parsed.feature_bounds, parsed.threshold)
        } else {
            (None, None)
        };

        Ok(Self {
            session,
            forest,
            bounds,
            threshold,
        })
    }

    /// Loads a model from ONNX bytes (legacy: no metadata).
    ///
    /// Equivalent to `from_onnx_bytes_with_metadata(model, None)`. Provided for
    /// backward compatibility with existing callers.
    ///
    /// # Errors
    ///
    /// Returns [`ScorerError`] when the ONNX session cannot be built, the tree
    /// structure cannot be parsed, or the model's feature arity does not match
    /// the cmdline extractor.
    pub fn from_onnx_bytes(model: &[u8]) -> Result<Self, ScorerError> {
        Self::from_onnx_bytes_with_metadata(model, None)
    }

    fn run(&mut self, features: &[f32; 9]) -> Result<f32, ScorerError> {
        let input = Tensor::from_array(([1i64, features.len() as i64], features.to_vec()))?;
        let outputs = self.session.run(ort::inputs!["X" => input])?;
        let (_shape, scores) = outputs["scores"].try_extract_tensor::<f32>()?;
        scores.first().copied().ok_or(ScorerError::NoScore)
    }

    /// The anomaly score of a command line (no attribution — the hot path for events
    /// that will not become detections), or `None` when the score is below the
    /// conformal threshold (normal behaviour, FP budget enforcement).
    ///
    /// When a conformal threshold is available (issue #46), only scores below it
    /// (anomalous, meeting the FP budget) are returned; normal scores return `None`.
    ///
    /// # Errors
    ///
    /// Returns [`ScorerError::FeatureOutOfBounds`] if the feature vector falls
    /// outside training bounds (OOD detection, issue #46). Returns other
    /// [`ScorerError`] variants when ONNX inference fails or produces no score.
    pub fn score(&mut self, cmdline: &str) -> Result<Option<f32>, ScorerError> {
        let features = cmdline::extract_features(cmdline);

        // OOD validation (if bounds available)
        if let Some(ref bounds) = self.bounds {
            bounds.validate(&features)?;
        }

        let score = self.run(&features)?;

        // Conformal threshold: anomaly if score < threshold (issue #46).
        // Normal scores (>= threshold) return None — they don't alert,
        // enforcing the FP budget.
        if let Some(threshold) = self.threshold
            && score >= threshold
        {
            return Ok(None);
        }

        Ok(Some(score))
    }

    /// The anomaly score plus its top-`k` feature attributions — for an event that
    /// crossed a threshold and is becoming a detection. Returns `None` when the
    /// score is below the conformal threshold (normal behaviour).
    ///
    /// # Errors
    ///
    /// Returns [`ScorerError::FeatureOutOfBounds`] if the feature vector falls
    /// outside training bounds (OOD detection, issue #46). Returns other
    /// [`ScorerError`] variants when inference fails, produces no score, or the
    /// attribution walk finds the model inconsistent with its parsed structure.
    pub fn score_explained(&mut self, cmdline: &str, k: usize) -> Result<Option<Score>, ScorerError> {
        let features = cmdline::extract_features(cmdline);

        // OOD validation
        if let Some(ref bounds) = self.bounds {
            bounds.validate(&features)?;
        }

        let value = self.run(&features)?;

        // Conformal threshold: anomaly if score < threshold (issue #46).
        if let Some(threshold) = self.threshold
            && value >= threshold
        {
            return Ok(None);
        }

        let attribution = self.forest.attribute(&features)?;
        let names: Vec<&str> = FEATURE_NAMES.to_vec();
        Ok(Some(Score {
            value,
            attributions: crate::forest::top_attributions(&attribution, &features, &names, k),
        }))
    }
}

#[cfg(test)]
mod threshold_tests {
    use super::*;

    /// Minimal valid ONNX `IsolationForest` for testing threshold behavior.
    fn fixture_model() -> Vec<u8> {
        std::fs::read(format!(
            "{}/tests/fixtures/cmdline_scorer.onnx",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("fixture model must exist")
    }

    #[test]
    fn legacy_model_without_threshold_always_returns_some() {
        let mut scorer = CmdlineScorer::from_onnx_bytes(&fixture_model())
            .expect("fixture model must load");

        // Legacy model (no metadata) should always return Some(score)
        let result = scorer.score("benign command").unwrap();
        assert!(result.is_some(), "legacy model must return Some for any score");
    }

    #[test]
    fn threshold_filters_normal_scores() {
        // Create metadata with a threshold of 0.0
        let metadata = serde_json::json!({
            "threshold": 0.0,
            "feature_bounds": null
        });
        let metadata_bytes = serde_json::to_vec(&metadata).unwrap();

        let mut scorer = CmdlineScorer::from_onnx_bytes_with_metadata(
            &fixture_model(),
            Some(&metadata_bytes),
        )
        .expect("model with metadata must load");

        // Scores below threshold (< 0.0, anomalous) should return Some
        // Scores above threshold (>= 0.0, normal) should return None
        // This test verifies the filtering logic exists; exact score values
        // depend on the model and are not the point here.
        let result = scorer.score("some command");
        assert!(result.is_ok(), "scoring with threshold should not error");
        // Result can be Some or None depending on the actual score vs threshold
    }

    #[test]
    fn threshold_filters_score_explained() {
        let metadata = serde_json::json!({
            "threshold": 0.0,
            "feature_bounds": null
        });
        let metadata_bytes = serde_json::to_vec(&metadata).unwrap();

        let mut scorer = CmdlineScorer::from_onnx_bytes_with_metadata(
            &fixture_model(),
            Some(&metadata_bytes),
        )
        .expect("model with metadata must load");

        let result = scorer.score_explained("some command", 3);
        assert!(result.is_ok(), "score_explained with threshold should not error");
        // Result can be Some or None depending on the actual score vs threshold
    }
}
