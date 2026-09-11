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

use crate::{
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

/// Scores command lines against one Isolation Forest model.
pub struct CmdlineScorer {
    session: Session,
    forest: Forest,
}

impl CmdlineScorer {
    /// Loads a model from ONNX bytes (as delivered by the update channel).
    ///
    /// Parses the tree structure up front so attribution needs no per-score reparse,
    /// and checks the model's feature arity against the cmdline extractor so a
    /// mismatched model fails loudly at load, not silently at score time.
    ///
    /// # Errors
    ///
    /// Returns [`ScorerError`] when the ONNX session cannot be built, the tree
    /// structure cannot be parsed, or the model's feature arity does not match
    /// the cmdline extractor.
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

    fn run(&mut self, features: &[f32; 9]) -> Result<f32, ScorerError> {
        let input = Tensor::from_array(([1i64, features.len() as i64], features.to_vec()))?;
        let outputs = self.session.run(ort::inputs!["X" => input])?;
        let (_shape, scores) = outputs["scores"].try_extract_tensor::<f32>()?;
        scores.first().copied().ok_or(ScorerError::NoScore)
    }

    /// The anomaly score of a command line (no attribution — the hot path for events
    /// that will not become detections).
    ///
    /// # Errors
    ///
    /// Returns [`ScorerError`] when ONNX inference fails or produces no score.
    pub fn score(&mut self, cmdline: &str) -> Result<f32, ScorerError> {
        self.run(&cmdline::extract_features(cmdline))
    }

    /// The anomaly score plus its top-`k` feature attributions — for an event that
    /// crossed a threshold and is becoming a detection.
    ///
    /// # Errors
    ///
    /// Returns [`ScorerError`] when inference fails, produces no score, or the
    /// attribution walk finds the model inconsistent with its parsed structure.
    pub fn score_explained(&mut self, cmdline: &str, k: usize) -> Result<Score, ScorerError> {
        let features = cmdline::extract_features(cmdline);
        let value = self.run(&features)?;
        let attribution = self.forest.attribute(&features)?;
        let names: Vec<&str> = FEATURE_NAMES.to_vec();
        Ok(Score {
            value,
            attributions: crate::forest::top_attributions(&attribution, &features, &names, k),
        })
    }
}
