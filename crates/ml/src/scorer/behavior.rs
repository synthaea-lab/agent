//! On-device T1 behavior scoring: runs the 23-feature Isolation Forest (ONNX) over one
//! process incarnation's [`crate::features::t1`] vector (cmdline 9 + correlation 8 +
//! lineage 6), issue #617.
//!
//! Where [`super::CmdlineScorer`] (T0) reads one command line and
//! [`super::correlation::CorrelationScorer`] (T2) reads one window of counts, this scores
//! what the two share with the parent lineage: it needs the incarnation's exec in the
//! bus window and nothing more, so there is no event-count gate (the correlation block
//! of a young process is simply small, and the model trained on such windows:
//! `train_behavior.py` windows end at the incarnation's last event).
//!
//! Like the T2 scorer it only computes: the agent runs it against the engine's bus and
//! decides what to do with the number. Nothing wires it into the agent yet; that waits
//! for a model trained on a real capture (#617).

use correlator::EventBus;
use ort::{session::Session, value::Tensor};

use super::{ModelMetadata, Score, ScorerError};
use crate::{
    bounds::FeatureBounds,
    features::t1::{self, FEATURE_COUNT, FEATURE_NAMES},
    forest::{Forest, ParseError},
};

/// Scores a process incarnation's behavior against one T1 Isolation Forest.
pub struct BehaviorScorer {
    session: Session,
    forest: Forest,
    bounds: Option<FeatureBounds>,
    /// Conformal threshold: anomaly if score < threshold (issue #46).
    /// `None` for a model without calibration.
    threshold: Option<f32>,
}

impl BehaviorScorer {
    /// Loads a model from ONNX bytes with optional `model_metadata.json` bytes.
    ///
    /// With metadata the model is **calibrated**: the file must carry both the conformal
    /// threshold and the feature bounds (as `train_behavior.py` always writes them), and
    /// both are applied. Without metadata the model is **uncalibrated**: every score is
    /// returned and no vector is rejected as out of distribution. There is no half-way:
    /// metadata with only one of the two is refused, since that would leave one guard off
    /// silently.
    ///
    /// # Errors
    ///
    /// Returns [`ScorerError`] when the ONNX session cannot be built, the tree
    /// structure cannot be parsed, the model is not 23 features wide (a T0 or T2 model
    /// shipped to this scorer), the metadata JSON is malformed or lacks the threshold or
    /// the feature bounds, or its feature bounds are not for exactly the T1 features, in
    /// this order (bounds for fewer features would skip the out-of-distribution guard on
    /// the rest).
    pub fn from_onnx_bytes_with_metadata(
        model: &[u8],
        metadata: Option<&[u8]>,
    ) -> Result<Self, ScorerError> {
        let session = Session::builder()?.commit_from_memory(model)?;
        let forest = Forest::from_onnx_bytes(model)?;

        if forest.n_features() != FEATURE_COUNT {
            return Err(ScorerError::FeatureArity {
                model: forest.n_features(),
                extractor: FEATURE_COUNT,
            });
        }

        let (bounds, threshold) = match metadata {
            Some(bytes) => {
                let parsed: ModelMetadata = serde_json::from_slice(bytes)
                    .map_err(|_| ParseError::Malformed("invalid metadata JSON"))?;
                // A metadata file means a calibrated model, and `train_behavior.py` always
                // writes both halves. Either one missing would switch its guard off without
                // a word (no bounds: any vector is scored; no threshold: every score is
                // returned), so it is refused here.
                let bounds = parsed
                    .feature_bounds
                    .ok_or(ParseError::Malformed("metadata has no feature bounds"))?;
                let threshold = parsed
                    .threshold
                    .ok_or(ParseError::Malformed("metadata has no threshold"))?;
                bounds.check_invariant()?;
                if bounds.feature_names != FEATURE_NAMES {
                    return Err(ParseError::Malformed(
                        "feature bounds are not for the T1 features",
                    )
                    .into());
                }
                (Some(bounds), Some(threshold))
            }
            None => (None, None),
        };

        Ok(Self {
            session,
            forest,
            bounds,
            threshold,
        })
    }

    /// Loads an uncalibrated model from ONNX bytes: no threshold and no bounds (see
    /// [`Self::from_onnx_bytes_with_metadata`]).
    ///
    /// # Errors
    ///
    /// As [`Self::from_onnx_bytes_with_metadata`].
    pub fn from_onnx_bytes(model: &[u8]) -> Result<Self, ScorerError> {
        Self::from_onnx_bytes_with_metadata(model, None)
    }

    fn run(&mut self, features: &[f32; FEATURE_COUNT]) -> Result<f32, ScorerError> {
        let input = Tensor::from_array(([1i64, FEATURE_COUNT as i64], features.to_vec()))?;
        let outputs = self.session.run(ort::inputs!["X" => input])?;
        let (_shape, scores) = outputs["scores"].try_extract_tensor::<f32>()?;
        scores.first().copied().ok_or(ScorerError::NoScore)
    }

    /// The vector to score, or `None` when there is nothing to score or the model's
    /// calibration says the process is normal (see [`Self::score`]).
    fn scorable(
        &mut self,
        bus: &EventBus,
        pid: u32,
        generation: Option<u64>,
    ) -> Result<Option<([f32; FEATURE_COUNT], f32)>, ScorerError> {
        let Some(features) = t1::extract_features(bus, pid, generation) else {
            return Ok(None);
        };
        if let Some(bounds) = &self.bounds {
            bounds.validate(&features)?;
        }
        let value = self.run(&features)?;
        if self.threshold.is_some_and(|threshold| value >= threshold) {
            return Ok(None);
        }
        Ok(Some((features, value)))
    }

    /// The anomaly score of the incarnation `(pid, generation)` over the bus's current
    /// window, or `None` when the window holds no exec for it (no command line and no
    /// lineage to score), or when the score reaches the conformal threshold (normal
    /// behavior: the false-positive budget is enforced here, not by the caller).
    ///
    /// `IsolationForest.decision_function`: negative = anomalous, positive = normal.
    ///
    /// # Errors
    ///
    /// [`ScorerError::FeatureOutOfBounds`] when the vector falls outside the training
    /// bounds: treat it as "no score available", not as "benign". Other [`ScorerError`]
    /// variants when inference fails or yields no score.
    pub fn score(
        &mut self,
        bus: &EventBus,
        pid: u32,
        generation: Option<u64>,
    ) -> Result<Option<f32>, ScorerError> {
        Ok(self.scorable(bus, pid, generation)?.map(|(_, value)| value))
    }

    /// The anomaly score plus its top-`k` feature attributions, under the same gates
    /// as [`Self::score`].
    ///
    /// # Errors
    ///
    /// As [`Self::score`], plus [`ScorerError::Parse`] when the attribution walk finds
    /// the model inconsistent with its parsed structure.
    pub fn score_explained(
        &mut self,
        bus: &EventBus,
        pid: u32,
        generation: Option<u64>,
        k: usize,
    ) -> Result<Option<Score>, ScorerError> {
        let Some((features, value)) = self.scorable(bus, pid, generation)? else {
            return Ok(None);
        };
        let attribution = self.forest.attribute(&features)?;
        Ok(Some(Score {
            value,
            attributions: crate::forest::top_attributions(
                &attribution,
                &features,
                &FEATURE_NAMES,
                k,
            ),
        }))
    }
}
