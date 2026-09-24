//! Out-of-distribution (OOD) detection via per-feature bounds.
//!
//! Models trained on benign baselines learn feature distributions from that data.
//! Inputs far outside the training range (e.g., cmdline length = 1M chars when
//! training max was 5K) are out-of-distribution and the model's score is
//! unreliable. This module validates feature vectors against bounds computed at
//! training time before allowing inference.
//!
//! See issue #46 for the design (conformal FP-budget thresholds + OOD guards).

use serde::{Deserialize, Serialize};

use crate::scorer::ScorerError;

/// Per-feature bounds for OOD detection.
///
/// Computed from the training set (70% split) with a margin (typically 5%) to
/// avoid false rejections on legitimate edge cases. Loaded from
/// `model_metadata.json` alongside the ONNX model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureBounds {
    pub feature_names: Vec<String>,
    pub min_values: Vec<f32>,
    pub max_values: Vec<f32>,
}

impl FeatureBounds {
    /// Validates the internal consistency of the bounds structure.
    ///
    /// Ensures `min_values.len() == max_values.len() == feature_names.len()` so
    /// `validate()` cannot panic on mismatched array access. A metadata sidecar
    /// with mismatched lengths (truncated write, manual edit, tampered file) is
    /// caught here at load time rather than panicking later in the hot path.
    ///
    /// # Errors
    ///
    /// Returns [`crate::forest::ParseError::Malformed`] if the array lengths
    /// don't match.
    pub(crate) fn check_invariant(&self) -> Result<(), crate::forest::ParseError> {
        if self.min_values.len() != self.max_values.len()
            || self.min_values.len() != self.feature_names.len()
        {
            return Err(crate::forest::ParseError::Malformed(
                "FeatureBounds arrays have mismatched lengths",
            ));
        }
        Ok(())
    }

    /// Validates a feature vector against the bounds.
    ///
    /// Returns `Ok(())` if all features are within bounds, or
    /// `Err(ScorerError::FeatureOutOfBounds)` for the first out-of-range feature.
    ///
    /// # Errors
    ///
    /// Returns [`ScorerError::FeatureOutOfBounds`] if any feature value falls
    /// outside its `[min, max]` range.
    ///
    /// # Panics
    ///
    /// Should never panic: `check_invariant()` is called at load time to ensure
    /// array lengths match. If this does panic, it indicates `check_invariant()`
    /// was not called on the bounds before use.
    pub fn validate(&self, features: &[f32]) -> Result<(), ScorerError> {
        for (i, &value) in features.iter().enumerate() {
            if i >= self.min_values.len() {
                // Allow extractors to produce more features than the model expects
                // (forward compatibility if extractors add features but models lag)
                break;
            }
            let min = self.min_values[i];
            let max = self.max_values[i]; // Safe: check_invariant ensures matching lengths
            if value < min || value > max {
                let feature_name = self
                    .feature_names
                    .get(i)
                    .map(|s| s.as_str())
                    .unwrap_or("unknown");
                return Err(ScorerError::FeatureOutOfBounds {
                    feature: feature_name.to_string(),
                    value,
                    min,
                    max,
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_in_bounds_passes() {
        let bounds = FeatureBounds {
            feature_names: vec!["length".to_string(), "entropy".to_string()],
            min_values: vec![0.0, 0.0],
            max_values: vec![100.0, 5.0],
        };

        // All values within bounds
        assert!(bounds.validate(&[50.0, 2.5]).is_ok());
        assert!(bounds.validate(&[0.0, 0.0]).is_ok()); // Exactly at min
        assert!(bounds.validate(&[100.0, 5.0]).is_ok()); // Exactly at max
    }

    #[test]
    fn test_validate_out_of_bounds_fails() {
        let bounds = FeatureBounds {
            feature_names: vec!["length".to_string(), "entropy".to_string()],
            min_values: vec![0.0, 0.0],
            max_values: vec![100.0, 5.0],
        };

        // Below min
        let err = bounds.validate(&[-1.0, 2.5]).unwrap_err();
        assert!(matches!(err, ScorerError::FeatureOutOfBounds { .. }));

        // Above max
        let err = bounds.validate(&[50.0, 10.0]).unwrap_err();
        assert!(matches!(err, ScorerError::FeatureOutOfBounds { .. }));
    }

    #[test]
    fn test_validate_extra_features_ignored() {
        let bounds = FeatureBounds {
            feature_names: vec!["length".to_string()],
            min_values: vec![0.0],
            max_values: vec![100.0],
        };

        // Extractor produces 3 features, but bounds only cover 1 → validate first only
        assert!(bounds.validate(&[50.0, 999.0, 999.0]).is_ok());
    }

    #[test]
    fn test_check_invariant_catches_mismatched_lengths() {
        // max_values shorter than min_values - would panic in validate()
        let bad_bounds = FeatureBounds {
            feature_names: vec!["length".to_string(), "entropy".to_string()],
            min_values: vec![0.0, 0.0],
            max_values: vec![100.0], // Missing second element!
        };

        assert!(
            bad_bounds.check_invariant().is_err(),
            "mismatched array lengths must be caught"
        );

        // feature_names longer than values
        let bad_bounds2 = FeatureBounds {
            feature_names: vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
            ],
            min_values: vec![0.0, 0.0],
            max_values: vec![1.0, 1.0],
        };

        assert!(
            bad_bounds2.check_invariant().is_err(),
            "mismatched feature_names length must be caught"
        );
    }
}
