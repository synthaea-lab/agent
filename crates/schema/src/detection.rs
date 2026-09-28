//! Detection output: what the engines (rules, Sigma, ML tiers, correlator, YARA)
//! emit when something crosses a threshold.
//!
//! Lives in `schema` because detections traverse the same serialization boundary as
//! events — sinks write them, transport ships them to the server, the case store
//! keeps them — so they need the same versioning and golden-fixture discipline.
//!
//! Design commitment carried by this type (see "Explanations at detection time" in
//! `docs/detection/ml.md`): an ML detection is never a bare score. It carries the
//! per-feature attributions computed on-device at inference time, so the analyst
//! sees *why*, and so the control plane can compose attributions with correlator
//! evidence into a structured case record.

use serde::{Deserialize, Serialize};

use crate::Event;

/// Analyst-facing severity. Ordered: `Low < Medium < High < Critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Which engine produced a detection, with enough identity to reproduce the verdict.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "engine", rename_all = "snake_case")]
pub enum DetectionSource {
    /// Native rule engine (stateless or stateful).
    Rule { rule_id: String },
    /// Compiled Sigma rule.
    Sigma { rule_id: String },
    /// An on-device ML tier (T0–T2). `model_id`/`model_version` name the registry
    /// entry (`ml/registry/`) so any score is traceable to a model card — rule 2 of
    /// `ml/README.md` depends on this being here.
    Ml {
        tier: u8,
        model_id: String,
        model_version: String,
    },
    /// Correlator case scoring (Bayesian belief over accumulated evidence).
    Correlator { case_id: String },
    /// YARA-X scan hit.
    Yara { rule_name: String },
}

/// One feature's contribution to an ML score — path attribution for tree ensembles,
/// computed on-device at inference time (nearly free for trees).
///
/// `feature` uses the exact name from the Rust/Python parity fixtures, so an
/// attribution is joinable to the feature definition on both sides of the seam.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoreAttribution {
    /// Feature name as defined in the parity fixtures (identical string in
    /// `crates/ml` and `ml/synthaea_ml/features/`).
    pub feature: String,
    /// The extracted value the model saw.
    pub value: f64,
    /// Signed contribution to the score (positive pushes toward anomalous).
    pub contribution: f64,
}

/// A detection: one engine's judgment about observed activity.
///
/// No `Eq`: attributions carry floats. Not an [`Event`] variant — events are what
/// sensors observe, detections are what engines conclude; sinks and transport handle
/// the two as distinct streams.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Detection {
    /// Nanoseconds since the UNIX epoch, engine clock (when the judgment was made,
    /// not when the triggering activity happened — that lives on the events).
    pub timestamp_ns: u64,
    pub severity: Severity,
    /// Analyst-facing one-line title (e.g. the rule title, or the ML scorer's name).
    pub title: String,
    pub source: DetectionSource,
    /// Calibrated score where the engine has one (ML tiers, correlator belief);
    /// `None` for binary hits (rules, Sigma, YARA). Calibration semantics — FP
    /// budgets, conformal thresholds — are the model card's contract, not encoded
    /// here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    /// Top contributing features for ML detections, ordered by `|contribution|`
    /// descending. Empty for engines without feature attribution. Bounded by the
    /// emitting engine (top-k), not by the schema.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attributions: Vec<ScoreAttribution>,
    /// ATT&CK technique identifiers (`T1234` or `T1234.001`), issue #74. Plural: a
    /// single alert can span more than one technique (e.g. a beacon detection
    /// tagged both C2 and exfiltration). Empty for engines that don't yet attribute
    /// a technique (ML tiers today — no model-to-technique mapping exists).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub techniques: Vec<String>,
    /// The triggering events, embedded by value — events carry no global id, so a
    /// detection is self-contained evidence. Engines bound how many they attach.
    pub events: Vec<Event>,
}
