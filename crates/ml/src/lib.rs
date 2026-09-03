//! # ml
//!
//! On-device ML scoring. Extracts feature vectors from events and correlation state, and
//! evaluates models trained by the `ml/` Python pipeline for anomaly and behavior
//! scoring. Inference is a native evaluator over flat model artifacts loaded from the
//! update channel — no ONNX runtime, no embedded models (ADR-0002). Must be bounded in
//! CPU and memory — inference happens on the endpoint.
//!
//! To be migrated from `old/crates/synthaea-ml`.
