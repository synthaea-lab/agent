//! # ml
//!
//! On-device ML scoring. Extracts feature vectors from events and correlation state, and
//! runs ONNX models (trained by the `ml/` Python pipeline) for anomaly and behavior
//! scoring. Must be bounded in CPU and memory — inference happens on the endpoint.
//!
//! To be migrated from `old/crates/synthaea-ml`.
