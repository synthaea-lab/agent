//! # ml
//!
//! On-device ML scoring. Extracts feature vectors from events and correlation state, and
//! runs ONNX models (trained by the `ml/` Python pipeline) for anomaly and behavior
//! scoring via statically linked onnxruntime (`ort`). Models are loaded from the update
//! channel, never embedded (ADR-0002). Must be bounded in CPU and memory — inference
//! happens on the endpoint.
//!
//! What exists today is the explanation side of the "never a bare score" commitment
//! (`docs/detection/ml.md`): [`forest`] parses tree structure back out of the model
//! file and computes per-feature path attributions that ship on every ML detection.
//! Feature extraction and the `ort` scoring wrapper are migrated next
//! (`old/crates/synthaea-ml`).

mod proto;

pub mod forest;

pub use forest::{Attribution, Forest, ParseError, top_attributions};
