//! # ml
//!
//! On-device ML scoring. Extracts feature vectors from events and correlation state, and
//! runs ONNX models (trained by the `ml/` Python pipeline) for anomaly and behavior
//! scoring via statically linked onnxruntime (`ort`). Models are loaded from the update
//! channel, never embedded (ADR-0002). Must be bounded in CPU and memory — inference
//! happens on the endpoint.
//!
//! - [`features`] — the feature extractors, each a Rust/Python parity seam pinned by a
//!   shared golden fixture;
//! - [`forest`] — tree structure parsed back out of the ONNX model, for per-feature
//!   attribution (the explanation side of "never a bare score", `docs/detection/ml.md`);
//! - [`scorer`] — [`CmdlineScorer`] (T0) and [`CorrelationScorer`] (T2), which run a
//!   model through `ort` and pair each score with its attribution.

mod proto;

pub mod features;
pub mod forest;
pub mod scorer;

pub use forest::{Attribution, Forest, ParseError, top_attributions};
pub use scorer::correlation::{CorrelationScorer, MIN_EVENT_COUNT, score_to_llr};
pub use scorer::{CmdlineScorer, Score, ScorerError};
