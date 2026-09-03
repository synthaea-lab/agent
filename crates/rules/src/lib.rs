//! # rules
//!
//! The detection rule engine. Evaluates normalized events against stateless rules
//! (single-event matches) and stateful rules (sequences, thresholds, parent/child
//! process relations). Emits detections consumed by the correlator.
//!
//! To be migrated from `old/crates/synthaea-rules` (T1055, T1059, T1071, T1105, ...).
