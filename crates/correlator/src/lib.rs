//! # correlator
//!
//! Correlates individual detections into cases: temporal windows, entity linking
//! (process trees, hosts, users), Bayesian log-likelihood-ratio scoring, and behavior
//! aggregation. The unit of output is a case, not an alert.
//!
//! To be migrated from `old/crates/synthaea-correlator` (bayes, behavior, engine, bus).
