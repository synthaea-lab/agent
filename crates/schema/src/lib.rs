//! # schema
//!
//! The platform boundary of the agent. Defines:
//!
//! - The internal event model (process, file, network, registry, ...) shared by every
//!   sensor, the rule engine, the correlator, and the ML feature extractors.
//! - The `Sensor` / `EventSink` contract that every platform sensor implements.
//! - Schema versioning rules for exporters.
//!
//! This crate must stay platform-agnostic and dependency-light: everything else in the
//! workspace depends on it. To be migrated from `old/crates/synthaea-schema`.
