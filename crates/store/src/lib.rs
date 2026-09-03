//! # store
//!
//! The agent's bounded local state. Two halves:
//!
//! - Entity store: the process graph and related entities (bounded, LRU-evicted) that
//!   rules and the correlator query for context.
//! - Event spool: durable store-and-forward buffer for events and detections while the
//!   control plane is unreachable, with size caps and backpressure.
