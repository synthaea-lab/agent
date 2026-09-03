//! # store
//!
//! The agent's bounded local state. Two halves:
//!
//! - [`BoundedMap`] — an LRU-bounded map for detection-engine state (entity tables,
//!   belief states, windowed counters). The rule this crate exists to enforce: **no
//!   unbounded growth on a long-lived agent** — the old iteration's engines kept
//!   plain `HashMap`s with a documented "known limitation"; every such map now has a
//!   cap and an eviction order.
//! - [`EventSpool`] — a durable store-and-forward buffer for events/detections while
//!   the control plane is unreachable: append-only JSONL segments on disk, a total
//!   byte cap with oldest-segment eviction (loss is counted, never silent), and
//!   restart-safe drain semantics for `transport` to flush from.

mod bounded;
mod spool;

pub use bounded::BoundedMap;
pub use spool::{EventSpool, SpoolStats};
