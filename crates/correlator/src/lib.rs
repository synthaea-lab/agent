//! # correlator
//!
//! Event correlation engine — multi-event behavioral detection. Migrated from
//! `old/crates/synthaea-correlator`.
//!
//! Unlike the stateless rules of `rules` (one event = one decision), this crate
//! correlates multiple events within a sliding time window to detect complete attack
//! scenarios (e.g. spawn + connection + file write by the same pid within N seconds).
//!
//! Principle: every incoming [`schema::Event`] is recorded in a bus ([`EventBus`]),
//! old events outside the window are evicted, then the co-occurrence rules are
//! evaluated over the current window and the Bayesian belief is updated.
//!
//! One module per responsibility:
//! - `event` — helpers over the shared [`schema::Event`] envelope (the old
//!   crate-local `TimedEvent` duplicate is gone);
//! - `bus` — the sliding window ([`EventBus`]);
//! - `rules` — the co-occurrence rules (one function per scenario);
//! - `behavior` — the per-pid behavioral vector ([`BehaviorVector`]);
//! - `bayes` — the naive Bayes filter ([`BeliefState`], calibrated LLRs);
//! - `engine` — the entry point ([`CorrelationEngine`]) that orchestrates it all.

mod bayes;
mod behavior;
mod bus;
mod engine;
mod event;
mod rules;

pub use bayes::BeliefState;
pub use behavior::BehaviorVector;
pub use bus::EventBus;
pub use engine::CorrelationEngine;
pub use rules::CorrelationAlert;

#[cfg(test)]
mod tests;
