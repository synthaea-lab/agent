//! # policy
//!
//! The policy model: which rules and models are active, which response actions are
//! permitted, thresholds, per-host overrides. Policies are versioned and signed;
//! distributed by the control plane, enforced by the agent — this crate holds the
//! shared types and evaluation logic so both sides agree by construction.
