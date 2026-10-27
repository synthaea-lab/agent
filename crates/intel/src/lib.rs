//! # intel
//!
//! On-device IOC (Indicator of Compromise) matching. Indicator sets — file hashes,
//! IP addresses, domains — ship as signed content via canary rings (like rules and
//! models) and are matched against the event stream: hashes against `enrich` output
//! on exec/write, IPs against connect events, domains against DNS telemetry as
//! sensors gain it. Matches are detections (`DetectionSource` gains an `Ioc` variant)
//! and feed the correlator like any other source.
//!
//! IOA (Indicators of Attack — behavioral patterns) are deliberately NOT a separate
//! engine: they are what `rules`, `sigma`, and the correlator already express; the
//! server-side feed pipeline converts IOA feeds into rule/sigma content. This crate
//! stays about fast set-membership on atomic indicators: memory-bounded (bloom or
//! binary-fuse filters over large hash sets with an exact confirmation tier),
//! updatable without agent restart.
//!
//! ## What is here (issue #60, first slice)
//!
//! The matching engine only, with no dependency outside the standard library and
//! `thiserror`: [`SetBuilder`] collects SHA-256 hashes and IP addresses with their feed,
//! [`IndicatorSet`] answers lookups (a Bloom pre-filter in front of an exact sorted tier, so the
//! filter can only save work and never decide), and [`Intel`] swaps a new set in without
//! stopping readers. The memory budget is enforced when a set is built. Not here yet:
//! domains, the `DetectionSource::Ioc` schema variant, wiring into the agent, signed delivery
//! of sets, and the server-side feed pipeline. See ADR-0038.

mod engine;
mod filter;
mod set;

pub use engine::Intel;
pub use set::{
    BuildError, DEFAULT_MEMORY_BUDGET_BYTES, FeedId, IndicatorKind, IndicatorSet, LoadReport,
    Match, ParseError, SetBuilder, SetStats, estimated_bytes, parse_sha256,
};
