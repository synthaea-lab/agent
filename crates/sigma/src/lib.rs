//! # sigma
//!
//! Minimal Sigma evaluation engine (<https://sigmahq.io>), migrated from
//! `old/crates/synthaea-sigma`. Supported subset:
//! - `Image`, `CommandLine`, and `ParentImage` fields mapped onto [`schema::ExecEvent`]
//!   (`ParentImage` uses the lineage field sensors fill when they can — a rule using it
//!   simply never matches events without lineage)
//! - Simple `selection` conditions (implicit AND between fields, OR between values),
//!   keyword lists
//! - `contains`/`startswith`/`endswith` modifiers and `*` wildcards at start/end
//! - `condition: selection` only
//!
//! Anything outside the subset is rejected **loudly at load time** — a rule with an
//! unsupported condition, field, or modifier fails to load with a precise error
//! instead of silently never matching (the old engine's behavior, fixed per issue #11).

pub mod engine;
mod eval;
pub mod rule;
mod validate;

#[cfg(test)]
mod tests;

pub use engine::{SigmaEngine, SigmaError};
pub use rule::SigmaAlert;
