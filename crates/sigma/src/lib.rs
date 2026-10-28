//! # sigma
//!
//! Minimal Sigma evaluation engine (<https://sigmahq.io>), migrated from
//! `old/crates/synthaea-sigma`. Supported subset:
//! - `Image`, `CommandLine`, and `ParentImage` fields mapped onto [`schema::ExecEvent`]
//!   (`ParentImage` uses the lineage field sensors fill when they can — a rule using it
//!   simply never matches events without lineage)
//! - Simple `selection` conditions (implicit AND between fields, OR between values by default;
//!   `|all` requires every listed value to match), a selection written as a list of maps (OR
//!   between the maps, issue #982), keyword lists
//! - `contains`/`startswith`/`endswith` modifiers, optionally followed by `|all`, and `*`
//!   wildcards at start/end; case-only duplicate field specs are refused
//! - conditions over any number of named blocks: `and`, `or`, `not` (that precedence),
//!   parentheses, `1 of` / `all of` a block, a `prefix*` pattern or `them` — see [`condition`]
//!   for the grammar and its bounds
//!
//! Anything outside the subset is rejected **loudly at load time** — a rule with an
//! unsupported condition, field, or modifier fails to load with a precise error
//! instead of silently never matching (the old engine's behavior, fixed per issue #11).

mod condition;
pub mod engine;
mod eval;
pub mod rule;
mod validate;

#[cfg(test)]
mod condition_tests;
#[cfg(test)]
mod tests;

pub use engine::{Platform, SigmaEngine, SigmaError};
pub use rule::SigmaAlert;
