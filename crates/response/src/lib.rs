//! # response
//!
//! Everything that ACTS on the endpoint, in two halves sharing one execution,
//! policy-gate, and audit substrate:
//!
//! - **Automated** (this module): verdict-driven actions — kill process, quarantine
//!   file, block network destination, isolate host. Every action is auditable,
//!   reversible where possible, and gated by policy.
//! - **Live response** ([`live`]): the analyst-driven counterpart — interactive,
//!   time-boxed sessions with a fixed command vocabulary (see the module docs).
//!
//! One crate on purpose: both halves execute privileged actions under the same
//! policy and audit rules; splitting them invited two enforcement paths.
//!
//! Issue #25 ships the first two automated actions: [`kill`] and [`quarantine`].
//! Host isolation and [`live`] (blocked on `transport`/server-side analyst auth)
//! are follow-up scope.

pub mod kill;
pub mod live;
pub mod quarantine;

pub use kill::{KillOutcome, kill_process};
pub use quarantine::{QuarantineOutcome, quarantine_file, unquarantine};
