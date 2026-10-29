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
//! [`isolation`] holds the platform-neutral half of host isolation (ADR-0037); the
//! firewall itself is injected by the binary. [`live`] (blocked on
//! `transport`/server-side analyst auth) is follow-up scope.

pub mod escalate;
pub mod isolation;
pub mod kill;
pub mod live;
pub mod quarantine;

pub use escalate::{ESCALATION_THRESHOLD, should_escalate};
pub use kill::{KillOutcome, kill_process};
pub use quarantine::{
    QuarantineOutcome, QuarantinedFile, is_still_quarantined, list_quarantined, quarantine_file,
    unquarantine,
};
