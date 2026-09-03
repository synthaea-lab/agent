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

pub mod live;
