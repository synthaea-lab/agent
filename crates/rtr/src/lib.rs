//! # rtr
//!
//! Real Time Response — the analyst-driven counterpart of the automated `response`
//! crate: an interactive, auditable session on a live endpoint, established through
//! the control plane over `transport`. Command vocabulary is a fixed, policy-gated
//! set (list processes, read/fetch file, kill process, pull memory region, run
//! script from the signed script library) — never an arbitrary shell.
//!
//! Constraints designed in from the start: every command and its output lands in the
//! audit log verbatim; sessions require an authenticated analyst identity from the
//! server and are time-boxed; policy decides per-tenant which commands are enabled;
//! the agent side executes but never originates.
