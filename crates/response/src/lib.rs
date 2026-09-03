//! # response
//!
//! Response layer (new in this iteration). Executes verdict-driven actions on the
//! endpoint: kill process, quarantine file, block network destination, isolate host.
//! Every action is auditable, reversible where possible, and gated by policy.
