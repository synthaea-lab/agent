//! # config
//!
//! Local, per-install agent configuration: file locations, server endpoints, resource
//! budgets, logging. Loaded and validated once at startup, shared by the binaries.
//! Distinct from `policy`, which is versioned, signed, and distributed by the control
//! plane at runtime.
