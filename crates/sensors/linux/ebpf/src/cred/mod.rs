//! Credential and isolation changes: `prctl` capability-model tampering, uid/gid changes,
//! capability sets and namespace manipulation. `raw.rs` routes the syscalls to these handlers.

pub(crate) mod capset;
pub(crate) mod identity;
pub(crate) mod namespace;
pub(crate) mod prctl;
