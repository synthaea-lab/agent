//! Kernel extension: module load/unload and eBPF program/map lifecycle. `raw.rs` routes
//! the syscalls to these handlers.

pub(crate) mod bpf;
pub(crate) mod module;
