//! Cross-process memory access and fileless code staging: `ptrace`,
//! `process_vm_readv`/`process_vm_writev`, and `memfd_create`. `raw.rs` routes the
//! syscalls to these handlers.

pub(crate) mod memfd;
pub(crate) mod process_vm;
pub(crate) mod ptrace;
