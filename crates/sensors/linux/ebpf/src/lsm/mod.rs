//! BPF LSM hooks: `file_open` (hit counter) and `inode_setattr` (explicit timestamp
//! requests). The programs attach by hook name, so `raw.rs` does not route them.

pub(crate) mod file_open;
pub(crate) mod inode_setattr;
