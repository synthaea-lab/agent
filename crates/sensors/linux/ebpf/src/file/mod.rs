//! File activity: opens, writes, deletes, renames, mode and owner changes, and extended
//! attributes. `raw.rs` routes the syscalls to these handlers.

pub(crate) mod chmod_chown;
pub(crate) mod open;
pub(crate) mod write_delete_rename;
pub(crate) mod xattr;
