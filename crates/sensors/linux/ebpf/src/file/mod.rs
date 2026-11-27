//! File activity: opens, writes, deletes, renames, mode and owner changes, and extended
//! attributes. `raw.rs` routes the syscalls to these handlers.

pub(crate) mod chmod_chown;
pub(crate) mod open;
pub(crate) mod write_delete_rename;
pub(crate) mod xattr;

use aya_ebpf::{macros::map, maps::ProgramArray};
use sensor_linux_wire::{MAX_PATH_LEN, is_filtered_path};

/// The file events' filter-and-output programs, by [`sensor_linux_wire::file_filter`] slot
/// (#351). Filled by userspace after load; a handler whose slot is empty outputs unfiltered.
#[map]
pub(crate) static FILE_FILTER_PROGS: ProgramArray =
    ProgramArray::with_max_entries(sensor_linux_wire::file_filter::COUNT, 0);

/// Whether `is_filtered_path` drops the path a handler stored in its event, `len` bytes of `buf`
/// (#351). The length is masked, not compared: the 6.1 verifier lost a compared bound on the
/// spilled length in the slot program, and a mask holds. Lossless:
/// `bpf_probe_read_user_str_bytes` keeps a byte of the buffer for the NUL, so a handler never
/// stores more than `MAX_PATH_LEN - 1`. An empty path (none read) is never filtered, as before.
#[inline(always)]
pub(crate) fn stored_path_filtered(
    buf: &[u8; MAX_PATH_LEN],
    len: u16,
    flags: i64,
    is_mutation: bool,
) -> bool {
    const _: () = assert!(MAX_PATH_LEN.is_power_of_two());
    let len = usize::from(len) & (MAX_PATH_LEN - 1);
    // SAFETY: `len` is below `MAX_PATH_LEN`, the length of `buf`.
    let path = unsafe { core::slice::from_raw_parts(buf.as_ptr(), len) };
    len > 0 && is_filtered_path(path, flags, is_mutation)
}
