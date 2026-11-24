//! The one place the probes depend on the target's word size (AS-009).
//!
//! The syscall handlers do not read a kernel tracepoint record: `raw.rs` decodes the syscall
//! from `pt_regs` and writes a [`SysEnterRecord`] / [`SysExitRecord`] into per-CPU scratch, then
//! hands it to the handler as its `TracePointContext`. These records copy the layout of the
//! kernel's `syscalls:sys_enter_*` / `sys_exit_*` records (8-byte header, the syscall number,
//! then `unsigned long` arguments), so an argument offset is just a field offset of
//! [`SysEnterRecord`], and the only thing that changes between targets is the width of
//! `unsigned long`: 8 bytes on `x86_64`/`aarch64`, 4 on i686.
//!
//! Handlers name an argument by index ([`arg_offset`]) and read it through
//! [`SyscallRecord::read_ulong_arg`] / [`SyscallRecord::read_long_arg`], which widen an i686 value the same way on every
//! target, so no handler needs a `#[cfg]`.

use aya_ebpf::programs::TracePointContext;

/// The kernel's `unsigned long`: a syscall argument, a pointer, a `size_t`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
pub(crate) type CULong = u64;
/// The kernel's `long`: the syscall number and its return value.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
pub(crate) type CLong = i64;
/// i686: `unsigned long` is 4 bytes.
#[cfg(bpf_target_arch = "x86")]
pub(crate) type CULong = u32;
/// i686: `long` is 4 bytes.
#[cfg(bpf_target_arch = "x86")]
pub(crate) type CLong = i32;

/// The synthetic `sys_enter_*` record `raw.rs` builds for a syscall handler.
#[repr(C)]
pub(crate) struct SysEnterRecord {
    pub(crate) common_header: [u32; 2],
    pub(crate) id: CLong,
    pub(crate) args: [CULong; 6],
}

/// The synthetic `sys_exit_*` record `raw.rs` builds for an exit handler.
#[repr(C)]
pub(crate) struct SysExitRecord {
    pub(crate) common_header: [u32; 2],
    pub(crate) id: CLong,
    pub(crate) ret: CLong,
}

/// Offset of syscall argument `index` (0-based) in a [`SysEnterRecord`]: 16 + 8 * index on
/// `x86_64`/`aarch64`, 12 + 4 * index on i686.
pub(crate) const fn arg_offset(index: usize) -> usize {
    core::mem::offset_of!(SysEnterRecord, args) + index * core::mem::size_of::<CULong>()
}

/// Offset of the return value in a [`SysExitRecord`]: 16 on `x86_64`/`aarch64`, 12 on i686.
pub(crate) const SYS_EXIT_RET_OFFSET: usize = core::mem::offset_of!(SysExitRecord, ret);

// The kernel's own `syscalls:*` records put the first argument (and `ret`) at 16 on 64-bit and at
// 12 on i686: `sys_enter_openat`'s format was read on both (see `file/open.rs`). The synthetic
// records must keep that layout, or every handler reads the wrong field.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const _: () = assert!(arg_offset(0) == 16 && arg_offset(1) == 24 && SYS_EXIT_RET_OFFSET == 16);
#[cfg(bpf_target_arch = "x86")]
const _: () = assert!(arg_offset(0) == 12 && arg_offset(1) == 16 && SYS_EXIT_RET_OFFSET == 12);

/// The six syscall arguments as the record stores them (narrowed to 4 bytes on i686).
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
#[inline(always)]
pub(crate) fn to_ulong_args(args: [u64; 6]) -> [CULong; 6] {
    args
}
/// The six syscall arguments as the record stores them (narrowed to 4 bytes on i686).
#[cfg(bpf_target_arch = "x86")]
#[inline(always)]
pub(crate) fn to_ulong_args(args: [u64; 6]) -> [CULong; 6] {
    args.map(|arg| arg as u32)
}

/// A syscall number or return value as the record stores it (narrowed to 4 bytes on i686).
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
#[inline(always)]
pub(crate) fn to_clong(value: i64) -> CLong {
    value
}
/// A syscall number or return value as the record stores it (narrowed to 4 bytes on i686).
#[cfg(bpf_target_arch = "x86")]
#[inline(always)]
pub(crate) fn to_clong(value: i64) -> CLong {
    value as i32
}

/// Reads an `unsigned long` (a `pt_regs` slot) from kernel memory, zero-extended.
///
/// # Safety
/// As `bpf_probe_read_kernel`: the helper handles a bad address and returns an error.
#[inline(always)]
#[allow(
    clippy::useless_conversion,
    reason = "the identity on 64-bit targets, a widening on i686"
)]
pub(crate) unsafe fn read_kernel_ulong(addr: *const u8) -> Option<u64> {
    unsafe { aya_ebpf::helpers::bpf_probe_read_kernel(addr.cast::<CULong>()) }
        .ok()
        .map(u64::from)
}

/// Size of an `unsigned long` (a pointer, a `size_t`) in user memory: 8, or 4 on i686.
pub(crate) const ULONG_SIZE: u64 = core::mem::size_of::<CULong>() as u64;

/// Reads an `unsigned long` (a `size_t`, a pointer) from user memory at `addr`, zero-extended.
///
/// # Safety
/// As `bpf_probe_read_user`: the helper handles a bad address and returns an error.
#[inline(always)]
#[allow(
    clippy::useless_conversion,
    reason = "the identity on 64-bit targets, a widening on i686"
)]
pub(crate) unsafe fn read_user_ulong(addr: u64) -> Result<u64, i32> {
    unsafe { aya_ebpf::helpers::bpf_probe_read_user(addr as *const CULong) }.map(u64::from)
}

/// Reads a [`SysEnterRecord`] / [`SysExitRecord`] field by offset, widened the same way on every
/// target, so a handler needs no `#[cfg]` around its argument reads.
pub(crate) trait SyscallRecord {
    /// Reads an unsigned argument (or any `unsigned long` field) at `offset`, zero-extended.
    ///
    /// # Safety
    /// `self` wraps a [`SysEnterRecord`] or [`SysExitRecord`] and `offset` is one of its
    /// `CULong` fields; see the crate-level Safety section for `read_at`.
    unsafe fn read_ulong_arg(&self, offset: usize) -> Result<u64, i32>;

    /// Reads a signed argument (or the return value) at `offset`, sign-extended.
    ///
    /// # Safety
    /// As [`SyscallRecord::read_ulong_arg`], for a `CLong` field.
    unsafe fn read_long_arg(&self, offset: usize) -> Result<i64, i32>;
}

impl SyscallRecord for TracePointContext {
    #[inline(always)]
    #[allow(
        clippy::useless_conversion,
        reason = "the identity on 64-bit targets, a widening on i686"
    )]
    unsafe fn read_ulong_arg(&self, offset: usize) -> Result<u64, i32> {
        unsafe { self.read_at::<CULong>(offset) }.map(u64::from)
    }

    #[inline(always)]
    #[allow(
        clippy::useless_conversion,
        reason = "the identity on 64-bit targets, a widening on i686"
    )]
    unsafe fn read_long_arg(&self, offset: usize) -> Result<i64, i32> {
        unsafe { self.read_at::<CLong>(offset) }.map(i64::from)
    }
}
