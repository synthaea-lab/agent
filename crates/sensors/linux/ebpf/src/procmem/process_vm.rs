//! `process_vm_readv(2)` and `process_vm_writev(2)` calls (issue #265).

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::map,
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;
use sensor_linux_wire::{ProcessVmReadEvent, ProcessVmWriteEvent};

use crate::{
    arch::{SyscallRecord, ULONG_SIZE, arg_offset, read_user_ulong},
    fill_event_meta, into_ret,
};

/// Ring buffer shared with userspace for `process_vm_readv` events (issue #265).
#[map]
static PROCESS_VM_READ_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
/// Per-CPU scratch for building one `ProcessVmReadEvent` (see `EXEC_SCRATCH`).
#[map]
static PROCESS_VM_READ_SCRATCH: PerCpuArray<ProcessVmReadEvent> =
    PerCpuArray::with_max_entries(1, 0);

/// Ring buffer shared with userspace for `process_vm_writev` events (issue #265).
#[map]
static PROCESS_VM_WRITE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
/// Per-CPU scratch for building one `ProcessVmWriteEvent` (see `EXEC_SCRATCH`).
#[map]
static PROCESS_VM_WRITE_SCRATCH: PerCpuArray<ProcessVmWriteEvent> =
    PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_process_vm_readv`/`sys_enter_process_vm_writev`
/// tracepoints (`x86_64/aarch64`, identical shape on both): `pid`(16), `lvec`(24),
/// `liovcnt`(32), `rvec`(40), `riovcnt`(48). Verified on 2026-09-22 on Arch
/// (kernel 6.6.9-arch1-1, `x86_64`) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_process_vm_readv/format` (and
/// `..._writev/format`, identical layout).
///
/// i686: derived from the record layout like every other syscall here, not read from an i686
/// kernel. The first hand-written i686 values started at 16 and read every argument one slot
/// late (#218).
const PROCESS_VM_PID_OFFSET: usize = arg_offset(0);
const PROCESS_VM_LIOVCNT_OFFSET: usize = arg_offset(2);
const PROCESS_VM_REMOTE_IOV_OFFSET: usize = arg_offset(3);
const PROCESS_VM_RIOVCNT_OFFSET: usize = arg_offset(4);

/// Reads `iovec[0].iov_len` from a user-space `struct iovec *`. On `x86_64/aarch64`
/// `iov_base` (a pointer, unread here) occupies the first 8 bytes and `iov_len`
/// (`size_t`) the next 8. On i686 the whole struct is 4+4 — a 32-bit userspace
/// process's `struct iovec` has no 8-byte fields — so `iov_len` sits at offset 4,
/// not 8, and is itself 4 bytes wide; reading it the 64-bit way would pull half of
/// the next struct into the value. `0` if `iov_ptr` is null, `count` is `0`
/// (nothing to read), or the read fails — best-effort, matching every other
/// user-memory read in this file.
fn read_first_iovec_len(iov_ptr: u64, count: u64) -> u64 {
    if iov_ptr == 0 || count == 0 {
        return 0;
    }
    // `iov_len` follows `iov_base`, a pointer: one `unsigned long` into the struct.
    unsafe { read_user_ulong(iov_ptr + ULONG_SIZE) }.unwrap_or(0)
}

pub fn sys_enter_process_vm_readv(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_process_vm_readv(ctx))
}

fn try_sys_enter_process_vm_readv(ctx: TracePointContext) -> Result<u32, u32> {
    let target_pid: u64 = unsafe {
        ctx.read_ulong_arg(PROCESS_VM_PID_OFFSET)
            .map_err(|_| 1u32)?
    };
    let local_iov_count: u64 = unsafe {
        ctx.read_ulong_arg(PROCESS_VM_LIOVCNT_OFFSET)
            .map_err(|_| 1u32)?
    };
    let remote_iov_ptr: u64 = unsafe {
        ctx.read_ulong_arg(PROCESS_VM_REMOTE_IOV_OFFSET)
            .map_err(|_| 1u32)?
    };
    let remote_iov_count: u64 = unsafe {
        ctx.read_ulong_arg(PROCESS_VM_RIOVCNT_OFFSET)
            .map_err(|_| 1u32)?
    };
    let remote_iov_len = read_first_iovec_len(remote_iov_ptr, remote_iov_count);

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = PROCESS_VM_READ_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);
        fill_event_meta(
            &mut (*e).meta,
            (bpf_get_current_pid_tgid() >> 32) as u32,
            uid_gid,
            &comm,
        );
        (*e).target_pid = target_pid as u32;
        (*e).local_iov_count = local_iov_count;
        (*e).remote_iov_count = remote_iov_count;
        (*e).remote_iov_len = remote_iov_len;

        if PROCESS_VM_READ_EVENTS
            .output::<ProcessVmReadEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping process_vm_readv event"
            );
        }
    }

    Ok(0)
}

pub fn sys_enter_process_vm_writev(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_process_vm_writev(ctx))
}

fn try_sys_enter_process_vm_writev(ctx: TracePointContext) -> Result<u32, u32> {
    let target_pid: u64 = unsafe {
        ctx.read_ulong_arg(PROCESS_VM_PID_OFFSET)
            .map_err(|_| 1u32)?
    };
    let local_iov_count: u64 = unsafe {
        ctx.read_ulong_arg(PROCESS_VM_LIOVCNT_OFFSET)
            .map_err(|_| 1u32)?
    };
    let remote_iov_ptr: u64 = unsafe {
        ctx.read_ulong_arg(PROCESS_VM_REMOTE_IOV_OFFSET)
            .map_err(|_| 1u32)?
    };
    let remote_iov_count: u64 = unsafe {
        ctx.read_ulong_arg(PROCESS_VM_RIOVCNT_OFFSET)
            .map_err(|_| 1u32)?
    };
    let remote_iov_len = read_first_iovec_len(remote_iov_ptr, remote_iov_count);

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = PROCESS_VM_WRITE_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);
        fill_event_meta(
            &mut (*e).meta,
            (bpf_get_current_pid_tgid() >> 32) as u32,
            uid_gid,
            &comm,
        );
        (*e).target_pid = target_pid as u32;
        (*e).local_iov_count = local_iov_count;
        (*e).remote_iov_count = remote_iov_count;
        (*e).remote_iov_len = remote_iov_len;

        if PROCESS_VM_WRITE_EVENTS
            .output::<ProcessVmWriteEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping process_vm_writev event"
            );
        }
    }

    Ok(0)
}
