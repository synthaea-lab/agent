//! File chmod/chown (issue #262 Phase 2)

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::map,
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;
use sensor_linux_wire::{FileChmodEvent, FileChownEvent, TASK_COMM_LEN, is_filtered_path};

use crate::fill_lineage;

/// Ring buffer shared with userspace for `chmod`/`fchmodat` events.
#[map]
static FILE_CHMOD_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `FileChmodEvent` (see `EXEC_SCRATCH`).
#[map]
static CHMOD_SCRATCH: PerCpuArray<FileChmodEvent> = PerCpuArray::with_max_entries(1, 0);

/// Ring buffer shared with userspace for `chown`/`lchown`/`fchownat` events.
#[map]
static FILE_CHOWN_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `FileChownEvent` (see `EXEC_SCRATCH`).
#[map]
static CHOWN_SCRATCH: PerCpuArray<FileChownEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_chmod` tracepoint (x86_64/aarch64): `filename`(16),
/// `mode`(24). Verified on 2026-09-22 on Alpine (kernel 6.18.50-0-virt, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_chmod/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const CHMOD_FILENAME_PTR_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const CHMOD_MODE_OFFSET: usize = 24;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const CHMOD_FILENAME_PTR_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const CHMOD_MODE_OFFSET: usize = 16;

/// Offsets of the `syscalls:sys_enter_fchmodat` tracepoint (x86_64/aarch64): `dfd`(16),
/// `filename`(24), `mode`(32). Verified on 2026-09-22 on Alpine (kernel 6.18.50-0-virt,
/// x86_64) via `/sys/kernel/tracing/events/syscalls/sys_enter_fchmodat/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const FCHMODAT_FILENAME_PTR_OFFSET: usize = 24;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const FCHMODAT_MODE_OFFSET: usize = 32;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const FCHMODAT_FILENAME_PTR_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const FCHMODAT_MODE_OFFSET: usize = 20;

pub fn sys_enter_chmod(ctx: TracePointContext) -> u32 {
    match try_sys_enter_chmod(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_chmod(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let filename_ptr: u64 = unsafe { ctx.read_at(CHMOD_FILENAME_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let filename_ptr: u64 = unsafe {
        ctx.read_at::<u32>(CHMOD_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let mode: u64 = unsafe { ctx.read_at(CHMOD_MODE_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let mode: u64 = unsafe { ctx.read_at::<u32>(CHMOD_MODE_OFFSET).map_err(|_| 1u32)? as u64 };

    emit_file_chmod_event(&ctx, filename_ptr, mode)
}

pub fn sys_enter_fchmodat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_fchmodat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_fchmodat(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let filename_ptr: u64 = unsafe {
        ctx.read_at(FCHMODAT_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    #[cfg(bpf_target_arch = "x86")]
    let filename_ptr: u64 = unsafe {
        ctx.read_at::<u32>(FCHMODAT_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let mode: u64 = unsafe { ctx.read_at(FCHMODAT_MODE_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let mode: u64 = unsafe { ctx.read_at::<u32>(FCHMODAT_MODE_OFFSET).map_err(|_| 1u32)? as u64 };

    emit_file_chmod_event(&ctx, filename_ptr, mode)
}

/// Shared by `sys_enter_chmod` and `sys_enter_fchmodat` above.
fn emit_file_chmod_event(
    ctx: &TracePointContext,
    filename_ptr: u64,
    mode: u64,
) -> Result<u32, u32> {
    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = CHMOD_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);
        (*e).meta.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        fill_lineage(&mut (*e).meta);
        (*e).meta.uid = uid_gid as u32;
        (*e).meta.gid = (uid_gid >> 32) as u32;
        (*e).meta.timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        (*e).meta.cgroup_id = aya_ebpf::helpers::bpf_get_current_cgroup_id();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            (*e).meta.comm[i] = comm[i];
            i += 1;
        }

        if filename_ptr != 0 {
            if let Ok(path) =
                bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut (*e).path)
            {
                if is_filtered_path(path, 0, true) {
                    return Ok(0);
                }
                (*e).path_len = path.len() as u16;
            }
        }
        (*e).mode = mode as u32;

        if FILE_CHMOD_EVENTS.output::<FileChmodEvent>(&*e, 0).is_err() {
            warn!(
                ctx,
                "sensor-linux-ebpf: ring buffer full, dropping chmod event"
            );
        }
    }

    Ok(0)
}

/// Offsets of the `syscalls:sys_enter_chown` tracepoint (x86_64/aarch64): `filename`(16),
/// `user`(24), `group`(32). Verified on 2026-09-22 on Alpine (kernel 6.18.50-0-virt,
/// x86_64) via `/sys/kernel/tracing/events/syscalls/sys_enter_chown/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const CHOWN_FILENAME_PTR_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const CHOWN_USER_OFFSET: usize = 24;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const CHOWN_GROUP_OFFSET: usize = 32;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const CHOWN_FILENAME_PTR_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const CHOWN_USER_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const CHOWN_GROUP_OFFSET: usize = 20;

/// Offsets of the `syscalls:sys_enter_lchown` tracepoint (x86_64/aarch64): identical
/// shape to `sys_enter_chown` above — `filename`(16), `user`(24), `group`(32). Verified
/// on 2026-09-22 on Alpine (kernel 6.18.50-0-virt, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_lchown/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const LCHOWN_FILENAME_PTR_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const LCHOWN_USER_OFFSET: usize = 24;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const LCHOWN_GROUP_OFFSET: usize = 32;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const LCHOWN_FILENAME_PTR_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const LCHOWN_USER_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const LCHOWN_GROUP_OFFSET: usize = 20;

/// Offsets of the `syscalls:sys_enter_fchownat` tracepoint (x86_64/aarch64): `dfd`(16),
/// `filename`(24), `user`(32), `group`(40), `flag`(48). Verified on 2026-09-22 on Alpine
/// (kernel 6.18.50-0-virt, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_fchownat/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const FCHOWNAT_FILENAME_PTR_OFFSET: usize = 24;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const FCHOWNAT_USER_OFFSET: usize = 32;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const FCHOWNAT_GROUP_OFFSET: usize = 40;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const FCHOWNAT_FILENAME_PTR_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const FCHOWNAT_USER_OFFSET: usize = 20;
#[cfg(bpf_target_arch = "x86")]
const FCHOWNAT_GROUP_OFFSET: usize = 24;

pub fn sys_enter_chown(ctx: TracePointContext) -> u32 {
    match try_sys_enter_chown(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_chown(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let filename_ptr: u64 = unsafe { ctx.read_at(CHOWN_FILENAME_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let filename_ptr: u64 = unsafe {
        ctx.read_at::<u32>(CHOWN_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let user: u64 = unsafe { ctx.read_at(CHOWN_USER_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let user: u64 = unsafe { ctx.read_at::<u32>(CHOWN_USER_OFFSET).map_err(|_| 1u32)? as u64 };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let group: u64 = unsafe { ctx.read_at(CHOWN_GROUP_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let group: u64 = unsafe { ctx.read_at::<u32>(CHOWN_GROUP_OFFSET).map_err(|_| 1u32)? as u64 };

    emit_file_chown_event(&ctx, filename_ptr, user, group)
}

pub fn sys_enter_lchown(ctx: TracePointContext) -> u32 {
    match try_sys_enter_lchown(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_lchown(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let filename_ptr: u64 = unsafe { ctx.read_at(LCHOWN_FILENAME_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let filename_ptr: u64 = unsafe {
        ctx.read_at::<u32>(LCHOWN_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let user: u64 = unsafe { ctx.read_at(LCHOWN_USER_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let user: u64 = unsafe { ctx.read_at::<u32>(LCHOWN_USER_OFFSET).map_err(|_| 1u32)? as u64 };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let group: u64 = unsafe { ctx.read_at(LCHOWN_GROUP_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let group: u64 = unsafe { ctx.read_at::<u32>(LCHOWN_GROUP_OFFSET).map_err(|_| 1u32)? as u64 };

    emit_file_chown_event(&ctx, filename_ptr, user, group)
}

pub fn sys_enter_fchownat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_fchownat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_fchownat(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let filename_ptr: u64 = unsafe {
        ctx.read_at(FCHOWNAT_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    #[cfg(bpf_target_arch = "x86")]
    let filename_ptr: u64 = unsafe {
        ctx.read_at::<u32>(FCHOWNAT_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let user: u64 = unsafe { ctx.read_at(FCHOWNAT_USER_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let user: u64 = unsafe { ctx.read_at::<u32>(FCHOWNAT_USER_OFFSET).map_err(|_| 1u32)? as u64 };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let group: u64 = unsafe { ctx.read_at(FCHOWNAT_GROUP_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let group: u64 = unsafe {
        ctx.read_at::<u32>(FCHOWNAT_GROUP_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    emit_file_chown_event(&ctx, filename_ptr, user, group)
}

/// Shared by `sys_enter_chown`, `sys_enter_lchown`, and `sys_enter_fchownat` above.
fn emit_file_chown_event(
    ctx: &TracePointContext,
    filename_ptr: u64,
    user: u64,
    group: u64,
) -> Result<u32, u32> {
    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = CHOWN_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);
        (*e).meta.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        fill_lineage(&mut (*e).meta);
        (*e).meta.uid = uid_gid as u32;
        (*e).meta.gid = (uid_gid >> 32) as u32;
        (*e).meta.timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        (*e).meta.cgroup_id = aya_ebpf::helpers::bpf_get_current_cgroup_id();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            (*e).meta.comm[i] = comm[i];
            i += 1;
        }

        if filename_ptr != 0 {
            if let Ok(path) =
                bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut (*e).path)
            {
                if is_filtered_path(path, 0, true) {
                    return Ok(0);
                }
                (*e).path_len = path.len() as u16;
            }
        }
        (*e).uid = user as u32;
        (*e).gid = group as u32;

        if FILE_CHOWN_EVENTS.output::<FileChownEvent>(&*e, 0).is_err() {
            warn!(
                ctx,
                "sensor-linux-ebpf: ring buffer full, dropping chown event"
            );
        }
    }

    Ok(0)
}
