//! Capability set change (issue #266)

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user},
    macros::map,
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;
use sensor_linux_wire::{CapSetEvent, TASK_COMM_LEN};

use crate::{fill_lineage, into_ret};

/// Ring buffer shared with userspace for `capset` events.
#[map]
static CAPSET_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `CapSetEvent` (see `EXEC_SCRATCH`).
#[map]
static CAPSET_SCRATCH: PerCpuArray<CapSetEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_capset` tracepoint (`hdrp`, `data`),
/// assumed standard layout — see `SINGLE_ID_OFFSET`'s note in `identity.rs`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const CAPSET_HDRP_PTR_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const CAPSET_DATA_PTR_OFFSET: usize = 24;
/// i686: inferred, not independently verified.
#[cfg(bpf_target_arch = "x86")]
const CAPSET_HDRP_PTR_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const CAPSET_DATA_PTR_OFFSET: usize = 16;

pub fn sys_enter_capset(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_capset(ctx))
}

/// `struct __user_cap_header_struct { __u32 version; int pid; }` — `version`
/// first, `pid` 4 bytes in.
const CAP_HEADER_PID_OFFSET: u64 = 4;
/// `_LINUX_CAPABILITY_VERSION_1`: 32-bit capabilities, `datap` points at a
/// single `__user_cap_data_struct`. Versions 2 and 3 (the ones libcap and the
/// kernel use today) pass an array of two, the second holding capabilities
/// 32-63.
const LINUX_CAPABILITY_VERSION_1: u32 = 0x1998_0330;
/// `struct __user_cap_data_struct { __u32 effective; __u32 permitted;
/// __u32 inheritable; }`: 12 bytes, so element `[1]` (the high word, #457)
/// starts at `CAP_DATA_STRIDE`.
const CAP_DATA_PERMITTED_OFFSET: u64 = 4;
const CAP_DATA_INHERITABLE_OFFSET: u64 = 8;
const CAP_DATA_STRIDE: u64 = 12;

/// Reads one `__user_cap_data_struct` at `ptr` as (effective, permitted,
/// inheritable); a field that can't be read counts as no capability.
#[inline(always)]
fn read_cap_data(ptr: u64) -> (u64, u64, u64) {
    let read = |offset: u64| {
        unsafe { bpf_probe_read_user((ptr + offset) as *const u32) }.map_or(0, u64::from)
    };
    (
        read(0),
        read(CAP_DATA_PERMITTED_OFFSET),
        read(CAP_DATA_INHERITABLE_OFFSET),
    )
}

fn try_sys_enter_capset(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let hdrp_ptr: u64 = unsafe { ctx.read_at(CAPSET_HDRP_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let hdrp_ptr: u64 = unsafe {
        ctx.read_at::<u32>(CAPSET_HDRP_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let data_ptr: u64 = unsafe { ctx.read_at(CAPSET_DATA_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let data_ptr: u64 = unsafe {
        ctx.read_at::<u32>(CAPSET_DATA_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    let target_pid: u32 = if hdrp_ptr != 0 {
        unsafe { bpf_probe_read_user((hdrp_ptr + CAP_HEADER_PID_OFFSET) as *const i32) }
            .map(|p: i32| p as u32)
            .unwrap_or(0)
    } else {
        0
    };
    // An unreadable header is treated as a modern one: reading `[1]` then
    // fails cleanly (high word 0) rather than dropping bits 32+.
    let version: u32 = if hdrp_ptr != 0 {
        unsafe { bpf_probe_read_user(hdrp_ptr as *const u32) }.unwrap_or(0)
    } else {
        0
    };

    let (effective, permitted, inheritable) = if data_ptr != 0 {
        let (eff_lo, perm_lo, inh_lo) = read_cap_data(data_ptr);
        let (eff_hi, perm_hi, inh_hi) = if version == LINUX_CAPABILITY_VERSION_1 {
            (0, 0, 0)
        } else {
            read_cap_data(data_ptr + CAP_DATA_STRIDE)
        };
        (
            eff_hi << 32 | eff_lo,
            perm_hi << 32 | perm_lo,
            inh_hi << 32 | inh_lo,
        )
    } else {
        (0, 0, 0)
    };

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = CAPSET_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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
        (*e).target_pid = target_pid;
        (*e).effective = effective;
        (*e).permitted = permitted;
        (*e).inheritable = inheritable;

        if CAPSET_EVENTS.output::<CapSetEvent>(&*e, 0).is_err() {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping capset event"
            );
        }
    }

    Ok(0)
}
