//! Capability-model tampering via prctl (issue #457, from #266)

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::map,
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;
use sensor_linux_wire::{PrctlEvent, TASK_COMM_LEN};

use crate::fill_lineage;

/// Ring buffer shared with userspace for filtered `prctl(2)` events.
#[map]
static PRCTL_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `PrctlEvent` (see `EXEC_SCRATCH`).
#[map]
static PRCTL_SCRATCH: PerCpuArray<PrctlEvent> = PerCpuArray::with_max_entries(1, 0);

/// `prctl(2)` options (`<linux/prctl.h>`) this probe cares about. `prctl` has
/// dozens of options and some run constantly (`PR_SET_NAME` on every thread
/// rename), so every other option returns before touching a ring buffer — the
/// same in-kernel filter as `sys_enter_bpf`'s `cmd` (see this crate's WIRE_VERSION
/// v19 changelog).
const PR_CAPBSET_DROP: u64 = 24;
const PR_SET_SECUREBITS: u64 = 28;

/// Offsets of the `syscalls:sys_enter_prctl` tracepoint (`option`, `arg2`),
/// assumed standard layout — see `INIT_MODULE_LEN_OFFSET`'s note in `kernel/module.rs`; verify
/// against `/sys/kernel/tracing/events/syscalls/sys_enter_prctl/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const PRCTL_OPTION_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const PRCTL_ARG2_OFFSET: usize = 24;
/// i686: inferred, not independently verified.
#[cfg(bpf_target_arch = "x86")]
const PRCTL_OPTION_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const PRCTL_ARG2_OFFSET: usize = 16;

pub fn sys_enter_prctl(ctx: TracePointContext) -> u32 {
    match try_sys_enter_prctl(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_prctl(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let option: u64 = unsafe { ctx.read_at(PRCTL_OPTION_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let option: u64 = unsafe { ctx.read_at::<u32>(PRCTL_OPTION_OFFSET).map_err(|_| 1u32)? as u64 };

    // `option` is an `int`: on 64-bit the register's upper half is unspecified,
    // so compare the low 32 bits only.
    let option = option as u32 as u64;
    if option != PR_CAPBSET_DROP && option != PR_SET_SECUREBITS {
        return Ok(0);
    }

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let arg: u64 = unsafe { ctx.read_at(PRCTL_ARG2_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let arg: u64 = unsafe { ctx.read_at::<u32>(PRCTL_ARG2_OFFSET).map_err(|_| 1u32)? as u64 };

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = PRCTL_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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
        (*e).option = option as u32;
        (*e).arg = arg;

        if PRCTL_EVENTS.output::<PrctlEvent>(&*e, 0).is_err() {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping prctl event"
            );
        }
    }

    Ok(0)
}
