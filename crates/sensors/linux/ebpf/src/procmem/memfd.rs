//! `memfd_create(2)`, paired entry and exit probes (issue #265).

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::map,
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;
use sensor_linux_wire::MemfdCreateEvent;

use crate::{
    arch::{SYS_EXIT_RET_OFFSET, SyscallRecord, arg_offset},
    fill_event_meta, into_ret,
};

/// Ring buffer shared with userspace for `memfd_create` events (issue #265).
#[map]
static MEMFD_CREATE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
/// Per-CPU scratch for building one `MemfdCreateEvent` (see `EXEC_SCRATCH`).
#[map]
static MEMFD_CREATE_SCRATCH: PerCpuArray<MemfdCreateEvent> = PerCpuArray::with_max_entries(1, 0);

/// The half-built `MemfdCreateEvent` between `sys_enter_memfd_create` and
/// `sys_exit_memfd_create`, keyed by `pid_tgid` (issue #510). The returned fd only
/// exists at exit, but `name`/`flags` are arguments read from user memory at enter,
/// so the enter probe builds the whole event and parks it here; the exit probe
/// fills `fd` and emits. Same enter/exit pairing as `ACCEPT_ARGS`, except the value
/// is the event itself (a few hundred bytes, inserted from map memory so it never
/// touches the 512-byte BPF stack). Not part of `sensor-linux-wire`'s ABI. A thread
/// that enters `memfd_create` and never returns leaks its entry — same accepted
/// risk as `ACCEPT_ARGS`, bounded by `max_entries`, not explicitly swept.
#[map]
static MEMFD_ARGS: HashMap<u64, MemfdCreateEvent> = HashMap::with_max_entries(1024, 0);

/// Offsets of the `syscalls:sys_enter_memfd_create` tracepoint (`x86_64`/`aarch64`):
/// `uname`(16), `flags`(24). Verified on 2026-09-22 on Arch (kernel
/// 6.6.9-arch1-1, `x86_64`) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_memfd_create/format`.
///
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
const MEMFD_CREATE_NAME_PTR_OFFSET: usize = arg_offset(0);
const MEMFD_CREATE_FLAGS_OFFSET: usize = arg_offset(1);

pub fn sys_enter_memfd_create(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_memfd_create(ctx))
}

fn try_sys_enter_memfd_create(ctx: TracePointContext) -> Result<u32, u32> {
    let name_ptr: u64 = unsafe {
        ctx.read_ulong_arg(MEMFD_CREATE_NAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    let flags: u64 = unsafe {
        ctx.read_ulong_arg(MEMFD_CREATE_FLAGS_OFFSET)
            .map_err(|_| 1u32)?
    };

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = MEMFD_CREATE_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);
        fill_event_meta(
            &mut (*e).meta,
            (bpf_get_current_pid_tgid() >> 32) as u32,
            uid_gid,
            &comm,
        );

        if name_ptr != 0
            && let Ok(name) = bpf_probe_read_user_str_bytes(name_ptr as *const u8, &mut (*e).name)
        {
            (*e).name_len = name.len() as u16;
        }
        (*e).flags = flags as u32;
        (*e).fd = -1;

        // Emitted at `sys_exit_memfd_create`, once the fd is known (#510).
        let pid_tgid = bpf_get_current_pid_tgid();
        let _ = MEMFD_ARGS.insert(&pid_tgid, &*e, 0);
    }

    Ok(0)
}

pub fn sys_exit_memfd_create(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_exit_memfd_create(ctx))
}

/// Completes the event `try_sys_enter_memfd_create` parked in `MEMFD_ARGS` with the
/// descriptor `memfd_create(2)` returned (issue #510). Emits nothing when the matching
/// enter wasn't tracked (`MEMFD_ARGS` was full) or the call failed (`ret < 0`), so the
/// `fd` a consumer sees is always the real descriptor.
fn try_sys_exit_memfd_create(ctx: TracePointContext) -> Result<u32, u32> {
    let ret: i64 = unsafe { ctx.read_long_arg(SYS_EXIT_RET_OFFSET).map_err(|_| 1u32)? };

    let pid_tgid = bpf_get_current_pid_tgid();
    let e = match MEMFD_ARGS.get_ptr_mut(&pid_tgid) {
        Some(e) => e,
        None => return Ok(0),
    };

    if ret >= 0 {
        unsafe {
            (*e).fd = ret as i32;
            if MEMFD_CREATE_EVENTS
                .output::<MemfdCreateEvent>(&*e, 0)
                .is_err()
            {
                warn!(
                    &ctx,
                    "sensor-linux-ebpf: ring buffer full, dropping memfd_create event"
                );
            }
        }
    }
    let _ = MEMFD_ARGS.remove(&pid_tgid);

    Ok(0)
}
