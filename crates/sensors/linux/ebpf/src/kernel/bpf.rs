//! eBPF program/map lifecycle (issue #264)

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::map,
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;
use sensor_linux_wire::BpfEvent;

use crate::{fill_event_meta, into_ret};

/// Ring buffer shared with userspace for filtered `bpf(2)` events.
#[map]
static BPF_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `BpfEvent` (see `EXEC_SCRATCH`).
#[map]
static BPF_SCRATCH: PerCpuArray<BpfEvent> = PerCpuArray::with_max_entries(1, 0);

/// `enum bpf_cmd` values (`<linux/bpf.h>`) this probe cares about. Every other
/// command — `BPF_MAP_LOOKUP_ELEM`/`BPF_MAP_UPDATE_ELEM`/etc., the overwhelming
/// majority of real `bpf(2)` traffic, including this agent's own sensor's
/// map reads/writes at runtime — is filtered in-kernel before touching the ring
/// buffer (see this crate's `WIRE_VERSION` v12 changelog).
const BPF_CMD_MAP_CREATE: u32 = 0;
const BPF_CMD_PROG_LOAD: u32 = 5;
const BPF_CMD_PROG_ATTACH: u32 = 8;

/// Offsets of the `syscalls:sys_enter_bpf` tracepoint (`cmd`, `uattr`, `size`),
/// assumed standard layout — see `INIT_MODULE_LEN_OFFSET`'s note in `module.rs`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const BPF_CMD_OFFSET: usize = 16;
/// i686: inferred, not independently verified.
#[cfg(bpf_target_arch = "x86")]
const BPF_CMD_OFFSET: usize = 12;

pub fn sys_enter_bpf(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_bpf(ctx))
}

fn try_sys_enter_bpf(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let cmd: u64 = unsafe { ctx.read_at(BPF_CMD_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let cmd: u64 = unsafe { ctx.read_at::<u32>(BPF_CMD_OFFSET).map_err(|_| 1u32)? as u64 };
    let cmd = cmd as u32;

    if cmd != BPF_CMD_MAP_CREATE && cmd != BPF_CMD_PROG_LOAD && cmd != BPF_CMD_PROG_ATTACH {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = BPF_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        fill_event_meta(
            &mut (*e).meta,
            (bpf_get_current_pid_tgid() >> 32) as u32,
            uid_gid,
            &comm,
        );
        (*e).cmd = cmd;

        if BPF_EVENTS.output::<BpfEvent>(&*e, 0).is_err() {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping bpf event"
            );
        }
    }

    Ok(0)
}
