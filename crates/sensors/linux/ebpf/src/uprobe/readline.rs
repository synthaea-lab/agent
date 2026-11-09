//! Uprobes: Shell readline capture (issue #90)

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{map, uretprobe},
    maps::{PerCpuArray, RingBuf},
    programs::RetProbeContext,
};
use aya_log_ebpf::warn;
use sensor_linux_wire::{ReadlineInputEvent, TASK_COMM_LEN};

use crate::fill_lineage;

/// Ring buffer for readline input events.
#[map]
static READLINE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `ReadlineInputEvent` (512 bytes input budget).
#[map]
static READLINE_SCRATCH: PerCpuArray<ReadlineInputEvent> = PerCpuArray::with_max_entries(1, 0);

/// Uretprobe on readline return: capture interactive shell command.
/// Signature: `char *readline(const char *prompt)`
/// The return value is a malloc'd string (freed by caller), or NULL on EOF/error.
#[uretprobe]
pub fn readline_exit(ctx: RetProbeContext) -> u32 {
    match try_readline_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_readline_exit(ctx: RetProbeContext) -> Result<u32, u32> {
    let line_ptr: u64 = ctx.ret::<u64>(); // readline's return value
    if line_ptr == 0 {
        return Ok(0); // EOF or error
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = READLINE_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        (*e).meta.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        fill_lineage(&mut (*e).meta);
        (*e).meta.uid = uid_gid as u32;
        (*e).meta.gid = (uid_gid >> 32) as u32;
        (*e).meta.timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            (*e).meta.comm[i] = comm[i];
            i += 1;
        }

        // Detect shell type from comm (userspace will override if needed).
        (*e).shell_type = if comm.starts_with(b"bash") {
            0 // bash
        } else if comm.starts_with(b"zsh") {
            1 // zsh
        } else {
            0 // default to bash
        };

        // Capture the full command line (budget: MAX_READLINE_INPUT).
        if let Ok(input) = bpf_probe_read_user_str_bytes(line_ptr as *const u8, &mut (*e).input) {
            (*e).input_len = input.len() as u32;
        }

        if READLINE_EVENTS
            .output::<ReadlineInputEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping readline event"
            );
        }
    }

    Ok(0)
}
