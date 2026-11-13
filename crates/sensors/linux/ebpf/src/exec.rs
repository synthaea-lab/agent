//! `sched_process_exec`: the exec event, with the argv the probe reads at exec (#48).
//!
//! The raw tracepoint supplies `task_struct *` and `linux_binprm *`; userspace
//! provides their BTF-derived member offsets, and this helper keeps event creation
//! shared with the old formatted tracepoint implementation.

use aya_ebpf::{
    Global,
    helpers::{
        bpf_get_current_comm, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
        bpf_probe_read_user_buf,
    },
    macros::map,
    maps::{PerCpuArray, RingBuf},
};
use sensor_linux_wire::{
    ARGV_HEAD_BYTES, ARGV_TAIL_BYTES, ARGV_WINDOW_BYTES, ExecEvent, ExecRecord, TASK_COMM_LEN,
};

use crate::PROC_LINEAGE;

/// Ring buffer shared with userspace for `exec` events. `ExecEvent` is assembled in
/// the per-CPU `EXEC_SCRATCH` entry (not on the stack — `image` is `MAX_PATH_LEN`
/// bytes) and emitted with a single `output` copy — the standard libbpf/Tetragon
/// "heap map" pattern. Filling a reserved ring-buffer slot field by field instead
/// needs per-byte loops over MAX_PATH_LEN, which blow the verifier's 1M-instruction
/// budget on pre-6.6 kernels (5.15, 6.1).
///
/// 512 KiB since a record carries the argv bytes it read (<https://github.com/synthaea-lab/agent/issues/48>, ADR-0045): a record is the
/// fixed `ExecEvent` plus its command line, so this holds about as many as 256 KiB of fixed
/// records did.
#[map]
static EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

/// Per-CPU scratch for building one `ExecRecord` off the stack (see `EXEC_EVENTS`).
#[map]
static EXEC_SCRATCH: PerCpuArray<ExecRecord> = PerCpuArray::with_max_entries(1, 0);

// argv at exec (https://github.com/synthaea-lab/agent/issues/48). Userspace sets these from the kernel's BTF (`btf.rs`,
// `ExecArgvOffsets`) and `EXEC_ARGV_ENABLED` only when all three were found; left at zero
// the probe reads no argv and userspace falls back to `/proc/<pid>/cmdline`.
#[unsafe(no_mangle)]
static EXEC_ARGV_ENABLED: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
static TASK_MM_OFFSET: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
static MM_ARG_START_OFFSET: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
static MM_ARG_END_OFFSET: Global<u32> = Global::new(0);

/// Reads the current task's argument block into `rec.argv` (<https://github.com/synthaea-lab/agent/issues/48>, ADR-0045): all of it when it
/// fits in `ARGV_WINDOW_BYTES`, else the first `ARGV_HEAD_BYTES` and the last `ARGV_TAIL_BYTES`.
/// At `sched_process_exec` the new `mm` is installed and `execve` has just copied the strings
/// onto the new stack, so `arg_start..arg_end` is this exec's argv. A failed head read leaves
/// both lengths at zero (userspace falls back to `/proc`); a failed tail read keeps the head.
/// Returns the number of argv bytes written after the fixed event, at most `ARGV_WINDOW_BYTES`.
///
/// # Safety
/// `rec` points at the per-CPU scratch entry, whose `event` the caller zeroed.
unsafe fn read_exec_argv(rec: *mut ExecRecord) -> usize {
    if EXEC_ARGV_ENABLED.load() == 0 {
        return 0;
    }
    // SAFETY: helper calls on the current task; every kernel pointer read goes through
    // `bpf_probe_read_kernel` and every user read through `bpf_probe_read_user_buf`, both of
    // which fail instead of faulting. `rec` is the caller's valid scratch entry.
    unsafe {
        let task = aya_ebpf::helpers::bpf_get_current_task() as *const u8;
        let Ok(mm) =
            bpf_probe_read_kernel(task.add(TASK_MM_OFFSET.load() as usize).cast::<*const u8>())
        else {
            return 0;
        };
        if mm.is_null() {
            return 0;
        }
        let (Ok(start), Ok(end)) = (
            bpf_probe_read_kernel(mm.add(MM_ARG_START_OFFSET.load() as usize).cast::<u64>()),
            bpf_probe_read_kernel(mm.add(MM_ARG_END_OFFSET.load() as usize).cast::<u64>()),
        ) else {
            return 0;
        };
        if end <= start {
            return 0;
        }
        let total = end - start;
        let argv = &mut (*rec).argv;
        // Lengths are clamped before each helper call so the verifier sees an upper bound,
        // and each window is one helper call, not a byte loop (same as the DNS/TLS payloads).
        let head = if total > ARGV_WINDOW_BYTES as u64 {
            ARGV_HEAD_BYTES
        } else {
            total as usize
        };
        if head == 0
            || head > ARGV_WINDOW_BYTES
            || bpf_probe_read_user_buf(start as *const u8, &mut argv[..head]).is_err()
        {
            return 0;
        }
        (*rec).event.argv_total = if total > u64::from(u32::MAX) {
            u32::MAX
        } else {
            total as u32
        };
        (*rec).event.argv_head_len = head as u16;
        if total <= ARGV_WINDOW_BYTES as u64 {
            return head;
        }
        let tail_src = (end - ARGV_TAIL_BYTES as u64) as *const u8;
        if bpf_probe_read_user_buf(tail_src, &mut argv[ARGV_HEAD_BYTES..ARGV_WINDOW_BYTES]).is_err()
        {
            return head;
        }
        (*rec).event.argv_tail_len = ARGV_TAIL_BYTES as u16;
        ARGV_WINDOW_BYTES
    }
}

pub(crate) fn record_sched_process_exec(pid: u32, filename_ptr: *const u8) -> u32 {
    let tgid = pid;

    let Ok(comm) = bpf_get_current_comm() else {
        return 1;
    };
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();
    let timestamp_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    // Assemble the event in per-CPU scratch, not on the stack and not field by
    // field in a reserved ring-buffer slot (that needs per-byte loops over
    // MAX_PATH_LEN, which blow the verifier's 1M-instruction budget on pre-6.6
    // kernels). One `output` copy emits it. argv is read here at exec time through
    // BTF-derived offsets (https://github.com/synthaea-lab/agent/issues/48); without them userspace reads `/proc/<pid>/cmdline`.
    let Some(rec) = EXEC_SCRATCH.get_ptr_mut(0) else {
        return 1;
    };
    unsafe {
        // Only the fixed part is zeroed: argv bytes past the lengths read below are never
        // emitted, so stale scratch bytes cannot reach userspace.
        let e: *mut ExecEvent = &raw mut (*rec).event;
        core::ptr::write_bytes(e, 0, 1);

        (*e).meta.pid = tgid;
        (*e).meta.uid = uid_gid as u32;
        (*e).meta.gid = (uid_gid >> 32) as u32;
        (*e).meta.timestamp_ns = timestamp_ns;
        (*e).meta.ppid = 0;
        (*e).meta.cgroup_id = aya_ebpf::helpers::bpf_get_current_cgroup_id();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            (*e).meta.comm[i] = comm[i];
            i += 1;
        }
        // Parent identity from the fork-lineage map.
        if let Some(l) = PROC_LINEAGE.get(&tgid) {
            (*e).meta.ppid = l.ppid;
            (*e).meta.process_generation = l.generation;
            (*e).meta.parent_generation = l.parent_generation;
            let mut i = 0usize;
            while i < TASK_COMM_LEN {
                (*e).pcomm[i] = l.comm[i];
                i += 1;
            }
            // The parent's own parent and its stamp, and whether the parent has exec'd, for
            // a parent that forked and never exec'd (#784): one more lookup, the parent's
            // entry. Only when that entry is the incarnation this child was forked from: if
            // the parent exited and its pid was reused, the entry describes someone else
            // and its forker would be lent to the child. Left zero otherwise.
            if let Some(parent) = PROC_LINEAGE.get(&l.ppid) {
                if parent.generation == l.parent_generation {
                    (*e).grandparent_pid = parent.ppid;
                    (*e).grandparent_generation = parent.parent_generation;
                    (*e).parent_execd = parent.execd;
                }
            }
        }
        // This process has exec'd: its children can no longer be told it runs its forker's
        // image. After the reads above, so the event describes the state before this exec.
        if let Some(own) = PROC_LINEAGE.get_ptr_mut(&tgid) {
            (*own).execd = 1;
        }

        // Authoritative image path: the tracepoint's own `filename` field (the
        // kernel's resolved `bprm->filename`), never argv[0]. One bounded
        // `…_str_bytes` copy into the scratch entry.
        if let Ok(s) = bpf_probe_read_kernel_str_bytes(filename_ptr, &mut (*e).image) {
            (*e).image_len = s.len() as u16;
        }

        let argv_len = read_exec_argv(rec);
        // A variable-length record (ADR-0045): the fixed event and the argv bytes read, no
        // more. The bound is re-checked here so the verifier sees the emitted size is at most
        // the scratch entry.
        if argv_len > ARGV_WINDOW_BYTES {
            return 1;
        }
        // SAFETY: `ExecRecord` is `repr(C)` with `event` first and `argv` right after it, so
        // the first `size_of::<ExecEvent>() + argv_len` bytes (argv_len <= ARGV_WINDOW_BYTES,
        // checked above) lie inside the scratch entry, and every one of them was written.
        let bytes = core::slice::from_raw_parts(
            rec.cast::<u8>(),
            core::mem::size_of::<ExecEvent>() + argv_len,
        );
        if EXEC_EVENTS.output::<[u8]>(bytes, 0).is_err() {
            return 1;
        }
    }

    0
}
