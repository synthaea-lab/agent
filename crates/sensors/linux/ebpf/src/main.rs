// SPDX-License-Identifier: GPL-2.0-only OR MIT
//! The Linux kernel probes: eBPF programs, their maps and the helpers they share. Each domain
//! module (`exec`, `file`, `net`, `cred`, ...) owns its programs; this root holds what every
//! domain uses.
//!
//! # Safety
//!
//! Nearly every `unsafe` block here is one of four patterns, so they are documented once here
//! instead of on each block (AS-029). A block that does anything else carries its own
//! `// SAFETY:` comment.
//!
//! - **Tracepoint arguments.** `ctx.read_at::<T>(OFFSET)` reads the raw tracepoint record at
//!   an offset taken from the tracepoint's `format` file, written next to each `*_OFFSET`
//!   constant. `read_at` goes through `bpf_probe_read_kernel`, so a wrong offset gives an
//!   error or a wrong value, never a fault.
//! - **Probe reads.** `bpf_probe_read_user`, `bpf_probe_read_kernel` and their `_str`/`_buf`
//!   forms copy from an address the kernel may not map. The helper handles the fault and
//!   returns an error, which every call site turns into an early return.
//! - **Per-CPU scratch.** `SCRATCH.get_ptr_mut(0)` gives this CPU's only slot of a
//!   `PerCpuArray`. A program does not nest on its own CPU, so nothing else writes it between
//!   the `write_bytes` that zeroes it and the `output` that copies it out. The field writes
//!   through `(*e)` stay inside that one value.
//! - **Map lookups.** `map.get(&key)` returns a reference into the map, which is copied or
//!   read before the program returns, and never kept.
#![no_std]
#![no_main]
#![allow(
    clippy::undocumented_unsafe_blocks,
    reason = "the recurring unsafe patterns are documented once in the crate-level Safety section (AS-029)"
)]

mod arch;
mod cred;
mod exec;
mod file;
mod kernel;
mod lsm;
mod mount_signal;
mod net;
mod procmem;
mod raw;
mod uprobe;

pub(crate) use arch::SYS_EXIT_RET_OFFSET;
use aya_ebpf::{helpers::bpf_get_current_pid_tgid, macros::map, maps::HashMap};
use sensor_linux_wire::{LineageEntry, TASK_COMM_LEN};

// Raw scheduler tracepoints expose task pointers instead of formatted event records.
// Their field offsets come from the running kernel's BTF in `userspace/src/btf.rs`;
// syscall arguments are decoded from `pt_regs` and passed to the existing handlers.

/// pid → parent identity (`real_parent->tgid` + its `comm`). Filled by
/// `sched_process_fork` and by userspace `/proc` priming at startup; entries removed
/// by `sched_process_exit`. Sized to the realistic live-pid space — a full map (fork
/// bomb) simply yields `ppid = 0`, which the correlation rules tolerate.
#[map]
pub(crate) static PROC_LINEAGE: HashMap<u32, LineageEntry> = HashMap::with_max_entries(65_536, 0);

/// Fills `meta.ppid` and `meta.process_generation` for the current thread group from
/// `PROC_LINEAGE`. Both stay `0` when the process forked before the probe attached
/// and `/proc` priming missed it — callers treat `ppid == 0` as "unknown", never as
/// pid 0, and `process_generation == 0` as "no stamp", never as a real generation
/// (issue #519). One lookup for both, since every probe wants both.
fn fill_lineage(meta: &mut sensor_linux_wire::EventMeta) {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if let Some(entry) = unsafe { PROC_LINEAGE.get(&tgid) } {
        meta.ppid = entry.ppid;
        meta.process_generation = entry.generation;
        meta.parent_generation = entry.parent_generation;
    }
}

/// Fills the `EventMeta` every event carries, in the order each probe used to write it by
/// hand (AS-008): `pid`, the lineage from `PROC_LINEAGE`, `uid`/`gid` from a
/// `bpf_get_current_uid_gid()` value, the timestamp, the cgroup and `comm`. `comm` is copied
/// with the same byte loop as before, so the generated code does not change shape.
#[inline(always)]
pub(crate) fn fill_event_meta(
    meta: &mut sensor_linux_wire::EventMeta,
    pid: u32,
    uid_gid: u64,
    comm: &[u8; TASK_COMM_LEN],
) {
    meta.pid = pid;
    fill_lineage(meta);
    meta.uid = uid_gid as u32;
    meta.gid = (uid_gid >> 32) as u32;
    // SAFETY: neither helper takes an argument; both only read the clock or the current task.
    meta.timestamp_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    // SAFETY: as above.
    meta.cgroup_id = unsafe { aya_ebpf::helpers::bpf_get_current_cgroup_id() };
    let mut i = 0usize;
    while i < TASK_COMM_LEN {
        meta.comm[i] = comm[i];
        i += 1;
    }
}

/// `sa_family_t` values (linux/socket.h) for the two tracked families. Any other family
/// (notably `AF_UNIX` = 1, very frequent — D-Bus, local sockets) is ignored: out of scope of
/// the threat model (outbound network connections only).
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// The `u32`/`i32` an eBPF program returns, from its `try_*` body: the success value and the
/// early-exit code are both just the return code, so the two arms collapse (AS-028).
#[inline(always)]
pub(crate) fn into_ret<T>(result: Result<T, T>) -> T {
    match result {
        Ok(ret) | Err(ret) => ret,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
