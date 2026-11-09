// SPDX-License-Identifier: GPL-2.0-only OR MIT
#![no_std]
#![no_main]

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

/// Offset of `ret` in every `sys_exit_*` tracepoint (x86_64/aarch64): 8-byte common
/// header + `__syscall_nr`(4, +4 padding) + `ret`(8, signed). Verified on
/// 2026-09-22 on Alpine (kernel 6.18.50-0-virt, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_exit_accept{,4}/format` — identical for
/// both.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const SYS_EXIT_RET_OFFSET: usize = 16;
/// i686: `ret` is a packed 4-byte `long`, not independently verified (see
/// `sys_enter_open`'s i686 note for the same packed-layout reasoning).
#[cfg(bpf_target_arch = "x86")]
const SYS_EXIT_RET_OFFSET: usize = 12;

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
