// SPDX-License-Identifier: GPL-2.0-only OR MIT
//! Raw tracepoint entrypoints for kernels where perf-event tracepoints are
//! blocked by `perf_event_paranoid`. The syscall router reconstructs the
//! regular syscall tracepoint record expected by the existing event handlers.

use aya_ebpf::{
    Global,
    helpers::bpf_probe_read_kernel,
    macros::{map, raw_tracepoint},
    maps::{Array, LruHashMap, PerCpuArray},
    programs::{RawTracePointContext, TracePointContext},
};
use aya_log_ebpf::{info, warn};
#[cfg(bpf_target_arch = "aarch64")]
use sensor_linux_wire::syscall_nr_from_i32;
use sensor_linux_wire::{
    DISPATCH_CONNECT, DISPATCH_SENDTO, DISPATCH_WRITE, LineageEntry, SIGNAL_SENDER_UNRELIABLE,
    TASK_COMM_LEN, encode_pending_syscall_exit, matching_pending_syscall_exit,
};

use crate::{
    PROC_LINEAGE,
    arch::{SysEnterRecord, SysExitRecord, read_kernel_ulong, to_clong, to_ulong_args},
    cred::{
        capset::sys_enter_capset,
        identity::{
            sys_enter_setfsgid, sys_enter_setfsuid, sys_enter_setgid, sys_enter_setresgid,
            sys_enter_setresuid, sys_enter_setuid,
        },
        namespace::{sys_enter_setns, sys_enter_unshare},
        prctl::sys_enter_prctl,
    },
    file::{
        chmod_chown::{
            sys_enter_chmod, sys_enter_chown, sys_enter_fchmodat, sys_enter_fchownat,
            sys_enter_lchown,
        },
        open::{sys_enter_open, sys_enter_openat},
        write_delete_rename::{
            sys_enter_rename, sys_enter_renameat, sys_enter_renameat2, sys_enter_unlink,
            sys_enter_unlinkat, sys_enter_write,
        },
        xattr::{sys_enter_removexattr, sys_enter_setxattr},
    },
    into_ret,
    kernel::{
        bpf::sys_enter_bpf,
        module::{sys_enter_delete_module, sys_enter_finit_module, sys_enter_init_module},
    },
    mount_signal::{
        mount::{sys_enter_mount, sys_enter_umount},
        signal::{emit_tool_signal_event, sys_enter_kill, sys_enter_tgkill, watched_tool_sigcgt},
    },
    net::{
        accept::{sys_enter_accept, sys_enter_accept4, sys_exit_accept, sys_exit_accept4},
        bind::sys_enter_bind,
        connect::sys_enter_connect,
        dns::{dns_udp_connect, dns_udp_sendto, dns_udp_write},
        listen::sys_enter_listen,
        recvfrom::{sys_enter_recvfrom, sys_exit_recvfrom},
        socket::{sys_enter_socket, sys_exit_socket},
        udp_send::sys_enter_sendto,
    },
    procmem::{
        memfd::{sys_enter_memfd_create, sys_exit_memfd_create},
        process_vm::{sys_enter_process_vm_readv, sys_enter_process_vm_writev},
        ptrace::sys_enter_ptrace,
    },
};

const MAX_SYSCALL_ID: u32 = 1024;
const EXIT_ACCEPT: u32 = 1;
const EXIT_ACCEPT4: u32 = 2;
const EXIT_MEMFD_CREATE: u32 = 3;
const EXIT_RECVFROM: u32 = 4;
const EXIT_SOCKET: u32 = 5;

/// syscall id → handler id. Userspace fills this from libc's architecture ABI.
#[map]
static SYSCALL_DISPATCH: Array<u32> = Array::with_max_entries(MAX_SYSCALL_ID, 0);

/// Handler tag and syscall number of an in-flight call whose event needs its
/// return value. Five syscalls use this path: accept, accept4, `memfd_create`,
/// recvfrom and socket. An LRU bounds blocked entries; `sys_exit` checks the actual
/// syscall number before dispatch so stale tags cannot route unrelated exits.
#[map]
static PENDING_SYSCALL_EXIT: LruHashMap<u64, u64> = LruHashMap::with_max_entries(4096, 0);

/// Counts a `PENDING_SYSCALL_EXIT` insert that still failed — shed, not silently
/// lost (the LRU's own eviction keeps steady-state inserts succeeding; this is
/// the rarer case of failing even after eviction). Per-CPU, summed by
/// `bpftool map dump`; not wired into agent-side health yet.
#[map]
static PENDING_SYSCALL_EXIT_DROPPED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Counts pending entries removed because the exiting syscall number could not
/// be read or did not match the syscall recorded at entry.
#[map]
static PENDING_EXIT_MISMATCH_DROPPED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// [`PENDING_SYSCALL_EXIT`]'s insert, with the drop counted instead of discarded.
#[inline(always)]
fn stash_pending_syscall_exit(pid_tgid: u64, action: u32, syscall_nr: u32) {
    let packed = encode_pending_syscall_exit(action, syscall_nr);
    if PENDING_SYSCALL_EXIT.insert(&pid_tgid, &packed, 0).is_err()
        && let Some(count) = PENDING_SYSCALL_EXIT_DROPPED.get_ptr_mut(0)
    {
        // SAFETY: `count` is a valid per-CPU slot pointer from `get_ptr_mut`; no
        // concurrent access from another CPU (each CPU owns its own slot).
        unsafe {
            *count = (*count).wrapping_add(1);
        }
    }
}

#[unsafe(no_mangle)]
static TASK_PID_OFFSET: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
static TASK_COMM_OFFSET: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
static BINPRM_FILENAME_OFFSET: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
static SYSCALL_ARG_OFFSETS: Global<[u32; 6]> = Global::new([0; 6]);
#[unsafe(no_mangle)]
static SYSCALL_NR_OFFSET: Global<u32> = Global::new(0);
/// `task_struct.tgid`, from the kernel's BTF (#1103): `signal_generate` hands over the target
/// task, and a signal to a thread of a tool names the thread, not the process.
#[unsafe(no_mangle)]
static TASK_TGID_OFFSET: Global<u32> = Global::new(0);

/// `SEND_SIG_PRIV` (1): the special `siginfo` pointer of a signal the kernel sends on its own
/// behalf (the OOM killer, `exit_group`, a CPU limit). It is dropped here because the sender is
/// not a process, but that does not mean no attacker is behind it: a process can make the kernel
/// send it (`prlimit` of `RLIMIT_CPU` on the tool, a lowered `memory.max` of the tool's cgroup),
/// and those kills are not seen (docs/detection/security-tool-stop.md, Known gaps).
/// `SEND_SIG_NOINFO` (0) is **not** one of
/// those: the kernel then builds an `SI_USER` siginfo for `current`, so it is a process acting.
/// `echo 1 > cgroup.kill` takes this path (`SIGKILL` to every process of the cgroup, `info`
/// null, the sender the writing process).
const SEND_SIG_PRIV: usize = 1;

/// `kernel_siginfo.si_code`: `si_signo` and `si_errno` come first, 4 bytes each, on every
/// architecture (the layout is userspace ABI).
const SIGINFO_CODE_OFFSET: usize = 8;

/// The bit of signal `sig` (1..=64) in a `SigCgt`-style set.
const fn sig_bit(sig: u32) -> u64 {
    1u64 << (sig - 1)
}

/// The signals a daemon commonly catches to reload or rotate (`SIGHUP`, `SIGUSR1`, `SIGUSR2`,
/// the real-time range 32..=64), as a bit set (bit `sig - 1`). For a tool whose `SigCgt` (the
/// value of its `SIGNAL_WATCH_TOOLS` entry, taken at scan time) has the bit, the signal is a
/// reload and is dropped here, so a storm of them cannot fill the shared ring ahead of a
/// `SIGKILL`. `SIGTERM`, `SIGINT`, `SIGQUIT` and `SIGABRT` are never in this set: a handler for
/// them is how a daemon shuts down.
const RELOAD_SIGNALS: u64 = {
    let mut set = sig_bit(1) | sig_bit(10) | sig_bit(12);
    let mut sig = 32;
    while sig <= 64 {
        set |= sig_bit(sig);
        sig += 1;
    }
    set
};

// `RELOAD_SIGNALS` must never hold a signal that ends a tool whatever its handlers: a later edit
// that added one would silence a kill. Bits are `sig - 1`: SIGINT 2, SIGQUIT 3, SIGABRT 6,
// SIGKILL 9, SIGTERM 15, SIGSTOP 19 (`SIGSTOP` is 19 and `SIGTSTP` 20 on x86_64 and aarch64).
const _: () = assert!(
    RELOAD_SIGNALS
        & ((1 << (2 - 1))
            | (1 << (3 - 1))
            | (1 << (6 - 1))
            | (1 << (9 - 1))
            | (1 << (15 - 1))
            | (1 << (19 - 1)))
        == 0,
    "RELOAD_SIGNALS holds a signal that ends or stops a tool"
);

/// `enum sig_result` of `signal_generate` (`include/trace/events/signal.h`): the signal was
/// ignored by the target (`TRACE_SIGNAL_IGNORED`), or was already pending and not queued again
/// (`TRACE_SIGNAL_ALREADY_PENDING`). Neither touches the tool, and a pending one was reported
/// (or counted as lost) when it was first queued. `SIGKILL` and `SIGSTOP` can be both: a second
/// one while the first is pending (every signal below `SIGRTMIN` queues once), or a `SIGKILL` to a
/// task already exiting; the first one is what counts. Except: when the pending `SIGSTOP` came
/// from the kernel (`SEND_SIG_PRIV`, the stop `PTRACE_ATTACH` queues), dropped below, a process's
/// `SIGSTOP` in that window is not seen; the `ptrace` is its own evidence.
const TRACE_SIGNAL_IGNORED: u32 = 1;
const TRACE_SIGNAL_ALREADY_PENDING: u32 = 2;

/// The signals worth reporting for a tool, as a bit set (bit `sig - 1`): every signal whose
/// default action ends or stops a process, `SIGHUP` included: one that reaches userspace without
/// being a caught reload (`RELOAD_SIGNALS`) is a signal that ends a tool with no handler. Left out: `SIGCHLD`, `SIGCONT`, `SIGURG`, `SIGWINCH`, which neither end nor stop it.
/// Real-time signals (32..=64) end a process with no handler, so they are kept.
/// Filtering here keeps the shared ring free of noise a sender could use to fill it before a
/// `SIGKILL`.
const TOOL_SIGNALS: u64 = {
    let mut set = u64::MAX;
    set &= !(1 << (17 - 1)); // SIGCHLD
    set &= !(1 << (18 - 1)); // SIGCONT
    set &= !(1 << (23 - 1)); // SIGURG
    set &= !(1 << (28 - 1)); // SIGWINCH
    set
};

/// A signal sent to a process of a listed security unit (`signal:signal_generate`, #1103): the
/// path that sees `kill`, `tgkill`, `tkill`, `pidfd_send_signal` and `rt_sigqueueinfo` alike, in
/// the **initial** pid namespace and once per target of a group kill, which the `sys_enter`
/// probes above cannot do (the pid argument is in the sender's namespace, `tkill` takes a
/// thread id and `pidfd_send_signal` a file descriptor). Arguments, in the kernel's order:
/// `sig`, `info`, `task` (the target), `group`, `result` (`enum sig_result`: 0 delivered, 1 ignored,
/// 2 already pending, 3 overflow fail, 4 lose info; format not read on a host, the order is that
/// of `TP_PROTO` in `include/trace/events/signal.h`). An ignored or already-pending signal is
/// dropped (`TRACE_SIGNAL_IGNORED`, `TRACE_SIGNAL_ALREADY_PENDING`): a flood of a signal the tool
/// ignores (`SIGPIPE` for `auditd`) would otherwise fill the ring ahead of a `SIGKILL`.
///
/// The common case, a signal to anything else, costs one read of `task->tgid` and one hash
/// lookup. Permission is checked before this tracepoint fires, so a refused `kill` (`EPERM`)
/// never reaches it: a delivered, ignored or already-pending signal does, and the last two are dropped below.
#[raw_tracepoint(tracepoint = "signal_generate")]
pub fn raw_signal_generate(ctx: RawTracePointContext) -> u32 {
    let sig = ctx.arg::<i64>(0) as u32;
    let info = ctx.arg::<*const u8>(1);
    let task = ctx.arg::<*const u8>(2);
    // `kill -0` is a liveness probe, a signal outside `TOOL_SIGNALS` does not end the tool, and
    // `SEND_SIG_PRIV` is the kernel's own signal: none is a process acting on the tool. A null
    // `info` (`SEND_SIG_NOINFO`) is kept and attributed to `current`.
    if sig == 0 || sig > 64 || TOOL_SIGNALS & (1u64 << (sig - 1)) == 0 {
        return 0;
    }
    if info as usize == SEND_SIG_PRIV {
        return 0;
    }
    // The 5th tracepoint argument; an `int` widened to the register, so compare the low half.
    let result = ctx.arg::<i64>(4) as u32;
    if result == TRACE_SIGNAL_IGNORED || result == TRACE_SIGNAL_ALREADY_PENDING {
        return 0;
    }
    // SAFETY: `task` is the kernel's `task_struct` pointer from the tracepoint; the read goes
    // through `bpf_probe_read_kernel`, which fails (and is handled) on a bad address.
    let Ok(target) = (unsafe {
        bpf_probe_read_kernel(task.add(TASK_TGID_OFFSET.load() as usize).cast::<i32>())
    }) else {
        return 0;
    };
    let target = target as u32;
    let Some(caught) = watched_tool_sigcgt(target) else {
        return 0;
    };
    // A reload the tool catches (`SIGHUP`, `SIGUSR1`, `SIGUSR2`, real-time): not an attack, and
    // dropped here so a storm of them cannot fill the ring ahead of a `SIGKILL`.
    let bit = 1u64 << (sig - 1);
    if RELOAD_SIGNALS & bit != 0 && caught & bit != 0 {
        return 0;
    }
    // No filter on `si_code`. A positive code is not proof of the kernel (`fcntl(F_SETOWN)` with
    // `F_SETSIG=SIGKILL` and `O_ASYNC` kills a tool with `POLL_IN`), and neither is a negative
    // one: `rt_sigqueueinfo` and `pidfd_send_signal` let a process pick any `si_code` below 0
    // (the kernel refuses a non-negative one, and `SI_TKILL`, toward another process), so
    // `SIGKILL` with `SI_TIMER` is a kill a filter on the code would hide. The three codes the
    // kernel raises from interrupt or completion context only mark the sender unreliable
    // (`current` is a bystander there, or the code is forged): the event is still reported.
    let mut sig = sig;
    if info as usize != 0 {
        // SAFETY: `info` is the kernel's `kernel_siginfo` pointer from the tracepoint (not
        // null, not `SEND_SIG_PRIV`, checked above); the read goes through `bpf_probe_read_kernel`.
        let Ok(code) =
            (unsafe { bpf_probe_read_kernel(info.add(SIGINFO_CODE_OFFSET).cast::<i32>()) })
        else {
            return 0;
        };
        if (-4..=-2).contains(&code) {
            sig |= SIGNAL_SENDER_UNRELIABLE;
        }
    }
    // A tool signalling itself (`abort()`, a worker thread): not a process acting on it.
    if (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32 == target {
        return 0;
    }
    into_ret(emit_tool_signal_event(&ctx, target, sig))
}

// Keeping these synthetic tracepoint records in per-CPU maps avoids adding their
// full size to the raw dispatcher’s BPF stack on top of each legacy handler’s
// stack frame. The verifier accounts for the whole call chain, which otherwise
// exceeds the 512-byte limit on syscall routes such as openat.
#[map]
static SYSCALL_ENTER_SCRATCH: PerCpuArray<SysEnterRecord> = PerCpuArray::with_max_entries(1, 0);
#[map]
static SYSCALL_EXIT_SCRATCH: PerCpuArray<SysExitRecord> = PerCpuArray::with_max_entries(1, 0);

#[raw_tracepoint(tracepoint = "sched_process_fork")]
pub fn raw_sched_process_fork(ctx: RawTracePointContext) -> u32 {
    let parent = ctx.arg::<*const u8>(0);
    let child = ctx.arg::<*const u8>(1);
    let parent_pid =
        unsafe { bpf_probe_read_kernel(parent.add(TASK_PID_OFFSET.load() as usize).cast::<i32>()) };
    let child_pid =
        unsafe { bpf_probe_read_kernel(child.add(TASK_PID_OFFSET.load() as usize).cast::<i32>()) };
    let (Ok(parent_pid), Ok(child_pid)) = (parent_pid, child_pid) else {
        warn!(&ctx, "sensor-linux-ebpf: raw fork could not read task pids");
        return 0;
    };

    let comm = unsafe {
        bpf_probe_read_kernel(
            parent
                .add(TASK_COMM_OFFSET.load() as usize)
                .cast::<[u8; TASK_COMM_LEN]>(),
        )
    }
    .unwrap_or([0; TASK_COMM_LEN]);
    let entry = LineageEntry {
        ppid: parent_pid as u32,
        comm,
        execd: 0,
        generation: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
        parent_generation: match unsafe { PROC_LINEAGE.get(&(parent_pid as u32)) } {
            Some(parent) => parent.generation,
            None => 0,
        },
    };
    match PROC_LINEAGE.insert(&(child_pid as u32), &entry, 0) {
        Ok(_) => info!(
            &ctx,
            "sensor-linux-ebpf: fork child={} parent={} inserted=1", child_pid, parent_pid
        ),
        Err(_) => info!(
            &ctx,
            "sensor-linux-ebpf: fork child={} parent={} inserted=0", child_pid, parent_pid
        ),
    }
    0
}

#[raw_tracepoint(tracepoint = "sched_process_exit")]
pub fn raw_sched_process_exit(ctx: RawTracePointContext) -> u32 {
    let task = ctx.arg::<*const u8>(0);
    if let Ok(pid) =
        unsafe { bpf_probe_read_kernel(task.add(TASK_PID_OFFSET.load() as usize).cast::<i32>()) }
    {
        let _ = PROC_LINEAGE.remove(&(pid as u32));
    }
    0
}

#[raw_tracepoint(tracepoint = "sched_process_exec")]
pub fn raw_sched_process_exec(ctx: RawTracePointContext) -> u32 {
    let task = ctx.arg::<*const u8>(0);
    let bprm = ctx.arg::<*const u8>(2);
    let pid =
        unsafe { bpf_probe_read_kernel(task.add(TASK_PID_OFFSET.load() as usize).cast::<i32>()) };
    let filename = unsafe {
        bpf_probe_read_kernel(
            bprm.add(BINPRM_FILENAME_OFFSET.load() as usize)
                .cast::<*const u8>(),
        )
    };
    if let (Ok(pid), Ok(filename)) = (pid, filename)
        && !filename.is_null()
    {
        let _ = crate::exec::record_sched_process_exec(pid as u32, filename);
    } else {
        warn!(
            &ctx,
            "sensor-linux-ebpf: raw exec could not read task or filename"
        );
    }
    0
}

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn raw_sys_enter(ctx: RawTracePointContext) -> u32 {
    let syscall_id = ctx.arg::<i64>(1);
    if syscall_id < 0 || syscall_id >= MAX_SYSCALL_ID as i64 {
        return 0;
    }
    let Some(action) = SYSCALL_DISPATCH.get(syscall_id as u32) else {
        return 0;
    };
    if *action == 0 {
        return 0;
    }

    let regs = ctx.arg::<*const u8>(0);
    let Some(args) = read_syscall_args(regs) else {
        return 0;
    };
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();

    let Some(record) = SYSCALL_ENTER_SCRATCH.get_ptr_mut(0) else {
        return 0;
    };
    // SAFETY: the per-CPU map value is writable and this raw tracepoint executes
    // non-preemptibly on the current CPU. Initialize the whole record so padding
    // and the synthetic common header are deterministic before legacy handlers
    // read its fields through TracePointContext.
    unsafe {
        core::ptr::write_bytes(
            record.cast::<u8>(),
            0,
            core::mem::size_of::<SysEnterRecord>(),
        );
    }
    unsafe {
        (*record).id = to_clong(syscall_id);
        (*record).args = to_ulong_args(args);
    }

    let trace_ctx = TracePointContext::new(record.cast());
    match *action {
        1 => sys_enter_openat(trace_ctx),
        2 => sys_enter_open(trace_ctx),
        DISPATCH_CONNECT => sys_enter_connect(trace_ctx),
        DISPATCH_WRITE => sys_enter_write(trace_ctx),
        5 => sys_enter_unlink(trace_ctx),
        6 => sys_enter_unlinkat(trace_ctx),
        7 => sys_enter_rename(trace_ctx),
        8 => sys_enter_renameat(trace_ctx),
        9 => sys_enter_renameat2(trace_ctx),
        10 => sys_enter_bind(trace_ctx),
        11 => sys_enter_chmod(trace_ctx),
        12 => sys_enter_fchmodat(trace_ctx),
        13 => sys_enter_chown(trace_ctx),
        14 => sys_enter_lchown(trace_ctx),
        15 => sys_enter_fchownat(trace_ctx),
        DISPATCH_SENDTO => sys_enter_sendto(trace_ctx),
        17 => sys_enter_listen(trace_ctx),
        18 => {
            stash_pending_syscall_exit(pid_tgid, EXIT_ACCEPT, syscall_id as u32);
            sys_enter_accept(trace_ctx)
        }
        19 => {
            stash_pending_syscall_exit(pid_tgid, EXIT_ACCEPT4, syscall_id as u32);
            sys_enter_accept4(trace_ctx)
        }
        20 => sys_enter_setxattr(trace_ctx),
        21 => sys_enter_removexattr(trace_ctx),
        22 => sys_enter_mount(trace_ctx),
        23 => sys_enter_umount(trace_ctx),
        24 => sys_enter_kill(trace_ctx),
        25 => sys_enter_tgkill(trace_ctx),
        26 => sys_enter_init_module(trace_ctx),
        27 => sys_enter_finit_module(trace_ctx),
        28 => sys_enter_delete_module(trace_ctx),
        29 => sys_enter_bpf(trace_ctx),
        30 => sys_enter_prctl(trace_ctx),
        31 => sys_enter_ptrace(trace_ctx),
        32 => sys_enter_process_vm_readv(trace_ctx),
        33 => sys_enter_process_vm_writev(trace_ctx),
        34 => {
            stash_pending_syscall_exit(pid_tgid, EXIT_MEMFD_CREATE, syscall_id as u32);
            sys_enter_memfd_create(trace_ctx)
        }
        35 => sys_enter_setuid(trace_ctx),
        36 => sys_enter_setgid(trace_ctx),
        37 => sys_enter_setresuid(trace_ctx),
        38 => sys_enter_setresgid(trace_ctx),
        39 => sys_enter_setfsuid(trace_ctx),
        40 => sys_enter_setfsgid(trace_ctx),
        41 => sys_enter_capset(trace_ctx),
        42 => sys_enter_setns(trace_ctx),
        43 => sys_enter_unshare(trace_ctx),
        44 => {
            stash_pending_syscall_exit(pid_tgid, EXIT_RECVFROM, syscall_id as u32);
            sys_enter_recvfrom(trace_ctx)
        }
        45 => {
            stash_pending_syscall_exit(pid_tgid, EXIT_SOCKET, syscall_id as u32);
            sys_enter_socket(trace_ctx)
        }
        _ => 0,
    }
}

/// DNS over UDP/53 capture (#458 part 3), a program of its own next to `raw_sys_enter` and
/// attached only with `--enable-dns-capture`. It looks at the same dispatch table, acts on
/// `connect`, `write` and `sendto` and ignores every other syscall. Not part of `raw_sys_enter`:
/// the verifier of the 5.15 kernel rejects that program once the DNS maps and code are in it
/// (`E2BIG`), and a verifier unit of its own also keeps the capture's cost off a host that did not
/// ask for it. The two programs run one after the other on a CPU, so they may share the
/// per-CPU record.
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn raw_dns_udp_enter(ctx: RawTracePointContext) -> u32 {
    let syscall_id = ctx.arg::<i64>(1);
    if syscall_id < 0 || syscall_id >= MAX_SYSCALL_ID as i64 {
        return 0;
    }
    let Some(action) = SYSCALL_DISPATCH.get(syscall_id as u32) else {
        return 0;
    };
    // The handler ids of `connect`, `write` and `sendto`, shared with `raw_sys_enter` and userspace.
    let action = *action;
    if action != DISPATCH_CONNECT && action != DISPATCH_WRITE && action != DISPATCH_SENDTO {
        return 0;
    }

    let regs = ctx.arg::<*const u8>(0);
    let Some(args) = read_syscall_args(regs) else {
        return 0;
    };
    let Some(record) = SYSCALL_ENTER_SCRATCH.get_ptr_mut(0) else {
        return 0;
    };
    // SAFETY: as in `raw_sys_enter`: a per-CPU value on a non-preemptible path, written whole
    // before the handlers read it through `TracePointContext`.
    unsafe {
        core::ptr::write_bytes(
            record.cast::<u8>(),
            0,
            core::mem::size_of::<SysEnterRecord>(),
        );
    }
    unsafe {
        (*record).id = to_clong(syscall_id);
        (*record).args = to_ulong_args(args);
    }

    let trace_ctx = TracePointContext::new(record.cast());
    match action {
        DISPATCH_CONNECT => dns_udp_connect(trace_ctx),
        DISPATCH_WRITE => dns_udp_write(trace_ctx),
        _ => dns_udp_sendto(trace_ctx),
    }
}

#[raw_tracepoint(tracepoint = "sys_exit")]
pub fn raw_sys_exit(ctx: RawTracePointContext) -> u32 {
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let Some(pending) = (unsafe { PENDING_SYSCALL_EXIT.get(&pid_tgid) }).copied() else {
        return 0;
    };
    let _ = PENDING_SYSCALL_EXIT.remove(&pid_tgid);
    let regs = ctx.arg::<*const u8>(0);
    let action = matching_pending_syscall_exit(Some(pending), read_syscall_nr(regs));
    let Some(action) = action else {
        if let Some(count) = PENDING_EXIT_MISMATCH_DROPPED.get_ptr_mut(0) {
            // SAFETY: the counter slot is owned by the current CPU.
            unsafe { *count = (*count).wrapping_add(1) };
        }
        return 0;
    };
    let return_value = ctx.arg::<i64>(1);

    let Some(record) = SYSCALL_EXIT_SCRATCH.get_ptr_mut(0) else {
        return 0;
    };
    // SAFETY: same per-CPU, non-preemptible scratch guarantee as the enter record.
    unsafe {
        core::ptr::write_bytes(
            record.cast::<u8>(),
            0,
            core::mem::size_of::<SysExitRecord>(),
        );
    }
    unsafe {
        (*record).ret = to_clong(return_value);
    }

    let trace_ctx = TracePointContext::new(record.cast());
    match action {
        EXIT_ACCEPT => sys_exit_accept(trace_ctx),
        EXIT_ACCEPT4 => sys_exit_accept4(trace_ctx),
        EXIT_MEMFD_CREATE => sys_exit_memfd_create(trace_ctx),
        EXIT_RECVFROM => sys_exit_recvfrom(trace_ctx),
        EXIT_SOCKET => sys_exit_socket(trace_ctx),
        _ => 0,
    }
}

/// Always inlined: `raw_sys_enter` and `raw_dns_udp_enter` both call it, and with two callers
/// LLVM compiles it as a real BPF-to-BPF call, which pushes `raw_sys_enter`'s combined stack past
/// the 512 bytes the verifier allows ("combined stack size of 3 calls is 544", kernel 5.15).
#[inline(always)]
fn read_syscall_args(regs: *const u8) -> Option<[u64; 6]> {
    let offsets = SYSCALL_ARG_OFFSETS.load();
    Some([
        unsafe { read_kernel_ulong(regs.add(offsets[0] as usize)) }?,
        unsafe { read_kernel_ulong(regs.add(offsets[1] as usize)) }?,
        unsafe { read_kernel_ulong(regs.add(offsets[2] as usize)) }?,
        unsafe { read_kernel_ulong(regs.add(offsets[3] as usize)) }?,
        unsafe { read_kernel_ulong(regs.add(offsets[4] as usize)) }?,
        unsafe { read_kernel_ulong(regs.add(offsets[5] as usize)) }?,
    ])
}

fn read_syscall_nr(regs: *const u8) -> Option<u32> {
    let offset = SYSCALL_NR_OFFSET.load() as usize;
    #[cfg(bpf_target_arch = "x86_64")]
    {
        let value = unsafe { bpf_probe_read_kernel(regs.add(offset).cast::<u64>()) }.ok()?;
        u32::try_from(value).ok()
    }
    #[cfg(bpf_target_arch = "aarch64")]
    {
        // arm64's arch/arm64/include/asm/ptrace.h defines pt_regs.syscallno as
        // s32, followed by the u32 GIC priority mask (pmr). Read only syscallno:
        // a 64-bit read would accidentally include the neighbouring pmr field.
        let value = unsafe { bpf_probe_read_kernel(regs.add(offset).cast::<i32>()) }.ok()?;
        syscall_nr_from_i32(value)
    }
    #[cfg(bpf_target_arch = "x86")]
    {
        unsafe { bpf_probe_read_kernel(regs.add(offset).cast::<u32>()) }.ok()
    }
}
