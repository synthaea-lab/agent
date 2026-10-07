//! Raw tracepoint entrypoints for kernels where perf-event tracepoints are
//! blocked by `perf_event_paranoid`. The syscall router reconstructs the
//! regular syscall tracepoint record expected by the existing event handlers.

use aya_ebpf::{
    Global,
    helpers::bpf_probe_read_kernel,
    macros::{map, raw_tracepoint},
    maps::{Array, HashMap, PerCpuArray},
    programs::{RawTracePointContext, TracePointContext},
};
use aya_log_ebpf::{info, warn};
use sensor_linux_wire::{LineageEntry, TASK_COMM_LEN};

use crate::{
    PROC_LINEAGE, sys_enter_accept, sys_enter_accept4, sys_enter_bind, sys_enter_bpf,
    sys_enter_capset, sys_enter_chmod, sys_enter_chown, sys_enter_connect, sys_enter_delete_module,
    sys_enter_fchmodat, sys_enter_fchownat, sys_enter_finit_module, sys_enter_init_module,
    sys_enter_kill, sys_enter_lchown, sys_enter_listen, sys_enter_memfd_create, sys_enter_mount,
    sys_enter_open, sys_enter_openat, sys_enter_prctl, sys_enter_process_vm_readv,
    sys_enter_process_vm_writev, sys_enter_ptrace, sys_enter_recvfrom, sys_enter_removexattr,
    sys_enter_rename, sys_enter_renameat, sys_enter_renameat2, sys_enter_sendto,
    sys_enter_setfsgid, sys_enter_setfsuid, sys_enter_setgid, sys_enter_setns, sys_enter_setresgid,
    sys_enter_setresuid, sys_enter_setuid, sys_enter_setxattr, sys_enter_tgkill, sys_enter_umount,
    sys_enter_unlink, sys_enter_unlinkat, sys_enter_unshare, sys_enter_write, sys_exit_accept,
    sys_exit_accept4, sys_exit_memfd_create, sys_exit_recvfrom,
};

const MAX_SYSCALL_ID: u32 = 1024;
const EXIT_ACCEPT: u32 = 1;
const EXIT_ACCEPT4: u32 = 2;
const EXIT_MEMFD_CREATE: u32 = 3;
const EXIT_RECVFROM: u32 = 4;

/// syscall id → handler id. Userspace fills this from libc's architecture ABI.
#[map]
static SYSCALL_DISPATCH: Array<u32> = Array::with_max_entries(MAX_SYSCALL_ID, 0);

/// syscall id of an in-flight call whose event needs its return value.
#[map]
static PENDING_SYSCALL_EXIT: HashMap<u64, u32> = HashMap::with_max_entries(4096, 0);

#[unsafe(no_mangle)]
static TASK_PID_OFFSET: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
static TASK_COMM_OFFSET: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
static BINPRM_FILENAME_OFFSET: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
static SYSCALL_ARG_OFFSETS: Global<[u32; 6]> = Global::new([0; 6]);

#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
#[repr(C)]
struct SysEnterRecord {
    common_header: [u32; 2],
    id: i64,
    args: [u64; 6],
}

#[cfg(bpf_target_arch = "x86")]
#[repr(C)]
struct SysEnterRecord {
    common_header: [u32; 2],
    id: i32,
    args: [u32; 6],
}

#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
#[repr(C)]
struct SysExitRecord {
    common_header: [u32; 2],
    id: i64,
    ret: i64,
}

// Keeping these synthetic tracepoint records in per-CPU maps avoids adding their
// full size to the raw dispatcher’s BPF stack on top of each legacy handler’s
// stack frame. The verifier accounts for the whole call chain, which otherwise
// exceeds the 512-byte limit on syscall routes such as openat.
#[map]
static SYSCALL_ENTER_SCRATCH: PerCpuArray<SysEnterRecord> = PerCpuArray::with_max_entries(1, 0);
#[map]
static SYSCALL_EXIT_SCRATCH: PerCpuArray<SysExitRecord> = PerCpuArray::with_max_entries(1, 0);

#[cfg(bpf_target_arch = "x86")]
#[repr(C)]
struct SysExitRecord {
    common_header: [u32; 2],
    id: i32,
    ret: i32,
}

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
        reserved: 0,
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
        let _ = crate::record_sched_process_exec(pid as u32, filename);
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
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    unsafe {
        (*record).id = syscall_id;
        (*record).args = args;
    }
    #[cfg(bpf_target_arch = "x86")]
    unsafe {
        (*record).id = syscall_id as i32;
        (*record).args = args.map(|arg| arg as u32);
    }

    let trace_ctx = TracePointContext::new(record.cast());
    match *action {
        1 => sys_enter_openat(trace_ctx),
        2 => sys_enter_open(trace_ctx),
        3 => sys_enter_connect(trace_ctx),
        4 => sys_enter_write(trace_ctx),
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
        16 => sys_enter_sendto(trace_ctx),
        17 => sys_enter_listen(trace_ctx),
        18 => {
            let _ = PENDING_SYSCALL_EXIT.insert(&pid_tgid, &EXIT_ACCEPT, 0);
            sys_enter_accept(trace_ctx)
        }
        19 => {
            let _ = PENDING_SYSCALL_EXIT.insert(&pid_tgid, &EXIT_ACCEPT4, 0);
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
            let _ = PENDING_SYSCALL_EXIT.insert(&pid_tgid, &EXIT_MEMFD_CREATE, 0);
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
            let _ = PENDING_SYSCALL_EXIT.insert(&pid_tgid, &EXIT_RECVFROM, 0);
            sys_enter_recvfrom(trace_ctx)
        }
        _ => 0,
    }
}

#[raw_tracepoint(tracepoint = "sys_exit")]
pub fn raw_sys_exit(ctx: RawTracePointContext) -> u32 {
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let Some(action) = (unsafe { PENDING_SYSCALL_EXIT.get(&pid_tgid) }).copied() else {
        return 0;
    };
    let _ = PENDING_SYSCALL_EXIT.remove(&pid_tgid);
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
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    unsafe {
        (*record).ret = return_value;
    }
    #[cfg(bpf_target_arch = "x86")]
    unsafe {
        (*record).ret = return_value as i32;
    }

    let trace_ctx = TracePointContext::new(record.cast());
    match action {
        EXIT_ACCEPT => sys_exit_accept(trace_ctx),
        EXIT_ACCEPT4 => sys_exit_accept4(trace_ctx),
        EXIT_MEMFD_CREATE => sys_exit_memfd_create(trace_ctx),
        EXIT_RECVFROM => sys_exit_recvfrom(trace_ctx),
        _ => 0,
    }
}

fn read_syscall_args(regs: *const u8) -> Option<[u64; 6]> {
    let offsets = SYSCALL_ARG_OFFSETS.load();
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    {
        Some([
            unsafe { bpf_probe_read_kernel(regs.add(offsets[0] as usize).cast::<u64>()) }.ok()?,
            unsafe { bpf_probe_read_kernel(regs.add(offsets[1] as usize).cast::<u64>()) }.ok()?,
            unsafe { bpf_probe_read_kernel(regs.add(offsets[2] as usize).cast::<u64>()) }.ok()?,
            unsafe { bpf_probe_read_kernel(regs.add(offsets[3] as usize).cast::<u64>()) }.ok()?,
            unsafe { bpf_probe_read_kernel(regs.add(offsets[4] as usize).cast::<u64>()) }.ok()?,
            unsafe { bpf_probe_read_kernel(regs.add(offsets[5] as usize).cast::<u64>()) }.ok()?,
        ])
    }
    #[cfg(bpf_target_arch = "x86")]
    {
        Some([
            unsafe { bpf_probe_read_kernel(regs.add(offsets[0] as usize).cast::<u32>()) }.ok()?
                as u64,
            unsafe { bpf_probe_read_kernel(regs.add(offsets[1] as usize).cast::<u32>()) }.ok()?
                as u64,
            unsafe { bpf_probe_read_kernel(regs.add(offsets[2] as usize).cast::<u32>()) }.ok()?
                as u64,
            unsafe { bpf_probe_read_kernel(regs.add(offsets[3] as usize).cast::<u32>()) }.ok()?
                as u64,
            unsafe { bpf_probe_read_kernel(regs.add(offsets[4] as usize).cast::<u32>()) }.ok()?
                as u64,
            unsafe { bpf_probe_read_kernel(regs.add(offsets[5] as usize).cast::<u32>()) }.ok()?
                as u64,
        ])
    }
}
