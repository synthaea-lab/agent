// SPDX-License-Identifier: GPL-2.0-only OR MIT
#![no_std]
#![no_main]

mod cred;
mod file;
mod kernel;
mod raw;
mod uprobe;

use aya_ebpf::{
    Global,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes, bpf_probe_read_user, bpf_probe_read_user_buf,
        bpf_probe_read_user_str_bytes,
    },
    macros::{lsm, map},
    maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::{LsmContext, RawTracePointContext, TracePointContext},
};
use aya_log_ebpf::{info, warn};
use file::write_delete_rename::{WRITE_BUF_OFFSET, WRITE_COUNT_OFFSET, WRITE_FD_OFFSET};
use sensor_linux_wire::{
    ARGV_HEAD_BYTES, ARGV_TAIL_BYTES, ARGV_WINDOW_BYTES, ConnectEvent, DnsUdpQueryEvent, ExecEvent,
    ExecRecord, FileSetTimeEvent, LineageEntry, MAX_DNS_UDP_PAYLOAD, MemfdCreateEvent, MountEvent,
    ProcessVmReadEvent, ProcessVmWriteEvent, PtraceEvent, SET_TIME_ATIME, SET_TIME_COMPONENT_LEN,
    SET_TIME_COMPONENTS, SET_TIME_MTIME, SET_TIME_TRUNCATED, SignalEvent, SocketAcceptEvent,
    SocketBindEvent, SocketCreateEvent, SocketListenEvent, TASK_COMM_LEN, UdpRecvEvent,
    UdpSendEvent,
};

// Raw scheduler tracepoints expose task pointers instead of formatted event records.
// Their field offsets come from the running kernel's BTF in `userspace/src/btf.rs`;
// syscall arguments are decoded from `pt_regs` and passed to the existing handlers.

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

// --- sched_process_exec -------------------------------------------------------------
//
// The raw tracepoint supplies `task_struct *` and `linux_binprm *`; userspace
// provides their BTF-derived member offsets, and this helper keeps event creation
// shared with the old formatted tracepoint implementation.
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

/// Ring buffer shared with userspace for `connect` events.
#[map]
static CONNECT_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `ConnectEvent` (see `EXEC_SCRATCH`).
#[map]
static CONNECT_SCRATCH: PerCpuArray<ConnectEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_connect` tracepoint (x86_64). Same stable layout as
/// `sys_enter_openat` (see `file/open.rs`): 8-byte common header, `__syscall_nr`, then the arguments
/// aligned on 8 bytes each — `fd`(16), `uservaddr`(24), `addrlen`(32). Not verified against
/// `/sys/kernel/tracing/events/syscalls/sys_enter_connect/format` on this machine (reading
/// requires root) — to be confirmed before trusting the data outside the lab.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const CONNECT_USERVADDR_PTR_OFFSET: usize = 24;
/// `fd` is the first argument, right after the 16-byte record header (same layout as `bind`'s
/// `BIND_FD_OFFSET` below, which was read from the tracefs `format` file).
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const CONNECT_FD_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const CONNECT_FD_OFFSET: usize = 12;

/// On i686, `fd`(12), `uservaddr`(16), `addrlen`(20) are packed without padding (the
/// `uservaddr` pointer is 4 bytes, not 8) — verified on 2026-08-19 via
/// `/sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/format` on the target i686
/// kernel (Debian 12 Bookworm, `6.1.0-52-686-pae`).
#[cfg(bpf_target_arch = "x86")]
const CONNECT_USERVADDR_PTR_OFFSET: usize = 16;

/// `sa_family_t` values (linux/socket.h) for the two tracked families. Any other family
/// (notably `AF_UNIX` = 1, very frequent — D-Bus, local sockets) is ignored: out of scope of
/// the threat model (outbound network connections only).
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

pub fn sys_enter_connect(ctx: TracePointContext) -> u32 {
    match try_sys_enter_connect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_connect(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let uservaddr_ptr: u64 = unsafe {
        ctx.read_at(CONNECT_USERVADDR_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    #[cfg(bpf_target_arch = "x86")]
    let uservaddr_ptr: u64 = unsafe {
        ctx.read_at::<u32>(CONNECT_USERVADDR_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    if uservaddr_ptr == 0 {
        return Ok(0);
    }

    // `sockaddr.sa_family` is the first field (u16), common to all the variants
    // (sockaddr_in, sockaddr_in6, sockaddr_un...).
    let family: u16 = match unsafe { bpf_probe_read_user(uservaddr_ptr as *const u16) } {
        Ok(f) => f,
        Err(_) => return Ok(0),
    };
    if family != AF_INET && family != AF_INET6 {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    // `sin_port`/`sin6_port`: same offset (2) in both structs, network byte order.
    let port_be: u16 =
        unsafe { bpf_probe_read_user((uservaddr_ptr + 2) as *const u16).map_err(|_| 1u32)? };
    // Address bytes read raw ([u8; N]), not as an integer: `bpf_probe_read_user::<u32>`
    // would apply native (LE) endianness and reverse the displayed address (observed
    // 2026-08-13: 127.0.0.11 shown as "11.0.0.127"). sockaddr_in::sin_addr at +4,
    // sockaddr_in6::sin6_addr at +8.
    let (v4, v6): ([u8; 4], [u8; 16]) = if family == AF_INET {
        (
            unsafe {
                bpf_probe_read_user((uservaddr_ptr + 4) as *const [u8; 4]).map_err(|_| 1u32)?
            },
            [0u8; 16],
        )
    } else {
        ([0u8; 4], unsafe {
            bpf_probe_read_user((uservaddr_ptr + 8) as *const [u8; 16]).map_err(|_| 1u32)?
        })
    };

    // Assemble in per-CPU scratch, then one `output` copy (see `try_sys_enter_openat`).
    let e = CONNECT_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    let pid = unsafe {
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
        (*e).is_ipv6 = family == AF_INET6;
        (*e).dport = u16::from_be(port_be);
        (*e).daddr_v4 = v4;
        (*e).daddr_v6 = v6;

        if CONNECT_EVENTS.output::<ConnectEvent>(&*e, 0).is_err() {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping connect event"
            );
        }
        (*e).meta.pid
    };

    info!(&ctx, "sensor-linux-ebpf: connect pid={}", pid);
    Ok(0)
}

/// Ring buffer shared with userspace for `bind` events.
#[map]
static SOCKET_BIND_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `SocketBindEvent` (see `EXEC_SCRATCH`).
#[map]
static BIND_SCRATCH: PerCpuArray<SocketBindEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_bind` tracepoint (x86_64/aarch64): `fd`(16),
/// `umyaddr`(24), `addrlen`(32) — identical shape to `sys_enter_connect` above.
/// Verified on 2026-09-21 on Alpine (kernel 6.18.50-0-virt, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_bind/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const BIND_FD_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const BIND_UMYADDR_PTR_OFFSET: usize = 24;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const BIND_FD_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const BIND_UMYADDR_PTR_OFFSET: usize = 16;

/// Key into [`BIND_ADDR_MAP`]: a process's fd table entry is per-process, so the
/// same fd number on two different pids is a different socket.
#[repr(C)]
#[derive(Clone, Copy)]
struct BindAddrKey {
    pid: u32,
    fd: u32,
}

/// Value in [`BIND_ADDR_MAP`]: the address a prior `bind(2)` on this `(pid, fd)`
/// claimed, same shape as `SocketBindEvent`'s address fields.
#[repr(C)]
#[derive(Clone, Copy)]
struct BindAddrValue {
    addr_v4: [u8; 4],
    addr_v6: [u8; 16],
    port: u16,
    is_ipv6: bool,
}

/// Correlates a later `listen(2)` back to the address an earlier `bind(2)` on the
/// same `(pid, fd)` claimed — `listen(2)`'s own arguments are just `fd`+`backlog`,
/// no address. Internal to this crate: never read by userspace, so it is not part
/// of `sensor-linux-wire`'s ABI and does not bump `WIRE_VERSION` on its own.
///
/// Entries are never explicitly removed (no `close(2)` probe tracks fd lifetime
/// yet): a `bind()` on a reused fd simply overwrites the old entry, and the
/// map is bounded (`insert` fails silently once full, same graceful-degradation
/// posture as every other best-effort correlation in this file) rather than
/// growing without limit.
#[map]
static BIND_ADDR_MAP: HashMap<BindAddrKey, BindAddrValue> = HashMap::with_max_entries(4096, 0);

pub fn sys_enter_bind(ctx: TracePointContext) -> u32 {
    match try_sys_enter_bind(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// Mirrors `try_sys_enter_connect` above field for field — same family filter, same
/// raw-byte address read (avoids the endianness bug documented on `ConnectEvent`),
/// same per-CPU-scratch assembly. Only the wire type, ring buffer, and field names
/// (`laddr`/`lport` vs `daddr`/`dport`) differ. Also records the address into
/// [`BIND_ADDR_MAP`] for `sys_enter_listen` to correlate against later.
fn try_sys_enter_bind(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let fd: u64 = unsafe { ctx.read_at(BIND_FD_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let fd: u64 = unsafe { ctx.read_at::<u32>(BIND_FD_OFFSET).map_err(|_| 1u32)? as u64 };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let umyaddr_ptr: u64 = unsafe { ctx.read_at(BIND_UMYADDR_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let umyaddr_ptr: u64 = unsafe {
        ctx.read_at::<u32>(BIND_UMYADDR_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    if umyaddr_ptr == 0 {
        return Ok(0);
    }

    let family: u16 = match unsafe { bpf_probe_read_user(umyaddr_ptr as *const u16) } {
        Ok(f) => f,
        Err(_) => return Ok(0),
    };
    if family != AF_INET && family != AF_INET6 {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let port_be: u16 =
        unsafe { bpf_probe_read_user((umyaddr_ptr + 2) as *const u16).map_err(|_| 1u32)? };
    let (v4, v6): ([u8; 4], [u8; 16]) = if family == AF_INET {
        (
            unsafe { bpf_probe_read_user((umyaddr_ptr + 4) as *const [u8; 4]).map_err(|_| 1u32)? },
            [0u8; 16],
        )
    } else {
        ([0u8; 4], unsafe {
            bpf_probe_read_user((umyaddr_ptr + 8) as *const [u8; 16]).map_err(|_| 1u32)?
        })
    };

    let e = BIND_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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
        (*e).is_ipv6 = family == AF_INET6;
        (*e).lport = u16::from_be(port_be);
        (*e).laddr_v4 = v4;
        (*e).laddr_v6 = v6;

        if SOCKET_BIND_EVENTS
            .output::<SocketBindEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping bind event"
            );
        }
    }

    let key = BindAddrKey {
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        fd: fd as u32,
    };
    // `BindAddrValue`'s field order (4 + 16 + 2 + bool = 23 bytes of data, but a
    // `u16` field forces the struct's alignment to 2, so its declared size is 24)
    // leaves a 1-byte tail pad that a plain struct literal never writes. That's
    // fine for a value that's only ever read back through this same typed struct
    // — but `bpf_map_update_elem` below copies the map's full declared value_size
    // (24) off the stack, and the verifier tracks stack initialization per byte:
    // on kernel 5.15 it rejects the load with "invalid indirect read from stack
    // ... size 24" because that pad byte was never provably written (issue #390 —
    // reproduced on Ubuntu 22.04/5.15, not on the Alpine 6.18/Arch 6.6 kernels
    // this sensor had been validated against before, so the stricter check isn't
    // universal). Zeroing the whole struct first covers the pad the same way
    // `core::ptr::write_bytes` already does for every ring-buffer scratch struct
    // in this file, just without a `PerCpuArray` backing it.
    let mut value: BindAddrValue = unsafe { core::mem::zeroed() };
    value.addr_v4 = v4;
    value.addr_v6 = v6;
    value.port = u16::from_be(port_be);
    value.is_ipv6 = family == AF_INET6;
    let _ = BIND_ADDR_MAP.insert(&key, &value, 0);

    Ok(0)
}

// --- Socket listen (issue #263 Phase 2) -----------------------------------------

/// Ring buffer shared with userspace for `listen` events.
#[map]
static SOCKET_LISTEN_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `SocketListenEvent` (see `EXEC_SCRATCH`).
#[map]
static LISTEN_SCRATCH: PerCpuArray<SocketListenEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_listen` tracepoint (x86_64/aarch64): `fd`(16),
/// `backlog`(24). Verified on 2026-09-22 on Alpine (kernel 6.18.50-0-virt, x86_64)
/// via `/sys/kernel/tracing/events/syscalls/sys_enter_listen/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const LISTEN_FD_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const LISTEN_BACKLOG_OFFSET: usize = 24;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const LISTEN_FD_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const LISTEN_BACKLOG_OFFSET: usize = 16;

pub fn sys_enter_listen(ctx: TracePointContext) -> u32 {
    match try_sys_enter_listen(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// `listen(2)` carries no address of its own — correlates against [`BIND_ADDR_MAP`]
/// on `(pid, fd)` to recover the address a prior `bind(2)` claimed. No match still
/// emits the event (a process just started listening is worth reporting on its
/// own), with `addr_resolved: false` and the address fields left zeroed.
fn try_sys_enter_listen(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let fd: u64 = unsafe { ctx.read_at(LISTEN_FD_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let fd: u64 = unsafe { ctx.read_at::<u32>(LISTEN_FD_OFFSET).map_err(|_| 1u32)? as u64 };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let backlog: u64 = unsafe { ctx.read_at(LISTEN_BACKLOG_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let backlog: u64 = unsafe {
        ctx.read_at::<u32>(LISTEN_BACKLOG_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let key = BindAddrKey { pid, fd: fd as u32 };
    let bound = unsafe { BIND_ADDR_MAP.get(&key) }.copied();

    let e = LISTEN_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        (*e).meta.pid = pid;
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
        (*e).backlog = backlog as u32;

        if let Some(addr) = bound {
            (*e).laddr_v4 = addr.addr_v4;
            (*e).laddr_v6 = addr.addr_v6;
            (*e).lport = addr.port;
            (*e).is_ipv6 = addr.is_ipv6;
            (*e).addr_resolved = true;
        }

        if SOCKET_LISTEN_EVENTS
            .output::<SocketListenEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping listen event"
            );
        }
    }

    Ok(0)
}

// --- UDP send (issue #263 Phase 2) ----------------------------------------------

/// Ring buffer shared with userspace for `sendto` events.
#[map]
static UDP_SEND_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `UdpSendEvent` (see `EXEC_SCRATCH`).
#[map]
static UDP_SEND_SCRATCH: PerCpuArray<UdpSendEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_sendto` tracepoint (x86_64/aarch64): `fd`(16),
/// `buff`(24), `len`(32), `flags`(40), `addr`(48), `addr_len`(56). Verified on
/// 2026-09-22 on Alpine (kernel 6.18.50-0-virt, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_sendto/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const SENDTO_FD_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const SENDTO_BUF_OFFSET: usize = 24;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const SENDTO_LEN_OFFSET: usize = 32;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const SENDTO_ADDR_PTR_OFFSET: usize = 48;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const SENDTO_FD_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const SENDTO_BUF_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const SENDTO_LEN_OFFSET: usize = 20;
#[cfg(bpf_target_arch = "x86")]
const SENDTO_ADDR_PTR_OFFSET: usize = 28;

pub fn sys_enter_sendto(ctx: TracePointContext) -> u32 {
    match try_sys_enter_sendto(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// Mirrors `try_sys_enter_connect`/`try_sys_enter_bind` above for the address read —
/// same family filter, same raw-byte address read (avoids the endianness bug
/// documented on `ConnectEvent`) — plus the requested payload size from `len`.
fn try_sys_enter_sendto(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let len: u64 = unsafe { ctx.read_at(SENDTO_LEN_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let len: u64 = unsafe { ctx.read_at::<u32>(SENDTO_LEN_OFFSET).map_err(|_| 1u32)? as u64 };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let addr_ptr: u64 = unsafe { ctx.read_at(SENDTO_ADDR_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let addr_ptr: u64 = unsafe {
        ctx.read_at::<u32>(SENDTO_ADDR_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    // NULL addr: a connected-socket send (or plain `send(2)`, which glibc issues as
    // `sendto(fd, buf, len, flags, NULL, 0)`) — no destination to report, same
    // treatment as `connect`/`bind`'s own null-address check.
    if addr_ptr == 0 {
        return Ok(0);
    }

    let family: u16 = match unsafe { bpf_probe_read_user(addr_ptr as *const u16) } {
        Ok(f) => f,
        Err(_) => return Ok(0),
    };
    if family != AF_INET && family != AF_INET6 {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let port_be: u16 =
        unsafe { bpf_probe_read_user((addr_ptr + 2) as *const u16).map_err(|_| 1u32)? };
    let (v4, v6): ([u8; 4], [u8; 16]) = if family == AF_INET {
        (
            unsafe { bpf_probe_read_user((addr_ptr + 4) as *const [u8; 4]).map_err(|_| 1u32)? },
            [0u8; 16],
        )
    } else {
        ([0u8; 4], unsafe {
            bpf_probe_read_user((addr_ptr + 8) as *const [u8; 16]).map_err(|_| 1u32)?
        })
    };

    let e = UDP_SEND_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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
        (*e).is_ipv6 = family == AF_INET6;
        (*e).dport = u16::from_be(port_be);
        (*e).daddr_v4 = v4;
        (*e).daddr_v6 = v6;
        (*e).size = len as u32;

        if UDP_SEND_EVENTS.output::<UdpSendEvent>(&*e, 0).is_err() {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping udp send event"
            );
        }
    }

    Ok(0)
}

// --- DNS over UDP/53 (issue #458 part 3) --------------------------------------------
//
// A DNS query leaves a process either through the libc resolver (the `getaddrinfo` uprobe of
// part 1 sees it) or straight through the socket: Go's resolver, musl, Rust resolvers and
// tools such as `dig`. This path sees the second kind. It reads the first
// `MAX_DNS_UDP_PAYLOAD` bytes of the datagram at syscall entry, from `sendto(2)` with an
// address and from `write(2)`/`sendto(2)` without one on a socket this process `connect(2)`ed
// to port 53 (`DNS_UDP_FDS`). Userspace parses the question. Queries only: the response is not
// read here. `sendmsg(2)`/`sendmmsg(2)` are not hooked (see `docs/sensors/sources.md`).

/// Ring buffer shared with userspace for DNS query datagrams.
#[map]
static DNS_UDP_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `DnsUdpQueryEvent` (see `EXEC_SCRATCH`).
#[map]
static DNS_UDP_SCRATCH: PerCpuArray<DnsUdpQueryEvent> = PerCpuArray::with_max_entries(1, 0);

/// Where a socket connected to port 53 goes: the destination, remembered at `connect(2)`.
#[derive(Clone, Copy)]
#[repr(C)]
struct DnsFdEntry {
    daddr_v4: [u8; 4],
    daddr_v6: [u8; 16],
    is_ipv6: bool,
}

/// (thread group id, fd) → the destination of a socket connected to port 53. LRU: a descriptor
/// that is closed is never removed explicitly, so a reused number can still be here until the
/// process connects it elsewhere or it ages out; userspace discards a payload that is not a
/// DNS question, so such a stale entry costs a wasted event, not a wrong one.
#[map]
static DNS_UDP_FDS: LruHashMap<u64, DnsFdEntry> = LruHashMap::with_max_entries(4096, 0);

const DNS_PORT: u16 = 53;
/// A DNS header is 12 bytes: anything shorter is not a message.
const DNS_HEADER_LEN: u64 = 12;

// Every helper below is `#[inline(always)]`, like `emit_mount_event`: a real BPF-to-BPF call is
// something the verifier of some kernels refuses to load.
/// The thread group id in the high half, the descriptor in the low half.
#[inline(always)]
fn dns_fd_key(pid_tgid: u64, fd: u64) -> u64 {
    (pid_tgid & 0xFFFF_FFFF_0000_0000) | (fd & 0xFFFF_FFFF)
}

/// `write(2)`/`sendto(2)` with no address on `fd`: a DNS query when this process connected `fd`
/// to port 53. `buf_offset` is where the buffer pointer sits in the tracepoint record.
#[inline(always)]
fn emit_dns_on_connected_socket(
    ctx: &TracePointContext,
    fd: u64,
    buf_offset: usize,
    len: u64,
) -> Result<u32, u32> {
    let key = dns_fd_key(bpf_get_current_pid_tgid(), fd);
    // SAFETY: the map value is plain data; it is copied out before anything else runs.
    let Some(entry) = (unsafe { DNS_UDP_FDS.get(&key) }).copied() else {
        return Ok(0);
    };
    emit_dns_udp_query(ctx, buf_offset, len, &entry)
}

/// Copies the first bytes of the datagram at `buf_offset` (a user pointer in the tracepoint
/// record) into a `DnsUdpQueryEvent` and sends it. Nothing is sent for a datagram shorter than
/// a DNS header or for a read that fails.
#[inline(always)]
fn emit_dns_udp_query(
    ctx: &TracePointContext,
    buf_offset: usize,
    len: u64,
    dest: &DnsFdEntry,
) -> Result<u32, u32> {
    if len < DNS_HEADER_LEN {
        return Ok(0);
    }
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let buf_ptr: u64 = unsafe { ctx.read_at(buf_offset).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let buf_ptr: u64 = unsafe { ctx.read_at::<u32>(buf_offset).map_err(|_| 1u32)? as u64 };
    if buf_ptr == 0 {
        return Ok(0);
    }
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if is_agent_own_pid(pid) {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();
    let e = DNS_UDP_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        // Same bounded single read as the TLS capture: the length is clamped first so the
        // verifier sees an upper bound, and it is one helper call, not a byte loop.
        let to_read = if len as usize > MAX_DNS_UDP_PAYLOAD {
            MAX_DNS_UDP_PAYLOAD
        } else {
            len as usize
        };
        let payload = &mut (*e).payload;
        if bpf_probe_read_user_buf(buf_ptr as *const u8, &mut payload[..to_read]).is_err() {
            return Ok(0);
        }
        (*e).payload_len = to_read as u16;

        (*e).meta.pid = pid;
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
        (*e).daddr_v4 = dest.daddr_v4;
        (*e).daddr_v6 = dest.daddr_v6;
        (*e).dport = DNS_PORT;
        (*e).is_ipv6 = dest.is_ipv6;

        if DNS_UDP_EVENTS.output::<DnsUdpQueryEvent>(&*e, 0).is_err() {
            warn!(
                ctx,
                "sensor-linux-ebpf: ring buffer full, dropping dns query event"
            );
        }
    }
    Ok(0)
}

/// The destination of the `sockaddr` at `addr_ptr` and its port in host order, or `None` for any
/// other family or an address that cannot be read.
#[inline(always)]
fn read_inet_dest(addr_ptr: u64) -> Option<(DnsFdEntry, u16)> {
    let family: u16 = unsafe { bpf_probe_read_user(addr_ptr as *const u16) }.ok()?;
    if family != AF_INET && family != AF_INET6 {
        return None;
    }
    // Same offsets and raw-byte address reads as `try_sys_enter_connect`.
    let port_be: u16 = unsafe { bpf_probe_read_user((addr_ptr + 2) as *const u16) }.ok()?;
    let (v4, v6): ([u8; 4], [u8; 16]) = if family == AF_INET {
        (
            unsafe { bpf_probe_read_user((addr_ptr + 4) as *const [u8; 4]) }.ok()?,
            [0u8; 16],
        )
    } else {
        (
            [0u8; 4],
            unsafe { bpf_probe_read_user((addr_ptr + 8) as *const [u8; 16]) }.ok()?,
        )
    };
    Some((
        DnsFdEntry {
            daddr_v4: v4,
            daddr_v6: v6,
            is_ipv6: family == AF_INET6,
        },
        u16::from_be(port_be),
    ))
}

/// The three entry points of `raw_dns_udp_enter` (raw.rs), a program of its own that is attached
/// only with `--enable-dns-capture`. Kept out of `raw_sys_enter` on purpose: that is one verifier
/// unit shared by every `sys_enter_*` handler, and the verifier of the 5.15 kernel rejects it
/// outright (`E2BIG`, before one instruction) once this code is added to it. Each reads the
/// descriptor and arguments from the synthetic record, as the handlers above do.
///
/// `connect(2)`: remembers a socket connected to port 53, so that a later `write(2)`/`send(2)`
/// without an address is recognised as a DNS query; a connect of the same descriptor to anything
/// else forgets it (a reused descriptor number).
///
/// Recorded at syscall entry, before the kernel has said whether the `connect` worked: one that
/// fails leaves an entry behind. It is bounded (the map is an LRU) and harmless, because userspace
/// drops any payload that is not a DNS query.
pub fn dns_udp_connect(ctx: TracePointContext) -> u32 {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let Ok(fd) = (unsafe { ctx.read_at::<u64>(CONNECT_FD_OFFSET) }) else {
        return 1;
    };
    #[cfg(bpf_target_arch = "x86")]
    let Ok(fd) = (unsafe { ctx.read_at::<u32>(CONNECT_FD_OFFSET) }).map(u64::from) else {
        return 1;
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let Ok(addr_ptr) = (unsafe { ctx.read_at::<u64>(CONNECT_USERVADDR_PTR_OFFSET) }) else {
        return 1;
    };
    #[cfg(bpf_target_arch = "x86")]
    let Ok(addr_ptr) = (unsafe { ctx.read_at::<u32>(CONNECT_USERVADDR_PTR_OFFSET) }).map(u64::from)
    else {
        return 1;
    };
    let key = dns_fd_key(bpf_get_current_pid_tgid(), fd);
    if addr_ptr != 0 {
        if let Some((entry, port)) = read_inet_dest(addr_ptr) {
            if port == DNS_PORT {
                let _ = DNS_UDP_FDS.insert(&key, &entry, 0);
                return 0;
            }
        }
    }
    let _ = DNS_UDP_FDS.remove(&key);
    0
}

/// `write(2)` on a socket this process connected to port 53 (Go's resolver does `connect` then
/// `write`).
pub fn dns_udp_write(ctx: TracePointContext) -> u32 {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let Ok(fd) = (unsafe { ctx.read_at::<u64>(WRITE_FD_OFFSET) }) else {
        return 1;
    };
    #[cfg(bpf_target_arch = "x86")]
    let Ok(fd) = (unsafe { ctx.read_at::<u32>(WRITE_FD_OFFSET) }).map(u64::from) else {
        return 1;
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let Ok(count) = (unsafe { ctx.read_at::<u64>(WRITE_COUNT_OFFSET) }) else {
        return 1;
    };
    #[cfg(bpf_target_arch = "x86")]
    let Ok(count) = (unsafe { ctx.read_at::<u32>(WRITE_COUNT_OFFSET) }).map(u64::from) else {
        return 1;
    };
    let _ = emit_dns_on_connected_socket(&ctx, fd, WRITE_BUF_OFFSET, count);
    0
}

/// `sendto(2)`: with an address, an unconnected query to port 53 (musl, Rust, `dig`); without
/// one (`send(2)` is `sendto` with a NULL address), a query on a socket connected to port 53.
pub fn dns_udp_sendto(ctx: TracePointContext) -> u32 {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let Ok(len) = (unsafe { ctx.read_at::<u64>(SENDTO_LEN_OFFSET) }) else {
        return 1;
    };
    #[cfg(bpf_target_arch = "x86")]
    let Ok(len) = (unsafe { ctx.read_at::<u32>(SENDTO_LEN_OFFSET) }).map(u64::from) else {
        return 1;
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let Ok(addr_ptr) = (unsafe { ctx.read_at::<u64>(SENDTO_ADDR_PTR_OFFSET) }) else {
        return 1;
    };
    #[cfg(bpf_target_arch = "x86")]
    let Ok(addr_ptr) = (unsafe { ctx.read_at::<u32>(SENDTO_ADDR_PTR_OFFSET) }).map(u64::from)
    else {
        return 1;
    };
    if addr_ptr == 0 {
        #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
        let Ok(fd) = (unsafe { ctx.read_at::<u64>(SENDTO_FD_OFFSET) }) else {
            return 1;
        };
        #[cfg(bpf_target_arch = "x86")]
        let Ok(fd) = (unsafe { ctx.read_at::<u32>(SENDTO_FD_OFFSET) }).map(u64::from) else {
            return 1;
        };
        let _ = emit_dns_on_connected_socket(&ctx, fd, SENDTO_BUF_OFFSET, len);
        return 0;
    }
    if let Some((dest, port)) = read_inet_dest(addr_ptr) {
        if port == DNS_PORT {
            let _ = emit_dns_udp_query(&ctx, SENDTO_BUF_OFFSET, len, &dest);
        }
    }
    0
}

// --- Socket accept (issue #263 Phase 2) -----------------------------------------
//
// First paired sys_enter/sys_exit probe in this crate. Every other probe here is
// sys_enter_*: it reads syscall arguments before the call runs, which is enough
// because the kernel hasn't touched anything yet. accept(2)/accept4(2) are
// different — the caller passes a sockaddr buffer that the kernel fills in DURING
// the call, so the peer address does not exist yet at sys_enter time. The standard
// sys_exit_* tracepoint format carries only __syscall_nr and the return value, not
// the original arguments, so sys_enter_accept{,4} stashes the caller's
// (fd, addr_ptr) in ACCEPT_ARGS (keyed by pid_tgid, the same entry/exit
// correlation pattern already used by the uprobes crate's SSL_READ_ARGS for
// SSL_read's output buffer), and sys_exit_accept{,4} reads it back once the kernel
// has actually written the peer address.

/// Ring buffer shared with userspace for `accept`/`accept4` events.
#[map]
static SOCKET_ACCEPT_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `SocketAcceptEvent` (see `EXEC_SCRATCH`).
#[map]
static ACCEPT_SCRATCH: PerCpuArray<SocketAcceptEvent> = PerCpuArray::with_max_entries(1, 0);

/// Stashed at `sys_enter_accept{,4}`, consumed at `sys_exit_accept{,4}`.
#[repr(C)]
#[derive(Clone, Copy)]
struct AcceptArgs {
    fd: u32,
    addr_ptr: u64,
}

/// Correlates `sys_enter_accept{,4}` with its matching `sys_exit_accept{,4}` on the
/// same thread. Not part of `sensor-linux-wire`'s ABI (never read by userspace).
/// A thread that enters `accept()` and never returns retains its entry. An LRU
/// evicts the stalest stash when full so blocked threads cannot blind later
/// accept telemetry host-wide.
#[map]
static ACCEPT_ARGS: LruHashMap<u64, AcceptArgs> = LruHashMap::with_max_entries(1024, 0);

/// Offsets of the `syscalls:sys_enter_accept`/`sys_enter_accept4` tracepoints
/// (x86_64/aarch64): `fd`(16), `upeer_sockaddr`(24) — identical shape for both
/// (accept4's extra `flags` argument trails at 40, not needed here). Verified on
/// 2026-09-22 on Alpine (kernel 6.18.50-0-virt, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_accept{,4}/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const ACCEPT_FD_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const ACCEPT_ADDR_PTR_OFFSET: usize = 24;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const ACCEPT_FD_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const ACCEPT_ADDR_PTR_OFFSET: usize = 16;

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

pub fn sys_enter_accept(ctx: TracePointContext) -> u32 {
    match stash_accept_args(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

pub fn sys_enter_accept4(ctx: TracePointContext) -> u32 {
    match stash_accept_args(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// Shared by `sys_enter_accept` and `sys_enter_accept4` — both have the same
/// `fd`/`upeer_sockaddr` layout.
fn stash_accept_args(ctx: &TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let fd: u64 = unsafe { ctx.read_at(ACCEPT_FD_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let fd: u64 = unsafe { ctx.read_at::<u32>(ACCEPT_FD_OFFSET).map_err(|_| 1u32)? as u64 };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let addr_ptr: u64 = unsafe { ctx.read_at(ACCEPT_ADDR_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let addr_ptr: u64 = unsafe {
        ctx.read_at::<u32>(ACCEPT_ADDR_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    if addr_ptr != 0 {
        let args = AcceptArgs {
            fd: fd as u32,
            addr_ptr,
        };
        let _ = ACCEPT_ARGS.insert(&pid_tgid, &args, 0);
    } else {
        let _ = ACCEPT_ARGS.remove(&pid_tgid);
    }

    Ok(0)
}

pub fn sys_exit_accept(ctx: TracePointContext) -> u32 {
    match try_sys_exit_accept(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

pub fn sys_exit_accept4(ctx: TracePointContext) -> u32 {
    match try_sys_exit_accept(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// Shared by `sys_exit_accept` and `sys_exit_accept4`. No-ops (returns `Ok(0)`
/// without emitting) when: the matching `sys_enter` wasn't tracked (NULL addr
/// or an evicted stash), the call failed (`ret < 0`), or the peer's address
/// family isn't one this sensor tracks.
fn try_sys_exit_accept(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let ret: i64 = unsafe { ctx.read_at(SYS_EXIT_RET_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let ret: i64 = unsafe { ctx.read_at::<i32>(SYS_EXIT_RET_OFFSET).map_err(|_| 1u32)? as i64 };

    let pid_tgid = bpf_get_current_pid_tgid();
    let args = match unsafe { ACCEPT_ARGS.get(&pid_tgid) } {
        Some(a) => *a,
        None => return Ok(0),
    };
    let _ = ACCEPT_ARGS.remove(&pid_tgid);

    if ret < 0 {
        return Ok(0);
    }
    let accepted_fd = ret as u32;

    let family: u16 = match unsafe { bpf_probe_read_user(args.addr_ptr as *const u16) } {
        Ok(f) => f,
        Err(_) => return Ok(0),
    };
    if family != AF_INET && family != AF_INET6 {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let port_be: u16 =
        unsafe { bpf_probe_read_user((args.addr_ptr + 2) as *const u16).map_err(|_| 1u32)? };
    let (v4, v6): ([u8; 4], [u8; 16]) = if family == AF_INET {
        (
            unsafe {
                bpf_probe_read_user((args.addr_ptr + 4) as *const [u8; 4]).map_err(|_| 1u32)?
            },
            [0u8; 16],
        )
    } else {
        ([0u8; 4], unsafe {
            bpf_probe_read_user((args.addr_ptr + 8) as *const [u8; 16]).map_err(|_| 1u32)?
        })
    };

    let e = ACCEPT_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        (*e).meta.pid = (pid_tgid >> 32) as u32;
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
        (*e).listen_fd = args.fd;
        (*e).accepted_fd = accepted_fd;
        (*e).peer_addr_v4 = v4;
        (*e).peer_addr_v6 = v6;
        (*e).peer_port = u16::from_be(port_be);
        (*e).is_ipv6 = family == AF_INET6;

        if SOCKET_ACCEPT_EVENTS
            .output::<SocketAcceptEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping accept event"
            );
        }
    }

    Ok(0)
}

// --- Socket creation (issue #263) -----------------------------------------------
//
// `socket(domain, type, protocol)`'s three arguments are the caller's own, already
// available at `sys_enter` — unlike `accept`/`recvfrom` there is no kernel-filled
// output buffer to wait for. The only reason this still needs the paired
// `sys_enter`/`sys_exit` shape is that the fd itself is the return value: the entry
// probe stashes the three arguments, the exit probe reads them back together with
// the fd and emits on success only.

/// Ring buffer shared with userspace for `socket` events.
#[map]
static SOCKET_CREATE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `SocketCreateEvent` (see `EXEC_SCRATCH`).
#[map]
static SOCKET_CREATE_SCRATCH: PerCpuArray<SocketCreateEvent> = PerCpuArray::with_max_entries(1, 0);

/// Stashed at `sys_enter_socket`, consumed at `sys_exit_socket`.
#[repr(C)]
#[derive(Clone, Copy)]
struct SocketCreateArgs {
    domain: i32,
    socket_type: i32,
    protocol: i32,
}

/// Correlates `sys_enter_socket` with its matching `sys_exit_socket` on the same
/// thread. Not part of `sensor-linux-wire`'s ABI. A thread that never returns from
/// `socket()` (it can block — `AF_ALG`, some out-of-tree protocol families) keeps
/// its entry; an LRU evicts the stalest one when full, same reasoning as
/// `ACCEPT_ARGS` and `PENDING_SYSCALL_EXIT` (#672).
#[map]
static SOCKET_CREATE_ARGS: LruHashMap<u64, SocketCreateArgs> =
    LruHashMap::with_max_entries(1024, 0);

/// `SOCK_CLOEXEC`/`SOCK_NONBLOCK` (`<bits/socket_type.h>`): the kernel ORs these
/// into the same `type` argument as `SOCK_STREAM`/`SOCK_DGRAM`/etc., so they are
/// masked off before reporting `socket_type` — a caller asking for a non-blocking
/// stream socket should read as `SOCK_STREAM`, not an unrecognized combined value.
const SOCK_CLOEXEC_FLAG: i32 = 0o2000000;
const SOCK_NONBLOCK_FLAG: i32 = 0o4000;

/// `AF_UNIX` (`<bits/socket.h>`): excluded from `socket_create` emission, not from
/// `SocketCreateArgs` capture. Local IPC sockets (systemd, journald, D-Bus, every
/// Unix-domain client) are a large share of all `socket()` calls on a running
/// system and never carry a family/protocol surprise the way `AF_PACKET` or a raw
/// socket does, so emitting one per call is pure correlator-bus volume for zero
/// current consumer, with nothing #263 or this event type needs them for (#714
/// review).
const AF_UNIX: i32 = 1;

/// Offsets of the `syscalls:sys_enter_socket` tracepoint (x86_64/aarch64):
/// `domain`(16), `type`(24), `protocol`(32) — the standard three-plain-argument
/// layout also verified for `tgkill`'s `(tgid, tid, sig)`. Verified on 2026-10-07
/// on Alpine (kernel 6.18.50-0-virt, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_socket/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const SOCKET_DOMAIN_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const SOCKET_TYPE_OFFSET: usize = 24;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const SOCKET_PROTOCOL_OFFSET: usize = 32;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const SOCKET_DOMAIN_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const SOCKET_TYPE_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const SOCKET_PROTOCOL_OFFSET: usize = 20;

pub fn sys_enter_socket(ctx: TracePointContext) -> u32 {
    match try_sys_enter_socket(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_socket(ctx: &TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let domain: i64 = unsafe { ctx.read_at(SOCKET_DOMAIN_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let domain: i64 = unsafe { ctx.read_at::<i32>(SOCKET_DOMAIN_OFFSET).map_err(|_| 1u32)? as i64 };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let raw_type: i64 = unsafe { ctx.read_at(SOCKET_TYPE_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let raw_type: i64 = unsafe { ctx.read_at::<i32>(SOCKET_TYPE_OFFSET).map_err(|_| 1u32)? as i64 };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let protocol: i64 = unsafe { ctx.read_at(SOCKET_PROTOCOL_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let protocol: i64 = unsafe {
        ctx.read_at::<i32>(SOCKET_PROTOCOL_OFFSET)
            .map_err(|_| 1u32)? as i64
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    let args = SocketCreateArgs {
        domain: domain as i32,
        socket_type: (raw_type as i32) & !(SOCK_CLOEXEC_FLAG | SOCK_NONBLOCK_FLAG),
        protocol: protocol as i32,
    };
    let _ = SOCKET_CREATE_ARGS.insert(&pid_tgid, &args, 0);

    Ok(0)
}

pub fn sys_exit_socket(ctx: TracePointContext) -> u32 {
    match try_sys_exit_socket(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_exit_socket(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let ret: i64 = unsafe { ctx.read_at(SYS_EXIT_RET_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let ret: i64 = unsafe { ctx.read_at::<i32>(SYS_EXIT_RET_OFFSET).map_err(|_| 1u32)? as i64 };

    let pid_tgid = bpf_get_current_pid_tgid();
    let args = match unsafe { SOCKET_CREATE_ARGS.get(&pid_tgid) } {
        Some(a) => *a,
        None => return Ok(0),
    };
    let _ = SOCKET_CREATE_ARGS.remove(&pid_tgid);

    if ret < 0 || args.domain == AF_UNIX {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = SOCKET_CREATE_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        (*e).meta.pid = (pid_tgid >> 32) as u32;
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
        (*e).domain = args.domain;
        (*e).socket_type = args.socket_type;
        (*e).protocol = args.protocol;
        (*e).fd = ret as u32;

        if SOCKET_CREATE_EVENTS
            .output::<SocketCreateEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping socket event"
            );
        }
    }

    Ok(0)
}

// --- Datagram receive (issue #263) ----------------------------------------------
//
// Same entry/exit shape as accept: `recvfrom(2)`'s source address is written by the
// kernel during the call, so `sys_enter_recvfrom` stashes the caller's `addr`
// pointer and `sys_exit_recvfrom` reads the sender from it on return. `recv(2)` is
// glibc's `recvfrom(..., NULL, NULL)` and is skipped by the NULL check.

/// Ring buffer shared with userspace for `recvfrom` events.
#[map]
static UDP_RECV_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `UdpRecvEvent` (see `EXEC_SCRATCH`).
#[map]
static UDP_RECV_SCRATCH: PerCpuArray<UdpRecvEvent> = PerCpuArray::with_max_entries(1, 0);

/// Stashed at `sys_enter_recvfrom`, consumed at `sys_exit_recvfrom`, keyed by
/// `pid_tgid`. The kernel writes the sender's address and `*addr_len` only on
/// return, and only for sockets that have a source address: a connected TCP
/// socket leaves both untouched, so the exit probe must check `*addr_len` first.
/// Not part of `sensor-linux-wire`'s ABI.
#[repr(C)]
#[derive(Clone, Copy)]
struct RecvfromArgs {
    addr_ptr: u64,
    addr_len_ptr: u64,
}

/// LRU rather than a plain hash: a thread that blocks in `recvfrom` forever leaks
/// its entry, and a full plain map would silently refuse every later insert
/// host-wide. The LRU evicts the stalest stash instead.
#[map]
static RECVFROM_ARGS: LruHashMap<u64, RecvfromArgs> = LruHashMap::with_max_entries(1024, 0);

/// Offsets of `addr`(48) and `addr_len`(56) in `syscalls:sys_enter_recvfrom`
/// (x86_64/aarch64): `fd`(16), `ubuf`(24), `size`(32), `flags`(40), the same layout
/// `sys_enter_sendto` reports. Verified on 2026-10-05 on Alpine (kernel 6.18.50-0-virt,
/// x86_64) via `/sys/kernel/tracing/events/syscalls/sys_enter_recvfrom/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const RECVFROM_ADDR_PTR_OFFSET: usize = 48;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const RECVFROM_ADDR_LEN_PTR_OFFSET: usize = 56;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const RECVFROM_ADDR_PTR_OFFSET: usize = 28;
#[cfg(bpf_target_arch = "x86")]
const RECVFROM_ADDR_LEN_PTR_OFFSET: usize = 32;

pub fn sys_enter_recvfrom(ctx: TracePointContext) -> u32 {
    match stash_recvfrom_addr(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn stash_recvfrom_addr(ctx: &TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let addr_ptr: u64 = unsafe { ctx.read_at(RECVFROM_ADDR_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let addr_len_ptr: u64 = unsafe {
        ctx.read_at(RECVFROM_ADDR_LEN_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    #[cfg(bpf_target_arch = "x86")]
    let addr_ptr: u64 = unsafe {
        ctx.read_at::<u32>(RECVFROM_ADDR_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(bpf_target_arch = "x86")]
    let addr_len_ptr: u64 = unsafe {
        ctx.read_at::<u32>(RECVFROM_ADDR_LEN_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    if addr_ptr != 0 {
        let args = RecvfromArgs {
            addr_ptr,
            addr_len_ptr,
        };
        let _ = RECVFROM_ARGS.insert(&pid_tgid, &args, 0);
    } else {
        let _ = RECVFROM_ARGS.remove(&pid_tgid);
    }

    Ok(0)
}

pub fn sys_exit_recvfrom(ctx: TracePointContext) -> u32 {
    match try_sys_exit_recvfrom(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// No-ops when the matching enter wasn't tracked, the call failed (`ret < 0`), the
/// kernel wrote no source address (`*addr_len == 0`, e.g. a connected TCP socket,
/// whose `addr` buffer still holds whatever the caller put there), or the sender's
/// address family isn't `AF_INET`/`AF_INET6`.
fn try_sys_exit_recvfrom(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let ret: i64 = unsafe { ctx.read_at(SYS_EXIT_RET_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let ret: i64 = unsafe { ctx.read_at::<i32>(SYS_EXIT_RET_OFFSET).map_err(|_| 1u32)? as i64 };

    let pid_tgid = bpf_get_current_pid_tgid();
    let args = match unsafe { RECVFROM_ARGS.get(&pid_tgid) } {
        Some(a) => *a,
        None => return Ok(0),
    };
    let _ = RECVFROM_ARGS.remove(&pid_tgid);

    if ret < 0 {
        return Ok(0);
    }

    let addr_len: u32 = match unsafe { bpf_probe_read_user(args.addr_len_ptr as *const u32) } {
        Ok(len) => len,
        Err(_) => return Ok(0),
    };
    if addr_len == 0 {
        return Ok(0);
    }
    let addr_ptr = args.addr_ptr;

    let family: u16 = match unsafe { bpf_probe_read_user(addr_ptr as *const u16) } {
        Ok(f) => f,
        Err(_) => return Ok(0),
    };
    if family != AF_INET && family != AF_INET6 {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let port_be: u16 =
        unsafe { bpf_probe_read_user((addr_ptr + 2) as *const u16).map_err(|_| 1u32)? };
    let (v4, v6): ([u8; 4], [u8; 16]) = if family == AF_INET {
        (
            unsafe { bpf_probe_read_user((addr_ptr + 4) as *const [u8; 4]).map_err(|_| 1u32)? },
            [0u8; 16],
        )
    } else {
        ([0u8; 4], unsafe {
            bpf_probe_read_user((addr_ptr + 8) as *const [u8; 16]).map_err(|_| 1u32)?
        })
    };

    let e = UDP_RECV_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        (*e).meta.pid = (pid_tgid >> 32) as u32;
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
        (*e).peer_addr_v4 = v4;
        (*e).peer_addr_v6 = v6;
        (*e).peer_port = u16::from_be(port_be);
        (*e).is_ipv6 = family == AF_INET6;
        (*e).size = ret as u32;

        if UDP_RECV_EVENTS.output::<UdpRecvEvent>(&*e, 0).is_err() {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping udp recv event"
            );
        }
    }

    Ok(0)
}

/// Ring buffer shared with userspace for `ptrace` events (issue #265).
#[map]
static PTRACE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `PtraceEvent` (see `EXEC_SCRATCH`).
#[map]
static PTRACE_SCRATCH: PerCpuArray<PtraceEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_ptrace` tracepoint (x86_64/aarch64):
/// `request`(16), `pid`(24), `addr`(32), `data`(40). Verified on 2026-09-22 on
/// Arch (kernel 6.6.9-arch1-1, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_ptrace/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const PTRACE_REQUEST_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const PTRACE_PID_OFFSET: usize = 24;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const PTRACE_ADDR_OFFSET: usize = 32;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const PTRACE_DATA_OFFSET: usize = 40;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const PTRACE_REQUEST_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const PTRACE_PID_OFFSET: usize = 20;
#[cfg(bpf_target_arch = "x86")]
const PTRACE_ADDR_OFFSET: usize = 24;
#[cfg(bpf_target_arch = "x86")]
const PTRACE_DATA_OFFSET: usize = 28;

pub fn sys_enter_ptrace(ctx: TracePointContext) -> u32 {
    match try_sys_enter_ptrace(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_ptrace(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let request: u64 = unsafe { ctx.read_at(PTRACE_REQUEST_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let request: u64 = unsafe {
        ctx.read_at::<u32>(PTRACE_REQUEST_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let target_pid: u64 = unsafe { ctx.read_at(PTRACE_PID_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let target_pid: u64 =
        unsafe { ctx.read_at::<u32>(PTRACE_PID_OFFSET).map_err(|_| 1u32)? as u64 };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let addr: u64 = unsafe { ctx.read_at(PTRACE_ADDR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let addr: u64 = unsafe { ctx.read_at::<u32>(PTRACE_ADDR_OFFSET).map_err(|_| 1u32)? as u64 };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let data: u64 = unsafe { ctx.read_at(PTRACE_DATA_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let data: u64 = unsafe { ctx.read_at::<u32>(PTRACE_DATA_OFFSET).map_err(|_| 1u32)? as u64 };

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = PTRACE_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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
        (*e).request = request;
        (*e).target_pid = target_pid as u32;
        (*e).addr = addr;
        (*e).data = data;

        if PTRACE_EVENTS.output::<PtraceEvent>(&*e, 0).is_err() {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping ptrace event"
            );
        }
    }

    Ok(0)
}

/// Ring buffer shared with userspace for `process_vm_readv` events (issue #265).
#[map]
static PROCESS_VM_READ_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
/// Per-CPU scratch for building one `ProcessVmReadEvent` (see `EXEC_SCRATCH`).
#[map]
static PROCESS_VM_READ_SCRATCH: PerCpuArray<ProcessVmReadEvent> =
    PerCpuArray::with_max_entries(1, 0);

/// Ring buffer shared with userspace for `process_vm_writev` events (issue #265).
#[map]
static PROCESS_VM_WRITE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
/// Per-CPU scratch for building one `ProcessVmWriteEvent` (see `EXEC_SCRATCH`).
#[map]
static PROCESS_VM_WRITE_SCRATCH: PerCpuArray<ProcessVmWriteEvent> =
    PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_process_vm_readv`/`sys_enter_process_vm_writev`
/// tracepoints (x86_64/aarch64, identical shape on both): `pid`(16), `lvec`(24),
/// `liovcnt`(32), `rvec`(40), `riovcnt`(48). Verified on 2026-09-22 on Arch
/// (kernel 6.6.9-arch1-1, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_process_vm_readv/format` (and
/// `..._writev/format`, identical layout).
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const PROCESS_VM_PID_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const PROCESS_VM_LIOVCNT_OFFSET: usize = 32;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const PROCESS_VM_REMOTE_IOV_OFFSET: usize = 40;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const PROCESS_VM_RIOVCNT_OFFSET: usize = 48;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const PROCESS_VM_PID_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const PROCESS_VM_LIOVCNT_OFFSET: usize = 24;
#[cfg(bpf_target_arch = "x86")]
const PROCESS_VM_REMOTE_IOV_OFFSET: usize = 28;
#[cfg(bpf_target_arch = "x86")]
const PROCESS_VM_RIOVCNT_OFFSET: usize = 32;

/// Reads `iovec[0].iov_len` from a user-space `struct iovec *`. On x86_64/aarch64
/// `iov_base` (a pointer, unread here) occupies the first 8 bytes and `iov_len`
/// (`size_t`) the next 8. On i686 the whole struct is 4+4 — a 32-bit userspace
/// process's `struct iovec` has no 8-byte fields — so `iov_len` sits at offset 4,
/// not 8, and is itself 4 bytes wide; reading it the 64-bit way would pull half of
/// the next struct into the value. `0` if `iov_ptr` is null, `count` is `0`
/// (nothing to read), or the read fails — best-effort, matching every other
/// user-memory read in this file.
fn read_first_iovec_len(iov_ptr: u64, count: u64) -> u64 {
    if iov_ptr == 0 || count == 0 {
        return 0;
    }
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    {
        unsafe { bpf_probe_read_user((iov_ptr + 8) as *const u64) }.unwrap_or(0)
    }
    #[cfg(bpf_target_arch = "x86")]
    {
        unsafe { bpf_probe_read_user((iov_ptr + 4) as *const u32) }.unwrap_or(0) as u64
    }
}

pub fn sys_enter_process_vm_readv(ctx: TracePointContext) -> u32 {
    match try_sys_enter_process_vm_readv(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_process_vm_readv(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let target_pid: u64 = unsafe { ctx.read_at(PROCESS_VM_PID_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let target_pid: u64 = unsafe {
        ctx.read_at::<u32>(PROCESS_VM_PID_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let local_iov_count: u64 = unsafe { ctx.read_at(PROCESS_VM_LIOVCNT_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let local_iov_count: u64 = unsafe {
        ctx.read_at::<u32>(PROCESS_VM_LIOVCNT_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let remote_iov_ptr: u64 = unsafe {
        ctx.read_at(PROCESS_VM_REMOTE_IOV_OFFSET)
            .map_err(|_| 1u32)?
    };
    #[cfg(bpf_target_arch = "x86")]
    let remote_iov_ptr: u64 = unsafe {
        ctx.read_at::<u32>(PROCESS_VM_REMOTE_IOV_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let remote_iov_count: u64 =
        unsafe { ctx.read_at(PROCESS_VM_RIOVCNT_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let remote_iov_count: u64 = unsafe {
        ctx.read_at::<u32>(PROCESS_VM_RIOVCNT_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    let remote_iov_len = read_first_iovec_len(remote_iov_ptr, remote_iov_count);

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = PROCESS_VM_READ_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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
        (*e).target_pid = target_pid as u32;
        (*e).local_iov_count = local_iov_count;
        (*e).remote_iov_count = remote_iov_count;
        (*e).remote_iov_len = remote_iov_len;

        if PROCESS_VM_READ_EVENTS
            .output::<ProcessVmReadEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping process_vm_readv event"
            );
        }
    }

    Ok(0)
}

pub fn sys_enter_process_vm_writev(ctx: TracePointContext) -> u32 {
    match try_sys_enter_process_vm_writev(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_process_vm_writev(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let target_pid: u64 = unsafe { ctx.read_at(PROCESS_VM_PID_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let target_pid: u64 = unsafe {
        ctx.read_at::<u32>(PROCESS_VM_PID_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let local_iov_count: u64 = unsafe { ctx.read_at(PROCESS_VM_LIOVCNT_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let local_iov_count: u64 = unsafe {
        ctx.read_at::<u32>(PROCESS_VM_LIOVCNT_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let remote_iov_ptr: u64 = unsafe {
        ctx.read_at(PROCESS_VM_REMOTE_IOV_OFFSET)
            .map_err(|_| 1u32)?
    };
    #[cfg(bpf_target_arch = "x86")]
    let remote_iov_ptr: u64 = unsafe {
        ctx.read_at::<u32>(PROCESS_VM_REMOTE_IOV_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let remote_iov_count: u64 =
        unsafe { ctx.read_at(PROCESS_VM_RIOVCNT_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let remote_iov_count: u64 = unsafe {
        ctx.read_at::<u32>(PROCESS_VM_RIOVCNT_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    let remote_iov_len = read_first_iovec_len(remote_iov_ptr, remote_iov_count);

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = PROCESS_VM_WRITE_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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
        (*e).target_pid = target_pid as u32;
        (*e).local_iov_count = local_iov_count;
        (*e).remote_iov_count = remote_iov_count;
        (*e).remote_iov_len = remote_iov_len;

        if PROCESS_VM_WRITE_EVENTS
            .output::<ProcessVmWriteEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping process_vm_writev event"
            );
        }
    }

    Ok(0)
}

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

/// Offsets of the `syscalls:sys_enter_memfd_create` tracepoint (x86_64/aarch64):
/// `uname`(16), `flags`(24). Verified on 2026-09-22 on Arch (kernel
/// 6.6.9-arch1-1, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_memfd_create/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const MEMFD_CREATE_NAME_PTR_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const MEMFD_CREATE_FLAGS_OFFSET: usize = 24;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const MEMFD_CREATE_NAME_PTR_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const MEMFD_CREATE_FLAGS_OFFSET: usize = 16;

pub fn sys_enter_memfd_create(ctx: TracePointContext) -> u32 {
    match try_sys_enter_memfd_create(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_memfd_create(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let name_ptr: u64 = unsafe {
        ctx.read_at(MEMFD_CREATE_NAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    #[cfg(bpf_target_arch = "x86")]
    let name_ptr: u64 = unsafe {
        ctx.read_at::<u32>(MEMFD_CREATE_NAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let flags: u64 = unsafe { ctx.read_at(MEMFD_CREATE_FLAGS_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let flags: u64 = unsafe {
        ctx.read_at::<u32>(MEMFD_CREATE_FLAGS_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = MEMFD_CREATE_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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

        if name_ptr != 0 {
            if let Ok(name) = bpf_probe_read_user_str_bytes(name_ptr as *const u8, &mut (*e).name) {
                (*e).name_len = name.len() as u16;
            }
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
    match try_sys_exit_memfd_create(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// Completes the event `try_sys_enter_memfd_create` parked in `MEMFD_ARGS` with the
/// descriptor `memfd_create(2)` returned (issue #510). Emits nothing when the matching
/// enter wasn't tracked (`MEMFD_ARGS` was full) or the call failed (`ret < 0`), so the
/// `fd` a consumer sees is always the real descriptor.
fn try_sys_exit_memfd_create(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let ret: i64 = unsafe { ctx.read_at(SYS_EXIT_RET_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let ret: i64 = unsafe { ctx.read_at::<i32>(SYS_EXIT_RET_OFFSET).map_err(|_| 1u32)? as i64 };

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

/// Per-CPU hit counter for the `file_open` LSM hook below — issue #91's foundation
/// slice, observation only. Exists so userspace (`sensor-linux-lsm`) has something
/// concrete to point at proving the hook actually fires, without yet deciding how an
/// LSM-sourced open relates to the tracepoint-sourced `FileOpenEvent` above (double-
/// counting the same open two ways needs a real answer, left to the follow-up that
/// also wires `-EPERM` to a `response` verdict — that plumbing does not exist yet).
#[map]
static LSM_FILE_OPEN_HITS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Observation-only LSM hook (issue #91 foundation). Fires at the security layer
/// regardless of entry path — including `io_uring`-submitted opens, which never reach
/// `syscalls:sys_enter_openat` (`file/open.rs`) (the blinding technique against tracepoint-only
/// EDRs this hook exists to close). Reads no `struct file` field: this slice proves
/// the hook attaches and fires, nothing more, so it needs no `vmlinux` BTF bindings
/// and no per-kernel offset table — same discipline as the rest of this probe.
#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match try_file_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    // `file_open`'s LSM_HOOK signature is `(struct file *file, int retval)` — `arg(1)`
    // is the verdict of whatever LSM program ran before us in the chain. Defer to an
    // earlier `-EPERM` rather than silently overriding it with our own `0`; this hook
    // never denies on its own (no verdict source to enforce yet).
    let retval: i32 = ctx.arg(1);
    if retval != 0 {
        // Forward the veto, not the exact code. `retval` reaches the verifier as an
        // unconstrained scalar (aya's `arg()` extraction loses the sign tracking a
        // raw i32 read would have), so returning it — or any value arithmetically
        // derived from it (`i32::clamp`, an if/else chain assigning to a binding —
        // both tried, both compile to a branchless sign-extend-and-mask select the
        // verifier's range tracking cannot see through) — fails the verifier's LSM
        // exit-state check, which requires every path provably within [-4095, 0]
        // (confirmed on real hardware, kernel 7.2.4: "R0 has smin=1 smax=4294967295
        // should have been in [-4095, 0]", still unconstrained even after an
        // explicit bounds comparison). The actual requirement here is only "never
        // override an earlier LSM's deny with our own allow" — the exact errno
        // doesn't matter to us, so return a fixed, compile-time-constant deny
        // instead of the arbitrary value.
        //
        // Review note (Nikolas, PR #239): this is a lossy, generic deny signal,
        // not a transparent forward — an operator debugging "why was this denied"
        // sees `EPERM` here regardless of whether the earlier LSM actually
        // returned `EACCES`, `EPIPE`, or anything else. Acceptable for this
        // observation-only hook (no policy enforcement reads this value today),
        // but anyone wiring real inline blocking on top of this hook later
        // (#131/#133) should not assume `attach_file_open`'s return value is the
        // original LSM's own errno.
        return Ok(-1);
    }

    if let Some(count) = LSM_FILE_OPEN_HITS.get_ptr_mut(0) {
        // SAFETY: `count` is a valid per-CPU slot pointer from `get_ptr_mut`; no
        // concurrent access from another CPU (each CPU owns its own slot).
        unsafe {
            *count = (*count).wrapping_add(1);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    info!(&ctx, "sensor-linux-ebpf: lsm file_open pid={}", pid);
    Ok(0)
}

// --- Explicit timestamp requests: `inode_setattr` LSM hook (#1036, #1044) ----------------
//
// Fires for every attribute change that reaches `notify_change`, whichever syscall (or
// io_uring op) asked: `utimensat`, `utimes`, `futimens`. `ia_valid` tells which attributes
// the caller named; `ATTR_ATIME_SET`/`ATTR_MTIME_SET` mean the caller chose the time itself,
// as opposed to `ATTR_ATIME`/`ATTR_MTIME` alone, which the kernel fills with "now" (a write,
// `touch` without `-d`, `UTIME_NOW`). Only the former is timestomping.
//
// The structs it reads (`iattr`, `dentry`, `qstr`) are read at offsets userspace resolves
// from the kernel BTF and patches into the globals below, the same way as the scheduler
// offsets: there are no vmlinux bindings here. Userspace sets `INODE_SETATTR_ENABLED` only
// when every offset resolved, so a kernel whose layout was not understood emits nothing
// rather than reading garbage.

/// 1 when the offsets below were resolved. Patched by the loader.
#[unsafe(no_mangle)]
static INODE_SETATTR_ENABLED: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
static IATTR_VALID_OFFSET: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
static IATTR_ATIME_OFFSET: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
static IATTR_MTIME_OFFSET: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
static DENTRY_PARENT_OFFSET: Global<u32> = Global::new(0);
/// `offsetof(struct dentry, d_name) + offsetof(struct qstr, name)`.
#[unsafe(no_mangle)]
static DENTRY_NAME_PTR_OFFSET: Global<u32> = Global::new(0);

/// `ATTR_ATIME_SET` / `ATTR_MTIME_SET` of `include/linux/fs.h`: bits 7 and 8 of `ia_valid`
/// since `ATTR_MODE` was bit 0 (stable uapi-adjacent values, not in BTF: they are macros).
const ATTR_ATIME_SET: u32 = 1 << 7;
const ATTR_MTIME_SET: u32 = 1 << 8;

/// Ring buffer shared with userspace for explicit timestamp requests. One event is about
/// 400 bytes and `tar x`/`cp -a` of a few thousand files emit one per file in a burst: 256 KiB
/// lost two thirds of a 3000-file unpack in the lab (#1044), so this one has 1 MiB.
#[map]
static FILE_SET_TIME_EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

/// Per-CPU scratch for building one `FileSetTimeEvent` (see `EXEC_SCRATCH`).
#[map]
static SET_TIME_SCRATCH: PerCpuArray<FileSetTimeEvent> = PerCpuArray::with_max_entries(1, 0);

/// Reads a `struct timespec64` (`tv_sec` at 0, `tv_nsec` at 8) at `base + offset`.
#[inline(always)]
fn read_timespec(base: *const u8, offset: u32) -> Option<(i64, i64)> {
    let at = unsafe { base.add(offset as usize) };
    let sec: i64 = unsafe { bpf_probe_read_kernel(at.cast::<i64>()) }.ok()?;
    let nsec: i64 = unsafe { bpf_probe_read_kernel(at.add(8).cast::<i64>()) }.ok()?;
    Some((sec, nsec))
}

#[lsm(hook = "inode_setattr")]
pub fn inode_setattr(ctx: LsmContext) -> i32 {
    match try_inode_setattr(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_inode_setattr(ctx: LsmContext) -> Result<i32, i32> {
    // `(struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *attr, int retval)`:
    // `arg(3)` is the verdict of an earlier LSM in the chain. Never override its deny; see
    // `try_file_open` for why the code is a constant and not forwarded.
    let retval: i32 = ctx.arg(3);
    if retval != 0 {
        return Ok(-1);
    }
    if INODE_SETATTR_ENABLED.load() == 0 {
        return Ok(0);
    }
    let dentry: *const u8 = ctx.arg(1);
    let attr: *const u8 = ctx.arg(2);
    if dentry.is_null() || attr.is_null() {
        return Ok(0);
    }

    let ia_valid: u32 = match unsafe {
        bpf_probe_read_kernel(attr.add(IATTR_VALID_OFFSET.load() as usize).cast::<u32>())
    } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };
    let mut flags: u16 = 0;
    if ia_valid & ATTR_ATIME_SET != 0 {
        flags |= SET_TIME_ATIME;
    }
    if ia_valid & ATTR_MTIME_SET != 0 {
        flags |= SET_TIME_MTIME;
    }
    if flags == 0 {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 0i32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();
    let e = SET_TIME_SCRATCH.get_ptr_mut(0).ok_or(0i32)?;
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

        if flags & SET_TIME_ATIME != 0
            && let Some((sec, nsec)) = read_timespec(attr, IATTR_ATIME_OFFSET.load())
        {
            (*e).atime_sec = sec;
            (*e).atime_nsec = nsec;
        }
        if flags & SET_TIME_MTIME != 0
            && let Some((sec, nsec)) = read_timespec(attr, IATTR_MTIME_OFFSET.load())
        {
            (*e).mtime_sec = sec;
            (*e).mtime_nsec = nsec;
        }

        // The dentry chain, file first, one fixed slot per name: a constant-bound loop the
        // verifier can follow (a variable-offset copy into one path buffer is what it
        // refuses). It ends at the filesystem root, whose `d_parent` is itself.
        let mut current = dentry;
        let mut depth = 0usize;
        let mut reached_root = false;
        while depth < SET_TIME_COMPONENTS {
            let parent: *const u8 = match bpf_probe_read_kernel(
                current
                    .add(DENTRY_PARENT_OFFSET.load() as usize)
                    .cast::<*const u8>(),
            ) {
                Ok(p) => p,
                Err(_) => break,
            };
            if parent == current || parent.is_null() {
                reached_root = true;
                break;
            }
            let name: *const u8 = match bpf_probe_read_kernel(
                current
                    .add(DENTRY_NAME_PTR_OFFSET.load() as usize)
                    .cast::<*const u8>(),
            ) {
                Ok(p) => p,
                Err(_) => break,
            };
            match bpf_probe_read_kernel_str_bytes(name, &mut (*e).components[depth]) {
                Ok(bytes) => {
                    if bytes.len() >= SET_TIME_COMPONENT_LEN - 1 {
                        flags |= SET_TIME_TRUNCATED;
                    }
                }
                Err(_) => break,
            }
            depth += 1;
            current = parent;
        }
        if !reached_root {
            flags |= SET_TIME_TRUNCATED;
        }
        (*e).depth = depth as u8;
        (*e).flags = flags;

        if FILE_SET_TIME_EVENTS
            .output::<FileSetTimeEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping set-time event"
            );
        }
    }
    Ok(0)
}

// --- Mount/unmount and signal telemetry (issue #362) --------------------------------
//
// Feeds the two platform-neutral `schema` variants #96 introduced for macOS
// (`Event::Mount`, `Event::Signal`) from Linux. See this crate's `WIRE_VERSION` v12
// changelog (`sensor-linux-wire`) for the full rationale.

/// Ring buffer shared with userspace for `mount`/`umount2` events.
#[map]
static MOUNT_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `MountEvent` (see `EXEC_SCRATCH`).
#[map]
static MOUNT_SCRATCH: PerCpuArray<MountEvent> = PerCpuArray::with_max_entries(1, 0);

/// `MS_RDONLY` (`linux/mount.h`) — stable UAPI constant, not a kernel-version-
/// dependent offset.
const MS_RDONLY: u64 = 1;

/// Offsets of the `syscalls:sys_enter_mount` tracepoint: `dev_name`(16, the
/// `source` arg), `dir_name`(24, `target`), `type`(32, `filesystemtype`),
/// `flags`(40, `mountflags`), `data`(48, unread). Verified on 2026-09-23 on Ubuntu
/// 22.04 (kernel 5.15.0-91-generic, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_mount/format` — matched the
/// standard `syscalls:*` layout inferred here on first write, no offset changes
/// needed.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const MOUNT_SOURCE_PTR_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const MOUNT_TARGET_PTR_OFFSET: usize = 24;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const MOUNT_FSTYPE_PTR_OFFSET: usize = 32;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const MOUNT_FLAGS_OFFSET: usize = 40;
#[cfg(bpf_target_arch = "x86")]
const MOUNT_SOURCE_PTR_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const MOUNT_TARGET_PTR_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const MOUNT_FSTYPE_PTR_OFFSET: usize = 20;
#[cfg(bpf_target_arch = "x86")]
const MOUNT_FLAGS_OFFSET: usize = 24;

/// glibc's `umount2(2)` libc wrapper maps to a kernel syscall the kernel itself
/// (`fs/namespace.c`) names plain `umount` — `SYSCALL_DEFINE2(umount, ...)`, not
/// `umount2` — so the tracepoint is `syscalls:sys_enter_umount`, confirmed live
/// (the assumed `sys_enter_umount2` name does not exist; this file's doc comments
/// below keep saying "`umount2(2)`" for the libc call itself, which IS
/// `umount2()`, while the identifiers here match the kernel's own name).
/// Offsets: `name`(16, the target path), `flags`(24). Verified on 2026-09-23 on
/// Ubuntu 22.04 (kernel 5.15.0-91-generic, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_umount/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const UMOUNT_TARGET_PTR_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const UMOUNT_TARGET_PTR_OFFSET: usize = 12;

pub fn sys_enter_mount(ctx: TracePointContext) -> u32 {
    match try_sys_enter_mount(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_mount(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let source_ptr: u64 = unsafe { ctx.read_at(MOUNT_SOURCE_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let source_ptr: u64 = unsafe {
        ctx.read_at::<u32>(MOUNT_SOURCE_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let target_ptr: u64 = unsafe { ctx.read_at(MOUNT_TARGET_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let target_ptr: u64 = unsafe {
        ctx.read_at::<u32>(MOUNT_TARGET_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let fstype_ptr: u64 = unsafe { ctx.read_at(MOUNT_FSTYPE_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let fstype_ptr: u64 = unsafe {
        ctx.read_at::<u32>(MOUNT_FSTYPE_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let flags: u64 = unsafe { ctx.read_at(MOUNT_FLAGS_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let flags: u64 = unsafe { ctx.read_at::<u32>(MOUNT_FLAGS_OFFSET).map_err(|_| 1u32)? as u64 };

    emit_mount_event(&ctx, target_ptr, source_ptr, fstype_ptr, flags, true)
}

pub fn sys_enter_umount(ctx: TracePointContext) -> u32 {
    match try_sys_enter_umount(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_umount(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let target_ptr: u64 = unsafe { ctx.read_at(UMOUNT_TARGET_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let target_ptr: u64 = unsafe {
        ctx.read_at::<u32>(UMOUNT_TARGET_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    emit_mount_event(&ctx, target_ptr, 0, 0, 0, false)
}

/// Shared by `sys_enter_mount` and `sys_enter_umount` above. `source_ptr`/
/// `fstype_ptr` are `0` on an unmount (`umount2(2)` has neither argument) — left
/// zero-length on the wire event, which `normalize::mount` maps to `None`.
///
/// Always inlined, on purpose: with six parameters LLVM 23 can emit this as a real
/// BPF-to-BPF call that passes the sixth on the stack, and the 7.2 kernel's verifier
/// rejects that ("callee expects 6 args, stack arg1 is not initialized"), so
/// `raw_sys_enter` fails to load and the agent exits seconds after it starts.
#[inline(always)]
fn emit_mount_event(
    ctx: &TracePointContext,
    mount_point_ptr: u64,
    source_ptr: u64,
    fstype_ptr: u64,
    flags: u64,
    mounted: bool,
) -> Result<u32, u32> {
    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = MOUNT_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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

        if mount_point_ptr != 0 {
            if let Ok(path) =
                bpf_probe_read_user_str_bytes(mount_point_ptr as *const u8, &mut (*e).mount_point)
            {
                (*e).mount_point_len = path.len() as u16;
            }
        }
        if source_ptr != 0 {
            if let Ok(path) =
                bpf_probe_read_user_str_bytes(source_ptr as *const u8, &mut (*e).source)
            {
                (*e).source_len = path.len() as u16;
            }
        }
        if fstype_ptr != 0 {
            if let Ok(s) = bpf_probe_read_user_str_bytes(fstype_ptr as *const u8, &mut (*e).fs_type)
            {
                (*e).fs_type_len = s.len() as u8;
            }
        }
        (*e).readonly = mounted && (flags & MS_RDONLY) != 0;
        (*e).mounted = mounted;

        if MOUNT_EVENTS.output::<MountEvent>(&*e, 0).is_err() {
            warn!(
                ctx,
                "sensor-linux-ebpf: ring buffer full, dropping mount event"
            );
        }
    }

    Ok(0)
}

/// Single-slot map holding the agent's own pid, written by userspace before any
/// signal probe below is attached (issue #362). Filters `kill`/`tgkill` at the
/// probe to the "tamper subset, never the firehose" this ring buffer can afford —
/// system-wide signal traffic (job control, `SIGCHLD` reaping, ordinary process
/// supervision) is far too high-volume to forward unfiltered. v1 scope: only the
/// agent's own pid is watched; the watchdog process and other registered security
/// processes are a documented future extension (see `sensor-linux-wire`'s
/// `WIRE_VERSION` v12 changelog), not implemented here.
///
/// Also reused by [`is_agent_own_pid`] (#514) to drop the agent's own file
/// activity at its source — same value, different consumer.
#[map]
static SIGNAL_WATCH_PID: Array<u32> = Array::with_max_entries(1, 0);

/// Whether `target_pid` is a signal target this sensor cares about — see
/// `SIGNAL_WATCH_PID` above. `0` (unset) never matches: userspace hasn't written
/// its pid yet, or wrote it as an explicit "watch nothing".
fn is_watched_signal_target(target_pid: u32) -> bool {
    matches!(SIGNAL_WATCH_PID.get(0), Some(&watched) if watched != 0 && watched == target_pid)
}

/// True when `pid` is the agent's own process — the same identity
/// `SIGNAL_WATCH_PID` already carries for the signal-tamper probes above,
/// reused here for a different purpose (#514): userspace's `EventSpool::push`
/// does an `open`+2×`write`+`sync_data` on the local spool file for every
/// single event it enriches (`crates/store/src/spool.rs`), all attributed to
/// the agent's own pid. Under a burst that already floods `FILE_WRITE_EVENTS`
/// (a `docker run`'s containerd/runc/dockerd writes), that self-traffic
/// roughly doubles the pressure on the same 256 KiB ring buffer, and every
/// drop's `warn!` was on top of that. It was already filtered — but only
/// *after* userspace paid for the ring-buffer slot, the decode, and the
/// allocation (`drain!`'s `schema_event.meta().pid != own_pid`,
/// `crates/sensors/linux/userspace/src/sensor.rs`). Dropping it here instead
/// gives that ring-buffer capacity back to real telemetry. The userspace
/// filter is left in place as a defense-in-depth for the narrow startup
/// window before `write_signal_watch_pid` runs (see its own doc comment).
fn is_agent_own_pid(pid: u32) -> bool {
    is_watched_signal_target(pid)
}

/// Ring buffer shared with userspace for `kill`/`tgkill` events that pass the
/// `SIGNAL_WATCH_PID` filter.
#[map]
static SIGNAL_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

/// Last `SIGKILL` sent to a watched target (issue #362). The ring-buffer event
/// above cannot attribute a `SIGKILL`: the victim is the agent itself, which dies
/// before it drains the buffer. This single slot is written synchronously at
/// `sys_enter_kill`/`sys_enter_tgkill`, before the kernel even delivers the signal.
/// Userspace pins it to bpffs, so the restarted agent can read who killed its
/// predecessor. Unpinned (no bpffs), it still loads, but the record dies with the
/// agent. Only `SIGKILL` lands here, because every catchable signal is already
/// attributed by `agent::kill_loudness`, and a `SIGSTOP` does not end the process.
#[map]
static SIGNAL_TAMPER_LAST: Array<SignalEvent> = Array::with_max_entries(1, 0);

/// `SIGKILL`'s number, the same on every Linux architecture.
const SIGKILL: u32 = 9;

/// Per-CPU scratch for building one `SignalEvent` (see `EXEC_SCRATCH`).
#[map]
static SIGNAL_SCRATCH: PerCpuArray<SignalEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_kill` tracepoint: `pid`(16), `sig`(24) on
/// x86_64/aarch64 — same inferred-not-verified status as the mount offsets above.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const KILL_PID_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const KILL_SIG_OFFSET: usize = 24;
#[cfg(bpf_target_arch = "x86")]
const KILL_PID_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const KILL_SIG_OFFSET: usize = 16;

/// Offsets of the `syscalls:sys_enter_tgkill` tracepoint: `tgid`(16), `tid`(24),
/// `sig`(32) on x86_64/aarch64 — same inferred-not-verified status as the mount
/// offsets above. `tgid` is the field compared against `SIGNAL_WATCH_PID`, the
/// same whole-process identity `kill(2)`'s `pid` argument carries — `tid` (the
/// specific thread within that group) is read but not otherwise used.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const TGKILL_TGID_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const TGKILL_SIG_OFFSET: usize = 32;
#[cfg(bpf_target_arch = "x86")]
const TGKILL_TGID_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const TGKILL_SIG_OFFSET: usize = 20;

// `tkill(2)` is deliberately NOT attached: it takes a thread id, not a
// thread-group id, and this filter watches a whole-process pid
// (`SIGNAL_WATCH_PID`) — there is no field in `tkill(2)`'s argument list
// comparable to that identity. Superseded by `tgkill(2)` in practice (glibc's
// `pthread_kill` uses `tgkill`, and a plain `kill(1)` uses `kill(2)`), so this
// is a narrow, accepted gap rather than a missing common path **for the agent's own pid**.
// The other security tools do not have it: `raw_signal_generate` (#1103) sees `tkill`,
// `pidfd_send_signal` and `rt_sigqueueinfo` too, and compares the target's `tgid`.

pub fn sys_enter_kill(ctx: TracePointContext) -> u32 {
    match try_sys_enter_kill(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_kill(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let pid: u64 = unsafe { ctx.read_at(KILL_PID_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let pid: u64 = unsafe { ctx.read_at::<u32>(KILL_PID_OFFSET).map_err(|_| 1u32)? as u64 };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let sig: u64 = unsafe { ctx.read_at(KILL_SIG_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let sig: u64 = unsafe { ctx.read_at::<u32>(KILL_SIG_OFFSET).map_err(|_| 1u32)? as u64 };

    emit_signal_event(&ctx, pid as u32, sig as u32)
}

pub fn sys_enter_tgkill(ctx: TracePointContext) -> u32 {
    match try_sys_enter_tgkill(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_tgkill(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let tgid: u64 = unsafe { ctx.read_at(TGKILL_TGID_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let tgid: u64 = unsafe { ctx.read_at::<u32>(TGKILL_TGID_OFFSET).map_err(|_| 1u32)? as u64 };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let sig: u64 = unsafe { ctx.read_at(TGKILL_SIG_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let sig: u64 = unsafe { ctx.read_at::<u32>(TGKILL_SIG_OFFSET).map_err(|_| 1u32)? as u64 };

    emit_signal_event(&ctx, tgid as u32, sig as u32)
}

/// Shared by `sys_enter_kill` and `sys_enter_tgkill` above. Drops silently
/// (`Ok(0)`, no scratch touch) when `target_pid` fails the `SIGNAL_WATCH_PID`
/// filter — this is the "regression-tested: ordinary signal traffic between
/// unrelated processes produces zero events" boundary issue #362 requires.
fn emit_signal_event(ctx: &TracePointContext, target_pid: u32, sig: u32) -> Result<u32, u32> {
    if !is_watched_signal_target(target_pid) {
        return Ok(0);
    }

    let e = SIGNAL_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        fill_signal_event(e, target_pid, sig)?;

        // Written before the ring-buffer output, so the slot is recorded even
        // when the ring is full.
        if sig == SIGKILL && SIGNAL_TAMPER_LAST.set(0, &*e, 0).is_err() {
            warn!(
                ctx,
                "sensor-linux-ebpf: failed to record SIGKILL in SIGNAL_TAMPER_LAST"
            );
        }

        if SIGNAL_EVENTS.output::<SignalEvent>(&*e, 0).is_err() {
            warn!(
                ctx,
                "sensor-linux-ebpf: ring buffer full, dropping signal event"
            );
        }
    }

    Ok(0)
}

/// Fills `e` with a signal event: `meta` is the SENDER (the current task), the target is
/// `target_pid` — same convention as macOS's `SignalToEsClient` (see `SignalEvent`'s doc comment
/// in `sensor-linux-wire`). Shared by the syscall probes above and [`emit_tool_signal_event`].
///
/// # Safety
///
/// `e` must point at a valid, writable `SignalEvent` (the per-CPU scratch slot).
#[inline(always)]
unsafe fn fill_signal_event(e: *mut SignalEvent, target_pid: u32, sig: u32) -> Result<(), u32> {
    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();
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
        (*e).signal = sig;
        (*e).target_pid = target_pid;
    }
    Ok(())
}

/// Thread-group ids of the processes of the listed security units (`SECURITY_SERVICES`), filled
/// and refreshed by userspace from each unit's cgroup (#1103). The value is the process's
/// `SigCgt` (the signals it catches, bit `sig - 1`) at scan time: a caught reload signal is
/// dropped in the probe. The size is `SIGNAL_WATCH_TOOLS_ENTRIES`, checked by the userspace
/// loader against `SECURITY_SERVICES.len()` times the per-unit process cap, with headroom.
#[map]
static SIGNAL_WATCH_TOOLS: HashMap<u32, u64> =
    HashMap::with_max_entries(sensor_linux_wire::SIGNAL_WATCH_TOOLS_ENTRIES, 0);

/// Tool signals lost because `SIGNAL_EVENTS` was full, per CPU: userspace sums and reports it.
#[map]
static SIGNAL_TOOL_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// The `SigCgt` of `tgid` when it is a process of a listed security unit, `None` otherwise.
#[inline(always)]
pub(crate) fn watched_tool_sigcgt(tgid: u32) -> Option<u64> {
    // SAFETY: the map is only read here; the value is copied out before the reference ends.
    unsafe { SIGNAL_WATCH_TOOLS.get(&tgid) }.copied()
}

/// Emits a signal sent to a process of a listed security unit, from the `signal_generate`
/// raw tracepoint (#1103). The target is already known to be watched and the signal to come from
/// a process (not the kernel): `raw_signal_generate` checked both. A kill of a tool does not take
/// the agent down, so the ring buffer is enough: nothing goes to `SIGNAL_TAMPER_LAST`.
#[inline(always)]
pub(crate) fn emit_tool_signal_event(
    ctx: &RawTracePointContext,
    target_tgid: u32,
    sig: u32,
) -> Result<u32, u32> {
    let e = SIGNAL_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    // SAFETY: `e` is this CPU's scratch slot (one per CPU, and a probe does not nest on its
    // own CPU), valid for a `SignalEvent`; `fill_signal_event` initialises it before `output`
    // copies it, and the drop counter is this CPU's own slot.
    unsafe {
        fill_signal_event(e, target_tgid, sig)?;
        if SIGNAL_EVENTS.output::<SignalEvent>(&*e, 0).is_err() {
            if let Some(drops) = SIGNAL_TOOL_DROPS.get_ptr_mut(0) {
                *drops += 1;
            }
            warn!(
                ctx,
                "sensor-linux-ebpf: ring buffer full, dropping signal event"
            );
        }
    }
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
