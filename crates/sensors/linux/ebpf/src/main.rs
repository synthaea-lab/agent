#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes, bpf_probe_read_user,
        bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::{info, warn};
use sensor_linux_wire::{
    ConnectEvent, ExecEvent, FileOpenEvent, LineageEntry, MAX_CMDLINE_LEN, TASK_COMM_LEN,
};

// Parent lineage (ppid + parent comm) comes from tracepoint fields via `PROC_LINEAGE`
// (issue #53) — no `real_parent` walk, so `read_ppid` and its per-kernel frozen
// offsets are gone. The executed image comes from the `sched_process_exec` tracepoint
// (issue #111). `cmdline` is still read from `mm->arg_start..arg_end` by frozen offset
// (`vmlinux*` bindings on 64-bit, `i686_offsets` on i686), unchanged from before —
// making that read portable too is tracked separately.
#[allow(
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unsafe_op_in_unsafe_fn
)]
#[cfg(bpf_target_arch = "x86_64")]
#[rustfmt::skip]
mod vmlinux;

/// aarch64 bindings from the live BTF of an Ampere/Ubuntu-24.04 instance (kernel
/// `6.17.0-1018-oracle`); 64-bit like x86_64, so standard struct reflection applies.
#[allow(
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unsafe_op_in_unsafe_fn
)]
#[cfg(bpf_target_arch = "aarch64")]
#[rustfmt::skip]
mod vmlinux_aarch64;

/// Ring buffer shared with userspace for `exec` events. `ExecEvent` (`image` +
/// `cmdline`) is larger than the 512-byte eBPF stack, so it is assembled in the
/// per-CPU `EXEC_SCRATCH` entry and emitted with a single `output` copy — the
/// standard libbpf/Tetragon "heap map" pattern. Filling a reserved slot field by
/// field instead needs per-byte loops over MAX_PATH_LEN / MAX_CMDLINE_LEN, which
/// blow the verifier's 1M-instruction budget on pre-6.6 kernels (5.15, 6.1).
#[map]
static EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `ExecEvent` off the stack (see `EXEC_EVENTS`).
#[map]
static EXEC_SCRATCH: PerCpuArray<ExecEvent> = PerCpuArray::with_max_entries(1, 0);

/// pid → parent identity (`real_parent->tgid` + its `comm`). Filled by
/// `sched_process_fork` and by userspace `/proc` priming at startup; entries removed
/// by `sched_process_exit`. Sized to the realistic live-pid space — a full map (fork
/// bomb) simply yields `ppid = 0`, which the correlation rules tolerate.
#[map]
static PROC_LINEAGE: HashMap<u32, LineageEntry> = HashMap::with_max_entries(65_536, 0);

/// `real_parent` of the current thread group, from `PROC_LINEAGE`. `0` when the
/// parent forked before the probe attached and `/proc` priming missed it — callers
/// treat `0` as "unknown", never as pid 0.
fn lineage_ppid() -> u32 {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    match unsafe { PROC_LINEAGE.get(&tgid) } {
        Some(entry) => entry.ppid,
        None => 0,
    }
}

/// Reads the argv blob (`\0`-separated argument strings) of the process being exec'd
/// straight from its user memory: `mm->arg_start..arg_end`, the buffer the kernel
/// places on the new stack at exec time — more robust than a deferred
/// `/proc/{pid}/cmdline` read that would miss short-lived processes. Frozen
/// `task_struct`/`mm_struct` offsets (BTF reflection on 64-bit, raw offsets on i686):
/// correct on the kernel the bindings came from, a short/empty read elsewhere, never a
/// crash. Making this portable is tracked separately — the lineage read (#53) no
/// longer touches these offsets.
///
/// Writes `[0..len]` of `buf`; `buf` must be a **stack** buffer (`bpf_probe_read_user`
/// only writes to stack, not to ring-buffer memory) and zero-initialised (the tail is
/// left untouched). `None` for kernel threads (null `mm`) or read failure.
#[cfg(bpf_target_arch = "x86_64")]
#[inline(always)]
fn read_argv(buf: &mut [u8; MAX_CMDLINE_LEN]) -> Option<u16> {
    let task = unsafe { bpf_get_current_task() } as *const vmlinux::task_struct;
    let mm: *const vmlinux::mm_struct =
        unsafe { bpf_probe_read_kernel(core::ptr::addr_of!((*task).mm) as *const _).ok()? };
    if mm.is_null() {
        return None;
    }
    let arg_start: u64 = unsafe {
        bpf_probe_read_kernel(core::ptr::addr_of!((*mm).__bindgen_anon_1.arg_start) as *const _)
            .ok()?
    };
    let arg_end: u64 = unsafe {
        bpf_probe_read_kernel(core::ptr::addr_of!((*mm).__bindgen_anon_1.arg_end) as *const _)
            .ok()?
    };
    let len = arg_end
        .saturating_sub(arg_start)
        .min(MAX_CMDLINE_LEN as u64) as usize;
    if len == 0 {
        return None;
    }
    unsafe { bpf_probe_read_user_buf(arg_start as *const u8, &mut buf[..len]).ok()? };
    Some(len as u16)
}

/// `task_struct`/`mm_struct` offsets for the i686 target (Debian 12 Bookworm, kernel
/// `6.1.0-52-686-pae`), via `pahole` on the `-dbg` vmlinux. Specific to that kernel —
/// regenerate if it changes. Raw offsets rather than `bindgen` reflection: on
/// `bpfel-unknown-none` a `c_ulong`/pointer is always 8 bytes regardless of the target
/// host arch, so 32-bit BTF-generated bindings would misplace every field.
#[cfg(bpf_target_arch = "x86")]
mod i686_offsets {
    pub const TASK_MM_OFFSET: usize = 1008;
    pub const MM_ARG_START_OFFSET: usize = 164;
    pub const MM_ARG_END_OFFSET: usize = 168;
}

#[cfg(bpf_target_arch = "x86")]
#[inline(always)]
fn read_argv(buf: &mut [u8; MAX_CMDLINE_LEN]) -> Option<u16> {
    use i686_offsets::{MM_ARG_END_OFFSET, MM_ARG_START_OFFSET, TASK_MM_OFFSET};
    let task = unsafe { bpf_get_current_task() } as usize;
    let mm: u32 = unsafe { bpf_probe_read_kernel((task + TASK_MM_OFFSET) as *const u32).ok()? };
    if mm == 0 {
        return None;
    }
    let arg_start: u32 =
        unsafe { bpf_probe_read_kernel((mm as usize + MM_ARG_START_OFFSET) as *const u32).ok()? };
    let arg_end: u32 =
        unsafe { bpf_probe_read_kernel((mm as usize + MM_ARG_END_OFFSET) as *const u32).ok()? };
    let len = arg_end
        .saturating_sub(arg_start)
        .min(MAX_CMDLINE_LEN as u32) as usize;
    if len == 0 {
        return None;
    }
    unsafe { bpf_probe_read_user_buf(arg_start as *const u8, &mut buf[..len]).ok()? };
    Some(len as u16)
}

#[cfg(bpf_target_arch = "aarch64")]
#[inline(always)]
fn read_argv(buf: &mut [u8; MAX_CMDLINE_LEN]) -> Option<u16> {
    let task = unsafe { bpf_get_current_task() } as *const vmlinux_aarch64::task_struct;
    let mm: *const vmlinux_aarch64::mm_struct =
        unsafe { bpf_probe_read_kernel(core::ptr::addr_of!((*task).mm) as *const _).ok()? };
    if mm.is_null() {
        return None;
    }
    let arg_start: u64 = unsafe {
        bpf_probe_read_kernel(core::ptr::addr_of!((*mm).__bindgen_anon_1.arg_start) as *const _)
            .ok()?
    };
    let arg_end: u64 = unsafe {
        bpf_probe_read_kernel(core::ptr::addr_of!((*mm).__bindgen_anon_1.arg_end) as *const _)
            .ok()?
    };
    let len = arg_end
        .saturating_sub(arg_start)
        .min(MAX_CMDLINE_LEN as u64) as usize;
    if len == 0 {
        return None;
    }
    unsafe { bpf_probe_read_user_buf(arg_start as *const u8, &mut buf[..len]).ok()? };
    Some(len as u16)
}

// --- sched:sched_process_fork -------------------------------------------------------
//
// Records `child_pid -> {parent_pid, parent_comm}`. All three come from the
// tracepoint's own record — a `char[16]` and two `pid_t`s — so the offsets are the
// standard tracepoint layout (8-byte common header, then the fields) and do not vary
// with pointer width across the x86_64 / i686 / aarch64 targets. Verify against
// `/sys/kernel/tracing/events/sched/sched_process_fork/format` when adding a kernel
// row to `lab/MATRIX.md`.
const FORK_PARENT_COMM_OFFSET: usize = 8;
const FORK_PARENT_PID_OFFSET: usize = 24;
const FORK_CHILD_PID_OFFSET: usize = 44;

#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    let _ = try_sched_process_fork(&ctx);
    0
}

fn try_sched_process_fork(ctx: &TracePointContext) -> Result<(), i64> {
    let child_pid: i32 = unsafe { ctx.read_at(FORK_CHILD_PID_OFFSET).map_err(|_| 1i64)? };
    let parent_pid: i32 = unsafe { ctx.read_at(FORK_PARENT_PID_OFFSET).map_err(|_| 1i64)? };
    let comm: [u8; TASK_COMM_LEN] =
        unsafe { ctx.read_at(FORK_PARENT_COMM_OFFSET).map_err(|_| 1i64)? };

    let entry = LineageEntry {
        ppid: parent_pid as u32,
        comm,
    };
    // BPF_ANY: overwrite a stale entry left by pid reuse.
    let _ = PROC_LINEAGE.insert(&(child_pid as u32), &entry, 0);
    Ok(())
}

// --- sched:sched_process_exit -----------------------------------------------------
//
// `sched_process_*` share the `sched_process_template` record: `comm[16]` at 8,
// `pid_t pid` at 24. Arch-independent.
const EXIT_PID_OFFSET: usize = 24;

#[tracepoint]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    if let Ok(pid) = unsafe { ctx.read_at::<i32>(EXIT_PID_OFFSET) } {
        let _ = PROC_LINEAGE.remove(&(pid as u32));
    }
    0
}

// --- sched:sched_process_exec --------------------------------------------------------
//
// Standard tracepoint layout, validated on 2026-08-12 on WSL2 6.6.114:
// `__data_loc char[] filename` at 8 (u32: low 16 bits offset, high 16 bits length),
// `pid_t pid` at 12. Arch-independent (no pointers in the record).
const FILENAME_DATA_LOC_OFFSET: usize = 8;
const PID_OFFSET: usize = 12;

#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    match try_sched_process_exec(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_process_exec(ctx: TracePointContext) -> Result<u32, u32> {
    let pid: i32 = unsafe { ctx.read_at(PID_OFFSET).map_err(|_| 1u32)? };
    let tgid = pid as u32;

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let data_loc: u32 = unsafe { ctx.read_at(FILENAME_DATA_LOC_OFFSET).map_err(|_| 1u32)? };
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();
    let timestamp_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    // `cmdline` is bounced through the stack — `bpf_probe_read_user` reads best
    // into a stack buffer — but it is the only stack value here now.
    let mut cmdline = [0u8; MAX_CMDLINE_LEN];
    let cmdline_len = read_argv(&mut cmdline).unwrap_or(0);

    // Assemble the event in per-CPU scratch, not on the stack and not field by
    // field in a reserved ring-buffer slot (that needs per-byte loops over
    // MAX_PATH_LEN / MAX_CMDLINE_LEN, which blow the verifier's 1M-instruction
    // budget on pre-6.6 kernels). One `output` copy emits it.
    let e = EXEC_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        (*e).meta.pid = tgid;
        (*e).meta.uid = uid_gid as u32;
        (*e).meta.gid = (uid_gid >> 32) as u32;
        (*e).meta.timestamp_ns = timestamp_ns;
        (*e).meta.ppid = 0;
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            (*e).meta.comm[i] = comm[i];
            i += 1;
        }
        // Parent identity from the fork-lineage map.
        if let Some(l) = PROC_LINEAGE.get(&tgid) {
            (*e).meta.ppid = l.ppid;
            let mut i = 0usize;
            while i < TASK_COMM_LEN {
                (*e).pcomm[i] = l.comm[i];
                i += 1;
            }
        }

        // Authoritative image path: the tracepoint's own `filename` field (the
        // kernel's resolved `bprm->filename`), never argv[0]. One bounded
        // `…_str_bytes` copy into the scratch entry.
        let filename_offset = (data_loc & 0xffff) as usize;
        let filename_src = (ctx.as_ptr() as *const u8).add(filename_offset);
        if let Ok(s) = bpf_probe_read_kernel_str_bytes(filename_src, &mut (*e).image) {
            (*e).image_len = s.len() as u16;
        }

        // argv blob: one fixed-size copy of the stack buffer. `read_argv` wrote
        // `[0..cmdline_len]`; the rest was zero-initialised (and so is the scratch
        // entry, from the `write_bytes` above).
        (*e).cmdline = cmdline;
        (*e).cmdline_len = cmdline_len;

        if EXEC_EVENTS.output::<ExecEvent>(&*e, 0).is_err() {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping exec event"
            );
        }
    }

    info!(&ctx, "sensor-linux-ebpf: exec pid={}", pid);
    Ok(0)
}

/// Ring buffer shared with userspace for `open` events.
#[map]
static FILE_OPEN_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `FileOpenEvent` (see `EXEC_SCRATCH`).
#[map]
static OPEN_SCRATCH: PerCpuArray<FileOpenEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_openat` tracepoint (x86_64). Standard, stable format of
/// the `syscalls:*` subsystem (documented, unlike `sched:*` tracepoints whose layout can vary
/// more): an 8-byte common header, `__syscall_nr` (4 bytes + padding), then the syscall
/// arguments aligned on 8 bytes each — `dfd`(16), `filename`(24), `flags`(32), `mode`(40).
/// Not yet verified against `/sys/kernel/tracing/events/syscalls/sys_enter_openat/format` on
/// this machine (reading requires root) — to be confirmed before trusting the data outside
/// the lab.
///
/// Known limit: `filename` is the raw path passed by the caller, not resolved against `dfd` —
/// a path relative to a non-standard directory descriptor will appear as-is, without the
/// absolute prefix. Known accepted limitation; conformance reports it.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const OPENAT_FILENAME_PTR_OFFSET: usize = 24;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const OPENAT_FLAGS_OFFSET: usize = 32;

/// On i686, no padding between arguments (all 4-byte `int`s/pointers, packed
/// consecutively): `dfd`(12), `filename`(16), `flags`(20), `mode`(24) — verified on
/// 2026-08-19 via `/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format` on the
/// target i686 kernel (Debian 12 Bookworm, `6.1.0-52-686-pae`). Unlike x86_64 above, the raw
/// value at this offset occupies 4 bytes, not 8 — see the `u32` read below.
#[cfg(bpf_target_arch = "x86")]
const OPENAT_FILENAME_PTR_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const OPENAT_FLAGS_OFFSET: usize = 20;

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_openat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_openat(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let filename_ptr: u64 = unsafe { ctx.read_at(OPENAT_FILENAME_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let filename_ptr: u64 = unsafe {
        ctx.read_at::<u32>(OPENAT_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let flags: i64 = unsafe { ctx.read_at(OPENAT_FLAGS_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let flags: i64 = unsafe { ctx.read_at::<i32>(OPENAT_FLAGS_OFFSET).map_err(|_| 1u32)? as i64 };

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    // Assemble in per-CPU scratch, then one `output` copy — a struct literal on
    // the stack leaves interior padding uninitialised, and `entry.write` copying
    // that into the ring buffer is rejected by the verifier on pre-6.6 kernels.
    let e = OPEN_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        (*e).meta.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*e).meta.ppid = lineage_ppid();
        (*e).meta.uid = uid_gid as u32;
        (*e).meta.gid = (uid_gid >> 32) as u32;
        (*e).meta.timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            (*e).meta.comm[i] = comm[i];
            i += 1;
        }
        (*e).flags = flags as u32;

        if filename_ptr != 0 {
            if let Ok(path) =
                bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut (*e).path)
            {
                (*e).path_len = path.len() as u16;
            }
        }

        if FILE_OPEN_EVENTS.output::<FileOpenEvent>(&*e, 0).is_err() {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping open event"
            );
        }
    }

    Ok(0)
}

/// Ring buffer shared with userspace for `connect` events.
#[map]
static CONNECT_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `ConnectEvent` (see `EXEC_SCRATCH`).
#[map]
static CONNECT_SCRATCH: PerCpuArray<ConnectEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_connect` tracepoint (x86_64). Same stable layout as
/// `sys_enter_openat` (see above): 8-byte common header, `__syscall_nr`, then the arguments
/// aligned on 8 bytes each — `fd`(16), `uservaddr`(24), `addrlen`(32). Not verified against
/// `/sys/kernel/tracing/events/syscalls/sys_enter_connect/format` on this machine (reading
/// requires root) — to be confirmed before trusting the data outside the lab.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const CONNECT_USERVADDR_PTR_OFFSET: usize = 24;

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

#[tracepoint]
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
        (*e).meta.ppid = lineage_ppid();
        (*e).meta.uid = uid_gid as u32;
        (*e).meta.gid = (uid_gid >> 32) as u32;
        (*e).meta.timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
