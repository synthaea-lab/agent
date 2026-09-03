#![no_std]
//! # sensor-linux-wire
//!
//! The ring-buffer ABI between the eBPF probes (`../ebpf`, `bpfel-unknown-none`) and
//! the userspace loader (`../userspace`): fixed-size `repr(C)` structs written by the
//! kernel side and read back with `read_unaligned` on the user side. Both crates must
//! be built from the same revision — this is an internal ABI, not a stable format.
//!
//! These types are deliberately NOT the agent's event model: the loader normalizes
//! them into `schema` types. The fixed limits below are wire/kernel constraints (the
//! eBPF stack is 512 bytes and events are built in place on it), not product limits —
//! truncation at these bounds is a sensor property reported by conformance. Raising
//! `MAX_CMDLINE_LEN` beyond the stack budget needs per-CPU scratch maps on the probe
//! side (tracked with the sensor work, not by editing the constant).

pub const TASK_COMM_LEN: usize = 16;
pub const MAX_PATH_LEN: usize = 256;
pub const MAX_CMDLINE_LEN: usize = 256;

/// Metadata common to every wire event: identity of the emitting process.
/// `uid`/`gid` come from `bpf_get_current_uid_gid()` (low/high 32 bits).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EventMeta {
    pub pid: u32,
    /// Parent PID — read from `current_task->real_parent->tgid`.
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    /// `bpf_ktime_get_ns()`: nanoseconds since boot (monotonic), NOT epoch — the
    /// loader adds the boot-to-epoch offset during normalization.
    pub timestamp_ns: u64,
    pub comm: [u8; TASK_COMM_LEN],
}

/// Process execution (`sched:sched_process_exec`). `cmdline` holds the argv buffer
/// copied from `mm->arg_start..arg_end`: `\0`-separated argument strings.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub meta: EventMeta,
    pub cmdline: [u8; MAX_CMDLINE_LEN],
    pub cmdline_len: u16,
}

/// File open (`syscalls:sys_enter_openat`). `path` is the raw path passed by the
/// caller, not resolved against `dfd` (known limitation, documented in the probe).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileOpenEvent {
    pub meta: EventMeta,
    pub path: [u8; MAX_PATH_LEN],
    pub path_len: u16,
    pub flags: u32,
}

/// Outbound network connection (`syscalls:sys_enter_connect`, AF_INET/AF_INET6 only).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectEvent {
    pub meta: EventMeta,
    /// Raw bytes of `sin_addr` in memory order — not a native-endian integer, to
    /// avoid the byte-reversal bug observed in real conditions on 2026-08-13
    /// (127.0.0.11 displayed as "11.0.0.127").
    pub daddr_v4: [u8; 4],
    pub daddr_v6: [u8; 16],
    pub dport: u16,
    pub is_ipv6: bool,
}
