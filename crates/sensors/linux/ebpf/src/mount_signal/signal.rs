//! `kill`/`tgkill` aimed at the agent (tamper signal), and signals to the processes of
//! listed security units from the `signal_generate` raw tracepoint (#1103).

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::map,
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{RawTracePointContext, TracePointContext},
};
use aya_log_ebpf::warn;
use sensor_linux_wire::{SignalEvent, TASK_COMM_LEN};

use crate::fill_lineage;

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
pub(crate) fn is_agent_own_pid(pid: u32) -> bool {
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
