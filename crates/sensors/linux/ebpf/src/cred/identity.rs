//! Identity change (issue #266)

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::map,
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;
use sensor_linux_wire::IdentityChangeEvent;

use crate::{
    arch::{CULong, SyscallRecord, arg_offset},
    fill_event_meta,
};

/// Ring buffer shared with userspace for `setuid`/`setgid`/`setresuid`/
/// `setresgid`/`setfsuid`/`setfsgid` events.
#[map]
static IDENTITY_CHANGE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `IdentityChangeEvent` (see `EXEC_SCRATCH`).
#[map]
static IDENTITY_CHANGE_SCRATCH: PerCpuArray<IdentityChangeEvent> =
    PerCpuArray::with_max_entries(1, 0);

const IDENTITY_KIND_SETUID: u8 = 0;
const IDENTITY_KIND_SETGID: u8 = 1;
const IDENTITY_KIND_SETRESUID: u8 = 2;
const IDENTITY_KIND_SETRESGID: u8 = 3;
const IDENTITY_KIND_SETFSUID: u8 = 4;
const IDENTITY_KIND_SETFSGID: u8 = 5;

/// Offset of `setuid(2)`/`setgid(2)`/`setfsuid(2)`/`setfsgid(2)`'s single
/// `uid_t`/`gid_t` argument — identical shape across all four, assumed
/// standard layout (16-byte header + 8 bytes/arg on `x86_64/aarch64`);
/// re-verify against `/format` on any newly supported kernel,
/// same posture as every other offset const in this file.
///
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
const SINGLE_ID_OFFSET: usize = arg_offset(0);

/// Offset of `setresuid(2)`/`setresgid(2)`'s first `uid_t`/`gid_t` argument
/// (real) — identical shape for both, assumed standard layout, same posture
/// as `SINGLE_ID_OFFSET`. effective and saved sit immediately after it, one
/// register width apart each, and `try_sys_enter_setres` reads all three in
/// a single `read_at::<[_; 3]>` instead of three separate reads at three
/// separate offsets: three reads, each with its own early-return `?`, was
/// enough extra verifier state to fail this function with "R2 !`read_ok`" at
/// its call sites under a forced `-O2` build (abuild's default.conf was
/// overriding Cargo's resolved opt-level for the Alpine package — see
/// packaging/linux/alpine/APKBUILD; the real fix was unsetting that
/// override, not this). Kept anyway as cheap hardening, same spirit as
/// `emit_mount_event`'s own note: `raw_sys_enter` (ebpf/src/raw.rs) is one
/// shared verifier unit across every `sys_enter_*` branch, so a rejection
/// anywhere in it loses all syscall telemetry, not just this probe. The
/// function is also `#[inline(always)]` now — confirmed live that this
/// alone (still with the original three reads) was already enough to pass
/// the verifier: the real mechanism is the BPF-to-BPF call/return, not the
/// read count. Both are kept: one less thing to re-diagnose if a future
/// change makes LLVM decide not to inline it anyway.
///
/// i686: inferred, not independently verified.
const RES_ID_REAL_OFFSET: usize = arg_offset(0);

/// Shared by all six probes below: fills `EventMeta` and the kind-specific id
/// fields into `IDENTITY_CHANGE_SCRATCH`, then emits. Mirrors
/// `emit_kernel_module_event`'s shape (#264) — one assembly helper for a
/// family of syscalls that share almost all of their event fields.
///
/// Always inlined, same reasoning as `emit_mount_event`: a real BPF-to-BPF
/// call hands the verifier a return/argument path it can't always prove,
/// and this has several call sites (one per probe below).
#[inline(always)]
fn emit_identity_change_event(
    ctx: &TracePointContext,
    kind: u8,
    real: u32,
    effective: u32,
    saved: u32,
) -> Result<u32, u32> {
    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = IDENTITY_CHANGE_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        fill_event_meta(
            &mut (*e).meta,
            (bpf_get_current_pid_tgid() >> 32) as u32,
            uid_gid,
            &comm,
        );
        (*e).kind = kind;
        (*e).real = real;
        (*e).effective = effective;
        (*e).saved = saved;

        if IDENTITY_CHANGE_EVENTS
            .output::<IdentityChangeEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                ctx,
                "sensor-linux-ebpf: ring buffer full, dropping identity change event"
            );
        }
    }

    Ok(0)
}

/// Reads a single 32-bit `uid_t`/`gid_t` syscall argument at `SINGLE_ID_OFFSET`,
/// shared by `setuid`/`setgid`/`setfsuid`/`setfsgid` — the four probes below
/// differ only in which `IDENTITY_KIND_*` they pass through.
///
/// Always inlined, same reasoning as `emit_mount_event`: four call sites,
/// and a real BPF-to-BPF call here would hand the verifier a return path
/// it can't always prove.
#[inline(always)]
fn read_single_id(ctx: &TracePointContext) -> Result<u32, u32> {
    let id: u64 = unsafe { ctx.read_ulong_arg(SINGLE_ID_OFFSET).map_err(|_| 1u32)? };
    Ok(id as u32)
}

pub fn sys_enter_setuid(ctx: TracePointContext) -> u32 {
    match read_single_id(&ctx) {
        Ok(uid) => match emit_identity_change_event(&ctx, IDENTITY_KIND_SETUID, uid, 0, 0) {
            Ok(ret) | Err(ret) => ret,
        },
        Err(ret) => ret,
    }
}

pub fn sys_enter_setgid(ctx: TracePointContext) -> u32 {
    match read_single_id(&ctx) {
        Ok(gid) => match emit_identity_change_event(&ctx, IDENTITY_KIND_SETGID, gid, 0, 0) {
            Ok(ret) | Err(ret) => ret,
        },
        Err(ret) => ret,
    }
}

pub fn sys_enter_setfsuid(ctx: TracePointContext) -> u32 {
    match read_single_id(&ctx) {
        Ok(fsuid) => match emit_identity_change_event(&ctx, IDENTITY_KIND_SETFSUID, fsuid, 0, 0) {
            Ok(ret) | Err(ret) => ret,
        },
        Err(ret) => ret,
    }
}

pub fn sys_enter_setfsgid(ctx: TracePointContext) -> u32 {
    match read_single_id(&ctx) {
        Ok(fsgid) => match emit_identity_change_event(&ctx, IDENTITY_KIND_SETFSGID, fsgid, 0, 0) {
            Ok(ret) | Err(ret) => ret,
        },
        Err(ret) => ret,
    }
}

pub fn sys_enter_setresuid(ctx: TracePointContext) -> u32 {
    match try_sys_enter_setres(&ctx) {
        Ok((real, effective, saved)) => {
            match emit_identity_change_event(&ctx, IDENTITY_KIND_SETRESUID, real, effective, saved)
            {
                Ok(ret) | Err(ret) => ret,
            }
        }
        Err(ret) => ret,
    }
}

pub fn sys_enter_setresgid(ctx: TracePointContext) -> u32 {
    match try_sys_enter_setres(&ctx) {
        Ok((real, effective, saved)) => {
            match emit_identity_change_event(&ctx, IDENTITY_KIND_SETRESGID, real, effective, saved)
            {
                Ok(ret) | Err(ret) => ret,
            }
        }
        Err(ret) => ret,
    }
}

#[inline(always)]
fn try_sys_enter_setres(ctx: &TracePointContext) -> Result<(u32, u32, u32), u32> {
    // One `bpf_probe_read_kernel` over all three contiguous arguments, not
    // three separate reads with three early returns — see the
    // `RES_ID_REAL_OFFSET` doc comment for why.
    let [real, effective, saved]: [CULong; 3] =
        unsafe { ctx.read_at(RES_ID_REAL_OFFSET).map_err(|_| 1u32)? };
    Ok((real as u32, effective as u32, saved as u32))
}
