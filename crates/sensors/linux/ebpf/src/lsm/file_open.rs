//! `file_open` LSM hook (issue #91): a per-CPU hit counter, observation only.
use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{lsm, map},
    maps::PerCpuArray,
    programs::LsmContext,
};
use aya_log_ebpf::info;

use crate::into_ret;

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
    into_ret(try_file_open(ctx))
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
