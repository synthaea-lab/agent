//! # sensor-linux-lsm
//!
//! BPF-LSM hook coverage — observation at the security layer instead of the syscall
//! boundary. Two reasons this exists next to the tracepoint probes:
//! - **Evasion resistance**: operations reach LSM hooks regardless of entry path —
//!   including `io_uring`-submitted file/network operations that never issue the
//!   classic syscalls tracepoints watch (the known blinding technique against
//!   tracepoint-based EDRs).
//! - **Inline prevention**: LSM hooks can return -EPERM — this is the Linux
//!   blocking path for `response` (deny exec/open/connect by verdict), which
//!   tracepoints structurally cannot provide.
//!
//! Requires `CONFIG_BPF_LSM` (lsm=bpf in the kernel cmdline on most distros) —
//! detected at startup and reported via capabilities/conformance, with tracepoint
//! coverage as the universal floor.
//!
//! ## Status (issue #91) — observation-only foundation
//!
//! What's here: the `file_open` LSM hook is compiled into `sensor-linux`'s eBPF
//! object (`crates/sensors/linux/ebpf`) and this crate loads/attaches it, counting
//! hits in the `LSM_FILE_OPEN_HITS` map (see [`file_open_hit_count`]) — proof the
//! hook fires, nothing more. It never returns a non-zero verdict.
//!
//! **Real-hardware validation, issue #91's first `Done when` item — DONE
//! 2026-09-18** (Hyper-V lab, Arch `7.2.4-arch1-2`, `bpf` in the active `lsm=`
//! list). `agent/tests/lsm_io_uring_evasion.rs` loads the eBPF object, attaches
//! this hook, drives a real `fio --ioengine=io_uring` write, and asserts the hit
//! counter increased — confirming the hook fires for an `io_uring`-submitted
//! write, the case tracepoints structurally cannot see.
//!
//! **Found and fixed along the way**: the `file_open` eBPF program's retval
//! passthrough (`if retval != 0 { return Ok(retval); }`, meant to defer to an
//! earlier LSM's own deny) failed the kernel verifier on this real kernel —
//! `arg()`'s extraction loses enough sign-tracking that the verifier can't prove
//! the LSM exit-state contract (`[-4095, 0]`) for an arbitrary forwarded value,
//! and this held even after adding explicit bounds comparisons (`i32::clamp` and
//! a hand-written if/else-if/else both compile to a branchless sign-extend-and-
//! mask select the verifier can't see through — see the fix's comment in
//! `crates/sensors/linux/ebpf/src/main.rs`). Fixed by returning a fixed constant
//! deny (`-1`) instead of forwarding the exact original errno — the only property
//! this hook actually needs to preserve ("never override an earlier LSM's deny
//! with our own allow"), and a compile-time constant trivially satisfies the
//! verifier. This program had never actually loaded on a real BPF-LSM-enabled
//! kernel before this session — BTF-presence alone (the WSL2 check this doc
//! previously described) did not catch it.
//!
//! Deliberately NOT here yet, and why:
//! - **Inline blocking** (`-EPERM` on a policy verdict, issue #91's second `Done
//!   when` item). `crates/response` and `crates/policy`'s verdict model don't
//!   exist yet (issues #131, #133) — there is nothing for a block decision to
//!   consult. Wiring blocking ahead of that would mean inventing the verdict
//!   contract here first, unreviewed.
//! - **`bprm_check`/`socket_connect` hooks** and a real `FileOpenEvent` emission from
//!   this path (today's hit counter is deliberately not a duplicate `FileOpenEvent`
//!   feed — an LSM-sourced open and the existing tracepoint-sourced one need a
//!   decided relationship, e.g. dedup by pid+path+timestamp window, before this counts
//!   as telemetry rather than a liveness signal).
//! - **Capability reporting on a kernel without `lsm=bpf`** (issue #91's third
//!   `Done when` item). Two separate gaps, not just "untested": (1) there is no
//!   schema surface for it yet — `schema::sensor::Capabilities` describes the
//!   *main* `Sensor`'s event quality (exec/file/connect/auth, attribution,
//!   lineage), not a supplementary poll source like this one (same "no `Sensor`
//!   impl, caller owns the handoff" shape as `sensor-linux-netlink`/
//!   `sensor-linux-journal`) — adding an LSM-coverage field to a struct shared
//!   with Windows/macOS sensors is a cross-cutting decision, not this crate's to
//!   make alone; (2) this crate isn't wired into `agent` at all yet (see the
//!   dev-only dependency in `agent/tests/lsm_io_uring_evasion.rs` — no
//!   production caller), so there is no live capability report to validate the
//!   correctness of in the first place. [`detect_hook_support`]'s own doc already
//!   covers the narrower "BTF presence isn't proof of a live hook" distinction at
//!   the function level.

use std::fmt;

use aya::{Btf, Ebpf, maps::PerCpuArray, programs::Lsm};
use aya_obj::btf::BtfKind;
use schema::sensor::SensorError;

/// Name of the eBPF program in `sensor-linux`'s compiled object (the function name
/// under `#[lsm(hook = "file_open")]` in `crates/sensors/linux/ebpf/src/main.rs`).
const FILE_OPEN_PROGRAM: &str = "file_open";
/// LSM hook name passed to `Lsm::load` — the kernel's hook, not our program name.
/// They happen to match for this one; kept as separate constants because they won't
/// for hooks added later (e.g. a program named `bprm_check` attaching to hook
/// `bprm_check_security`).
const FILE_OPEN_HOOK: &str = "file_open";
/// Name of the per-CPU hit-counter map in the eBPF object (`LSM_FILE_OPEN_HITS`).
const FILE_OPEN_HITS_MAP: &str = "LSM_FILE_OPEN_HITS";

#[derive(Debug)]
enum LsmAttachError {
    /// No BTF at all, or no `bpf_lsm_<hook>` type in it — this kernel was not built
    /// with `CONFIG_BPF_LSM=y` (or lacks `CONFIG_DEBUG_INFO_BTF=y`). The honest
    /// "capability absent" case, not a bug.
    NoBtfSupport(aya::BtfError),
    ProgramMissing,
    NotAnLsmProgram,
    /// BTF has the hook's type, but the kernel verifier or attach syscall refused —
    /// most commonly "bpf" is not in the active `lsm=` boot list, so the type is
    /// compiled in but the hook is not live.
    Load(aya::programs::ProgramError),
    Attach(aya::programs::ProgramError),
}

impl fmt::Display for LsmAttachError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoBtfSupport(e) => write!(f, "kernel has no BPF-LSM BTF support: {e}"),
            Self::ProgramMissing => {
                write!(f, "program `{FILE_OPEN_PROGRAM}` not found in eBPF object")
            }
            Self::NotAnLsmProgram => write!(f, "`{FILE_OPEN_PROGRAM}` is not an LSM program"),
            Self::Load(e) => write!(f, "kernel verifier rejected `{FILE_OPEN_PROGRAM}`: {e}"),
            Self::Attach(e) => write!(f, "failed to attach LSM hook `{FILE_OPEN_HOOK}`: {e}"),
        }
    }
}

impl std::error::Error for LsmAttachError {}

/// Whether this kernel exposes BTF for the `bpf_lsm_<hook>` function type (`hook`
/// without the prefix, e.g. `"file_open"`) — i.e. it was built with
/// `CONFIG_BPF_LSM=y` and `CONFIG_DEBUG_INFO_BTF=y`. Cheap and safe to call up front:
/// reads `/sys/kernel/btf/vmlinux`, no root, no `bpf(2)` syscall — unlike
/// [`attach_file_open`], which needs the eBPF object already loaded (root).
///
/// Necessary, not sufficient: the "bpf" LSM also needs to be in the active `lsm=` boot
/// list for a program to actually fire once attached. This only rules out kernels
/// with no support at all — a `false` here is definitive, a `true` is not a guarantee
/// [`attach_file_open`] will succeed.
#[must_use]
pub fn detect_hook_support(hook: &str) -> bool {
    let Ok(btf) = Btf::from_sys_fs() else {
        return false;
    };
    btf.id_by_type_name_kind(&format!("bpf_lsm_{hook}"), BtfKind::Func)
        .is_ok()
}

/// Loads and attaches the `file_open` LSM hook from `ebpf` (already loaded via
/// [`sensor_linux::load_ebpf`] — the LSM program lives in the same compiled object as
/// the tracepoint probes, not a separate one).
///
/// A `Result::Err` here is the capability probe, not necessarily an operational
/// problem: a kernel without `CONFIG_BPF_LSM`, or one that has it compiled in but not
/// in the active `lsm=` boot list, both fail here and both mean "no LSM coverage on
/// this host" — report it via capabilities, don't retry or panic.
///
/// # Errors
///
/// See [`LsmAttachError`]'s variants for the specific failure reasons above.
pub fn attach_file_open(ebpf: &mut Ebpf) -> Result<(), SensorError> {
    let btf = Btf::from_sys_fs().map_err(LsmAttachError::NoBtfSupport)?;
    let program: &mut Lsm = ebpf
        .program_mut(FILE_OPEN_PROGRAM)
        .ok_or(LsmAttachError::ProgramMissing)?
        .try_into()
        .map_err(|_| LsmAttachError::NotAnLsmProgram)?;
    program
        .load(FILE_OPEN_HOOK, &btf)
        .map_err(LsmAttachError::Load)?;
    program.attach().map_err(LsmAttachError::Attach)?;
    Ok(())
}

/// Sum of the per-CPU `file_open` LSM hit counter — proof of life for
/// [`attach_file_open`], not an event count (see the crate doc on why this is a
/// counter and not yet a `FileOpenEvent` feed).
///
/// # Errors
///
/// Returns [`SensorError`] when the map is missing (attach never ran) or is not the
/// expected type.
pub fn file_open_hit_count(ebpf: &mut Ebpf) -> Result<u64, SensorError> {
    let map = ebpf
        .map_mut(FILE_OPEN_HITS_MAP)
        .ok_or_else(|| -> SensorError { format!("map {FILE_OPEN_HITS_MAP} not found").into() })?;
    let array: PerCpuArray<_, u64> = PerCpuArray::try_from(map).map_err(|e| -> SensorError {
        format!("{FILE_OPEN_HITS_MAP} is not a per-CPU array: {e}").into()
    })?;
    let values = array
        .get(&0, 0)
        .map_err(|e| -> SensorError { format!("reading {FILE_OPEN_HITS_MAP}: {e}").into() })?;
    Ok(values.iter().sum())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_hook_support_rejects_a_nonexistent_hook_name() {
        // Portable regardless of this kernel's BPF-LSM config: no kernel BTF has a
        // `bpf_lsm_<garbage>` type, so this is `false` everywhere, unlike asserting
        // on a real hook name (`file_open`), whose answer depends on whether the test
        // machine's kernel has CONFIG_BPF_LSM=y — true on the Hyper-V lab kernels,
        // false on this WSL2 one (no /sys/kernel/security/lsm at all).
        assert!(!detect_hook_support("this_hook_does_not_exist_xyz"));
    }
}
