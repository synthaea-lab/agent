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
//! - **Structured capability reporting on a kernel without `lsm=bpf`** (issue #91's
//!   third `Done when` item, issue #313). `agent::cmd_run` now loads/attaches this
//!   hook at startup (behind the same `can_use_ebpf()` preflight the primary
//!   sensor uses — no point attempting a second `Ebpf::load` on a host that can't
//!   do eBPF at all) and logs the outcome honestly: attached, not supported on
//!   this kernel, or compiled-in-but-not-live. What's still missing is a
//!   *structured* surface for that outcome — `schema::sensor::Capabilities`
//!   describes the *main* `Sensor`'s event quality (exec/file/connect/auth,
//!   attribution, lineage), not a supplementary poll source like this one (same
//!   "no `Sensor` impl, caller owns the handoff" shape as `sensor-linux-netlink`/
//!   `sensor-linux-journal`), and adding an LSM-coverage field to a struct shared
//!   with Windows/macOS sensors is a cross-cutting schema decision, not this
//!   crate's to make alone — a log line is the honest, scoped answer until that
//!   decision is made. [`detect_hook_support`]'s own doc already covers the
//!   narrower "BTF presence isn't proof of a live hook" distinction at the
//!   function level.

#[cfg(target_os = "linux")]
mod attach;

#[cfg(target_os = "linux")]
pub use attach::{attach_file_open, detect_hook_support, file_open_hit_count};
