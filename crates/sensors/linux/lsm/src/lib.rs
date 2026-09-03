//! # sensor-linux-lsm
//!
//! BPF-LSM hook coverage — observation at the security layer instead of the syscall
//! boundary. Two reasons this exists next to the tracepoint probes:
//! - **Evasion resistance**: operations reach LSM hooks regardless of entry path —
//!   including io_uring-submitted file/network operations that never issue the
//!   classic syscalls tracepoints watch (the known blinding technique against
//!   tracepoint-based EDRs).
//! - **Inline prevention**: LSM hooks can return -EPERM — this is the Linux
//!   blocking path for `response` (deny exec/open/connect by verdict), which
//!   tracepoints structurally cannot provide.
//!
//! Requires `CONFIG_BPF_LSM` (lsm=bpf in the kernel cmdline on most distros) —
//! detected at startup and reported via capabilities/conformance, with tracepoint
//! coverage as the universal floor.
