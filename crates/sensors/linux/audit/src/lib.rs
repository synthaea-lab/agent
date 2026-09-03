//! # sensor-linux-audit
//!
//! Linux fallback sensor for hosts where eBPF is unavailable or restricted (old kernels,
//! lockdown mode, some container hosts). Sources: audit netlink (execve, connect),
//! fanotify (file events). Reduced fidelity versus the eBPF sensor; the conformance
//! suite records exactly what is lost.
