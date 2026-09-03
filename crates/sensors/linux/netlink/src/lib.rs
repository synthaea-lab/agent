//! # sensor-linux-netlink
//!
//! Kernel netlink families as a supplementary, zero-probe source:
//! - `sock_diag` — periodic socket-table snapshots (listening/established with
//!   inode→pid join): listen-port telemetry and drift detection without a probe.
//! - `nfnetlink conntrack` — flow accounting (bytes/packets/duration per flow),
//!   giving beacon detection volume/periodicity features events alone lack.
//! - proc connector — fork/exec/exit notifications as a cheap cross-check for the
//!   eBPF stream (a gap between the two is itself a tamper signal).
//!
//! No special kernel config; runs where eBPF cannot; complements, never replaces,
//! the probe-based sensors.
