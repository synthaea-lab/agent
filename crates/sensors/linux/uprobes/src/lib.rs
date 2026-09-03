//! # sensor-linux-uprobes
//!
//! Userspace-function probes (eBPF uprobes) — telemetry the kernel boundary cannot
//! see:
//! - `SSL_read`/`SSL_write` (OpenSSL/BoringSSL/GnuTLS) — plaintext of TLS traffic
//!   BEFORE encryption / after decryption: C2 content visibility with no MITM, no
//!   certificates, no proxy. Budgeted capture (first N bytes, allowlisted comms).
//! - `bash`/`zsh` readline — interactive shell commands at typing time, catching
//!   what execve never sees (shell builtins, history-evading input).
//!
//! Probes attach per-binary (symbol resolution against the on-disk library, tracked
//! across updates); the probe programs join the `ebpf` crate build, this crate owns
//! attachment, symbol resolution, and normalization into schema events.
