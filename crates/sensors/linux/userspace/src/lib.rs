//! # sensor-linux
//!
//! Linux platform sensor (userspace side). Loads and attaches the eBPF probes from
//! `sensor-linux-ebpf` (compiled into `OUT_DIR` by build.rs when the eBPF toolchain is
//! present), drains their ring buffers, normalizes the wire structs into `schema`
//! events, and feeds them to the `EventSink`.
//!
//! Migrated from `old/crates/synthaea-sensor-linux`, with the normalization layer new
//! in this iteration: the old code passed wire structs straight to the sink; the
//! schema is now unbounded/owned, so [`normalize`] converts (and is unit-tested on
//! every platform — only the sensor itself is Linux-only).

mod dns_udp;
pub mod normalize;
// Built for its tests only: no capture feeds this parser yet, so nothing outside them reads it. The
// capture is the next part of https://github.com/synthaea-lab/agent/issues/22; that change turns
// this line into a plain `mod`.
#[cfg(test)]
mod tls_client_hello;

#[cfg(all(target_os = "linux", any(ebpf_embedded, test)))]
mod btf;
#[cfg(target_os = "linux")]
mod drain;
#[cfg(target_os = "linux")]
mod ebpf;
#[cfg(target_os = "linux")]
mod parent_image;
#[cfg(target_os = "linux")]
mod proc;
#[cfg(target_os = "linux")]
mod rings;
// Events the probes lost to a full ring, counted kernel-side and logged per ring (#304).
#[cfg(target_os = "linux")]
mod ring_drops;
#[cfg(target_os = "linux")]
mod sensor;
#[cfg(all(target_os = "linux", any(ebpf_embedded, test)))]
mod syscall;
// Which processes belong to a listed security unit, for the `signal_generate` probe (#1103).
#[cfg(target_os = "linux")]
mod unit_procs;
// Whether a signal's sender is the agent's own watchdog (#322).
#[cfg(target_os = "linux")]
mod watchdog;
#[cfg(all(target_os = "linux", ebpf_embedded))]
pub use ebpf::verifier_loader;
#[cfg(target_os = "linux")]
pub use ebpf::{RAW_TRACEPOINTS, load_ebpf, load_program};
#[cfg(target_os = "linux")]
pub use parent_image::ParentImageEvictions;
#[cfg(target_os = "linux")]
pub use proc::{SeedProcess, read_seed_processes};
#[cfg(target_os = "linux")]
pub use sensor::LinuxSensor;
