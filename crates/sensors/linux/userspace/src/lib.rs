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

pub mod normalize;

#[cfg(target_os = "linux")]
mod container;
#[cfg(target_os = "linux")]
mod docker;
#[cfg(target_os = "linux")]
mod ebpf;
#[cfg(target_os = "linux")]
mod proc;
#[cfg(target_os = "linux")]
mod sensor;
#[cfg(target_os = "linux")]
// Only `load_ebpf` reads the fork layout, and it exists only with embedded probes.
// Without bpf-linker (the CI runner) the module is dead code, but its parser tests
// still run.
#[cfg_attr(not(ebpf_embedded), allow(dead_code))]
mod tracefs;

#[cfg(target_os = "linux")]
pub use ebpf::{TRACEPOINTS, load_ebpf, load_program};
#[cfg(target_os = "linux")]
pub use sensor::LinuxSensor;
