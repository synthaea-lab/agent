//! # sensor-linux
//!
//! Linux platform sensor (userspace side). Loads and attaches the eBPF probes from
//! `sensor-linux-ebpf` (compiled into OUT_DIR by build.rs when the eBPF toolchain is
//! present), drains their ring buffers, normalizes the wire structs into `schema`
//! events, and feeds them to the `EventSink`.
//!
//! Migrated from `old/crates/synthaea-sensor-linux`, with the normalization layer new
//! in this iteration: the old code passed wire structs straight to the sink; the
//! schema is now unbounded/owned, so [`normalize`] converts (and is unit-tested on
//! every platform — only the sensor itself is Linux-only).

pub mod normalize;

#[cfg(target_os = "linux")]
mod sensor;
#[cfg(target_os = "linux")]
pub use sensor::{LinuxSensor, TRACEPOINTS, load_ebpf, load_program};
