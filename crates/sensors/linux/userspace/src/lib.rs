//! # sensor-linux
//!
//! Linux platform sensor (userspace). Loads the eBPF probes from
//! `sensor-linux-ebpf`, drains their ring buffers, normalizes raw kernel events
//! into the shared schema, and feeds them to the `EventSink`.
//!
//! To be migrated from `old/crates/synthaea-sensor-linux`.
