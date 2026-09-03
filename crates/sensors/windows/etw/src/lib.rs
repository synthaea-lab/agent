//! # sensor-windows
//!
//! Windows platform sensor. Subscribes to ETW providers (process creation, file open,
//! network connect, registry, image load), normalizes events into the shared schema, and
//! feeds them to the `EventSink`. A kernel driver is a later milestone; ETW is the base.
//!
//! Compiles to a stub on non-Windows targets so `cargo check --workspace` works anywhere.
//! To be migrated from `old/crates/synthaea-sensor-windows`.
