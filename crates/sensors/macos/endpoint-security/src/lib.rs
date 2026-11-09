//! # sensor-macos
//!
//! macOS user-mode sensor built on `EndpointSecurity`, NOTIFY events only:
//! exec, file, BTM persistence, logins, quarantine provenance, mount, signals
//! aimed at ES clients and XPC connects.
//!
//! A C shim (`shim/es_shim.c`, built by `build.rs`) flattens the subscribed
//! messages into plain structs; [`raw`] and [`normalize`] are portable and
//! unit-tested on any host, only `ffi` and `sensor` are macOS-gated. The
//! client needs root, the `com.apple.developer.endpoint-security.client`
//! entitlement and Full Disk Access. See `docs/sensors/macos/endpoint-security.md`.

pub mod normalize;
pub mod raw;

// The record conversion in `ffi` is plain Rust over `repr(C)` structs, so its
// tests run on any host; only the extern calls need macOS.
#[cfg(any(target_os = "macos", test))]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod ffi;
#[cfg(target_os = "macos")]
mod sensor;
#[cfg(target_os = "macos")]
pub use sensor::{MacosSensor, MacosSensorError, StopHandle};
