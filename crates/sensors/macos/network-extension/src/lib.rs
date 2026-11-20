//! # sensor-macos-network-extension
//!
//! Agent side of the macOS network sensor: flows (`NEFilterDataProvider`)
//! and DNS (`NEDNSProxyProvider`) come from a Swift system extension in
//! `extension/`, since `NetworkExtension` providers cannot run in the agent
//! process. This crate holds the [`wire`] protocol, the socket [`receiver`]
//! and [`normalize()`] into the existing `Connect`, `NetworkFlow` and
//! `DnsQuery` shapes. See `docs/sensors/macos/network-extension.md`.

pub mod normalize;
pub mod receiver;
pub mod wire;

pub use normalize::normalize;
#[cfg(unix)]
pub use receiver::socket::{accept_loop, listen};
pub use receiver::{NormalizedNeStream, SkewCounters, SkewTotals};

/// Errors from the receiver path.
#[derive(Debug, thiserror::Error)]
pub enum NetworkExtensionError {
    #[error("I/O error on the extension socket: {0}")]
    Io(#[from] std::io::Error),
}
