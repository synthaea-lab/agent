//! # sensor-macos-network-extension
//!
//! The network/DNS visibility `EndpointSecurity` does not carry (issue #33):
//! flows with process attribution (inbound + outbound) via
//! `NEFilterDataProvider`, and DNS query/response pairs via
//! `NEDNSProxyProvider`.
//!
//! ## Architecture: a seam, not a single binary
//!
//! Apple only runs `NetworkExtension` providers inside a **system extension**
//! (Swift, `NetworkExtension.framework`, its own sandbox and entitlements) —
//! a Rust agent cannot host them. This crate is therefore the agent side of
//! a two-part sensor:
//!
//! - `extension/` — the Swift providers (built and packaged per
//!   `packaging/macos`, not by cargo): extract pid/path from each flow's
//!   audit token and write versioned NDJSON records over a Unix socket in
//!   the shared app-group container;
//! - this crate — the [`wire`] protocol, the socket [`receiver`], and
//!   [`normalize()`] into **existing** schema shapes (`Connect`,
//!   `NetworkFlow`, `DnsQuery` — no schema change; the BEACON rule and the
//!   correlator consume macOS flows exactly like Linux/Windows ones).
//!
//! The wire format is versioned independently ([`wire::WIRE_VERSION`]);
//! records from a newer/older extension are skipped and counted, never
//! guessed at.
//!
//! **Status:** wire protocol, receiver, and normalization are done and
//! tested (including a real socket round trip); the Swift providers are
//! compile-checked scaffolds pending the packaging/approval lab pass
//! (system extensions need Developer-ID signing + user/MDM approval — see
//! `packaging/macos/README.md`). The "beacon detected on macOS" scenario
//! from the issue's Done-when rides that lab session, on the same
//! entitled-binary setup as the ES sensor's.

pub mod normalize;
pub mod receiver;
pub mod wire;

pub use normalize::normalize;
pub use receiver::NormalizedNeStream;
#[cfg(unix)]
pub use receiver::socket::{accept_loop, listen};

/// Errors from the receiver path.
#[derive(Debug, thiserror::Error)]
pub enum NetworkExtensionError {
    #[error("I/O error on the extension socket: {0}")]
    Io(#[from] std::io::Error),
}
