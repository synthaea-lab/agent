//! # ipc
//!
//! The local control channel the agent exposes on the endpoint, consumed
//! by the endpoint UI (`ui/`) and the CLI. Named pipe on Windows, Unix
//! domain socket on Linux/macOS, with peer authentication (caller
//! identity) and a versioned, read-mostly protocol: agent status, sensor
//! health, recent detections, policy version.
//!
//! ## Layout
//!
//! - **`protocol`** — the wire types (`Request`, `Response`,
//!   `ClientHello`, `ServerHello`, `WireError`, and their payloads).
//! - **`frame`** — JSON-lines framing over an async byte stream, with a
//!   1 MiB per-message cap.
//! - **`stream`** — the transport layer: OS-native `Listener` (named
//!   pipe or Unix socket) and per-connection `Stream`, plus peer-
//!   credentials read (Win32 elevation on Windows, `SO_PEERCRED` on
//!   Unix).
//! - **`server`** — the agent-hosted accept loop and dispatch through
//!   the caller-supplied [`Handler`] trait.
//! - **`client`** — the [`Client`] used by cli/ui: connect, handshake,
//!   then one or more request/response calls.
//!
//! ## Contract highlights (issue #26)
//!
//! - **cli↔agent on Linux, macOS, Windows** — the same [`Client`] API
//!   works on all three OSes.
//! - **Unauthorized peers rejected** — v1 policy is
//!   root-on-Unix-or-elevated-on-Windows; a non-privileged caller sees
//!   [`WireError::Unauthorized`] and gets EOF immediately after.
//!
//! Mutating commands are deliberately out of scope in v1 — every request
//! is read-only. The variants for `kill`, `quarantine`, `isolate` land
//! when the authorization model they need (per-capability, policy-gated)
//! is designed.

pub mod client;
pub mod error;
pub mod frame;
pub mod protocol;
pub mod server;
pub mod stream;

pub use client::Client;
pub use error::{ClientError, ServerError};
pub use protocol::{
    ClientHello, DetectionSummary, PolicyVersionResponse, RecentDetectionsResponse, Request,
    Response, SensorHealth, SensorHealthResponse, SensorState, ServerHello, StatusResponse,
    WireError, PROTOCOL_VERSION,
};
pub use server::{Handler, Server, StubHandler, RECENT_DETECTIONS_HARD_LIMIT};
pub use stream::PeerCreds;
