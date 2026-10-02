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
//! Mutating commands are deliberately out of scope for the most part —
//! `kill`, `quarantine`, `isolate` land as new variants once the
//! authorization model they need (per-capability, policy-gated) is
//! designed. `ReloadContent` (v2, issue #30) is a deliberate, narrow
//! exception: see its own doc comment in [`protocol::Request`] for why it
//! doesn't need that same model. So are `SuppressVerdict`/`UnsuppressVerdict`
//! (v3, issue #613): they change only the agent's own fused-verdict view
//! (never the alert log, a process, or a file), are reversible, and every
//! change is audited.

pub mod client;
pub mod error;
pub mod frame;
pub mod protocol;
pub mod server;
pub mod stream;

pub use client::Client;
pub use error::{ClientError, ServerError};
pub use protocol::{
    ClientHello, DetectionSummary, PROTOCOL_VERSION, PolicyVersionResponse,
    RecentDetectionsResponse, ReloadContentResponse, Request, Response, SensorHealth,
    SensorHealthResponse, SensorState, ServerHello, StatusResponse, SuppressionEntry,
    SuppressionResponse, WireError,
};
pub use server::{Handler, RECENT_DETECTIONS_HARD_LIMIT, Server, StubHandler};
pub use stream::PeerCreds;
