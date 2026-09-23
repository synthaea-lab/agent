//! # transport
//!
//! Agent ↔ control-plane communication: mTLS channel, enrollment, store-and-forward
//! event upload with backpressure, policy and content download, heartbeat.
//!
//! ## Architecture
//!
//! Transport is the bridge between the on-device collection/detection stack and the
//! control plane. It drains the `store::EventSpool`, uploads events to the server,
//! sends periodic heartbeats, and downloads policy updates.
//!
//! ```text
//! ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
//! │ Sensors     │────►│ DetectionSink│────►│ EventSpool  │
//! └─────────────┘     └─────────────┘     └──────┬──────┘
//!                                                │
//!                                                ▼
//!                                        ┌───────────────┐
//!                                        │  Transport    │
//!                                        │  - drain      │
//!                                        │  - upload     │
//!                                        │  - heartbeat  │
//!                                        └───────┬───────┘
//!                                                │ mTLS
//!                                                ▼
//!                                        ┌───────────────┐
//!                                        │    Server     │
//!                                        └───────────────┘
//! ```
//!
//! ## Graceful Degradation
//!
//! Transport never blocks the agent. When the server is unreachable:
//! - Events continue to spool locally (up to the byte cap)
//! - Retry with exponential backoff
//! - Flush accumulated events on reconnect
//!
//! ## At-least-once Delivery
//!
//! Uses the two-phase drain/ack protocol from `store::EventSpool`:
//! 1. `drain_oldest()` returns events and marks segment as in-flight
//! 2. Upload to server
//! 3. `ack()` deletes segment only after successful upload
//! 4. On crash before ack, segment is re-delivered on restart

mod client;
mod config;
mod error;
mod upload;

pub use client::TransportClient;
pub use config::TransportConfig;
pub use error::{Result, TransportError};
pub use upload::{EventDrain, EventUploader, UploadLoop};

/// Default server endpoint for event ingestion.
pub const DEFAULT_INGEST_ENDPOINT: &str = "/api/v1/ingest/events";

/// Default server endpoint for heartbeat.
pub const DEFAULT_HEARTBEAT_ENDPOINT: &str = "/api/v1/ingest/heartbeat";

/// Default retry backoff base (doubles on each retry, capped).
pub const DEFAULT_RETRY_BASE_MS: u64 = 1000;

/// Maximum retry backoff.
pub const DEFAULT_RETRY_MAX_MS: u64 = 60_000;

/// Default upload batch size (events per request).
pub const DEFAULT_BATCH_SIZE: usize = 100;

/// Default number of consecutive retryable failures on the same in-flight
/// segment before it is skipped to restore forward progress. Mirrors
/// `store::EventSpool`'s suggested `MAX_DRAIN_ATTEMPTS` — `store` and
/// `transport` are both leaf crates and may not depend on each other, so the
/// value is duplicated by convention rather than shared by import.
pub const DEFAULT_MAX_DRAIN_ATTEMPTS: u32 = 5;
