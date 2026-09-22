//! # sensor-macos-unifiedlog
//!
//! macOS unified-log ingestion as a supplementary sensor (issue #95) — the
//! macOS sibling of `sensor-linux-journal`, for the high-value channels
//! `EndpointSecurity` does not carry:
//!
//! - **sudo outcomes** → the shared [`schema::AuthEvent`] (ADR-0005), with the
//!   same mapping semantics as the Linux journal sensor (root target =
//!   privileged session, other target = explicit credentials, incorrect
//!   password = failure);
//! - **TCC decisions** (tccd granting/denying screen capture, microphone,
//!   Accessibility, Full Disk Access...) → [`schema::TccDecisionEvent`],
//!   joined from tccd's `AUTHREQ_CTX`/`AUTHREQ_RESULT` record pair by a
//!   bounded, counted [`tcc::TccJoiner`];
//! - **Gatekeeper scan verdicts** (syspolicyd's `GK evaluateScanResult`) →
//!   [`schema::GatekeeperVerdictEvent`], with the raw result code kept
//!   uninterpreted (undocumented by Apple) and team/signing ids as the join
//!   keys toward the corresponding exec event.
//!
//! Firehose discipline (three gates: daemon-side predicate, exact-message
//! classifier, counted sliding-window shed) is documented on [`stream`];
//! provenance (which daemon logged it, when) rides every event's meta.
//!
//! **Status:** record parsing, classification, the TCC join, and normalization
//! are pinned against verbatim live captures from a real macOS 26 machine
//! (2026-09-22) — see the unit tests. The message formats are not documented
//! by Apple; the tests are the tripwire for an OS update changing one.
//! Like `sensor-linux-journal`, there is deliberately no
//! [`schema::sensor::Sensor`] implementation — this is a supplementary tail
//! wired directly into `agent::commands::macos::cmd_run` alongside the
//! `EndpointSecurity` sensor.
//!
//! Known limitation: syspolicyd hash-redacts file paths in the public log
//! stream (the private-data logging profile reveals them — see
//! `docs/sensors/macos.md`), so Gatekeeper events may carry an opaque target
//! token; TCC's requesting-client identity is likewise redacted on the
//! records parsed here, so `TccDecisionEvent::client` stays `None` today.

mod classify;
mod normalize;
mod record;
mod stream;
mod tcc;

pub use classify::{UnifiedLogEvent, classify};
pub use normalize::normalize;
pub use record::{LogRecord, parse_record};
#[cfg(target_os = "macos")]
pub use stream::process::spawn_stream;
pub use stream::{NormalizedLogStream, PREDICATE};
pub use tcc::TccJoiner;

/// Errors from parsing a unified-log record or driving `log stream`.
#[derive(Debug, thiserror::Error)]
pub enum UnifiedLogError {
    #[error("failed to parse log line as JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("log record is missing expected field {0:?}")]
    MissingField(&'static str),
    #[error("I/O error reading the log stream: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to spawn or read from `log stream`: {0}")]
    Spawn(std::io::Error),
}
