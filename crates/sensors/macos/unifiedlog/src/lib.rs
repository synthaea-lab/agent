//! # sensor-macos-unifiedlog
//!
//! Tails the macOS unified log for what `EndpointSecurity` does not carry:
//! sudo outcomes ([`schema::AuthEvent`], same mapping as the Linux journal
//! sensor), TCC decisions ([`schema::TccDecisionEvent`], joined by
//! [`tcc::TccJoiner`]) and Gatekeeper verdicts
//! ([`schema::GatekeeperVerdictEvent`]).
//!
//! The message formats are undocumented; the unit tests, built from verbatim
//! macOS 26 captures, are the tripwire for an OS update changing one. There
//! is no [`schema::sensor::Sensor`] implementation: the agent runs this as a
//! supplementary tail. See `docs/sensors/macos/unified-log.md`.

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
