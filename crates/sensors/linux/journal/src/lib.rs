//! # sensor-linux-journal
//!
//! OS-log ingestion as a supplementary sensor: tails journald (via `journalctl -f -o
//! json`, see the module doc on [`tail`] for why a subprocess and not `libsystemd`
//! FFI) for the high-value channels raw syscalls do not express —
//! - authentication: sshd accepts/failures, PAM sessions, sudo/su usage (the
//!   lateral-movement telemetry on servers)
//! - service lifecycle: unit starts/stops/failures (persistence + tamper context)
//!
//! Records normalize into schema events with their journal provenance kept;
//! filtering is allowlist-based (never ship the whole journal).
//!
//! **Status (issue #93, foundation):** [`classify`] and [`JournalRecord`] parsing are
//! done and tested against a mix of real captures (sudo command + PAM session
//! open/close, taken from this dev machine's own journal — see the test fixtures'
//! comments for which) and documented-but-unverified formats (sshd accept/fail: no
//! `sshd` on this box; su: blocked here by an interactive-auth prompt this
//! non-interactive session can't answer). [`tail::spawn_follow`] and
//! [`tail::current_cursor`] shell out to `journalctl` and are exercised by an
//! integration test that skips itself if `journalctl` is not on `PATH` rather than
//! asserting a specific journal history exists.
//!
//! Deliberately **not** here yet, matching the same discipline as issue #91's
//! foundation:
//! - No `schema::Event` variant. The issue's own text says this event type is
//!   "shared with Windows 4624 and macOS login work" — `schema` has no
//!   auth/session event at all today (checked), so designing one is a cross-platform
//!   decision, not something to bake into a Linux-only PR unreviewed.
//! - No [`schema::sensor::Sensor`] implementation — same reason: `run` would need to
//!   push a [`schema::Event`] that doesn't exist yet.
//! - No cursor persistence across restarts (the `crates/store` integration) or lab
//!   validation of the sshd/su paths — needs the Hyper-V lab kernels.

mod classify;
mod record;
mod tail;

pub use classify::{JournalEvent, classify};
pub use record::{JournalRecord, parse_record};
pub use tail::ClassifiedJournal;
#[cfg(target_os = "linux")]
pub use tail::process::{current_cursor, spawn_follow};

/// Errors from parsing a journal record or driving `journalctl`.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("failed to parse journal line as JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("journal record is missing expected field {0:?}")]
    MissingField(&'static str),
    #[error("I/O error reading the journal stream: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to spawn or read from journalctl: {0}")]
    Spawn(std::io::Error),
}
