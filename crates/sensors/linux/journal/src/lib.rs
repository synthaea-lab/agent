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
//! **Status (issue #93):** [`classify`]/[`JournalRecord`] parsing, and the
//! [`auth`] mapping into the shared `schema::AuthEvent` (issue #94 having landed
//! `Event::Auth` since this crate's foundation was written — see [`auth`]'s module
//! doc), are done and tested. Real-hardware validation (Hyper-V lab, Arch Linux):
//! `sshd` accept and `sudo` both confirmed to land as normalized `AuthEvent`s.
//! Found along the way: this box's OpenSSH (9.8+ privsep refactor) re-execs the
//! per-connection worker as `sshd-session`, never `sshd` — the original
//! `identifier == "sshd"` check (written against documentation, no `sshd` on the
//! original dev box to verify against) would have silently never matched on real
//! hardware; both identifiers are now checked. Also confirmed: unprivileged
//! `journalctl` cannot read these auth records at all on this box (journald's
//! per-unit read ACL) — a non-issue for this sensor in practice since the agent
//! already needs root for eBPF, but worth remembering if testing this crate
//! standalone. `su`/`sshd` login-failure mapping is implemented and unit-tested
//! but still unverified against a real prompt/failed attempt.
//!
//! Deliberately **not** here yet:
//! - No [`schema::sensor::Sensor`] implementation — like `sensor-linux-netlink`
//!   (issue #92), this is a supplementary poll/tail source wired directly into
//!   `agent::commands::linux::cmd_run` alongside the main sensor, not a
//!   standalone `Sensor`.
//! - No cursor persistence across agent restarts (the `crates/store` integration)
//!   — not required by issue #93's `Done when`; a restart re-tailing from "now"
//!   rather than resuming is an accepted gap for a follow-up, not this issue.
//! - No unit-lifecycle mapping (`JournalEvent::UnitStarted`/`Stopped`/`Failed`) —
//!   see [`auth`]'s module doc for why.

mod auth;
mod classify;
mod record;
mod tail;

pub use auth::to_auth_event;
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
