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
//! but still unverified against a real prompt/failed attempt. Same caveat for
//! `sudo`/`su`'s own wrong-password case (`JournalEvent::PamAuthFailure`, #381,
//! T1548.003): implemented and unit-tested against the documented `pam_unix(...
//! :auth): authentication failure; ...` format, not yet confirmed against a
//! real failed attempt (this crate's Hyper-V lab host has no interactive TTY
//! for one, same limitation as the pre-existing `su`/`sshd` case above).
//!
//! Also done: [`persistence::UnitPersistenceTracker`] maps a unit's first
//! observed start into `schema::FileOpenEvent`/`FLAG_PERSISTENCE_SYSTEMD_ARTIFACT`
//! (T1543.002) — the cross-platform decision [`auth`]'s module doc had left
//! open, resolved once issue #224 (Windows' own service-lifecycle event
//! reconciliation) landed and confirmed `sensor-windows-eventlog`'s precedent:
//! reuse `FileOpenEvent` + a flag, no new `Event` variant. See that module's
//! doc for why this is an approximation ("first start seen by this agent
//! process"), not a true install signal.
//!
//! Also done (#1085, T1562.001): [`unitstop::to_unit_stop_event`] maps the stop of a unit of
//! `schema::SECURITY_SERVICES` into `schema::FileOpenEvent`/`FLAG_UNIT_STOPPED`, filtered here so
//! the other units that stop at every reboot never leave the sensor. The journal names no actor:
//! the event says a stop happened, not who asked. Unit job records are only trusted from a
//! systemd manager (`_PID=1`, or `_COMM=systemd` for a `--user` manager): `JOB_TYPE`/`UNIT` are
//! client-settable journal fields, so before this a `logger`-style record could claim a start or
//! stop of any unit. A stop is only reported from the system manager (a user can name a user unit
//! `falco.service`). Not lab-verified: a system-manager `JOB_TYPE=stop` record has not been
//! captured on a real host (the only capture is a user manager's, see `record.rs`'s tests).
//!
//! **Liveness (#71, #83):** the iterator yields allowlisted records only, so the agent's
//! silence heartbeat hangs on [`ClassifiedJournal::with_line_hook`], which sees every
//! non-blank line, and the canary line (`CANARY_IDENTIFIER`) the agent writes into
//! journald every 30 s guarantees there is one to see on an idle host.
//!
//! Deliberately **not** here yet:
//! - No [`schema::sensor::Sensor`] implementation — like `sensor-linux-netlink`
//!   (issue #92), this is a supplementary poll/tail source wired directly into
//!   `agent::commands::linux::cmd_run` alongside the main sensor, not a
//!   standalone `Sensor`.
//! - No cursor persistence *in this crate* — `process::current_cursor`/
//!   `process::spawn_follow(after_cursor)` are the mechanism, but reading a prior
//!   run's cursor back and writing the current one as records arrive is
//!   `agent::journal_cursor`'s job (issue #321: a restart now resumes from the
//!   last persisted cursor via a small file next to the alerts output, no
//!   `crates/store` integration needed — first start still begins at "now", same
//!   as before). [`persistence::UnitPersistenceTracker`]'s seen-set is still
//!   agent-process-local and still resets on restart — a known limitation of that
//!   tracker (see its own doc), unrelated to and not closed by the journal
//!   cursor now being persisted.

mod auth;
mod canary;
mod classify;
mod persistence;
mod record;
mod tail;
mod unitstop;

pub use auth::to_auth_event;
pub use canary::{CANARY_IDENTIFIER, canary_payload};
#[cfg(target_os = "linux")]
pub use canary::{JOURNAL_SOCKET, send_canary};
pub use classify::{JournalEvent, classify};
pub use persistence::UnitPersistenceTracker;
pub use record::{JournalRecord, parse_record};
pub use tail::ClassifiedJournal;
#[cfg(target_os = "linux")]
pub use tail::process::{current_cursor, spawn_follow};
pub use unitstop::to_unit_stop_event;

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
