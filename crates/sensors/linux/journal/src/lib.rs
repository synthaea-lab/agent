//! # sensor-linux-journal
//!
//! OS-log ingestion as a supplementary sensor: tails journald (sd-journal API)
//! for the high-value channels raw syscalls do not express —
//! - authentication: sshd accepts/failures, PAM sessions, sudo/su usage (the
//!   lateral-movement telemetry on servers)
//! - service lifecycle: unit starts/stops/failures (persistence + tamper context)
//!
//! Records normalize into schema events with their journal provenance kept;
//! filtering is allowlist-based (never ship the whole journal).
