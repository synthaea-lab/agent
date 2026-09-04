//! # tamper
//!
//! Runtime tamper protection — the agent defending itself, beyond the watchdog's
//! restart loop. Planned capabilities:
//!
//! - **Self-integrity**: hash-verify the agent/watchdog binaries and config against
//!   the manifest installed by `updater`; mismatch is a detection, not just a log.
//! - **Sensor-silence detection**: a heartbeat per sensor — an attacker who stops
//!   telemetry (e.g. kills an ETW session, detaches a probe) without killing the
//!   process produces silence, and silence itself raises an alert locally AND
//!   reaches the server (audit F-2/P5 generalized to every platform).
//! - **Protected-resource monitoring**: watch the agent's own files, services,
//!   registry keys, and launchd/systemd units through the normal event stream —
//!   any process touching them that is not `updater` is a high-severity detection.
//! - **Kill-loudness**: termination attempts (who, when, how) recorded to the spool
//!   before dying where the platform allows it.
//!
//! Honest scope (from the old README, kept true here): none of this stops a
//! kernel-level adversary — that needs PPL/ELAM, SIP, LSM (per-platform milestones).
//! What it does is make every tampering path loud, attributable, and fleet-visible.
//!
//! ## Implemented so far
//!
//! - [`heartbeat`] — sensor-silence detection: the platform-agnostic core of the F-2
//!   canary, turning "a sensor stopped producing telemetry" into an alert. The
//!   integrity and protected-resource halves are tracked by #71.

pub mod heartbeat;

pub use heartbeat::{SensorHeartbeat, SilenceMonitor, SilenceVerdict};
