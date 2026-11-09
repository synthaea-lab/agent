//! # sensor-windows-eventlog
//!
//! Windows Event Log channels as a supplementary, driverless sensor: an
//! allowlist of Security, System, `AppLocker`, WDAC, Defender, Task Scheduler,
//! Terminal Services and Kerberos events, normalized into `schema` events
//! (persistence artifacts, logons, sessions, policy denials, Defender
//! verdicts, log clears).
//!
//! Both transports go through the Event Log reader API, never a live ETW
//! subscription: System 7045 comes from a classic provider TDH cannot decode,
//! and an ad-hoc ETW consumer never receives Security 4698. The default
//! transport polls with `EvtQuery` every 2 s; `EvtSubscribe` push delivery is
//! opt-in per host. Both share the target table, the [`xml`] parsers and the
//! counters.
//!
//! `EventLogConfig` is this crate's own type, since sensor crates depend only
//! on `schema`; the agent converts its policy into it. See
//! `docs/sensors/windows/eventlog.md`.
// `EventLogConfig` is a code span, not an intra-doc link: it is Windows-gated,
// so a link would break the docs build on other hosts.

pub mod xml;

// Reads a channel's `Enabled` setting, so a disabled one is reported rather
// than polled in silence.
#[cfg(windows)]
mod channel;
// Portable so its messages are tested on every host.
#[cfg_attr(not(windows), allow(dead_code))]
mod error;
// The polling transport's channel read (`EvtQuery`, UTF-16).
#[cfg(windows)]
mod query;
#[cfg(windows)]
mod sensor;
// The `EvtSubscribe` transport, selected per host by `EventLogConfig::transport`.
#[cfg(windows)]
mod subscribe;
// Only `sensor.rs` calls into it outside tests, so it is dead code off Windows.
#[cfg_attr(not(windows), allow(dead_code))]
mod targets;
#[cfg(windows)]
pub use sensor::{EventLogConfig, EventLogCounters, EventLogSensor, EventLogTransport};
