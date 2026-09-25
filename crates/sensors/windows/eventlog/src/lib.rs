//! # sensor-windows-eventlog
//!
//! Windows Event Log channels as a supplementary, driverless sensor
//! (`EvtSubscribe` push subscriptions on an allowlist):
//! - Security: 4624/4625/4648 (logons — lateral movement), 4688 fallback, 4672
//! - System: 7045 (service install — persistence)
//! - Security: 4720 (local account creation — persistence)
//! - Microsoft-Windows-AppLocker + WDAC, Defender operational, Task-Scheduler
//!
//! Implements three persistence detections, ported from a spike validated
//! end-to-end on a real Windows VM (see
//! `docs/adr/0004-windows-persistence-detection-via-eventlog-polling.md` for the
//! full investigation and rationale — summary below), plus logon/session-event
//! normalization:
//!
//! - **T1543.003** — Create or Modify System Process: Windows Service. System log,
//!   event **7045** ("A service was installed in the system").
//! - **T1053.005** — Scheduled Task/Job: Scheduled Task. Security log, event
//!   **4698** ("A scheduled task was created").
//! - **T1053.005**, task-hijack sub-case — an *existing* task's action rewritten.
//!   Security log, event **4702** ("A scheduled task was updated"), same audit
//!   subcategory as 4698, lab-validated via `schtasks /change` (2026-09-22). Own
//!   flag (`schema::FLAG_PERSISTENCE_TASK_UPDATE_ARTIFACT`); Windows rewrites its
//!   own tasks routinely, so the consuming rule adds a suspicious-action-path gate
//!   the other persistence rules do not need.
//! - **T1136.001** — Create Account: Local Account. Security log, event **4720**
//!   ("A user account was created"). Scoped to local SAM accounts on this host;
//!   domain account creation writes 4720 on the DC, not the reporting machine,
//!   so it is T1136.002 territory and out of scope for a userland EDR here.
//! - **Logon/session events** (#94): Security log events **4624** (successful
//!   logon), **4625** (failed logon), **4648** (explicit-credential logon — a
//!   classic RunAs/lateral-movement signal), and **4672** (special privileges
//!   assigned to a new logon), normalized into `schema::Event::Auth` — the same
//!   shape `sensor-linux-journal` (not yet implemented) is meant to emit its own
//!   auth events as, per `docs/adr/0005-windows-logon-events-shared-auth-event-type.md`.
//!   Unlike the two persistence detections above, the field names this module
//!   parses have not yet been reconciled against a real lab-VM capture — see
//!   `xml::LogonEvent`'s doc before relying on this in production.
//!
//! ## Why `wevtutil` polling, not `EvtSubscribe` (yet)
//!
//! The rest of this crate's name and this module's original design intent point at
//! `EvtSubscribe` — the native Windows Event Log push-subscription API — as the
//! long-term mechanism for this crate (real-time, no polling latency, no shelling
//! out). **That is still the right target.** What ships here instead is a
//! `wevtutil`-polling implementation, for a narrower reason than "`EvtSubscribe`
//! doesn't work": the investigation behind this code tested a **live ETW
//! subscription** (`ferrisetw`/TDH, the same mechanism `sensor-windows` uses for the
//! kernel providers) against the "Service Control Manager" and
//! "Microsoft-Windows-Security-Auditing" providers, not the native Event Log
//! `EvtSubscribe` API — a different Windows API, one layer up, specifically built
//! for subscribing to channels (System/Security/...) rather than raw ETW providers,
//! and the one real EDR/SIEM agents typically use for exactly this. It was not
//! evaluated here, for lack of time in the original investigation window, and may
//! well not hit either of the two walls documented below. Switching to it is the
//! natural follow-up for whoever picks up #94 for real: it would remove the poll
//! interval (currently 2s, see `POLL_INTERVAL` in `sensor.rs`), the process
//! spawn per query, and the fragile substring XML parsing — none of which are
//! fundamental to the detection logic, just to this stopgap plumbing. The
//! logon-event poller added for #94 shares this same trade-off and the same
//! target: it reads the Security channel through `wevtutil` today for
//! consistency with the two detections already here, not because logon events
//! were separately confirmed to have the same ETW problem.
//!
//! What *is* validated (in lab, on a real Windows VM, true positive + true negative
//! for both techniques): consuming these two events via a raw ETW subscription does
//! not work, for two unrelated reasons —
//! - **7045**: "Service Control Manager" is a classic/legacy ETW provider
//!   (`Qualifiers='16384'` in `wevtutil`'s XML rendering); `ferrisetw`/TDH can only
//!   resolve a schema for manifest-based providers, so `event_id()` always reports
//!   `0` and `event_schema()` fails with `TdhNativeError(IoError { code: 1168 })`.
//! - **4698**: "Microsoft-Windows-Security-Auditing" IS manifest-based (GUID
//!   confirmed, keyword filter adjusted, `SeSecurityPrivilege` enabled successfully)
//!   — yet the ETW callback is simply never invoked, even for events confirmed via
//!   `wevtutil` to have just been generated while the sensor was running. The
//!   Security log appears to not be subscribable in real time by a third-party ETW
//!   consumer created ad hoc, regardless of settings.
//!
//! `wevtutil` polling sidesteps both (it goes through the classic Event Log reader
//! API, not ETW), at the cost of up to `POLL_INTERVAL` of detection latency and a
//! child-process spawn per poll tick — an accepted trade-off for a persistence
//! detection (the attacker already had to run `sc create` / `schtasks /create`
//! before the event exists at all; a couple of seconds of latency does not change
//! the outcome).
//!
//! ## Schema fit
//!
//! The two persistence detections are reported as `schema::FileOpenEvent` (not a
//! new `Event` variant), marked with `schema::FLAG_PERSISTENCE_ARTIFACT` /
//! `FLAG_PERSISTENCE_TASK_ARTIFACT` / `FLAG_PERSISTENCE_TASK_UPDATE_ARTIFACT` /
//! `FLAG_PERSISTENCE_ACCOUNT_ARTIFACT` — see those constants' docs for why, and
//! `rules::check_service_persistence` / `check_scheduled_task_persistence` for
//! the consuming rules. Pragmatic reuse, not the final shape: a dedicated event
//! family (`docs/architecture/event-schema.md` already lists "Registry" as a
//! planned Windows-only family) is the natural home once one exists for other
//! reasons too.
//!
//! Logon events are different: `schema::Event::Auth` is a real, dedicated
//! variant (schema version bumped for #94) rather than another reuse of
//! `FileOpenEvent` — deliberately, since it is meant to be shared with a future
//! Linux sensor rather than staying Windows-only stopgap plumbing. See
//! `docs/adr/0005-windows-logon-events-shared-auth-event-type.md`.
//!
//! ## Additional detection channels (#283)
//!
//! Two extra operational channels supplement the Security-channel poll targets
//! above, both **always-on** (no `auditpol` toggle) so they cover the same
//! techniques even on a host where the audit subcategory for 4698 was left
//! disabled:
//!
//! - **`AppLocker` EXE/DLL block** (`Microsoft-Windows-AppLocker/EXE and DLL`
//!   channel, event **8004**): an executable was refused execution by
//!   `AppLocker` policy. Reported as `FileOpenEvent` with
//!   `schema::FLAG_APPLICATION_BLOCKED` — a defensive signal (a known-bad
//!   payload stopped at the OS boundary), not a persistence artifact, so it
//!   takes its own flag rather than reusing a `FLAG_PERSISTENCE_*` bit.
//! - **Task Scheduler Operational — task registered**
//!   (`Microsoft-Windows-TaskScheduler/Operational` channel, event **106**):
//!   the always-on complement to Security 4698. Emitted whenever any scheduled
//!   task is registered on this host. The event carries no task XML, so the
//!   sensor reads the actions back from the task's definition file under
//!   `%SystemRoot%\System32\Tasks` and reports the same shape as a 4698
//!   (`schema::FLAG_PERSISTENCE_TASK_ARTIFACT`, action-unknown placeholder when
//!   the file is gone or unreadable). A registration seen on *both* channels is
//!   reported once by the rules layer (`rules::RuleState`, #422); both raw
//!   events are kept.
//!
//! ## Transport: polling (default) vs. `EvtSubscribe` (#322)
//!
//! The two transports coexist and are selected per host via
//! `EventLogTransport` in `EventLogConfig`:
//!
//! - `EventLogTransport::Polling` — the default. One thread per
//!   enabled target runs a `wevtutil` `qe` loop at the `POLL_INTERVAL`
//!   cadence (2s), same shape as the pre-#322 implementation and same
//!   trade-offs as documented in the section above.
//! - `EventLogTransport::Subscribe` — one `EvtSubscribe`
//!   subscription per enabled target, with a Windows callback delivering
//!   events the moment they land in the channel. Removes the polling
//!   latency and the subprocess churn. Available since #322; opt-in at the
//!   config layer so hosts adopt it after validation rather than the whole
//!   fleet flipping on a version bump.
//!
//! Both transports reuse the same `PollTarget` table (`sensor.rs`), the
//! same `xml::parse_*` parsers, and the same `EventLogCounters` — only the
//! delivery mechanism differs. See `subscribe.rs` for the OS-facing details
//! of the callback-based path.
//!
//! ## Configurable allowlist and volume counters (#94)
//!
// Plain code spans, not intra-doc links, for the three items below: they are
// Windows-gated, so links to them would break the Linux docs build CI runs.
//! `EventLogConfig` toggles the poll targets above independently (4698 and
//! 4702 share one toggle; a disabled target is never even queried), and
//! `EventLogCounters` (via `EventLogSensor::counters`) exposes a live count
//! of events actually normalized per target. This crate cannot depend on
//! `policy` (`sensor-*` crates depend only on `schema` —
//! `tools/check-deps.py`), so `EventLogConfig` is this crate's own type; the
//! `agent` binary converts `policy::EventLogPolicy` into it at construction
//! time. See `docs/adr/0006-eventlog-channel-allowlist-and-volume-counters.md`.

pub mod xml;

#[cfg(windows)]
mod sensor;
// The `EvtSubscribe` transport (issue #322) — enabled per-host via
// `EventLogConfig::transport`. Gated `#[cfg(windows)]` because it binds
// against `windows-sys`; the Linux CI leg keeps compiling `xml.rs`.
#[cfg(windows)]
mod subscribe;
#[cfg(windows)]
pub use sensor::{EventLogConfig, EventLogCounters, EventLogSensor, EventLogTransport};
