//! # sensor-windows-eventlog
//!
//! Windows Event Log channels as a supplementary, driverless sensor
//! (EvtSubscribe push subscriptions on an allowlist):
//! - Security: 4624/4625/4648 (logons — lateral movement), 4688 fallback, 4672
//! - System: 7045 (service install — persistence)
//! - Microsoft-Windows-AppLocker + WDAC, Defender operational, Task-Scheduler
//!
//! Rationale: many detections need exactly these records, they cost no kernel work,
//! and ETW does not carry all of them. Allowlisted channels + rendered-field
//! normalization into schema events; volume-bounded like every other source.
