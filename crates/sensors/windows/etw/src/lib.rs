//! # sensor-windows
//!
//! Windows user-mode sensor built on ETW (Kernel-Process, Kernel-Network,
//! Kernel-File), migrated from the old iteration with the coverage-audit findings
//! fixed at the source:
//!
//! - **F-1**: the command line is the REAL command line, read from the target's PEB
//!   (`NtQueryInformationProcess` + `ReadProcessMemory`), never the image path.
//! - **F-2**: the session name is randomized per start, but under a fixed
//!   `wtrace-` prefix — every session matching it is enumerated and stopped at
//!   startup (issue #408 — catches every orphan left by any number of consecutive
//!   unclean shutdowns, not just the most recent). That prefix is itself a
//!   fingerprint: an attacker can enumerate our session exactly the way we do
//!   (`logman query -ets | findstr wtrace-`), so the session is still stoppable.
//!   The guarantee is that stopping it is *loud*, not that it's impossible: the
//!   silence watchdog turns a stopped trace into a sensor error instead of quiet
//!   blindness.
//! - **F-3**: every event carries the process's user SID and integrity level
//!   (`User::Windows`), resolved from the process token.
//! - **F-4**: unbounded strings via the new schema — multi-KB encoded command lines
//!   survive intact.
//! - **F-5**: NT device paths normalize through a real `QueryDosDeviceW` volume map,
//!   not a hardcoded `C:`.
//! - **F-6** (partial): `CreateNewFile` (EID 30) joins `NameCreate` (EID 12); full
//!   delete/rename semantics need schema variants and land with the ransomware pack
//!   (#82) / driver (#39).
//! - **F-7**: IPv6 connects (EID 58/26) are first-class, and a short dedup window
//!   prevents Connect+Send double-counting.
//!
//! The provider expansion (registry, DNS, image load, AMSI, WMI — audit P2–P8) is
//! #21; each provider arrives as its own module. Compiles to a stub off Windows.
//!
//! Download provenance (#365): a Kernel-File write to a `:Zone.Identifier`
//! stream (mark-of-the-web) is read back and reported as
//! `schema::FileQuarantineEvent`, the macOS quarantine-xattr sibling — see
//! [`zone_identifier`].

pub mod normalize;
#[cfg(any(windows, test))]
mod pid_cache;
#[cfg(windows)]
mod providers;

#[cfg(windows)]
mod sensor;
#[cfg(windows)]
mod winapi;
pub mod zone_identifier;
#[cfg(windows)]
pub use sensor::WindowsSensor;
