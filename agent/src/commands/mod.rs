//! Per-platform implementations of the subcommands. All of the agent's
//! `cfg(target_os)` lives here — the sink stays platform-agnostic, and each
//! platform's commands live in their own module (same shape as the watchdog's
//! `service/` tree). On a platform without a wired sensor (macOS until M5),
//! the commands compile and fail cleanly at runtime instead of breaking the
//! workspace build.

#[cfg(any(target_os = "linux", windows))]
mod common;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
pub(crate) use linux::{cmd_capture_baseline, cmd_capture_events, cmd_run, cmd_status};
#[cfg(windows)]
pub(crate) use windows::{cmd_capture_baseline, cmd_capture_events, cmd_run, cmd_status};

#[cfg(not(any(target_os = "linux", windows)))]
const UNSUPPORTED_PLATFORM: &str = "no sensor is wired for this platform yet — Linux (eBPF) and Windows (ETW) are \
     live; macOS (EndpointSecurity) arrives with M5. This build is for development \
     only (cargo check/test).";

#[cfg(not(any(target_os = "linux", windows)))]
pub(crate) fn cmd_status() -> anyhow::Result<()> {
    anyhow::bail!(UNSUPPORTED_PLATFORM)
}

#[cfg(not(any(target_os = "linux", windows)))]
pub(crate) fn cmd_run(
    _alerts: &std::path::Path,
    _events: &std::path::Path,
    _enable_kill: bool,
    _enable_quarantine: bool,
    _server: Option<&str>,
) -> anyhow::Result<()> {
    anyhow::bail!(UNSUPPORTED_PLATFORM)
}

#[cfg(not(any(target_os = "linux", windows)))]
pub(crate) fn cmd_capture_events(_output: &std::path::Path) -> anyhow::Result<()> {
    anyhow::bail!(UNSUPPORTED_PLATFORM)
}

#[cfg(not(any(target_os = "linux", windows)))]
pub(crate) fn cmd_capture_baseline(_output: &std::path::Path) -> anyhow::Result<()> {
    anyhow::bail!(UNSUPPORTED_PLATFORM)
}
