//! Per-platform implementations of the subcommands. All of the agent's
//! `cfg(target_os)` lives here — the sink stays platform-agnostic, and each
//! platform's commands live in their own module (same shape as the watchdog's
//! `service/` tree). On a platform without a wired sensor, the commands
//! compile and fail cleanly at runtime instead of breaking the workspace
//! build.

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod common;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
pub(crate) use linux::{cmd_capture_baseline, cmd_capture_events, cmd_run, cmd_status};
#[cfg(target_os = "macos")]
pub(crate) use macos::{cmd_capture_baseline, cmd_capture_events, cmd_run, cmd_status};
#[cfg(windows)]
pub(crate) use windows::{cmd_capture_baseline, cmd_capture_events, cmd_run, cmd_status};

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
const UNSUPPORTED_PLATFORM: &str = "no sensor is wired for this platform — Linux (eBPF), Windows (ETW), and macOS \
     (EndpointSecurity) are live. This build is for development only (cargo check/test).";

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub(crate) fn cmd_status() -> anyhow::Result<()> {
    anyhow::bail!(UNSUPPORTED_PLATFORM)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub(crate) fn cmd_run(
    _alerts: &std::path::Path,
    _events: &std::path::Path,
    _enable_kill: bool,
    _enable_quarantine: bool,
    _enable_tls_capture: bool,
    _enable_readline_capture: bool,
    _server: Option<&str>,
) -> anyhow::Result<()> {
    anyhow::bail!(UNSUPPORTED_PLATFORM)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub(crate) fn cmd_capture_events(_output: &std::path::Path) -> anyhow::Result<()> {
    anyhow::bail!(UNSUPPORTED_PLATFORM)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub(crate) fn cmd_capture_baseline(_output: &std::path::Path) -> anyhow::Result<()> {
    anyhow::bail!(UNSUPPORTED_PLATFORM)
}
