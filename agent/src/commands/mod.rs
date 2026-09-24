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

/// Everything `cmd_run` needs, bundled so the function stays under clippy's
/// argument-count lint — `state_dir` (#30/#71, the updater base directory
/// `crate::integrity` reads the persisted release manifest from) was the eighth
/// positional parameter, past the seventh clippy already flags. Every platform's
/// `cmd_run` takes the same struct, even the ones that only use part of it — same
/// "accepted for parity, inert here" posture the individual fields already had.
pub(crate) struct RunOptions<'a> {
    pub(crate) alerts: &'a std::path::Path,
    pub(crate) events: &'a std::path::Path,
    // Read only by `linux::cmd_run` (integrity monitoring, response, uprobes
    // capture — all Linux-only mechanisms); `windows`/`macos::cmd_run` destructure
    // and discard them for CLI-signature parity, same "accepted, inert here"
    // posture the individual parameters had before this struct existed. Bundling
    // them turns that per-platform inertness into a whole-field dead-code
    // finding on any target that isn't Linux, unlike a bare unused fn parameter —
    // hence the explicit allow rather than relying on the `_` destructuring alone.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) state_dir: &'a std::path::Path,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) enable_kill: bool,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) enable_quarantine: bool,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) enable_tls_capture: bool,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) enable_readline_capture: bool,
    pub(crate) server: Option<&'a str>,
    /// Where the local IPC control channel listens for `cli` (issue #388),
    /// from `cfg.ipc.endpoint`: a Unix socket path, or a Windows named pipe.
    pub(crate) ipc_endpoint: &'a str,
}

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
pub(crate) fn cmd_run(_opts: RunOptions) -> anyhow::Result<()> {
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
