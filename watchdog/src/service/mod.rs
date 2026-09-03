//! Service installation — layer 2 of kill resistance: the service manager runs the
//! watchdog (never the agent directly) and restarts it if it dies. One submodule
//! per platform mechanism (SCM / systemd / launchd), each exporting the same
//! `cmd_install` / `cmd_uninstall` pair.

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const SERVICE_NAME: &str = "SynthaEDR";
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const SERVICE_DISPLAY: &str = "Synthaea EDR Agent";
#[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
pub(crate) const SERVICE_DESC: &str =
    "Supervises the Synthaea EDR agent and restarts it if it is killed";

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
pub(crate) mod windows;

#[cfg(target_os = "linux")]
pub(crate) use linux::{cmd_install, cmd_uninstall};
#[cfg(target_os = "macos")]
pub(crate) use macos::{cmd_install, cmd_uninstall};
#[cfg(windows)]
pub(crate) use windows::{cmd_install, cmd_uninstall};

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub(crate) fn cmd_install(
    _: Option<std::path::PathBuf>,
    _: std::path::PathBuf,
) -> anyhow::Result<()> {
    anyhow::bail!("install is only supported on Windows, Linux, and macOS")
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub(crate) fn cmd_uninstall() -> anyhow::Result<()> {
    anyhow::bail!("uninstall is only supported on Windows, Linux, and macOS")
}
