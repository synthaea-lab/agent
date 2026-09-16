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
    "Synthaea Endpoint Detection & Response — real-time behavioral monitoring";

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

/// Subcommand `status`: the service manager's view. The query command's own exit
/// code is informational (a stopped or absent service is a valid answer, not an
/// error). Linux delegates to `linux::cmd_status` since the query itself is
/// service-manager-dependent (systemd vs. `OpenRC`, detected there).
pub(crate) fn cmd_status() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::cmd_status()
    }

    #[cfg(not(target_os = "linux"))]
    {
        let (program, args): (&str, &[&str]) = if cfg!(windows) {
            ("sc", &["query", SERVICE_NAME])
        } else if cfg!(target_os = "macos") {
            ("launchctl", &["print", "system/com.synthaea.agent"])
        } else {
            anyhow::bail!("status is only supported on Windows, Linux, and macOS")
        };

        let status = std::process::Command::new(program)
            .args(args)
            .status()
            .map_err(|e| anyhow::anyhow!("cannot launch {program}: {e}"))?;
        if !status.success() {
            println!(
                "[watchdog] service not running or not installed ({program} exited {status})."
            );
        }
        Ok(())
    }
}
