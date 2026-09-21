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
pub(crate) use linux::{cmd_install, cmd_uninstall, drift_report, snapshot_definition};
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

// ── Shared install-path resolution + #103 hardening (Unix service arms) ──────

/// Paths baked into the generated unit/script: absolute, so they survive the
/// service manager starting the process with `/` as its working directory.
#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct ResolvedPaths {
    pub(crate) watchdog_abs: std::path::PathBuf,
    pub(crate) agent_abs: std::path::PathBuf,
    pub(crate) alerts_abs: std::path::PathBuf,
}

#[cfg(unix)]
pub(crate) fn resolve_paths(
    agent_bin: Option<std::path::PathBuf>,
    alerts: std::path::PathBuf,
) -> anyhow::Result<ResolvedPaths> {
    use anyhow::Context as _;

    let agent = crate::paths::resolve_agent_bin(agent_bin)?;
    anyhow::ensure!(agent.exists(), "agent not found: {}", agent.display());
    let agent_abs = agent
        .canonicalize()
        .with_context(|| format!("canonicalize {}", agent.display()))?;

    // The unit/script runs the watchdog (layer 2), which supervises the agent
    // (layer 1) — same shape as the Windows SCM service and the launchd daemon.
    let watchdog_abs = std::env::current_exe()
        .context("current_exe")?
        .canonicalize()
        .context("canonicalize watchdog")?;

    // #103: refuse to install pointing at a binary an unprivileged user could
    // overwrite in place — the integrity check `supervise::watchdog_loop` does
    // at every respawn is worthless if the file it re-hashes lives in a
    // directory anyone can drop a replacement into.
    for bin in [&agent_abs, &watchdog_abs] {
        if let Some(dir) = bin.parent() {
            crate::tamper::refuse_world_writable_dir(dir)
                .with_context(|| format!("checking install directory for {}", bin.display()))?;
        }
        crate::tamper::harden_permissions(bin, 0o755)
            .with_context(|| format!("hardening permissions on {}", bin.display()))?;
        crate::tamper::harden_ownership(bin)
            .with_context(|| format!("hardening ownership on {}", bin.display()))?;
    }

    let alerts_abs =
        std::path::absolute(&alerts).with_context(|| format!("absolutize {}", alerts.display()))?;
    if let Some(parent) = alerts_abs.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }

    Ok(ResolvedPaths {
        watchdog_abs,
        agent_abs,
        alerts_abs,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::resolve_paths;

    /// #103 parity regression: `resolve_paths` is the shared install gate, so a
    /// world-writable agent directory must be refused on every Unix arm — the
    /// macOS installer used to inline its own resolution and silently skip
    /// this check (it existed only in `service/linux.rs`).
    #[test]
    fn install_refuses_agent_in_world_writable_directory() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("wd-ww-install-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let agent = dir.join("agent");
        std::fs::write(&agent, b"#!/bin/sh\n").unwrap();

        let err = resolve_paths(Some(agent), dir.join("alerts.ndjson"))
            .expect_err("a world-writable agent directory must be refused");
        assert!(
            format!("{err:#}").contains("world-writable"),
            "unexpected error: {err:#}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
