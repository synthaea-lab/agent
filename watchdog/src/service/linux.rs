//! Linux: systemd unit with `Restart=always` — systemd restarts the watchdog, the
//! watchdog restarts the agent.

use std::path::PathBuf;

use anyhow::{Context as _, bail};

use super::SERVICE_DESC;
use crate::paths::{child_log_path, resolve_agent_bin};

const SYSTEMD_UNIT: &str = "/etc/systemd/system/synthaea-agent.service";

pub(crate) fn cmd_install(agent_bin: Option<PathBuf>, alerts: PathBuf) -> anyhow::Result<()> {
    let agent = resolve_agent_bin(agent_bin)?;
    anyhow::ensure!(agent.exists(), "agent not found: {}", agent.display());

    let agent_abs = agent
        .canonicalize()
        .with_context(|| format!("canonicalize {}", agent.display()))?;

    // The unit runs the watchdog (layer 2), which supervises the agent (layer 1) —
    // same shape as the Windows SCM service and the launchd daemon.
    let watchdog_abs = std::env::current_exe()
        .context("current_exe")?
        .canonicalize()
        .context("canonicalize watchdog")?;

    // Services start with `/` as working directory — pin the alerts path down
    // before it lands in the unit file.
    let alerts_abs =
        std::path::absolute(&alerts).with_context(|| format!("absolutize {}", alerts.display()))?;
    if let Some(parent) = alerts_abs.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }

    let unit = format!(
        "[Unit]\nDescription={desc}\nAfter=network.target\n\n\
         [Service]\nType=simple\n\
         ExecStart=\"{watchdog}\" run --agent-bin \"{agent}\" --alerts \"{out}\"\n\
         Restart=always\nRestartSec=5s\nUser=root\n\
         StandardOutput=journal\nStandardError=journal\n\
         SyslogIdentifier=synthaea-watchdog\n\n\
         [Install]\nWantedBy=multi-user.target\n",
        desc = SERVICE_DESC,
        watchdog = watchdog_abs.display(),
        agent = agent_abs.display(),
        out = alerts_abs.display(),
    );

    std::fs::write(SYSTEMD_UNIT, &unit)
        .with_context(|| format!("writing {SYSTEMD_UNIT} (root required)"))?;
    run_systemctl(&["daemon-reload"])?;
    run_systemctl(&["enable", "--now", "synthaea-agent.service"])?;

    println!("[watchdog] systemd service installed and started.");
    println!("  Alerts: {}", alerts_abs.display());
    println!("  Check: watchdog status");
    println!(
        "  Logs : journalctl -u synthaea-agent -f (watchdog); agent output in {}",
        child_log_path()
    );
    Ok(())
}

pub(crate) fn cmd_uninstall() -> anyhow::Result<()> {
    let _ = run_systemctl(&["stop", "synthaea-agent.service"]);
    run_systemctl(&["disable", "synthaea-agent.service"])?;
    if std::path::Path::new(SYSTEMD_UNIT).exists() {
        std::fs::remove_file(SYSTEMD_UNIT).with_context(|| format!("removing {SYSTEMD_UNIT}"))?;
    }
    run_systemctl(&["daemon-reload"])?;
    println!("[watchdog] synthaea-agent service uninstalled.");
    Ok(())
}

fn run_systemctl(args: &[&str]) -> anyhow::Result<()> {
    let status = std::process::Command::new("systemctl")
        .args(args)
        .status()
        .context("cannot launch systemctl")?;
    if !status.success() {
        bail!("systemctl {} failed ({})", args.join(" "), status);
    }
    Ok(())
}
