//! macOS: launchd daemon with `KeepAlive` — launchd restarts the agent directly
//! (its throttle interval plays the restart-delay role).

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};

use crate::paths::resolve_agent_bin;

const LAUNCHD_LABEL: &str = "com.synthaea.agent";
const LAUNCHD_PLIST: &str = "/Library/LaunchDaemons/com.synthaea.agent.plist";

/// Minimal escaping for text nodes in the generated plist (paths may contain
/// `&`, `<`, `>` — anything else is legal as-is inside an XML text node).
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn launchd_plist(agent: &Path, alerts: &Path) -> String {
    let work_dir = agent.parent().unwrap_or_else(|| Path::new("/"));
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{agent}</string>
        <string>run</string>
        <string>--alerts</string>
        <string>{alerts}</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{work_dir}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>StandardOutPath</key>
    <string>/var/log/synthaea-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/synthaea-agent.log</string>
</dict>
</plist>
"#,
        label = LAUNCHD_LABEL,
        agent = xml_escape(&agent.to_string_lossy()),
        alerts = xml_escape(&alerts.to_string_lossy()),
        work_dir = xml_escape(&work_dir.to_string_lossy()),
    )
}

pub(crate) fn cmd_install(agent_bin: Option<PathBuf>, alerts: PathBuf) -> anyhow::Result<()> {
    let agent = resolve_agent_bin(agent_bin)?;
    anyhow::ensure!(agent.exists(), "agent not found: {}", agent.display());

    let agent_abs = agent
        .canonicalize()
        .with_context(|| format!("canonicalize {}", agent.display()))?;

    // launchd daemons start with `/` as working directory — a relative alerts
    // path must be pinned down before it lands in the plist.
    let alerts_abs =
        std::path::absolute(&alerts).with_context(|| format!("absolutize {}", alerts.display()))?;
    if let Some(parent) = alerts_abs.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }

    std::fs::write(LAUNCHD_PLIST, launchd_plist(&agent_abs, &alerts_abs))
        .with_context(|| format!("writing {LAUNCHD_PLIST} (root required)"))?;
    run_launchctl(&["bootstrap", "system", LAUNCHD_PLIST])?;

    println!("[watchdog] launchd daemon installed and started.");
    println!("  Alerts: {}", alerts_abs.display());
    println!("  Check: sudo launchctl print system/{LAUNCHD_LABEL}");
    println!("  Logs : /var/log/synthaea-agent.log");
    println!("  Uninstall: watchdog uninstall");
    Ok(())
}

pub(crate) fn cmd_uninstall() -> anyhow::Result<()> {
    // bootout fails when the daemon is not loaded — like the systemd/SCM arms,
    // uninstall still removes the on-disk definition in that case.
    let _ = run_launchctl(&["bootout", &format!("system/{LAUNCHD_LABEL}")]);
    if std::path::Path::new(LAUNCHD_PLIST).exists() {
        std::fs::remove_file(LAUNCHD_PLIST).with_context(|| format!("removing {LAUNCHD_PLIST}"))?;
    }
    println!("[watchdog] {LAUNCHD_LABEL} daemon uninstalled.");
    Ok(())
}

fn run_launchctl(args: &[&str]) -> anyhow::Result<()> {
    let status = std::process::Command::new("launchctl")
        .args(args)
        .status()
        .context("cannot launch launchctl")?;
    if !status.success() {
        bail!("launchctl {} failed ({})", args.join(" "), status);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launchd_plist_escapes_paths_and_pins_the_working_directory() {
        let plist = launchd_plist(
            Path::new("/opt/A&B/agent"),
            Path::new("/var/lib/synthaea/alerts.ndjson"),
        );
        assert!(plist.contains("<string>com.synthaea.agent</string>"));
        assert!(plist.contains("<string>/opt/A&amp;B/agent</string>"));
        assert!(plist.contains("<key>WorkingDirectory</key>\n    <string>/opt/A&amp;B</string>"));
        assert!(plist.contains("<string>/var/lib/synthaea/alerts.ndjson</string>"));
        assert!(plist.contains("<key>KeepAlive</key>\n    <true/>"));
    }
}
