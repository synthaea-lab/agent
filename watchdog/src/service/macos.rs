//! macOS: launchd daemon with `KeepAlive`. The daemon runs the watchdog (layer
//! 2), which supervises the agent (layer 1) — same shape as the Windows SCM
//! service and the systemd unit.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};

use super::resolve_paths;
use crate::paths::child_log_path;

const LAUNCHD_LABEL: &str = "com.synthaea.agent";
const LAUNCHD_PLIST: &str = "/Library/LaunchDaemons/com.synthaea.agent.plist";

/// Minimal escaping for text nodes in the generated plist (paths may contain
/// `&`, `<`, `>` — anything else is legal as-is inside an XML text node).
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn launchd_plist(watchdog: &Path, agent: &Path, alerts: &Path) -> String {
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
        <string>{watchdog}</string>
        <string>run</string>
        <string>--agent-bin</string>
        <string>{agent}</string>
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
    <string>/var/log/synthaea-watchdog.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/synthaea-watchdog.log</string>
</dict>
</plist>
"#,
        label = LAUNCHD_LABEL,
        watchdog = xml_escape(&watchdog.to_string_lossy()),
        agent = xml_escape(&agent.to_string_lossy()),
        alerts = xml_escape(&alerts.to_string_lossy()),
        work_dir = xml_escape(&work_dir.to_string_lossy()),
    )
}

pub(crate) fn cmd_install(agent_bin: Option<PathBuf>, alerts: PathBuf) -> anyhow::Result<()> {
    // Shared with the Linux arms — including the #103 world-writable/ownership
    // hardening this arm used to silently drop (the check existed only on
    // Linux, so a macOS install from ~/Downloads passed unexamined).
    let paths = resolve_paths(agent_bin, alerts)?;

    std::fs::write(
        LAUNCHD_PLIST,
        launchd_plist(&paths.watchdog_abs, &paths.agent_abs, &paths.alerts_abs),
    )
    .with_context(|| format!("writing {LAUNCHD_PLIST} (root required)"))?;
    // #103: same treatment the systemd unit gets — don't rely on umask for a
    // root-owned service definition's permissions.
    crate::tamper::harden_permissions(Path::new(LAUNCHD_PLIST), 0o644)
        .with_context(|| format!("hardening permissions on {LAUNCHD_PLIST}"))?;
    crate::tamper::harden_ownership(Path::new(LAUNCHD_PLIST))
        .with_context(|| format!("hardening ownership on {LAUNCHD_PLIST}"))?;
    run_launchctl(&["bootstrap", "system", LAUNCHD_PLIST])?;

    println!("[watchdog] launchd daemon installed and started.");
    println!("  Alerts: {}", paths.alerts_abs.display());
    println!("  Check: watchdog status");
    println!(
        "  Logs : /var/log/synthaea-watchdog.log (watchdog); agent output in {}",
        child_log_path()
    );
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
    fn launchd_plist_runs_the_watchdog_and_escapes_paths() {
        let plist = launchd_plist(
            Path::new("/opt/A&B/watchdog"),
            Path::new("/opt/A&B/agent"),
            Path::new("/var/lib/synthaea/alerts.ndjson"),
        );
        assert!(plist.contains("<string>com.synthaea.agent</string>"));
        // launchd runs the watchdog, which supervises the agent.
        assert!(
            plist.contains("<string>/opt/A&amp;B/watchdog</string>\n        <string>run</string>")
        );
        assert!(
            plist.contains(
                "<string>--agent-bin</string>\n        <string>/opt/A&amp;B/agent</string>"
            )
        );
        assert!(plist.contains("<string>/var/lib/synthaea/alerts.ndjson</string>"));
        assert!(plist.contains("<key>WorkingDirectory</key>\n    <string>/opt/A&amp;B</string>"));
        assert!(plist.contains("<key>KeepAlive</key>\n    <true/>"));
    }
}
