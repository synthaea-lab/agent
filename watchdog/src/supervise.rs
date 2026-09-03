//! The supervision loop — layer 1 of kill resistance, identical on every OS: spawn
//! the agent, watch it, respawn on exit. (Layer 2 is the service manager restarting
//! the watchdog itself — see [`crate::service`].)

use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::paths::{child_log_path, resolve_agent_bin};

/// Restarts the agent in a loop until `stop_flag` becomes true.
pub(crate) fn watchdog_loop(
    agent: &Path,
    alerts: &Path,
    restart_delay: u64,
    stop_flag: &AtomicBool,
) {
    while !stop_flag.load(Ordering::SeqCst) {
        eprintln!("[watchdog] starting the agent...");
        let mut child = match spawn_agent(agent, alerts) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[watchdog] spawn failed: {e}. Retrying in {restart_delay}s...");
                if !sleep_unless_stopped(stop_flag, restart_delay) {
                    return;
                }
                continue;
            }
        };
        if !watch_child(&mut child, restart_delay, stop_flag) {
            return;
        }
    }
}

/// Spawns one agent run with its output captured to the child log.
fn spawn_agent(agent: &Path, alerts: &Path) -> std::io::Result<Child> {
    // Force the working directory to the agent binary's folder. In a service
    // session (session 0 on Windows), the default working dir is System32 — the
    // agent would not find rules content nor write alerts.ndjson in the right
    // place.
    let work_dir = agent.parent().unwrap_or_else(|| Path::new("."));
    let log_out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(child_log_path())
        .ok();
    let mut cmd = std::process::Command::new(agent);
    cmd.arg("run")
        .arg("--alerts")
        .arg(alerts)
        .current_dir(work_dir);
    if let Some(f) = log_out {
        let f2 = f.try_clone().ok();
        cmd.stderr(std::process::Stdio::from(f));
        if let Some(f2) = f2 {
            cmd.stdout(std::process::Stdio::from(f2));
        }
    }
    cmd.spawn()
}

/// Watches one child until it exits (→ `true`: restart it) or the stop flag rises
/// (→ `false`: kill it and end supervision). Polls in short steps to react to the
/// stop flag quickly.
fn watch_child(child: &mut Child, restart_delay: u64, stop_flag: &AtomicBool) -> bool {
    loop {
        if stop_flag.load(Ordering::SeqCst) {
            let _ = child.kill();
            return false;
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                eprintln!("[watchdog] agent exited ({status}). Restarting in {restart_delay}s...");
                return sleep_unless_stopped(stop_flag, restart_delay);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(500)),
            Err(e) => {
                eprintln!("[watchdog] try_wait error: {e}");
                return true;
            }
        }
    }
}

/// Sleeps `secs` in interruptible steps; `false` when the stop flag rose mid-wait.
fn sleep_unless_stopped(stop_flag: &AtomicBool, secs: u64) -> bool {
    for _ in 0..(secs * 2) {
        if stop_flag.load(Ordering::SeqCst) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    true
}

/// Subcommand `run`: direct supervision (fallback without service rights, and the
/// body of Windows service mode).
pub(crate) fn cmd_run(
    agent_bin: Option<PathBuf>,
    alerts: PathBuf,
    restart_delay: u64,
) -> anyhow::Result<()> {
    let agent = resolve_agent_bin(agent_bin)?;
    anyhow::ensure!(agent.exists(), "agent not found: {}", agent.display());

    eprintln!(
        "[watchdog] supervising {} → alerts in {}",
        agent.display(),
        alerts.display()
    );
    eprintln!("[watchdog] Ctrl+C to stop the watchdog (the agent will be stopped too)");

    let stop = AtomicBool::new(false);
    watchdog_loop(&agent, &alerts, restart_delay, &stop);
    Ok(())
}
