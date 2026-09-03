//! `watchdog` — kill resistance for the agent. Migrated from `old/watchdog`.
//!
//! Three CLI subcommands:
//!   install   — installs the watchdog as a system service (systemd / SC Manager) with auto-restart
//!   uninstall — uninstalls the service
//!   run       — pure-Rust supervision loop (fallback without service rights, or SCM service mode)
//!
//! Kill resistance is the same two layers on every OS: the service manager runs the
//! watchdog (never the agent directly), and the watchdog's supervision loop spawns and
//! respawns the agent. Kill the agent → the watchdog restarts it; kill the watchdog →
//! the service manager restarts it. To stop it for good, go through the service manager:
//!   Windows: the watchdog is the Windows service; `sc failure` restart policy. (sc stop)
//!   Linux  : systemd unit with `Restart=always RestartSec=5s`.  (systemctl stop)
//!   macOS  : launchd daemon with `KeepAlive`.                   (launchctl bootout)

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, bail};
use clap::{Parser, Subcommand};

// The service constants are consumed by the Windows/SCM and Linux/systemd arms only.
#[cfg_attr(not(windows), allow(dead_code))]
const SERVICE_NAME: &str = "SynthaEDR";
#[cfg_attr(not(windows), allow(dead_code))]
const SERVICE_DISPLAY: &str = "Synthaea EDR Agent";
#[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
const SERVICE_DESC: &str =
    "Synthaea Endpoint Detection & Response — real-time behavioral monitoring";
const DEFAULT_ALERTS: &str = "alerts.ndjson";

#[cfg(target_os = "linux")]
const SYSTEMD_UNIT: &str = "/etc/systemd/system/synthaea-agent.service";

#[cfg(target_os = "macos")]
const LAUNCHD_LABEL: &str = "com.synthaea.agent";
#[cfg(target_os = "macos")]
const LAUNCHD_PLIST: &str = "/Library/LaunchDaemons/com.synthaea.agent.plist";

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "watchdog",
    about = "Installs and supervises the Synthaea agent as a system service"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Installs the watchdog as a system service with automatic restart.
    /// Requires administrator / root rights.
    Install {
        /// Path to the agent binary (default: same folder as this binary).
        #[arg(long)]
        agent_bin: Option<PathBuf>,

        /// JSON-Lines alerts output file.
        #[arg(long, default_value = DEFAULT_ALERTS)]
        alerts: PathBuf,
    },

    /// Stops and uninstalls the service.
    Uninstall,

    /// Direct supervision loop — respawns the agent if dead.
    /// Also used as the entry point when the watchdog is launched by the Windows SCM.
    Run {
        /// Path to the agent binary (default: same folder as this binary).
        #[arg(long)]
        agent_bin: Option<PathBuf>,

        /// JSON-Lines alerts output file.
        #[arg(long, default_value = DEFAULT_ALERTS)]
        alerts: PathBuf,

        /// Restart delay in seconds after a crash.
        #[arg(long, default_value = "5")]
        restart_delay: u64,
    },
}

// ── agent path resolution ─────────────────────────────────────────────────────

fn resolve_agent_bin(explicit: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(strip_unc_prefix(p));
    }
    let mut path = std::env::current_exe().context("cannot resolve current_exe")?;
    path.pop();
    path.push(agent_binary_name());
    Ok(strip_unc_prefix(path))
}

fn agent_binary_name() -> &'static str {
    if cfg!(windows) { "agent.exe" } else { "agent" }
}

/// Strips the `\\?\` prefix added by canonicalize() on Windows.
/// CreateProcess does not support this prefix and fails silently when given one.
fn strip_unc_prefix(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        path
    }
}

/// Where the supervised agent's stdout/stderr go: in a service session the inherited
/// streams go nowhere and crash diagnostics would be lost. (The old iteration used a
/// single hardcoded `C:\Windows\Temp` path on every OS — on Linux that literally
/// created a file named `C:\Windows\Temp\…` in the working directory.)
fn child_log_path() -> &'static str {
    if cfg!(windows) {
        r"C:\Windows\Temp\synthaea-agent.log"
    } else {
        "/var/tmp/synthaea-agent.log"
    }
}

// ── Shared supervision loop (all platforms) ───────────────────────────────────

/// Restarts the agent in a loop until `stop_flag` becomes true.
fn watchdog_loop(
    agent: &std::path::Path,
    alerts: &std::path::Path,
    restart_delay: u64,
    stop_flag: &std::sync::atomic::AtomicBool,
) {
    use std::sync::atomic::Ordering;

    loop {
        if stop_flag.load(Ordering::SeqCst) {
            break;
        }

        eprintln!("[watchdog] starting the agent...");
        // Force the working directory to the agent binary's folder. In a service
        // session (session 0 on Windows), the default working dir is System32 — the
        // agent would not find rules content nor write alerts.ndjson in the right
        // place.
        let work_dir = agent.parent().unwrap_or_else(|| std::path::Path::new("."));
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
        let child = cmd.spawn();

        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[watchdog] spawn failed: {e}. Retrying in {restart_delay}s...");
                for _ in 0..(restart_delay * 2) {
                    if stop_flag.load(Ordering::SeqCst) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(500));
                }
                continue;
            }
        };

        // Watch the child in a short loop to react quickly to stop_flag.
        loop {
            if stop_flag.load(Ordering::SeqCst) {
                let _ = child.kill();
                return;
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    eprintln!(
                        "[watchdog] agent exited ({status}). Restarting in {restart_delay}s..."
                    );
                    for _ in 0..(restart_delay * 2) {
                        if stop_flag.load(Ordering::SeqCst) {
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(500));
                    }
                    break; // restart
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(500)),
                Err(e) => {
                    eprintln!("[watchdog] try_wait error: {e}");
                    break;
                }
            }
        }
    }
}

// ── Subcommand: run (CLI fallback, no SCM) ────────────────────────────────────

fn cmd_run(agent_bin: Option<PathBuf>, alerts: PathBuf, restart_delay: u64) -> anyhow::Result<()> {
    use std::sync::atomic::AtomicBool;

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

// ── Windows: SCM service ──────────────────────────────────────────────────────

#[cfg(windows)]
mod win_service {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    use super::*;

    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    // Mandatory windows-service macro to generate the FFI entry point.
    define_windows_service!(ffi_service_main, service_main);

    pub fn run_as_service() -> windows_service::Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    fn service_main(_args: Vec<std::ffi::OsString>) {
        if let Err(e) = run_service_logic() {
            eprintln!("[watchdog-service] fatal error: {e:#}");
        }
    }

    fn run_service_logic() -> anyhow::Result<()> {
        let agent = resolve_agent_bin(None)?;
        let alerts = std::path::PathBuf::from(DEFAULT_ALERTS);

        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_ctl = stop_flag.clone();

        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    stop_flag_ctl.store(true, Ordering::SeqCst);
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };

        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
            .context("registering SCM handler")?;

        // Report RUNNING
        status_handle
            .set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: ServiceState::Running,
                controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })
            .context("set_service_status RUNNING")?;

        watchdog_loop(&agent, &alerts, 5, &stop_flag);

        // Report STOPPED
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        });

        Ok(())
    }
}

#[cfg(windows)]
fn cmd_install(agent_bin: Option<PathBuf>, alerts: PathBuf) -> anyhow::Result<()> {
    let agent = resolve_agent_bin(agent_bin)?;
    anyhow::ensure!(agent.exists(), "agent not found: {}", agent.display());

    // The service points at the watchdog itself (not the agent).
    let watchdog_abs = std::env::current_exe()
        .context("current_exe")?
        .canonicalize()
        .context("canonicalize watchdog")?;
    let out_abs = alerts.canonicalize().unwrap_or_else(|_| alerts.clone());

    // No arguments: the watchdog detects on its own that it was launched by the SCM.
    let bin_path = format!("\"{}\"", watchdog_abs.display());

    run_sc(&[
        "create",
        SERVICE_NAME,
        "binPath=",
        &bin_path,
        "start=",
        "auto",
        "DisplayName=",
        SERVICE_DISPLAY,
    ])?;
    run_sc(&["description", SERVICE_NAME, SERVICE_DESC])?;
    // Automatic restart if the watchdog itself is killed (2 layers of protection).
    run_sc(&[
        "failure",
        SERVICE_NAME,
        "reset=",
        "0",
        "actions=",
        "restart/5000/restart/5000/restart/5000",
    ])?;
    run_sc(&["start", SERVICE_NAME])?;

    println!("[watchdog] service \"{SERVICE_NAME}\" installed and started.");
    println!("  Alerts: {}", out_abs.display());
    println!("  Check: sc query {SERVICE_NAME}");
    println!("  Uninstall: watchdog uninstall");
    Ok(())
}

#[cfg(windows)]
fn cmd_uninstall() -> anyhow::Result<()> {
    let _ = run_sc(&["stop", SERVICE_NAME]);
    run_sc(&["delete", SERVICE_NAME])?;
    println!("[watchdog] service \"{SERVICE_NAME}\" removed.");
    Ok(())
}

#[cfg(windows)]
fn run_sc(args: &[&str]) -> anyhow::Result<()> {
    let status = std::process::Command::new("sc")
        .args(args)
        .status()
        .context("cannot launch sc.exe")?;
    if !status.success() {
        bail!("sc {} failed ({})", args.join(" "), status);
    }
    Ok(())
}

// ── Linux: systemd ────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn cmd_install(agent_bin: Option<PathBuf>, alerts: PathBuf) -> anyhow::Result<()> {
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
    println!("  Check: systemctl status synthaea-agent");
    println!(
        "  Logs : journalctl -u synthaea-agent -f (watchdog); agent output in {}",
        child_log_path()
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn cmd_uninstall() -> anyhow::Result<()> {
    let _ = run_systemctl(&["stop", "synthaea-agent.service"]);
    run_systemctl(&["disable", "synthaea-agent.service"])?;
    if std::path::Path::new(SYSTEMD_UNIT).exists() {
        std::fs::remove_file(SYSTEMD_UNIT).with_context(|| format!("removing {SYSTEMD_UNIT}"))?;
    }
    run_systemctl(&["daemon-reload"])?;
    println!("[watchdog] synthaea-agent service uninstalled.");
    Ok(())
}

#[cfg(target_os = "linux")]
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

// ── macOS: launchd ────────────────────────────────────────────────────────────

/// Minimal escaping for text nodes in the generated plist (paths may contain
/// `&`, `<`, `>` — anything else is legal as-is inside an XML text node).
#[cfg(target_os = "macos")]
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(target_os = "macos")]
fn launchd_plist(agent: &std::path::Path, alerts: &std::path::Path) -> String {
    let work_dir = agent.parent().unwrap_or_else(|| std::path::Path::new("/"));
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

#[cfg(target_os = "macos")]
fn cmd_install(agent_bin: Option<PathBuf>, alerts: PathBuf) -> anyhow::Result<()> {
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

#[cfg(target_os = "macos")]
fn cmd_uninstall() -> anyhow::Result<()> {
    // bootout fails when the daemon is not loaded — like the systemd/SCM arms,
    // uninstall still removes the on-disk definition in that case.
    let _ = run_launchctl(&["bootout", &format!("system/{LAUNCHD_LABEL}")]);
    if std::path::Path::new(LAUNCHD_PLIST).exists() {
        std::fs::remove_file(LAUNCHD_PLIST).with_context(|| format!("removing {LAUNCHD_PLIST}"))?;
    }
    println!("[watchdog] {LAUNCHD_LABEL} daemon uninstalled.");
    Ok(())
}

#[cfg(target_os = "macos")]
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

// ── Unsupported platform stubs ────────────────────────────────────────────────

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn cmd_install(_: Option<PathBuf>, _: PathBuf) -> anyhow::Result<()> {
    bail!("install is only supported on Windows, Linux, and macOS")
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn cmd_uninstall() -> anyhow::Result<()> {
    bail!("uninstall is only supported on Windows, Linux, and macOS")
}

// ── main ──────────────────────────────────────────────────────────────────────

fn run_cli() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Install { agent_bin, alerts } => cmd_install(agent_bin, alerts),
        Command::Uninstall => cmd_uninstall(),
        Command::Run {
            agent_bin,
            alerts,
            restart_delay,
        } => cmd_run(agent_bin, alerts, restart_delay),
    }
}

fn main() {
    // On Windows: try the service-mode dispatch first. If launched by the SCM
    // (service_dispatcher::start succeeds), we enter win_service::run_as_service()
    // and never come back here. If launched directly from the CLI, start() fails
    // with ERROR_FAILED_SERVICE_CONTROLLER_CONNECT (1063) → we fall into run_cli().
    #[cfg(windows)]
    {
        use windows_service::Error;
        match win_service::run_as_service() {
            Ok(()) => return,
            Err(Error::Winapi(ref e)) if e.raw_os_error() == Some(1063) => {
                // Not launched by the SCM — normal CLI mode
            }
            Err(e) => {
                eprintln!("[watchdog] service dispatcher error: {e}");
                std::process::exit(1);
            }
        }
    }

    if let Err(e) = run_cli() {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_unc_prefix_removes_the_windows_long_path_prefix() {
        assert_eq!(
            strip_unc_prefix(PathBuf::from(r"\\?\C:\edr\agent.exe")),
            PathBuf::from(r"C:\edr\agent.exe")
        );
        assert_eq!(
            strip_unc_prefix(PathBuf::from("/opt/synthaea/agent")),
            PathBuf::from("/opt/synthaea/agent")
        );
    }

    #[test]
    fn resolve_agent_bin_defaults_next_to_the_watchdog() {
        let p = resolve_agent_bin(None).unwrap();
        assert_eq!(
            p.file_name().unwrap().to_string_lossy(),
            agent_binary_name()
        );
    }

    #[test]
    fn explicit_agent_path_wins() {
        let p = resolve_agent_bin(Some(PathBuf::from("/x/agent"))).unwrap();
        assert_eq!(p, PathBuf::from("/x/agent"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launchd_plist_escapes_paths_and_pins_the_working_directory() {
        let plist = launchd_plist(
            std::path::Path::new("/opt/A&B/agent"),
            std::path::Path::new("/var/lib/synthaea/alerts.ndjson"),
        );
        assert!(plist.contains("<string>com.synthaea.agent</string>"));
        assert!(plist.contains("<string>/opt/A&amp;B/agent</string>"));
        assert!(plist.contains("<key>WorkingDirectory</key>\n    <string>/opt/A&amp;B</string>"));
        assert!(plist.contains("<string>/var/lib/synthaea/alerts.ndjson</string>"));
        assert!(plist.contains("<key>KeepAlive</key>\n    <true/>"));
    }
}
