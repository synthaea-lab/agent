//! `watchdog` — kill resistance for the agent. Migrated from `old/watchdog`.
//!
//! Four CLI subcommands:
//!   install   — installs the watchdog as a system service with auto-restart
//!   uninstall — uninstalls the service
//!   status    — shows the service state as the platform's service manager sees it
//!   run       — pure-Rust supervision loop (service entry point, or fallback without
//!               service rights)
//!
//! Kill resistance is the same two layers on every OS: the service manager runs the
//! watchdog (never the agent directly), and the watchdog's supervision loop spawns and
//! respawns the agent. Kill the agent → the watchdog restarts it; kill the watchdog →
//! the service manager restarts it. To stop it for good, go through the service manager:
//!   Windows: the watchdog is the Windows service; `sc failure` restart policy. (sc stop)
//!   Linux  : systemd unit with `Restart=always RestartSec=5s`.  (systemctl stop)
//!   macOS  : launchd daemon with `KeepAlive`.                   (launchctl bootout)
//!
//! On Unix a stop request arrives as SIGTERM (systemd stop, launchctl bootout); the
//! watchdog traps it, kills the agent, and exits — the same clean-stop semantics the
//! Windows SCM control handler provides.
//!
//! Module map: `paths` (agent/binary/log resolution), `supervise` (the respawn
//! loop), `service` (per-platform install/uninstall: SCM, systemd, launchd),
//! `tamper` (install-surface hardening and integrity checks, issue #103).

mod paths;
mod service;
mod supervise;
mod tamper;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use paths::DEFAULT_ALERTS;

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

    /// Shows the service state as the platform's service manager sees it.
    Status,

    /// Direct supervision loop — respawns the agent if dead.
    /// Also the entry point when launched by the service manager.
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

        /// Heartbeat check interval in seconds (#102): how often the progress
        /// counter the agent writes is polled for advancement.
        #[arg(long, default_value = "5")]
        heartbeat_interval_secs: u64,

        /// Consecutive stalled heartbeat checks before the agent is considered
        /// hung and killed/restarted (#102).
        #[arg(long, default_value = "6")]
        heartbeat_miss_limit: u32,
    },
}

fn run_cli() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Install { agent_bin, alerts } => service::cmd_install(agent_bin, alerts),
        Command::Uninstall => service::cmd_uninstall(),
        Command::Status => service::cmd_status(),
        Command::Run {
            agent_bin,
            alerts,
            restart_delay,
            heartbeat_interval_secs,
            heartbeat_miss_limit,
        } => supervise::cmd_run(
            agent_bin,
            alerts,
            restart_delay,
            heartbeat_interval_secs,
            heartbeat_miss_limit,
        ),
    }
}

fn main() {
    // On Windows: try the service-mode dispatch first. If launched by the SCM
    // (service_dispatcher::start succeeds), we enter service::windows::run_as_service()
    // and never come back here. If launched directly from the CLI, start() fails
    // with ERROR_FAILED_SERVICE_CONTROLLER_CONNECT (1063) → we fall into run_cli().
    #[cfg(windows)]
    {
        use windows_service::Error;
        match service::windows::run_as_service() {
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
