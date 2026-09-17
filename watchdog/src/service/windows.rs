//! Windows: the watchdog runs as an SCM service with an `sc failure` restart
//! policy, and detects service-mode launch itself (see `main`'s dispatch).

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context as _, bail};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

use super::{SERVICE_DESC, SERVICE_DISPLAY, SERVICE_NAME};
use crate::{
    paths::{DEFAULT_ALERTS, resolve_agent_bin},
    supervise::watchdog_loop,
};

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

// Mandatory windows-service macro to generate the FFI entry point.
define_windows_service!(ffi_service_main, service_main);

pub(crate) fn run_as_service() -> windows_service::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn service_main(_args: Vec<std::ffi::OsString>) {
    if let Err(e) = run_service_logic() {
        eprintln!("[watchdog-service] fatal error: {e:#}");
    }
}

fn run_service_logic() -> anyhow::Result<()> {
    // Not `_args` above: the SCM only populates `service_main`'s argument list
    // when a caller starts the service via `StartService` with explicit
    // arguments — never on ordinary auto-start at boot, which is how this
    // service actually runs. `binPath` is what the SCM launches every time
    // (auto-start included), so `cmd_install` persists `--agent-bin`/
    // `--alerts` there instead, and this reads them back from the real
    // process command line (#112: previously hardcoded to `None`/
    // `DEFAULT_ALERTS` here, silently dropping whatever was configured at
    // install time across a reboot).
    let (agent_bin_override, alerts) = parse_persisted_args(std::env::args());
    let agent = resolve_agent_bin(agent_bin_override)?;

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

    // Hardcoded defaults matching the CLI's own `--heartbeat-interval-secs`/
    // `--heartbeat-miss-limit` defaults (#102): `service_main`'s argument list
    // isn't populated on ordinary auto-start (see `parse_persisted_args`'s
    // doc), so — same as `restart_delay` above — these can't be threaded
    // through `binPath` without a larger change; matching the existing
    // `restart_delay` precedent rather than introducing a new asymmetry.
    watchdog_loop(&agent, &alerts, 5, 5, 6, &stop_flag);

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

/// Extracts `--agent-bin`/`--alerts` from a `run --agent-bin <path> --alerts
/// <path>` style argument list — the exact shape [`build_bin_path`] persists
/// into the service's `binPath`. A tiny manual scan rather than pulling the
/// full `clap` `Cli` in for two flags; unknown/missing flags fall back to
/// [`resolve_agent_bin`]'s own default resolution and [`DEFAULT_ALERTS`].
fn parse_persisted_args(args: impl Iterator<Item = String>) -> (Option<PathBuf>, PathBuf) {
    let args: Vec<String> = args.collect();
    let mut agent_bin = None;
    let mut alerts = PathBuf::from(DEFAULT_ALERTS);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--agent-bin" if i + 1 < args.len() => {
                agent_bin = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--alerts" if i + 1 < args.len() => {
                alerts = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            _ => i += 1,
        }
    }
    (agent_bin, alerts)
}

pub(crate) fn cmd_install(agent_bin: Option<PathBuf>, alerts: PathBuf) -> anyhow::Result<()> {
    let agent = resolve_agent_bin(agent_bin)?;
    anyhow::ensure!(agent.exists(), "agent not found: {}", agent.display());

    // The service points at the watchdog itself (not the agent).
    let watchdog_abs = std::env::current_exe()
        .context("current_exe")?
        .canonicalize()
        .context("canonicalize watchdog")?;
    let agent_abs = agent
        .canonicalize()
        .with_context(|| format!("canonicalize {}", agent.display()))?;
    // Services start with `C:\Windows\System32` as the working directory —
    // pin the alerts path down (`std::path::absolute`, not `.canonicalize()`:
    // the file usually does not exist yet on a fresh install, and the old
    // `.canonicalize().unwrap_or_else(|_| alerts.clone())` fallback silently
    // kept a cwd-relative path in exactly that case) before it's persisted
    // into `binPath` — the same treatment `service/linux.rs`'s `ExecStart=`
    // and `service/macos.rs`'s `ProgramArguments` already give it.
    let alerts_abs =
        std::path::absolute(&alerts).with_context(|| format!("absolutize {}", alerts.display()))?;
    if let Some(parent) = alerts_abs.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }

    let bin_path = build_bin_path(&watchdog_abs, &agent_abs, &alerts_abs);

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
    println!("  Alerts: {}", alerts_abs.display());
    println!("  Check: watchdog status");
    println!("  Uninstall: watchdog uninstall");
    Ok(())
}

/// Builds the service's `binPath=` value: the SCM launches the process with
/// exactly this command line every time, including ordinary auto-start at
/// boot — unlike `service_main`'s argument list (see [`parse_persisted_args`]),
/// this is how `--agent-bin`/`--alerts` actually survive a reboot (#112). Each
/// path argument is individually quoted for `CommandLineToArgvW`, matching the
/// systemd `ExecStart=`/launchd `ProgramArguments` treatment in the other two
/// installers.
fn build_bin_path(watchdog: &Path, agent: &Path, alerts: &Path) -> String {
    format!(
        "\"{}\" run --agent-bin \"{}\" --alerts \"{}\"",
        watchdog.display(),
        agent.display(),
        alerts.display(),
    )
}

pub(crate) fn cmd_uninstall() -> anyhow::Result<()> {
    let _ = run_sc(&["stop", SERVICE_NAME]);
    run_sc(&["delete", SERVICE_NAME])?;
    println!("[watchdog] service \"{SERVICE_NAME}\" removed.");
    Ok(())
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_bin_path_quotes_each_argument() {
        let bin_path = build_bin_path(
            Path::new(r"C:\Program Files\Synthaea\watchdog.exe"),
            Path::new(r"C:\Program Files\Synthaea\agent.exe"),
            Path::new(r"C:\ProgramData\Synthaea\alerts.ndjson"),
        );
        assert_eq!(
            bin_path,
            r#""C:\Program Files\Synthaea\watchdog.exe" run --agent-bin "C:\Program Files\Synthaea\agent.exe" --alerts "C:\ProgramData\Synthaea\alerts.ndjson""#
        );
    }

    #[test]
    fn parse_persisted_args_round_trips_build_bin_path() {
        // What cmd_install persists into binPath is exactly what
        // run_service_logic must read back after a reboot. Reproduces how the
        // SCM hands args to the process (whitespace-split argv, matching
        // CommandLineToArgvW) for paths with no embedded spaces or quotes.
        let bin_path = build_bin_path(
            Path::new(r"C:\edr\watchdog.exe"),
            Path::new(r"C:\edr\agent.exe"),
            Path::new(r"C:\edr\alerts.ndjson"),
        );
        let argv = bin_path.split(' ').map(|s| s.trim_matches('"').to_string());
        let (agent_bin, alerts) = parse_persisted_args(argv);
        assert_eq!(agent_bin, Some(PathBuf::from(r"C:\edr\agent.exe")));
        assert_eq!(alerts, PathBuf::from(r"C:\edr\alerts.ndjson"));
    }

    #[test]
    fn parse_persisted_args_defaults_when_absent() {
        let (agent_bin, alerts) =
            parse_persisted_args(["watchdog.exe".to_string(), "run".to_string()].into_iter());
        assert_eq!(agent_bin, None);
        assert_eq!(alerts, PathBuf::from(DEFAULT_ALERTS));
    }

    #[test]
    fn parse_persisted_args_agent_bin_only_keeps_default_alerts() {
        let (agent_bin, alerts) = parse_persisted_args(
            ["watchdog.exe", "run", "--agent-bin", r"C:\edr\agent.exe"]
                .into_iter()
                .map(String::from),
        );
        assert_eq!(agent_bin, Some(PathBuf::from(r"C:\edr\agent.exe")));
        assert_eq!(alerts, PathBuf::from(DEFAULT_ALERTS));
    }

    #[test]
    fn parse_persisted_args_ignores_dangling_flag_without_value() {
        // A truncated/malformed binPath (should never happen from
        // build_bin_path, but defends run_service_logic against a corrupted
        // registry value) falls back to defaults rather than panicking.
        let (agent_bin, alerts) = parse_persisted_args(
            ["watchdog.exe", "run", "--agent-bin"]
                .into_iter()
                .map(String::from),
        );
        assert_eq!(agent_bin, None);
        assert_eq!(alerts, PathBuf::from(DEFAULT_ALERTS));
    }
}
