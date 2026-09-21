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

/// Hardened service ACL (issue #103): only `SY` (`LocalSystem`) keeps
/// `SERVICE_STOP`/`SERVICE_PAUSE_CONTINUE`/`DELETE` — built-in Administrators
/// (`BA`) keep query/start/interrogate/`READ_CONTROL`/`WRITE_DAC`/`WRITE_OWNER`
/// but lose the rights an attacker with local admin (not SYSTEM) would use
/// for a smash-and-grab `sc stop`/`sc delete`. `BA` keeping `WRITE_DAC` is
/// deliberate: it's what lets [`cmd_uninstall`] reset the ACL back before its
/// own `sc stop`/`sc delete`, so the *tool* still works for an admin while a
/// bare `sc stop`/`sc delete` typed by hand does not. `IU`/`SU`/`WD`
/// (interactive/service-logon/everyone) get read-only rights.
///
/// This is friction, not a real boundary — an admin can always run
/// `watchdog uninstall`, or hand-run the same `sc sdset` this module does, to
/// undo it. Matches the issue's own framing: detection + friction + audit
/// trail against local admin, not a claim to stop it outright.
const HARDENED_SERVICE_SDDL: &str = "D:(A;;GA;;;SY)(A;;CCLCSWRPLOCRRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWLOCRRC;;;WD)";

/// The stock rights `BA` needs to `sc stop`/`sc delete` itself — restored by
/// [`cmd_uninstall`] before it does exactly that, and by [`cmd_install`]
/// before re-running `sc description`/`sc failure` (both `SERVICE_CHANGE_CONFIG`)
/// on a service a previous install already hardened.
const PERMISSIVE_SERVICE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWLOCRRC;;;WD)";

/// Applies [`HARDENED_SERVICE_SDDL`]. Best-effort: a failure here (e.g. `sc
/// sdset` itself blocked by some other policy) leaves the service installed
/// and functional, just without the extra ACL friction — worth a loud
/// warning, not worth failing an otherwise-successful install over.
fn harden_service_acl() {
    if let Err(e) = run_sc(&["sdset", SERVICE_NAME, HARDENED_SERVICE_SDDL]) {
        eprintln!(
            "[watchdog] warning: could not harden service ACL ({e}) — \
             service is installed and running, but not protected against \
             a non-SYSTEM sc stop/delete"
        );
    }
}

/// Applies [`PERMISSIVE_SERVICE_SDDL`]. Best-effort and silent on failure:
/// called before an operation that needs the stock rights back, on a service
/// that may not be hardened yet (fresh install) or may not exist at all
/// (uninstall of a service that was never installed) — either is a normal,
/// expected outcome here, not an error worth surfacing.
fn reset_service_acl_best_effort() {
    let _ = run_sc(&["sdset", SERVICE_NAME, PERMISSIVE_SERVICE_SDDL]);
}

pub(crate) fn cmd_install(agent_bin: Option<PathBuf>, alerts: PathBuf) -> anyhow::Result<()> {
    let agent = resolve_agent_bin(agent_bin)?;
    anyhow::ensure!(agent.exists(), "agent not found: {}", agent.display());

    // Undo any hardening from a previous install before `sc description`/`sc
    // failure` below, which need SERVICE_CHANGE_CONFIG — a no-op (harmlessly
    // failing, ignored) on a fresh install where the service doesn't exist yet.
    reset_service_acl_best_effort();

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
    harden_service_acl();

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
    // Undo the #103 ACL hardening first: an admin running this tool should be
    // able to uninstall even though the hardened ACL denies a bare `sc
    // stop`/`sc delete` to anyone but SYSTEM. Best-effort — a service that
    // was never hardened, or never installed, just no-ops here.
    reset_service_acl_best_effort();
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
    fn hardened_sddl_denies_stop_pause_delete_to_administrators() {
        // The `BA` (built-in Administrators) clause must not grant WP
        // (SERVICE_STOP), DT (SERVICE_PAUSE_CONTINUE), or SD (DELETE) — that's
        // the entire point of #103's hardening. Isolate BA's own clause
        // rather than scanning the whole string, since SY's clause
        // legitimately grants all of these via GA.
        let ba_clause = HARDENED_SERVICE_SDDL
            .split(')')
            .find(|clause| clause.ends_with(";;;BA"))
            .expect("SDDL has a BA clause");
        for right in ["WP", "DT", "SD"] {
            assert!(
                !ba_clause.contains(right),
                "BA clause {ba_clause:?} must not grant {right}"
            );
        }
    }

    #[test]
    fn hardened_sddl_still_lets_administrators_write_dac() {
        // BA must keep WRITE_DAC (WD) — cmd_uninstall relies on it to reset
        // the ACL back to PERMISSIVE_SERVICE_SDDL before its own stop/delete.
        let ba_clause = HARDENED_SERVICE_SDDL
            .split(')')
            .find(|clause| clause.ends_with(";;;BA"))
            .expect("SDDL has a BA clause");
        assert!(ba_clause.contains("WD"), "BA clause {ba_clause:?} needs WD");
    }

    #[test]
    fn hardened_sddl_grants_system_full_control() {
        assert!(HARDENED_SERVICE_SDDL.contains("(A;;GA;;;SY)"));
    }

    #[test]
    fn permissive_sddl_restores_administrators_to_full_control() {
        assert!(PERMISSIVE_SERVICE_SDDL.contains("(A;;GA;;;BA)"));
    }

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
