//! Windows: the watchdog runs as an SCM service with an `sc failure` restart
//! policy, and detects service-mode launch itself (see `main`'s dispatch).

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

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
use crate::paths::{DEFAULT_ALERTS, resolve_agent_bin};
use crate::supervise::watchdog_loop;

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
    let agent = resolve_agent_bin(None)?;
    let alerts = PathBuf::from(DEFAULT_ALERTS);

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

pub(crate) fn cmd_install(agent_bin: Option<PathBuf>, alerts: PathBuf) -> anyhow::Result<()> {
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
