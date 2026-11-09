//! Linux: service-manager integration — systemd unit or `OpenRC` `init.d` script,
//! both with unlimited automatic respawn (`Restart=always` / `supervise-daemon`
//! with `respawn_max="0"`), so the service manager restarts the watchdog, the
//! watchdog restarts the agent. Alpine and other non-glibc/non-systemd distros run
//! `OpenRC`, not systemd (issue #213) — detected at install time, not assumed.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use config::identity::{
    LINUX_SERVICE, SERVICE_DESCRIPTION, UNIX_WATCHDOG_LOG, WATCHDOG_SYSLOG_IDENTIFIER,
};

use super::resolve_paths;

/// `<service>.service`, the unit name `systemctl` takes.
fn systemd_unit() -> String {
    format!("{LINUX_SERVICE}.service")
}

/// Where a manual install writes the unit; packages ship theirs under
/// `/usr/lib/systemd/system` instead (#36).
fn systemd_unit_path() -> String {
    format!("/etc/systemd/system/{}", systemd_unit())
}

fn openrc_script_path() -> String {
    format!("/etc/init.d/{LINUX_SERVICE}")
}

/// Symlink `systemctl enable` creates for our unit's `WantedBy=multi-user.target`
/// (see `install_systemd`) — its disappearance means the service was disabled.
fn systemd_enable_link() -> String {
    format!(
        "/etc/systemd/system/multi-user.target.wants/{}",
        systemd_unit()
    )
}

/// Symlink `rc-update add <service> default` creates — its disappearance
/// means `rc-update del`/equivalent ran.
fn openrc_enable_link() -> String {
    format!("/etc/runlevels/default/{LINUX_SERVICE}")
}

enum InitSystem {
    Systemd,
    OpenRc,
}

/// Detects the running init system the same way systemd itself does (`sd_booted()`):
/// `/run/systemd/system` only exists when systemd is PID 1. `OpenRC` never creates it;
/// `openrc-run` (the interpreter every `/etc/init.d` script is run through) is the
/// `OpenRC` marker instead.
fn detect_init_system() -> anyhow::Result<InitSystem> {
    if std::path::Path::new("/run/systemd/system").exists() {
        Ok(InitSystem::Systemd)
    } else if std::path::Path::new("/sbin/openrc-run").exists() {
        Ok(InitSystem::OpenRc)
    } else {
        bail!("no supported init system detected (neither systemd nor OpenRC)")
    }
}

/// A snapshot of the installed service definition's on-disk state, taken once
/// (typically at watchdog startup) so a later snapshot can be compared against it
/// — see [`drift_report`] (issue #103: "definition drift detection").
pub(crate) struct DefinitionSnapshot {
    definition_path: PathBuf,
    enable_link: PathBuf,
    /// `None` if the definition file was already missing when snapshotted (a
    /// broken or removed install, or `run` used directly without `install`).
    digest: Option<[u8; 32]>,
    enabled: bool,
}

/// Reads the current on-disk state of whichever definition/enable-link pair
/// matches the detected init system. Best-effort by design: a missing
/// definition file is a `None` digest, not an error — `run` without a prior
/// `install` is a supported, if unsupervised-by-a-service-manager, mode.
pub(crate) fn snapshot_definition() -> anyhow::Result<DefinitionSnapshot> {
    let (definition_path, enable_link) = match detect_init_system()? {
        InitSystem::Systemd => (
            PathBuf::from(systemd_unit_path()),
            PathBuf::from(systemd_enable_link()),
        ),
        InitSystem::OpenRc => (
            PathBuf::from(openrc_script_path()),
            PathBuf::from(openrc_enable_link()),
        ),
    };
    let digest = crate::tamper::sha256_file(&definition_path).ok();
    let enabled = enable_link.exists();
    Ok(DefinitionSnapshot {
        definition_path,
        enable_link,
        digest,
        enabled,
    })
}

/// Compares two snapshots of the same installation, describing anything that
/// changed between them in a human-readable line each — empty means no drift.
#[must_use]
pub(crate) fn drift_report(
    baseline: &DefinitionSnapshot,
    current: &DefinitionSnapshot,
) -> Vec<String> {
    let mut report = Vec::new();
    match (&baseline.digest, &current.digest) {
        (Some(b), Some(c)) if b != c => report.push(format!(
            "service definition {} was modified after the watchdog started",
            current.definition_path.display()
        )),
        (Some(_), None) => report.push(format!(
            "service definition {} was deleted after the watchdog started",
            current.definition_path.display()
        )),
        _ => {}
    }
    if baseline.enabled && !current.enabled {
        report.push(format!(
            "service was disabled ({} no longer exists)",
            current.enable_link.display()
        ));
    }
    report
}

pub(crate) fn cmd_install(agent_bin: Option<PathBuf>, alerts: PathBuf) -> anyhow::Result<()> {
    match detect_init_system()? {
        InitSystem::Systemd => install_systemd(agent_bin, alerts),
        InitSystem::OpenRc => install_openrc(agent_bin, alerts),
    }
}

pub(crate) fn cmd_uninstall() -> anyhow::Result<()> {
    match detect_init_system()? {
        InitSystem::Systemd => uninstall_systemd(),
        InitSystem::OpenRc => uninstall_openrc(),
    }
}

/// Linux status query, dispatched by init system (called from `service::cmd_status`).
pub(crate) fn cmd_status() -> anyhow::Result<()> {
    match detect_init_system()? {
        InitSystem::Systemd => status_systemd(),
        InitSystem::OpenRc => status_openrc(),
    }
}

fn install_systemd(agent_bin: Option<PathBuf>, alerts: PathBuf) -> anyhow::Result<()> {
    // Check if running from package installation (issue #36)
    // Package-managed units are in /usr/lib/systemd/system/, manual installs in /etc/systemd/system/
    let unit_name = systemd_unit();
    let packaged_unit = PathBuf::from(format!("/usr/lib/systemd/system/{unit_name}"));

    if packaged_unit.exists() {
        // Package already installed the unit - just enable it
        run("systemctl", &["daemon-reload"])?;
        run("systemctl", &["enable", "--now", &unit_name])?;
        println!("[watchdog] Using package-installed systemd unit.");
        println!("  Status: systemctl status {LINUX_SERVICE}");
        println!("  Logs:   journalctl -u {LINUX_SERVICE} -f");
        return Ok(());
    }

    // Fallback: runtime generation for development/manual installs
    let paths = resolve_paths(agent_bin, alerts)?;

    let unit = format!(
        "[Unit]\nDescription={desc}\nAfter=network.target\n\n\
         [Service]\nType=simple\n\
         ExecStart=\"{watchdog}\" run --agent-bin \"{agent}\" --alerts \"{out}\"\n\
         Restart=always\nRestartSec=5s\nUser=root\n\
         StandardOutput=journal\nStandardError=journal\n\
         SyslogIdentifier={syslog_id}\n\n\
         [Install]\nWantedBy=multi-user.target\n",
        desc = SERVICE_DESCRIPTION,
        syslog_id = WATCHDOG_SYSLOG_IDENTIFIER,
        watchdog = paths.watchdog_abs.display(),
        agent = paths.agent_abs.display(),
        out = paths.alerts_abs.display(),
    );

    let unit_path = systemd_unit_path();
    std::fs::write(&unit_path, &unit)
        .with_context(|| format!("writing {unit_path} (root required)"))?;
    // #103: don't rely on umask for a root-owned service definition's permissions.
    crate::tamper::harden_permissions(Path::new(&unit_path), 0o644)
        .with_context(|| format!("hardening permissions on {unit_path}"))?;
    crate::tamper::harden_ownership(Path::new(&unit_path))
        .with_context(|| format!("hardening ownership on {unit_path}"))?;
    run("systemctl", &["daemon-reload"])?;
    run("systemctl", &["enable", "--now", &unit_name])?;

    println!("[watchdog] systemd service installed and started (development mode).");
    println!("  Alerts: {}", paths.alerts_abs.display());
    println!("  Check: watchdog status");
    println!("  Logs : journalctl -u {LINUX_SERVICE} -f (watchdog and agent output)");
    Ok(())
}

fn uninstall_systemd() -> anyhow::Result<()> {
    let unit_name = systemd_unit();
    let unit_path = systemd_unit_path();
    let _ = run("systemctl", &["stop", &unit_name]);
    run("systemctl", &["disable", &unit_name])?;
    if Path::new(&unit_path).exists() {
        std::fs::remove_file(&unit_path).with_context(|| format!("removing {unit_path}"))?;
    }
    run("systemctl", &["daemon-reload"])?;
    println!("[watchdog] {LINUX_SERVICE} service uninstalled.");
    Ok(())
}

fn status_systemd() -> anyhow::Result<()> {
    let status = std::process::Command::new("systemctl")
        .args(["status", &systemd_unit(), "--no-pager"])
        .status()
        .context("cannot launch systemctl")?;
    if !status.success() {
        println!("[watchdog] service not running or not installed (systemctl exited {status}).");
    }
    Ok(())
}

/// `respawn_max` defaults to `5` (within a 1800s `respawn_period`), not unlimited —
/// confirmed on Alpine by `ps aux` showing `supervise-daemon` invoked with those
/// exact values despite the generated script setting neither: they come from the
/// site-wide `/etc/rc.conf` `SUPERVISE DAEMON CONFIGURATION VARIABLES` block,
/// applied to every `supervisor=supervise-daemon` service that doesn't override
/// them. `/etc/rc.conf` documents `respawn_max=0` as "unlimited" — that's the
/// `Restart=always` equivalent we want, so it's set explicitly rather than relying
/// on `OpenRC`'s own default.
fn install_openrc(agent_bin: Option<PathBuf>, alerts: PathBuf) -> anyhow::Result<()> {
    let paths = resolve_paths(agent_bin, alerts)?;

    let script = format!(
        "#!/sbin/openrc-run\n\n\
         description=\"{desc}\"\n\n\
         supervisor=supervise-daemon\n\
         command=\"{watchdog}\"\n\
         command_args=\"run --agent-bin \\\"{agent}\\\" --alerts \\\"{out}\\\"\"\n\
         pidfile=\"/run/${{RC_SVCNAME}}.pid\"\n\
         respawn_max=\"0\"\n\
         output_log=\"{log}\"\n\
         error_log=\"{log}\"\n\n\
         depend() {{\n\
         \tneed net\n\
         \tafter net\n\
         }}\n",
        desc = SERVICE_DESCRIPTION,
        log = UNIX_WATCHDOG_LOG,
        watchdog = paths.watchdog_abs.display(),
        agent = paths.agent_abs.display(),
        out = paths.alerts_abs.display(),
    );

    let script_path = openrc_script_path();
    std::fs::write(&script_path, &script)
        .with_context(|| format!("writing {script_path} (root required)"))?;
    set_executable(&script_path)?;
    // #103: same ownership hardening the systemd unit gets above.
    crate::tamper::harden_ownership(Path::new(&script_path))
        .with_context(|| format!("hardening ownership on {script_path}"))?;

    run("rc-update", &["add", LINUX_SERVICE, "default"])?;
    run("rc-service", &[LINUX_SERVICE, "start"])?;

    println!("[watchdog] OpenRC service installed and started.");
    println!("  Alerts: {}", paths.alerts_abs.display());
    println!("  Check: watchdog status");
    println!("  Logs : {UNIX_WATCHDOG_LOG} (watchdog and agent output)");
    Ok(())
}

fn uninstall_openrc() -> anyhow::Result<()> {
    let script_path = openrc_script_path();
    let _ = run("rc-service", &[LINUX_SERVICE, "stop"]);
    let _ = run("rc-update", &["del", LINUX_SERVICE, "default"]);
    if Path::new(&script_path).exists() {
        std::fs::remove_file(&script_path).with_context(|| format!("removing {script_path}"))?;
    }
    println!("[watchdog] {LINUX_SERVICE} OpenRC service uninstalled.");
    Ok(())
}

fn status_openrc() -> anyhow::Result<()> {
    let status = std::process::Command::new("rc-service")
        .args([LINUX_SERVICE, "status"])
        .status()
        .context("cannot launch rc-service")?;
    if !status.success() {
        println!("[watchdog] service not running or not installed (rc-service exited {status}).");
    }
    Ok(())
}

/// `openrc-run` refuses to execute a script that isn't marked executable.
fn set_executable(path: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut perms = std::fs::metadata(path)
        .with_context(|| format!("stat {path}"))?
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).with_context(|| format!("chmod {path}"))
}

fn run(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = std::process::Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("cannot launch {program}"))?;
    if !status.success() {
        bail!("{program} {} failed ({status})", args.join(" "));
    }
    Ok(())
}
