//! Linux: service-manager integration — systemd unit or `OpenRC` `init.d` script,
//! both with unlimited automatic respawn (`Restart=always` / `supervise-daemon`
//! with `respawn_max="0"`), so the service manager restarts the watchdog, the
//! watchdog restarts the agent. Alpine and other non-glibc/non-systemd distros run
//! `OpenRC`, not systemd (issue #213) — detected at install time, not assumed.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};

use super::SERVICE_DESC;
use crate::paths::{child_log_path, resolve_agent_bin};

const SYSTEMD_UNIT: &str = "/etc/systemd/system/synthaea-agent.service";
const OPENRC_SCRIPT: &str = "/etc/init.d/synthaea-agent";

/// Symlink `systemctl enable` creates for our unit's `WantedBy=multi-user.target`
/// (see `install_systemd`) — its disappearance means the service was disabled.
const SYSTEMD_ENABLE_LINK: &str =
    "/etc/systemd/system/multi-user.target.wants/synthaea-agent.service";
/// Symlink `rc-update add synthaea-agent default` creates — its disappearance
/// means `rc-update del`/equivalent ran.
const OPENRC_ENABLE_LINK: &str = "/etc/runlevels/default/synthaea-agent";

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

/// Paths baked into the generated unit/script: absolute, so they survive the
/// service manager starting the process with `/` as its working directory.
struct ResolvedPaths {
    watchdog_abs: PathBuf,
    agent_abs: PathBuf,
    alerts_abs: PathBuf,
}

fn resolve_paths(agent_bin: Option<PathBuf>, alerts: PathBuf) -> anyhow::Result<ResolvedPaths> {
    let agent = resolve_agent_bin(agent_bin)?;
    anyhow::ensure!(agent.exists(), "agent not found: {}", agent.display());
    let agent_abs = agent
        .canonicalize()
        .with_context(|| format!("canonicalize {}", agent.display()))?;

    // The unit/script runs the watchdog (layer 2), which supervises the agent
    // (layer 1) — same shape as the Windows SCM service and the launchd daemon.
    let watchdog_abs = std::env::current_exe()
        .context("current_exe")?
        .canonicalize()
        .context("canonicalize watchdog")?;

    // #103: refuse to install pointing at a binary an unprivileged user could
    // overwrite in place — the integrity check `supervise::watchdog_loop` does
    // at every respawn is worthless if the file it re-hashes lives in a
    // directory anyone can drop a replacement into.
    for bin in [&agent_abs, &watchdog_abs] {
        if let Some(dir) = bin.parent() {
            crate::tamper::refuse_world_writable_dir(dir)
                .with_context(|| format!("checking install directory for {}", bin.display()))?;
        }
        crate::tamper::harden_permissions(bin, 0o755)
            .with_context(|| format!("hardening permissions on {}", bin.display()))?;
    }

    let alerts_abs =
        std::path::absolute(&alerts).with_context(|| format!("absolutize {}", alerts.display()))?;
    if let Some(parent) = alerts_abs.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }

    Ok(ResolvedPaths {
        watchdog_abs,
        agent_abs,
        alerts_abs,
    })
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
            PathBuf::from(SYSTEMD_UNIT),
            PathBuf::from(SYSTEMD_ENABLE_LINK),
        ),
        InitSystem::OpenRc => (
            PathBuf::from(OPENRC_SCRIPT),
            PathBuf::from(OPENRC_ENABLE_LINK),
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
pub(crate) fn drift_report(baseline: &DefinitionSnapshot, current: &DefinitionSnapshot) -> Vec<String> {
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
    let packaged_unit = Path::new("/usr/lib/systemd/system/synthaea-agent.service");

    if packaged_unit.exists() {
        // Package already installed the unit - just enable it
        run("systemctl", &["daemon-reload"])?;
        run("systemctl", &["enable", "--now", "synthaea-agent.service"])?;
        println!("[watchdog] Using package-installed systemd unit.");
        println!("  Status: systemctl status synthaea-agent");
        println!("  Logs:   journalctl -u synthaea-agent -f");
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
         SyslogIdentifier=synthaea-watchdog\n\n\
         [Install]\nWantedBy=multi-user.target\n",
        desc = SERVICE_DESC,
        watchdog = paths.watchdog_abs.display(),
        agent = paths.agent_abs.display(),
        out = paths.alerts_abs.display(),
    );

    std::fs::write(SYSTEMD_UNIT, &unit)
        .with_context(|| format!("writing {SYSTEMD_UNIT} (root required)"))?;
    // #103: don't rely on umask for a root-owned service definition's permissions.
    crate::tamper::harden_permissions(std::path::Path::new(SYSTEMD_UNIT), 0o644)
        .with_context(|| format!("hardening permissions on {SYSTEMD_UNIT}"))?;
    run("systemctl", &["daemon-reload"])?;
    run("systemctl", &["enable", "--now", "synthaea-agent.service"])?;

    println!("[watchdog] systemd service installed and started (development mode).");
    println!("  Alerts: {}", paths.alerts_abs.display());
    println!("  Check: watchdog status");
    println!(
        "  Logs : journalctl -u synthaea-agent -f (watchdog); agent output in {}",
        child_log_path()
    );
    Ok(())
}

fn uninstall_systemd() -> anyhow::Result<()> {
    let _ = run("systemctl", &["stop", "synthaea-agent.service"]);
    run("systemctl", &["disable", "synthaea-agent.service"])?;
    if std::path::Path::new(SYSTEMD_UNIT).exists() {
        std::fs::remove_file(SYSTEMD_UNIT).with_context(|| format!("removing {SYSTEMD_UNIT}"))?;
    }
    run("systemctl", &["daemon-reload"])?;
    println!("[watchdog] synthaea-agent service uninstalled.");
    Ok(())
}

fn status_systemd() -> anyhow::Result<()> {
    let status = std::process::Command::new("systemctl")
        .args(["status", "synthaea-agent.service", "--no-pager"])
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
         output_log=\"/var/log/synthaea-watchdog.log\"\n\
         error_log=\"/var/log/synthaea-watchdog.log\"\n\n\
         depend() {{\n\
         \tneed net\n\
         \tafter net\n\
         }}\n",
        desc = SERVICE_DESC,
        watchdog = paths.watchdog_abs.display(),
        agent = paths.agent_abs.display(),
        out = paths.alerts_abs.display(),
    );

    std::fs::write(OPENRC_SCRIPT, &script)
        .with_context(|| format!("writing {OPENRC_SCRIPT} (root required)"))?;
    set_executable(OPENRC_SCRIPT)?;

    run("rc-update", &["add", "synthaea-agent", "default"])?;
    run("rc-service", &["synthaea-agent", "start"])?;

    println!("[watchdog] OpenRC service installed and started.");
    println!("  Alerts: {}", paths.alerts_abs.display());
    println!("  Check: watchdog status");
    println!(
        "  Logs : /var/log/synthaea-watchdog.log (watchdog); agent output in {}",
        child_log_path()
    );
    Ok(())
}

fn uninstall_openrc() -> anyhow::Result<()> {
    let _ = run("rc-service", &["synthaea-agent", "stop"]);
    let _ = run("rc-update", &["del", "synthaea-agent", "default"]);
    if std::path::Path::new(OPENRC_SCRIPT).exists() {
        std::fs::remove_file(OPENRC_SCRIPT)
            .with_context(|| format!("removing {OPENRC_SCRIPT}"))?;
    }
    println!("[watchdog] synthaea-agent OpenRC service uninstalled.");
    Ok(())
}

fn status_openrc() -> anyhow::Result<()> {
    let status = std::process::Command::new("rc-service")
        .args(["synthaea-agent", "status"])
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
