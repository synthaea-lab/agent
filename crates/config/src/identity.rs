//! The agent's observable identity: the names someone on the host (or on the
//! wire) can see and hardcode to find, stop, or blind the agent (#596,
//! ADR-0044).
//!
//! Every such name the user-mode binaries and leaf crates use is a constant
//! here, never a literal at the call site. Sensor crates cannot depend on this
//! crate, so the agent passes them the names they need at construction. The
//! default config paths and the `SYNTHAEA_*` override variables are the same
//! kind of name and stay next to the code that reads them
//! ([`crate::DEFAULT_CONFIG_PATH`], [`crate::ENV_CONFIG_PATH`],
//! [`crate::apply_env_overrides`]).
//!
//! Nothing is randomized yet: these are the fixed values the morph milestone
//! (M4) will replace per install. Names that are *persisted* across restarts
//! and looked up by prefix ([`ETW_SESSION_PREFIX`]) will then have to be read
//! from the install's config, not generated per start, or the agent would stop
//! finding its own orphans.

/// The Windows service the watchdog installs itself as. The service SID
/// `NT SERVICE\<name>` derives from it, and the minifilter's agent-only port
/// check (#560) compares against that SID.
pub const WINDOWS_SERVICE_NAME: &str = "SynthaEDR";

/// The Windows service's display name (`services.msc`, `sc qc`).
pub const WINDOWS_SERVICE_DISPLAY: &str = "Synthaea EDR Agent";

/// The service description on Windows (SCM) and Linux (the unit's
/// `Description=`).
pub const SERVICE_DESCRIPTION: &str =
    "Synthaea Endpoint Detection & Response — real-time behavioral monitoring";

/// The Linux service name: the systemd unit `<name>.service` and the `OpenRC`
/// script `/etc/init.d/<name>`. `packaging/linux` ships a unit file with the
/// same name.
pub const LINUX_SERVICE: &str = "synthaea-agent";

/// The launchd label of the macOS daemon; its plist is
/// `/Library/LaunchDaemons/<label>.plist`.
pub const LAUNCHD_LABEL: &str = "com.synthaea.agent";

/// Where the watchdog's own output goes when the service manager has no journal
/// for it (`OpenRC`, launchd).
pub const UNIX_WATCHDOG_LOG: &str = "/var/log/synthaea-watchdog.log";

/// The `SyslogIdentifier=` of the watchdog's systemd unit (its journal tag).
pub const WATCHDOG_SYSLOG_IDENTIFIER: &str = "synthaea-watchdog";

/// Set by the watchdog on the agent it spawns: how many times it has started
/// the agent since the watchdog itself started (#863).
pub const WATCHDOG_RESTARTS_ENV: &str = "SYNTHAEA_WATCHDOG_RESTARTS";

/// Set by the watchdog on the agent it spawns: the self-protection events the
/// watchdog has reported since it started (#863).
pub const WATCHDOG_TAMPER_EVENTS_ENV: &str = "SYNTHAEA_WATCHDOG_TAMPER_EVENTS";

/// Prefix of the ETW session names the Windows sensor starts. The suffix is
/// random per start, and startup stops every session with this prefix to reap
/// the ones an unclean shutdown left behind (#408).
pub const ETW_SESSION_PREFIX: &str = "wtrace-";

/// Prefix of the Windows sensor's liveness canary file in the temp directory;
/// the process id follows it.
pub const ETW_CANARY_PREFIX: &str = "synthaea-canary-";

/// The socket the macOS network extension writes its NDJSON stream to.
pub const MACOS_NE_SOCKET: &str = "/var/run/synthaea-ne.sock";

/// The product token the agent names itself with in its HTTP `User-Agent`
/// (`<token>/<version>`).
pub const PRODUCT_TOKEN: &str = "synthaea-agent";

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;

    fn repo_file(relative: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative)
    }

    fn read(relative: &str) -> String {
        std::fs::read_to_string(repo_file(relative))
            .unwrap_or_else(|e| panic!("reading {relative}: {e}"))
    }

    // Packaging and the Swift extension cannot import these constants, so they
    // are the second spelling of each name; renaming one without the other
    // would install a service the watchdog cannot find, or a socket nobody reads.
    #[test]
    fn the_packaged_linux_unit_carries_the_identity_names() {
        let unit = read(&format!("packaging/linux/systemd/{LINUX_SERVICE}.service"));
        assert!(unit.contains(&format!("SyslogIdentifier={WATCHDOG_SYSLOG_IDENTIFIER}")));
        assert!(repo_file(&format!("packaging/linux/alpine/{LINUX_SERVICE}.initd")).exists());
    }

    #[test]
    fn the_network_extension_falls_back_to_the_agents_socket() {
        let swift = read(
            "crates/sensors/macos/network-extension/extension/Sources/FilterDataProvider.swift",
        );
        assert!(swift.contains(&format!("\"{MACOS_NE_SOCKET}\"")));
    }
}
