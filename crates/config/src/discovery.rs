//! Where the agent looks for its config file, and in what order.
//!
//! Per ADR-0013 §3 ("Discovery order"), the order is
//! `--config <path>` (caller-supplied) > `SYNTHAEA_CONFIG` env variable >
//! the default OS path from [`DEFAULT_CONFIG_PATH`]. Exactly one file is
//! loaded per binary invocation — no merging.
//!
//! [`discover`] returns the path that WOULD be read; it does NOT actually
//! read the file (that's [`crate::load_from`]'s job). Splitting the two
//! makes the "which path did the agent pick?" question answerable in
//! `--dry-run` or health-check contexts without touching disk twice.

use std::path::{Path, PathBuf};

use crate::error::ConfigError;

/// The environment variable name that overrides [`DEFAULT_CONFIG_PATH`].
pub const ENV_CONFIG_PATH: &str = "SYNTHAEA_CONFIG";

/// Absolute path the agent falls back to when no `--config` and no
/// `SYNTHAEA_CONFIG` are set. Chosen for consistency with EDR industry
/// conventions (see ADR-0013 §Consequences).
#[cfg(target_os = "linux")]
pub const DEFAULT_CONFIG_PATH: &str = "/etc/synthaea/agent.toml";

/// Absolute path the agent falls back to when no `--config` and no
/// `SYNTHAEA_CONFIG` are set.
#[cfg(target_os = "windows")]
pub const DEFAULT_CONFIG_PATH: &str = r"C:\ProgramData\Synthaea\agent.toml";

/// Absolute path the agent falls back to when no `--config` and no
/// `SYNTHAEA_CONFIG` are set.
#[cfg(target_os = "macos")]
pub const DEFAULT_CONFIG_PATH: &str = "/Library/Application Support/Synthaea/agent.toml";

/// Absolute path the agent falls back to on any other Unix (fallback for
/// developer platforms; no production support implied).
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub const DEFAULT_CONFIG_PATH: &str = "/etc/synthaea/agent.toml";

/// Return the path the agent would read for its configuration, resolving
/// the discovery order from ADR-0013 §3.
///
/// - `cli_arg` is `Some(path)` when the caller passed `--config <path>`
///   on the command line. Set: `path` wins outright — the caller took
///   responsibility for choosing.
/// - Otherwise, [`ENV_CONFIG_PATH`] is checked. Set to a non-empty value:
///   that value wins.
/// - Otherwise, [`DEFAULT_CONFIG_PATH`] is returned.
///
/// This function does NOT check whether the resulting path exists; that
/// check happens in [`crate::load_from`] and produces a
/// [`ConfigError::NotFound`] or [`ConfigError::Io`] depending on which of
/// the discovery layers picked the path (a caller-supplied `--config`
/// path that's missing is `Io`, not `NotFound` — the operator was explicit,
/// so silence would hide a typo).
///
/// # Errors
///
/// Never fails when `cli_arg` is `Some(_)`. Otherwise, the only failure is
/// [`ConfigError::NotFound`] with the exhaustive `searched` list — but
/// that variant is emitted by [`crate::load`] once a missing file is
/// confirmed at the default location, not by this pure resolution step.
/// Kept `Result`-typed for symmetry with the rest of the crate.
pub fn discover(cli_arg: Option<&Path>) -> Result<DiscoveredPath, ConfigError> {
    if let Some(p) = cli_arg {
        return Ok(DiscoveredPath {
            path: p.to_path_buf(),
            source: DiscoverySource::CliArg,
        });
    }
    if let Ok(from_env) = std::env::var(ENV_CONFIG_PATH)
        && !from_env.is_empty()
    {
        return Ok(DiscoveredPath {
            path: PathBuf::from(from_env),
            source: DiscoverySource::EnvVar,
        });
    }
    Ok(DiscoveredPath {
        path: PathBuf::from(DEFAULT_CONFIG_PATH),
        source: DiscoverySource::DefaultOsPath,
    })
}

/// The path discovery picked, tagged with the source that supplied it.
///
/// The tag flows into error messages so operators reading a "file missing"
/// failure know whether they typo'd a `--config`, mis-set an env variable,
/// or forgot to install the file altogether.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredPath {
    /// The absolute path that was selected.
    pub path: PathBuf,
    /// Which discovery layer supplied it.
    pub source: DiscoverySource,
}

/// Which layer of the discovery order produced the selected path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverySource {
    /// The caller passed `--config <path>` explicitly.
    CliArg,
    /// The `SYNTHAEA_CONFIG` environment variable was set.
    EnvVar,
    /// Neither of the above; the OS-specific default was used.
    DefaultOsPath,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::env_lock;

    // Every test in this module scribbles on `SYNTHAEA_CONFIG`, so all of
    // them acquire the crate-wide env lock (shared with `load` and `secret`
    // tests). Each test also removes the variable at end so nothing leaks
    // into another test that acquires the lock next.

    fn unset_env() {
        // SAFETY: env access serialized by `env_lock`.
        unsafe {
            std::env::remove_var(ENV_CONFIG_PATH);
        }
    }

    #[test]
    fn cli_arg_wins() {
        let _guard = env_lock();
        unset_env();
        let p = PathBuf::from("/tmp/from-cli.toml");
        let d = discover(Some(&p)).unwrap();
        assert_eq!(d.path, p);
        assert_eq!(d.source, DiscoverySource::CliArg);
    }

    #[test]
    fn cli_arg_wins_over_env() {
        let _guard = env_lock();
        // SAFETY: env access serialized by `env_lock`.
        unsafe {
            std::env::set_var(ENV_CONFIG_PATH, "/tmp/from-env.toml");
        }
        let cli = PathBuf::from("/tmp/from-cli.toml");
        let d = discover(Some(&cli)).unwrap();
        assert_eq!(d.path, cli);
        assert_eq!(d.source, DiscoverySource::CliArg);
        unset_env();
    }

    #[test]
    fn env_wins_over_default() {
        let _guard = env_lock();
        // SAFETY: env access serialized by `env_lock`.
        unsafe {
            std::env::set_var(ENV_CONFIG_PATH, "/tmp/from-env.toml");
        }
        let d = discover(None).unwrap();
        assert_eq!(d.path, PathBuf::from("/tmp/from-env.toml"));
        assert_eq!(d.source, DiscoverySource::EnvVar);
        unset_env();
    }

    #[test]
    fn empty_env_falls_through_to_default() {
        // An operator who exports `SYNTHAEA_CONFIG=` on their shell must not
        // land silently on the empty path; treat it as "unset".
        let _guard = env_lock();
        // SAFETY: env access serialized by `env_lock`.
        unsafe {
            std::env::set_var(ENV_CONFIG_PATH, "");
        }
        let d = discover(None).unwrap();
        assert_eq!(d.path, PathBuf::from(DEFAULT_CONFIG_PATH));
        assert_eq!(d.source, DiscoverySource::DefaultOsPath);
        unset_env();
    }

    #[test]
    fn default_wins_when_nothing_set() {
        let _guard = env_lock();
        unset_env();
        let d = discover(None).unwrap();
        assert_eq!(d.path, PathBuf::from(DEFAULT_CONFIG_PATH));
        assert_eq!(d.source, DiscoverySource::DefaultOsPath);
    }
}
