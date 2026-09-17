//! Path resolution shared by supervision and service installation: where the agent
//! binary lives, where its output goes.

use std::path::PathBuf;

use anyhow::Context as _;

/// Default JSON-Lines alerts output file (CLI default and service-mode default).
pub(crate) const DEFAULT_ALERTS: &str = "alerts.ndjson";

/// Resolves the agent binary: the explicit `--agent-bin` path when given,
/// otherwise next to the watchdog executable.
///
/// A relative `--agent-bin` is made absolute against the current directory here,
/// not left for `spawn_agent` to sort out: `Command::current_dir` changes the
/// child's working directory before it execs, so a still-relative program path
/// resolves against the *new* directory instead of the one the caller meant —
/// `target/release/agent` with a working dir of `target/release` looks for
/// `target/release/target/release/agent` and fails with ENOENT.
pub(crate) fn resolve_agent_bin(explicit: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(p) = explicit {
        let absolute = std::path::absolute(&p)
            .with_context(|| format!("cannot resolve --agent-bin path: {}", p.display()))?;
        return Ok(strip_unc_prefix(absolute));
    }
    let mut path = std::env::current_exe().context("cannot resolve current_exe")?;
    path.pop();
    path.push(agent_binary_name());
    Ok(strip_unc_prefix(path))
}

pub(crate) fn agent_binary_name() -> &'static str {
    if cfg!(windows) { "agent.exe" } else { "agent" }
}

/// Strips the `\\?\` prefix added by `canonicalize()` on Windows.
/// `CreateProcess` does not support this prefix and fails silently when given one.
pub(crate) fn strip_unc_prefix(path: PathBuf) -> PathBuf {
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
pub(crate) fn child_log_path() -> &'static str {
    if cfg!(windows) {
        r"C:\Windows\Temp\synthaea-agent.log"
    } else {
        "/var/tmp/synthaea-agent.log"
    }
}

/// Derives the heartbeat file path from the alerts output path (#102) — the
/// two always travel together, so no separate CLI flag or install-time wiring
/// is needed for it. **Must stay in sync with `agent::heartbeat::heartbeat_path_for`**,
/// which computes the same transform independently (the two crates share no
/// dependency to hang a single implementation off of — `watchdog` cannot
/// depend on the binary-only `agent` crate).
pub(crate) fn heartbeat_path_for(alerts: &std::path::Path) -> PathBuf {
    alerts.with_extension("heartbeat")
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
        // "/x/agent" is fully absolute on Unix but only *rooted* on Windows (no
        // drive letter) — resolve_agent_bin's std::path::absolute() call
        // legitimately prepends the current drive there, so exact equality
        // isn't portable. Assert what this test actually cares about: the
        // explicit path wins over the next-to-the-watchdog default, i.e. the
        // result stays absolute and still ends with the path we gave it —
        // same pattern as explicit_relative_agent_path_is_made_absolute below.
        let explicit = PathBuf::from("/x/agent");
        let p = resolve_agent_bin(Some(explicit.clone())).unwrap();
        assert!(p.is_absolute(), "expected an absolute path, got {p:?}");
        assert!(
            p.ends_with("x/agent"),
            "resolved path {p:?} should still end with the explicit {explicit:?}"
        );
    }

    #[test]
    fn explicit_relative_agent_path_is_made_absolute() {
        // Regression test for the bug this session found on the Alpine VM: a
        // relative --agent-bin survived unresolved all the way to spawn_agent's
        // Command::new(agent).current_dir(work_dir), which changes the child's
        // cwd before exec — so the still-relative program path resolved against
        // the *new* directory and spawning failed with ENOENT.
        let relative = PathBuf::from("target/release/agent");
        let p = resolve_agent_bin(Some(relative.clone())).unwrap();
        assert!(p.is_absolute(), "expected an absolute path, got {p:?}");
        assert!(
            p.ends_with(&relative),
            "absolutized path {p:?} should still end with {relative:?}"
        );
    }

    #[test]
    fn heartbeat_path_is_derived_from_alerts() {
        // Must match agent::heartbeat::heartbeat_path_for byte for byte —
        // this is the independent side of that transform (see its doc).
        assert_eq!(
            heartbeat_path_for(std::path::Path::new("/var/lib/synthaea/alerts.ndjson")),
            PathBuf::from("/var/lib/synthaea/alerts.heartbeat")
        );
    }
}
