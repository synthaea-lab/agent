//! Test support for cross-repo contract tests: find the sibling checkouts of the
//! public Synthaea repos next to this workspace.
//!
//! The public repos that test against each other (`synthaea-lab/agent`, `server`,
//! `ml`, `rules`, `scenarios`) are cloned side by side in one directory:
//!
//! ```text
//! <SYNTHAEA_ROOT>/
//!   agent/      this workspace (synthaea-lab/agent)
//!   server/     synthaea-lab/server
//!   ml/         synthaea-lab/ml
//!   rules/      synthaea-lab/rules
//!   scenarios/  synthaea-lab/scenarios (attack scenarios; no contract test reads it yet)
//! ```
//!
//! A contract test whose other half lives in a sibling (a golden fixture the server
//! writes, the Python feature vectors, the shipped detection content) reads it through
//! this crate. When the sibling is absent the test prints one `skipped: ...` line and
//! returns, so the agent builds and tests alone; with `SYNTHAEA_REQUIRE_SIBLINGS=1` (set
//! in CI) a missing sibling panics instead, so a contract test can never pass by not
//! running.
//!
//! - [`ROOT_ENV`] (`SYNTHAEA_ROOT`) overrides where the siblings are looked up.
//! - [`REQUIRE_ENV`] (`SYNTHAEA_REQUIRE_SIBLINGS`) turns a skip into a failure.
//!
//! Dev-dependency only (enforced by `tools/check-deps.py`); it has no dependencies.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

/// Environment variable naming the directory that holds the sibling checkouts.
/// Unset or empty: the parent directory of this workspace.
pub const ROOT_ENV: &str = "SYNTHAEA_ROOT";

/// Environment variable that, set to `1`, makes a missing sibling a test failure
/// instead of a skip.
pub const REQUIRE_ENV: &str = "SYNTHAEA_REQUIRE_SIBLINGS";

/// The directory the sibling repos are checked out in: `$SYNTHAEA_ROOT` when
/// set and non-empty, else the parent directory of this workspace. Canonicalized when
/// the directory exists, returned as-is otherwise.
#[must_use]
pub fn root() -> PathBuf {
    root_from(std::env::var_os(ROOT_ENV))
}

/// The file or directory `rel` inside sibling repo `repo` (e.g. `("ml",
/// "tests/fixtures/t1_golden.jsonl")`), or `None` when it does not exist.
#[must_use]
pub fn path(repo: &str, rel: &str) -> Option<PathBuf> {
    let path = expected_path(repo, rel);
    path.exists().then_some(path)
}

/// The contents of file `rel` inside sibling repo `repo`, or `None` when it does not
/// exist.
///
/// # Panics
///
/// When the file exists but cannot be read as UTF-8 text: a broken fixture is a test
/// failure, not a reason to skip.
#[must_use]
pub fn read(repo: &str, rel: &str) -> Option<String> {
    let path = path(repo, rel)?;
    match std::fs::read_to_string(&path) {
        Ok(text) => Some(text),
        Err(e) => panic!("reading sibling fixture {}: {e}", path.display()),
    }
}

/// Reports that a test cannot run because `rel` in sibling repo `repo` is missing: one
/// `skipped: ...` line on stderr, after which the caller returns early. The
/// [`require!`] and [`require_path!`] macros call this; call it directly only where
/// they do not fit.
///
/// # Panics
///
/// When `SYNTHAEA_REQUIRE_SIBLINGS` is `1`: in CI a contract test that did not run is a
/// failure.
pub fn skip(repo: &str, rel: &str) {
    let message = skip_message(repo, rel);
    if is_required(std::env::var_os(REQUIRE_ENV)) {
        panic!("{message} ({REQUIRE_ENV}=1 makes this a failure)");
    }
    eprintln!("{message}");
}

/// Reads file `rel` from sibling repo `repo`, or [skips](skip) the enclosing test and
/// returns from it.
///
/// `require!(repo, rel)` returns `()` from the enclosing function when the sibling is
/// missing; `require!(repo, rel, value)` returns `value` instead (e.g. `None` from a
/// helper returning `Option`).
///
/// ```ignore
/// let golden = siblings::require!("ml", "tests/fixtures/t1_golden.jsonl");
/// ```
#[macro_export]
macro_rules! require {
    ($repo:expr, $rel:expr) => {
        match $crate::read($repo, $rel) {
            ::core::option::Option::Some(text) => text,
            ::core::option::Option::None => {
                $crate::skip($repo, $rel);
                return;
            }
        }
    };
    ($repo:expr, $rel:expr, $or:expr) => {
        match $crate::read($repo, $rel) {
            ::core::option::Option::Some(text) => text,
            ::core::option::Option::None => {
                $crate::skip($repo, $rel);
                return $or;
            }
        }
    };
}

/// Resolves `rel` (a file or directory) in sibling repo `repo` to a `PathBuf`, or
/// [skips](skip) the enclosing test and returns from it. Same two forms as
/// [`require!`].
///
/// ```ignore
/// let sigma = siblings::require_path!("rules", "sigma");
/// ```
#[macro_export]
macro_rules! require_path {
    ($repo:expr, $rel:expr) => {
        match $crate::path($repo, $rel) {
            ::core::option::Option::Some(path) => path,
            ::core::option::Option::None => {
                $crate::skip($repo, $rel);
                return;
            }
        }
    };
    ($repo:expr, $rel:expr, $or:expr) => {
        match $crate::path($repo, $rel) {
            ::core::option::Option::Some(path) => path,
            ::core::option::Option::None => {
                $crate::skip($repo, $rel);
                return $or;
            }
        }
    };
}

fn root_from(env: Option<OsString>) -> PathBuf {
    let root = match env {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        // agent/crates/siblings -> agent/crates -> agent -> <SYNTHAEA_ROOT>
        _ => Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.."),
    };
    root.canonicalize().unwrap_or(root)
}

fn expected_path(repo: &str, rel: &str) -> PathBuf {
    root().join(repo).join(rel)
}

fn is_required(env: Option<OsString>) -> bool {
    env.is_some_and(|value| value == "1")
}

fn skip_message(repo: &str, rel: &str) -> String {
    format!(
        "skipped: needs sibling repo `{repo}` ({}); check out synthaea-lab/{repo} next to \
         this repo as {repo}/ or set {ROOT_ENV}",
        expected_path(repo, rel).display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_root_is_the_parent_of_this_workspace() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let expected = workspace.join("..").canonicalize().unwrap();
        assert_eq!(root_from(None), expected);
        assert_eq!(root_from(Some(OsString::new())), expected);
    }

    #[test]
    fn an_explicit_root_wins_and_is_kept_as_is_when_it_does_not_exist() {
        let missing = PathBuf::from("/nonexistent/synthaea-siblings");
        assert_eq!(root_from(Some(missing.clone().into())), missing);
    }

    #[test]
    fn only_the_value_one_requires_the_siblings() {
        assert!(is_required(Some("1".into())));
        assert!(!is_required(None));
        assert!(!is_required(Some("0".into())));
        assert!(!is_required(Some("true".into())));
    }

    #[test]
    fn a_missing_sibling_is_none() {
        assert_eq!(path("no-such-repo", "no/such/file"), None);
        assert_eq!(read("no-such-repo", "no/such/file"), None);
    }

    #[test]
    fn the_skip_message_names_the_repo_the_path_and_the_fix() {
        let message = skip_message("ml", "tests/fixtures/x.jsonl");
        assert!(message.starts_with("skipped: needs sibling repo `ml` ("));
        // Compared as a joined path, not a literal: on Windows the root is a verbatim
        // `\\?\` path, and joining onto one normalizes `/` to `\`.
        let expected = expected_path("ml", "tests/fixtures/x.jsonl");
        assert!(message.contains(&expected.display().to_string()));
        assert!(
            expected.ends_with(
                Path::new("ml")
                    .join("tests")
                    .join("fixtures")
                    .join("x.jsonl")
            )
        );
        assert!(message.contains("check out synthaea-lab/ml next to this repo as ml/"));
        assert!(message.ends_with("set SYNTHAEA_ROOT"));
    }
}
