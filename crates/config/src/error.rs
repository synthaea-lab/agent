//! Error type returned by every operation in this crate.
//!
//! Every variant carries enough context for an operator reading the process's
//! stderr to know **which** field was wrong, **what** was expected, and
//! **where** the file that produced the error lives — per ADR-0013 §8
//! ("Validation: at-load, fail-fast, precise errors").

use std::path::PathBuf;

/// Anything that can go wrong loading, validating, or overriding config.
///
/// Variants are stable: `agent`, `watchdog`, and `cli` all pattern-match on
/// them to decide the exit code they present to the operator.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Discovery walked every location in `--config` > `SYNTHAEA_CONFIG` >
    /// default OS path order and found nothing. The `searched` list is
    /// exactly what was tried, in order, so the operator can copy-paste one
    /// of these paths as a `--config` argument. Per ADR-0013 §5, the binary
    /// refuses to start rather than fall back on invented defaults.
    #[error(
        "no configuration file found. Searched (in discovery order):\n{}\n\
         Generate a default template with `cli config init`, or set the \
         `SYNTHAEA_CONFIG` environment variable.",
        format_paths(.searched)
    )]
    NotFound {
        /// Paths tried, first attempted first.
        searched: Vec<PathBuf>,
    },

    /// The file at `path` couldn't be read from disk (missing when the caller
    /// passed an explicit `--config` path, permission denied, I/O error).
    #[error("failed to read configuration file `{path}`: {source}")]
    Io {
        /// Path the caller was trying to read.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// The file exists and is readable but is not valid TOML.
    ///
    /// `source` is the raw parser error; it already carries a line/column
    /// annotation from the `toml` crate, so operators can jump to the offset
    /// without extra work.
    ///
    /// Boxed to keep `ConfigError` small enough for clippy's
    /// `result_large_err` — `toml::de::Error` alone is >100 bytes and would
    /// bloat every `Result<T, ConfigError>` return across the crate.
    #[error("failed to parse `{path}` as TOML: {source}")]
    Parse {
        /// Path being parsed.
        path: PathBuf,
        /// Underlying parser error.
        source: Box<toml::de::Error>,
    },

    /// A `schema_version` field either was missing at the top of the file or
    /// had a value this build cannot understand. `expected` is the crate's
    /// [`crate::SCHEMA_VERSION`]; the operator either upgrades the file (for
    /// a bump the release notes describe) or the binary (for a downgrade).
    #[error(
        "schema_version mismatch in `{path}`: found {found}, this build \
         expects {expected}. Check the release notes for the migration path."
    )]
    SchemaVersionMismatch {
        /// Path being loaded.
        path: PathBuf,
        /// Version literally present in the file.
        found: u32,
        /// Version this build supports.
        expected: u32,
    },

    /// A field failed a semantic check that the deserializer itself couldn't
    /// enforce (e.g. `resources.spool_max_mb == 0`, an empty
    /// `server.control_plane_url`). `field` is a dot-path
    /// (`resources.spool_max_mb`), `expected` describes the accepted shape,
    /// `value` is what the file (or the env override) actually carried.
    #[error(
        "invalid value for `{field}` (expected {expected}, got `{value}`) \
         in `{origin}`."
    )]
    Invalid {
        /// Dot-path of the failing field.
        field: String,
        /// Constraint the value violated.
        expected: String,
        /// Value that violated the constraint, stringified.
        value: String,
        /// Where the value came from: a file path, or `env:SYNTHAEA_FOO`.
        /// Not named `source` because thiserror reserves that name for the
        /// `#[source]` auto-annotation.
        origin: String,
    },

    /// A field declared as a secret didn't start with a supported provider
    /// prefix (`envvar:` or `file:`). Per ADR-0013 §7, the load fails rather
    /// than accepting a literal cleartext secret with a "looks like a
    /// literal" heuristic.
    #[error(
        "field `{field}` in `{origin}` is a secret but is not a supported \
         reference. Expected `envvar:NAME` or `file:/absolute/path`, got \
         `{value}`."
    )]
    SecretInvalid {
        /// Dot-path of the offending secret field.
        field: String,
        /// What was written in the file, stringified.
        value: String,
        /// Where the value came from: a file path, or `env:SYNTHAEA_FOO`.
        /// Not named `source` because thiserror reserves that name for the
        /// `#[source]` auto-annotation.
        origin: String,
    },

    /// An `envvar:NAME` secret reference resolved but the process's
    /// environment doesn't define `NAME`, or a `file:/path` reference points
    /// somewhere the process can't read. Split from [`Self::Io`] because the
    /// remediation is different (operator's env / permission setup, not a
    /// config edit).
    #[error("failed to resolve secret `{reference}` for field `{field}`: {reason}")]
    SecretResolve {
        /// Dot-path of the field whose secret couldn't be resolved.
        field: String,
        /// The reference literal, e.g. `envvar:SYNTHAEA_TOKEN`.
        reference: String,
        /// Human-readable cause.
        reason: String,
    },

    /// An env override (`SYNTHAEA_FOO=bar`) was set but the value doesn't
    /// parse to the declared type of the target field. Emitted by
    /// [`crate::apply_env_overrides`] before any override is applied, so a
    /// partial override never runs.
    #[error(
        "environment variable `{env_var}` = `{value}` is not a valid \
         override for field `{field}` (expected {expected})."
    )]
    EnvOverrideParse {
        /// The env variable that carried the bad value.
        env_var: String,
        /// Target field, dot-path.
        field: String,
        /// Constraint the value violated.
        expected: String,
        /// Value as read from the environment.
        value: String,
    },
}

fn format_paths(paths: &[PathBuf]) -> String {
    if paths.is_empty() {
        return "  (none)".to_string();
    }
    paths
        .iter()
        .enumerate()
        .map(|(i, p)| format!("  {}. {}", i + 1, p.display()))
        .collect::<Vec<_>>()
        .join("\n")
}
