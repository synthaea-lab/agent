//! Types describing what the on-disk `agent.toml` file carries.
//!
//! Every field mirrors an [`ADR-0013`] decision or an obvious operational
//! setting. The struct layout **is** the file format — a new field is a
//! schema-visible change; a rename is a breaking change that requires a
//! [`SCHEMA_VERSION`] bump.
//!
//! [`ADR-0013`]: ../../../docs/adr/0013-agent-local-configuration.md
//!
//! ## Absent-field policy
//!
//! Every sub-section is serde-required (no `#[serde(default)]` on the
//! top-level struct), so a missing section fails the parse with a precise
//! error the operator can act on — silent defaults would defeat the
//! fail-fast rule from ADR-0013 §5. Inside a section, primitive fields that
//! do have a documented default value use `#[serde(default = "...")]` so
//! the template stays short without making the type ambiguous.

use std::{path::PathBuf, time::Duration};

use serde::Deserialize;

use crate::secret::SecretRef;

/// The schema version this build understands. See ADR-0013 §Deferred on
/// versioning. Bump only on a breaking change; additive fields with
/// `#[serde(default)]` do not require a bump.
pub const SCHEMA_VERSION: u32 = 1;

/// The whole `agent.toml` document, deserialized.
///
/// A file whose `schema_version` doesn't equal [`SCHEMA_VERSION`] fails to
/// load with [`crate::ConfigError::SchemaVersionMismatch`] before any of the
/// fields below are inspected — old configs never smuggle their way through
/// as "close enough".
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// Must equal [`SCHEMA_VERSION`]. Present in every file, at the top, so
    /// `head -1 agent.toml` is enough to know which build shape it targets.
    pub schema_version: u32,
    /// How the agent reaches its control plane.
    pub server: ServerConfig,
    /// Where and how the agent logs.
    pub log: LogConfig,
    /// Where the agent keeps its on-disk state (spool, cache, model store).
    pub storage: StorageConfig,
    /// Local IPC binding read by `crates/ipc` (issue #26).
    pub ipc: IpcConfig,
    /// Boot-time resource ceilings.
    pub resources: ResourcesConfig,
}

/// Control-plane reachability and offline-mode fallback.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Absolute URL of the control plane's ingest endpoint (`https://...`).
    /// Empty or non-`https://` values fail validation.
    pub control_plane_url: String,
    /// Path to the client mTLS certificate (PEM) presented to the control
    /// plane.
    pub mtls_cert: PathBuf,
    /// Path to the client mTLS private key (PEM). Its **passphrase** is a
    /// secret and lives in [`Self::mtls_passphrase`] as a reference.
    pub mtls_key: PathBuf,
    /// Reference to the private-key passphrase. Never a cleartext literal;
    /// see [`SecretRef`] and ADR-0013 §7.
    pub mtls_passphrase: SecretRef,
    /// If `true`, the agent continues to operate against its cached policy
    /// snapshot when the control plane is unreachable. If `false`, an
    /// unreachable control plane is a hard failure at boot.
    #[serde(default = "default_offline_fallback")]
    pub offline_fallback: bool,
}

/// Logging destination and verbosity.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    /// Directory the agent writes its rotated log files into. The agent
    /// creates it at boot if it doesn't already exist.
    pub dir: PathBuf,
    /// Default log verbosity. Accepted values: `trace`, `debug`, `info`,
    /// `warn`, `error`. Case-insensitive; anything else fails validation.
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Maximum on-disk size of the log directory, in mebibytes. Zero means
    /// "no cap" and fails validation — the operator must opt into
    /// unbounded logging with a comment, not by omission.
    #[serde(default = "default_log_max_mb")]
    pub max_mb: u64,
}

/// State locations. Everything under `state_dir` is agent-writable and
/// survives reboots; nothing under it is operator-editable at runtime.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// Root directory for agent state (spool, cache, model registry).
    pub state_dir: PathBuf,
    /// Maximum on-disk size of the event spool, in mebibytes. Enforced at
    /// boot — the spooler refuses to start if it can't reserve this much
    /// under [`Self::state_dir`].
    #[serde(default = "default_spool_max_mb")]
    pub spool_max_mb: u64,
}

/// Where the agent listens for admin commands (issue #26).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpcConfig {
    /// Absolute path to the Unix domain socket (Linux, macOS) or Windows
    /// named-pipe name (`\\.\pipe\synthaea-agent`). One field, two
    /// platforms — validation checks the shape against the current OS.
    pub endpoint: String,
}

/// Boot-time resource ceilings enforced by the agent before any sensor
/// initialization.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourcesConfig {
    /// Size of the tokio worker pool. Zero delegates to tokio's default
    /// heuristic (`num_cpus`), which is the recommended value on hosts
    /// where the agent is not intentionally boxed by cgroup CPU limits.
    #[serde(default = "default_worker_threads")]
    pub worker_threads: u32,
    /// Maximum backoff, in **milliseconds**, applied between successive
    /// reconnection attempts to the control plane. Deserialized as an
    /// integer to keep the file format machine-parseable across languages;
    /// exposed as a [`Duration`] via [`Self::max_reconnect_backoff`].
    #[serde(
        default = "default_reconnect_backoff_ms",
        rename = "max_reconnect_backoff_ms"
    )]
    pub max_reconnect_backoff_ms: u64,
}

impl ResourcesConfig {
    /// Typed view over [`Self::max_reconnect_backoff_ms`]. Kept separate so
    /// the serde surface stays operator-friendly (integers, no unit suffix
    /// ambiguity).
    #[must_use]
    pub fn max_reconnect_backoff(&self) -> Duration {
        Duration::from_millis(self.max_reconnect_backoff_ms)
    }
}

fn default_offline_fallback() -> bool {
    true
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_max_mb() -> u64 {
    1024
}
fn default_spool_max_mb() -> u64 {
    4096
}
fn default_worker_threads() -> u32 {
    0
}
fn default_reconnect_backoff_ms() -> u64 {
    60_000
}
