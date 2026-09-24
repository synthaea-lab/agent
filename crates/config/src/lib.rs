//! # config
//!
//! Local, per-install agent configuration: file locations, server endpoints,
//! resource budgets, logging. Loaded and validated once at startup, shared by
//! the `agent`, `watchdog`, and `cli` binaries. Distinct from `policy`, which
//! is versioned, signed, and distributed by the control plane at runtime
//! (ADR-0010 / ADR-0011). This crate is the single source of local truth: no
//! binary parses its own dialect.
//!
//! ## Contract
//!
//! Per ADR-0013 ("Agent local configuration"):
//!
//! - **Format**: TOML.
//! - **Discovery**: `--config <path>` (caller-supplied) > `SYNTHAEA_CONFIG`
//!   env > default OS path (`/etc/synthaea/agent.toml` on Linux,
//!   `C:\ProgramData\Synthaea\agent.toml` on Windows,
//!   `/Library/Application Support/Synthaea/agent.toml` on macOS).
//! - **Fail-fast**: no in-memory defaults are silently constructed if no file
//!   is found; every validation error names the field path and the offending
//!   value; every secret field is validated at load.
//! - **Schema version**: every file must carry a top-level `schema_version`
//!   equal to [`SCHEMA_VERSION`]; a mismatch fails the load.
//! - **Env overrides**: individual fields can be overridden by
//!   `SYNTHAEA_*`-prefixed variables (see [`apply_env_overrides`]); overrides
//!   are re-validated before use.
//! - **Reload**: not supported in v1; changes take effect on the next binary
//!   restart.
//!
//! ## Typical use
//!
//! ```ignore
//! use config::{load, AgentConfig};
//!
//! let cfg: AgentConfig = load(None)?; // None = use discovery
//! ```
//!
//! Pass `Some(path)` from a `--config` command-line argument to bypass
//! discovery. All errors are [`ConfigError`]; callers are expected to log the
//! error and exit non-zero rather than continue with partial state.

#![deny(missing_docs)]

mod discovery;
mod error;
mod load;
mod schema;
mod secret;
mod template;

#[cfg(test)]
pub(crate) mod test_util;

pub use discovery::{DEFAULT_CONFIG_PATH, ENV_CONFIG_PATH, discover};
pub use error::ConfigError;
pub use load::{apply_env_overrides, load, load_from};
pub use schema::{
    AgentConfig, IpcConfig, LogConfig, ResourcesConfig, SCHEMA_VERSION, ServerConfig, StorageConfig,
};
pub use secret::SecretRef;
pub use template::{DEFAULT_TEMPLATE, write_default_template};
