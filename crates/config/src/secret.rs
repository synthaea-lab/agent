//! Externally-referenced secrets.
//!
//! Per ADR-0013 §7 ("Secrets: external references only"), secret fields in
//! the on-disk config file never carry cleartext values. Instead, they carry
//! a reference to a provider that the load-time code resolves against the
//! running process's environment or filesystem. If a field declared as a
//! secret contains a bare string with no supported provider prefix, the load
//! fails with [`crate::ConfigError::SecretInvalid`] — the "looks like a
//! literal secret" heuristic is intentionally rejected.
//!
//! A rejected value is never echoed back: it is most likely the cleartext
//! secret the operator typed by mistake, and config errors go to stderr and
//! the service journal. Errors name the field and the [`SecretRefError`]
//! class only.
//!
//! The set of providers below is closed at v1; adding one (e.g. `HashiCorp`
//! Vault, AWS Secrets Manager, Windows Credential Store) is an
//! implementation change (a new [`SecretRef`] variant and its resolve arm),
//! not a schema change, per ADR-0013 §Deferred.

use std::path::PathBuf;

use serde::{Deserialize, Deserializer};

use crate::error::ConfigError;

/// A validated reference to a secret held outside the config file.
///
/// Deserialized from a string literal in the TOML file: `envvar:SYNTHAEA_TOKEN`
/// or `file:/etc/synthaea/certs/mtls.key.pass`. Every value of this type is a
/// usable reference: anything else is rejected at load with
/// [`ConfigError::SecretInvalid`], which carries the field path. Every
/// `SecretRef` field of the schema must be listed in
/// `load::SECRET_FIELDS` so that rejection happens before typed
/// deserialization (a test in `load.rs` enforces it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretRef {
    /// Resolved from the process's environment (`std::env::var(name)`).
    /// Typically populated by a systemd `EnvironmentFile=` unit, a Windows
    /// service manager entry, or a launchd plist.
    EnvVar(String),
    /// Resolved by reading the full contents of the file at this path.
    /// Typically `0600 root:root` on Linux, ACL-locked to `LocalSystem` on
    /// Windows. The file's contents (trimmed of trailing whitespace) are the
    /// secret value.
    File(PathBuf),
}

/// Why a config value is not a usable [`SecretRef`]. Deliberately carries no
/// part of the value, which may be a cleartext secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SecretRefError {
    /// The value is not a string (a number, a table...).
    #[error("the value is not a string")]
    NotAString,
    /// The value starts with neither `envvar:` nor `file:` — typically a
    /// cleartext secret written in place of a reference.
    #[error("the value has no supported provider prefix")]
    UnsupportedProvider,
    /// `envvar:` with nothing after it.
    #[error("the `envvar:` reference names no variable")]
    EmptyEnvVarName,
    /// `file:` with nothing after it.
    #[error("the `file:` reference names no path")]
    EmptyFilePath,
}

impl SecretRef {
    /// Parse a raw literal (`envvar:X`, `file:/x`) into a `SecretRef`.
    ///
    /// # Errors
    ///
    /// Returns the [`SecretRefError`] class on an unrecognized prefix, an
    /// empty `envvar:` name, or an empty `file:` path.
    pub fn parse(raw: &str) -> Result<Self, SecretRefError> {
        if let Some(name) = raw.strip_prefix("envvar:") {
            if name.is_empty() {
                return Err(SecretRefError::EmptyEnvVarName);
            }
            Ok(SecretRef::EnvVar(name.to_string()))
        } else if let Some(path) = raw.strip_prefix("file:") {
            if path.is_empty() {
                return Err(SecretRefError::EmptyFilePath);
            }
            Ok(SecretRef::File(PathBuf::from(path)))
        } else {
            Err(SecretRefError::UnsupportedProvider)
        }
    }

    /// Resolve this reference to a cleartext secret at load time.
    ///
    /// `field` is the dot-path of the config field this secret belongs to;
    /// it flows into any error variant so operators know which field failed.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::SecretResolve`] when the referenced source is
    /// missing, empty, or unreadable.
    pub fn resolve(&self, field: &str) -> Result<String, ConfigError> {
        match self {
            SecretRef::EnvVar(name) => {
                let value = std::env::var(name).map_err(|_| ConfigError::SecretResolve {
                    field: field.to_string(),
                    reference: format!("envvar:{name}"),
                    reason: format!("environment variable `{name}` is not set"),
                })?;
                if value.is_empty() {
                    return Err(ConfigError::SecretResolve {
                        field: field.to_string(),
                        reference: format!("envvar:{name}"),
                        reason: format!("environment variable `{name}` is set but empty"),
                    });
                }
                Ok(value)
            }
            SecretRef::File(path) => {
                let raw =
                    std::fs::read_to_string(path).map_err(|e| ConfigError::SecretResolve {
                        field: field.to_string(),
                        reference: format!("file:{}", path.display()),
                        reason: format!("could not read secret file: {e}"),
                    })?;
                let trimmed = raw.trim_end().to_string();
                if trimmed.is_empty() {
                    return Err(ConfigError::SecretResolve {
                        field: field.to_string(),
                        reference: format!("file:{}", path.display()),
                        reason: "secret file is empty".to_string(),
                    });
                }
                Ok(trimmed)
            }
        }
    }
}

// serde support: deserialize a SecretRef from a TOML string. The loader has
// already rejected malformed secrets with a field-path-carrying
// `ConfigError::SecretInvalid` (`load::validate_secret_references`) before
// typed deserialization runs, so this error is a backstop. Its message names
// the class only; the field path is something a serde `Deserialize` impl
// cannot carry on its own (issue #281).
impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        SecretRef::parse(&raw).map_err(|problem| {
            serde::de::Error::custom(format!("{SECRET_REJECTED_PREFIX}: {problem}"))
        })
    }
}

/// Leading text of the backstop serde error, so a test can tell a secret
/// field missing from `load::SECRET_FIELDS` apart from any other parse error.
pub(crate) const SECRET_REJECTED_PREFIX: &str = "not a supported secret reference";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_envvar_reference() {
        let r = SecretRef::parse("envvar:SYNTHAEA_TOKEN").unwrap();
        assert_eq!(r, SecretRef::EnvVar("SYNTHAEA_TOKEN".to_string()));
    }

    #[test]
    fn parses_file_reference() {
        let r = SecretRef::parse("file:/etc/synthaea/token").unwrap();
        assert_eq!(r, SecretRef::File(PathBuf::from("/etc/synthaea/token")));
    }

    #[test]
    fn rejects_bare_literal() {
        assert_eq!(
            SecretRef::parse("hunter2"),
            Err(SecretRefError::UnsupportedProvider)
        );
    }

    #[test]
    fn rejects_empty_envvar_name() {
        assert_eq!(
            SecretRef::parse("envvar:"),
            Err(SecretRefError::EmptyEnvVarName)
        );
    }

    #[test]
    fn rejects_empty_file_path() {
        assert_eq!(
            SecretRef::parse("file:"),
            Err(SecretRefError::EmptyFilePath)
        );
    }

    #[test]
    fn rejects_unknown_prefix() {
        // `vault:` is a plausible future provider — v1 rejects it explicitly
        // rather than silently treating it as literal.
        assert!(SecretRef::parse("vault:secret/synthaea/token").is_err());
    }

    #[test]
    fn deserializes_via_serde() {
        // Round-trip through a mini-TOML doc to prove the deserialize impl
        // integrates with the parser used by the rest of the crate.
        #[derive(Deserialize)]
        struct Holder {
            token: SecretRef,
        }
        let doc = r#"token = "envvar:MY_TOK""#;
        let h: Holder = toml::from_str(doc).unwrap();
        assert_eq!(h.token, SecretRef::EnvVar("MY_TOK".to_string()));
    }

    #[test]
    fn serde_rejects_a_bare_literal_without_echoing_it() {
        #[derive(Debug, Deserialize)]
        struct Holder {
            #[allow(dead_code)]
            token: SecretRef,
        }
        let doc = r#"token = "hunter2""#;
        let err = toml::from_str::<Holder>(doc).unwrap_err();
        assert!(err.message().starts_with(SECRET_REJECTED_PREFIX));
        assert!(!err.message().contains("hunter2"));
    }

    #[test]
    fn resolves_from_env() {
        let _guard = crate::test_util::env_lock();
        // SAFETY: env access serialized by the crate-wide env lock.
        unsafe {
            std::env::set_var("SYNTHAEA_TEST_RESOLVE_ENV", "value-from-env");
        }
        let r = SecretRef::EnvVar("SYNTHAEA_TEST_RESOLVE_ENV".to_string());
        let out = r.resolve("test.field").unwrap();
        // SAFETY: as above.
        unsafe {
            std::env::remove_var("SYNTHAEA_TEST_RESOLVE_ENV");
        }
        assert_eq!(out, "value-from-env");
    }

    #[test]
    fn resolve_env_missing_reports_field() {
        let _guard = crate::test_util::env_lock();
        // SAFETY: env access serialized by the crate-wide env lock.
        unsafe {
            std::env::remove_var("SYNTHAEA_DEFINITELY_UNSET_XYZ");
        }
        let r = SecretRef::EnvVar("SYNTHAEA_DEFINITELY_UNSET_XYZ".to_string());
        let err = r.resolve("server.token").unwrap_err();
        assert!(matches!(err, ConfigError::SecretResolve { .. }));
        // The field must appear in the display for the operator to know which
        // config line failed.
        assert!(format!("{err}").contains("server.token"));
    }
}
