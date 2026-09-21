//! End-to-end config loading: discover, read, parse, validate, override.
//!
//! `load` is the entry point every binary calls. `load_from` is the same
//! flow with the discovery step short-circuited by an explicit path, which
//! `cli config validate` (issue #27, deferred) and integration tests use.
//!
//! `apply_env_overrides` is a separate step from parsing so failures produce
//! a distinct error variant ([`ConfigError::EnvOverrideParse`]) and so
//! operators can call `SYNTHAEA_LOG_LEVEL=debug agent --dry-run` without
//! editing the file to try a different value.

use std::path::Path;

use crate::discovery::{discover, DiscoverySource};
use crate::error::ConfigError;
use crate::schema::{AgentConfig, SCHEMA_VERSION};

/// Perform the full discovery-and-load flow, then apply env overrides.
///
/// This is what `agent`, `watchdog`, and `cli` call once at boot. See
/// [`crate::discover`] for the discovery order (`--config` > env > OS
/// default).
///
/// # Errors
///
/// Any of the [`ConfigError`] variants; each carries enough context for the
/// operator to know which layer failed and what to fix.
pub fn load(cli_arg: Option<&Path>) -> Result<AgentConfig, ConfigError> {
    let discovered = discover(cli_arg)?;
    // A missing file at the default location is `NotFound` — the operator
    // never picked this path, so we surface the whole discovery order for
    // them. A missing file at a caller-supplied `--config` path or a
    // caller-set env variable is `Io` — they were explicit, so silence
    // would hide a typo.
    if !discovered.path.exists() {
        return match discovered.source {
            DiscoverySource::DefaultOsPath => Err(ConfigError::NotFound {
                searched: vec![discovered.path],
            }),
            DiscoverySource::CliArg | DiscoverySource::EnvVar => Err(ConfigError::Io {
                path: discovered.path.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no such file or directory",
                ),
            }),
        };
    }
    let mut cfg = load_from(&discovered.path)?;
    apply_env_overrides(&mut cfg, &discovered.path)?;
    Ok(cfg)
}

/// Read one file, parse it, and validate. Callers that already know which
/// path to read (integration tests, `cli config validate`) skip
/// [`crate::discover`] and call this directly.
///
/// Does NOT apply env overrides — [`apply_env_overrides`] is a separate
/// step so its own failures carry a distinct error variant.
///
/// # Errors
///
/// - [`ConfigError::Io`] when the file can't be read.
/// - [`ConfigError::Parse`] when the file isn't valid TOML for the current
///   [`AgentConfig`] shape.
/// - [`ConfigError::SchemaVersionMismatch`] when the file's
///   `schema_version` doesn't match [`SCHEMA_VERSION`].
/// - [`ConfigError::Invalid`] on a semantic check the deserializer can't
///   enforce.
pub fn load_from(path: &Path) -> Result<AgentConfig, ConfigError> {
    let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    parse_and_validate(&raw, path)
}

/// Parse an in-memory TOML string as an [`AgentConfig`] and validate it.
///
/// Kept as a separate step so tests can exercise validation without
/// touching disk. Not exported: callers use [`load_from`].
fn parse_and_validate(raw: &str, source_path: &Path) -> Result<AgentConfig, ConfigError> {
    // Check schema_version FIRST, via a minimal probe, before letting serde
    // attempt the full deserialize. Otherwise a v2 file with new required
    // fields would emit an obscure "missing field" error instead of the
    // explicit schema_version mismatch operators can act on.
    let probe: SchemaProbe = toml::from_str(raw).map_err(|source| ConfigError::Parse {
        path: source_path.to_path_buf(),
        source: Box::new(source),
    })?;
    if probe.schema_version != SCHEMA_VERSION {
        return Err(ConfigError::SchemaVersionMismatch {
            path: source_path.to_path_buf(),
            found: probe.schema_version,
            expected: SCHEMA_VERSION,
        });
    }

    let cfg: AgentConfig = toml::from_str(raw).map_err(|source| ConfigError::Parse {
        path: source_path.to_path_buf(),
        source: Box::new(source),
    })?;
    validate_semantics(&cfg, source_path)?;
    Ok(cfg)
}

/// Minimal probe to read `schema_version` without deserializing the full
/// document. `#[serde(deny_unknown_fields)]` is deliberately absent so the
/// probe tolerates every other field in the file.
#[derive(serde::Deserialize)]
struct SchemaProbe {
    schema_version: u32,
}

/// Checks that a fully-deserialized [`AgentConfig`] carries semantically
/// valid values (URL shapes, non-zero budgets, log level enum).
///
/// Everything in here is a rule the type system alone can't enforce.
fn validate_semantics(cfg: &AgentConfig, source_path: &Path) -> Result<(), ConfigError> {
    let src = source_path.display().to_string();

    // server.control_plane_url — non-empty https://…
    if !cfg.server.control_plane_url.starts_with("https://") {
        return Err(ConfigError::Invalid {
            field: "server.control_plane_url".into(),
            expected: "an `https://` URL".into(),
            value: cfg.server.control_plane_url.clone(),
            origin: src.clone(),
        });
    }

    // log.level — one of the accepted enum values.
    let level_lower = cfg.log.level.to_ascii_lowercase();
    if !matches!(
        level_lower.as_str(),
        "trace" | "debug" | "info" | "warn" | "error"
    ) {
        return Err(ConfigError::Invalid {
            field: "log.level".into(),
            expected: "one of `trace`, `debug`, `info`, `warn`, `error`".into(),
            value: cfg.log.level.clone(),
            origin: src.clone(),
        });
    }

    // log.max_mb — zero is "no cap", explicitly refused per the field's own
    // documentation. Operators who want unbounded logging document that
    // choice in the config file with an explicit large value, not a `0`.
    if cfg.log.max_mb == 0 {
        return Err(ConfigError::Invalid {
            field: "log.max_mb".into(),
            expected: "a positive integer (0 is not accepted; state the cap explicitly)".into(),
            value: "0".into(),
            origin: src.clone(),
        });
    }

    // storage.spool_max_mb — zero can't reserve any spool at boot, so it's
    // rejected. If disk spooling is genuinely unwanted, that's a future
    // schema addition (e.g. `spool.enabled = false`), not a zero-sized cap.
    if cfg.storage.spool_max_mb == 0 {
        return Err(ConfigError::Invalid {
            field: "storage.spool_max_mb".into(),
            expected: "a positive integer".into(),
            value: "0".into(),
            origin: src.clone(),
        });
    }

    // ipc.endpoint — shape check per OS. On Windows the endpoint is a named
    // pipe (`\\.\pipe\...`), everywhere else it's an absolute filesystem
    // path (Unix domain socket).
    if cfg.ipc.endpoint.is_empty() {
        return Err(ConfigError::Invalid {
            field: "ipc.endpoint".into(),
            expected: "a non-empty pipe name (Windows) or absolute socket path (Unix)".into(),
            value: cfg.ipc.endpoint.clone(),
            origin: src.clone(),
        });
    }
    #[cfg(target_os = "windows")]
    {
        if !cfg.ipc.endpoint.starts_with(r"\\.\pipe\") {
            return Err(ConfigError::Invalid {
                field: "ipc.endpoint".into(),
                expected: r"a Windows named pipe (`\\.\pipe\...`)".into(),
                value: cfg.ipc.endpoint.clone(),
                origin: src.clone(),
            });
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if !Path::new(&cfg.ipc.endpoint).is_absolute() {
            return Err(ConfigError::Invalid {
                field: "ipc.endpoint".into(),
                expected: "an absolute filesystem path (Unix domain socket)".into(),
                value: cfg.ipc.endpoint.clone(),
                origin: src.clone(),
            });
        }
    }

    // server.mtls_cert / server.mtls_key — absolute paths only. A relative
    // path resolves from the working directory of whichever binary reads
    // the config, which is different for `agent` (systemd) vs `cli` (user
    // shell); an absolute path is the only shared meaning.
    for (field, path) in [
        ("server.mtls_cert", &cfg.server.mtls_cert),
        ("server.mtls_key", &cfg.server.mtls_key),
    ] {
        if !path.is_absolute() {
            return Err(ConfigError::Invalid {
                field: field.into(),
                expected: "an absolute filesystem path".into(),
                value: path.display().to_string(),
                origin: src.clone(),
            });
        }
    }

    // storage.state_dir — absolute, same rationale.
    if !cfg.storage.state_dir.is_absolute() {
        return Err(ConfigError::Invalid {
            field: "storage.state_dir".into(),
            expected: "an absolute filesystem path".into(),
            value: cfg.storage.state_dir.display().to_string(),
            origin: src.clone(),
        });
    }
    // log.dir — same.
    if !cfg.log.dir.is_absolute() {
        return Err(ConfigError::Invalid {
            field: "log.dir".into(),
            expected: "an absolute filesystem path".into(),
            value: cfg.log.dir.display().to_string(),
            origin: src.clone(),
        });
    }

    Ok(())
}

/// Apply `SYNTHAEA_*` environment variable overrides to an already-parsed
/// config, then re-run semantic validation. Every override that doesn't
/// parse to the target field's type is a load failure — no silent skip.
///
/// The mapping is explicit (one match arm per overridable field) rather
/// than a generic `serde_env` walk so the set of overridable fields is
/// auditable in one place. Fields not listed here are NOT overridable via
/// env; that's intentional (a `SYNTHAEA_SERVER_MTLS_KEY=/tmp/bad` set on a
/// laptop should never redirect a production agent's key path).
///
/// `source_path` is only used to reconstruct the "where did this value
/// come from" tag in follow-up validation errors — for env-derived
/// failures, `EnvOverrideParse` is emitted directly with the variable
/// name, not the file path.
///
/// # Errors
///
/// - [`ConfigError::EnvOverrideParse`] when a variable is set but its
///   value doesn't parse to the target type.
/// - [`ConfigError::Invalid`] when a parsed override violates a semantic
///   rule (e.g. `SYNTHAEA_LOG_LEVEL=verbose`).
pub fn apply_env_overrides(cfg: &mut AgentConfig, source_path: &Path) -> Result<(), ConfigError> {
    if let Some(raw) = read_env("SYNTHAEA_SERVER_URL")? {
        cfg.server.control_plane_url = raw;
    }
    if let Some(raw) = read_env("SYNTHAEA_OFFLINE_FALLBACK")? {
        cfg.server.offline_fallback =
            parse_env_bool("SYNTHAEA_OFFLINE_FALLBACK", "server.offline_fallback", &raw)?;
    }
    if let Some(raw) = read_env("SYNTHAEA_LOG_LEVEL")? {
        cfg.log.level = raw;
    }
    if let Some(raw) = read_env("SYNTHAEA_LOG_MAX_MB")? {
        cfg.log.max_mb = parse_env_u64("SYNTHAEA_LOG_MAX_MB", "log.max_mb", &raw)?;
    }
    if let Some(raw) = read_env("SYNTHAEA_SPOOL_MAX_MB")? {
        cfg.storage.spool_max_mb =
            parse_env_u64("SYNTHAEA_SPOOL_MAX_MB", "storage.spool_max_mb", &raw)?;
    }
    if let Some(raw) = read_env("SYNTHAEA_IPC_ENDPOINT")? {
        cfg.ipc.endpoint = raw;
    }
    if let Some(raw) = read_env("SYNTHAEA_WORKER_THREADS")? {
        cfg.resources.worker_threads =
            parse_env_u32("SYNTHAEA_WORKER_THREADS", "resources.worker_threads", &raw)?;
    }
    validate_semantics(cfg, source_path)?;
    Ok(())
}

/// Read an env variable, treating an empty value as "not set" (consistent
/// with `discover`'s handling of `SYNTHAEA_CONFIG=`).
fn read_env(name: &str) -> Result<Option<String>, ConfigError> {
    match std::env::var(name) {
        Ok(v) if v.is_empty() => Ok(None),
        Ok(v) => Ok(Some(v)),
        Err(_) => Ok(None),
    }
}

fn parse_env_u64(env_var: &str, field: &str, raw: &str) -> Result<u64, ConfigError> {
    raw.parse::<u64>()
        .map_err(|_| ConfigError::EnvOverrideParse {
            env_var: env_var.to_string(),
            field: field.to_string(),
            expected: "a non-negative 64-bit integer".to_string(),
            value: raw.to_string(),
        })
}

fn parse_env_u32(env_var: &str, field: &str, raw: &str) -> Result<u32, ConfigError> {
    raw.parse::<u32>()
        .map_err(|_| ConfigError::EnvOverrideParse {
            env_var: env_var.to_string(),
            field: field.to_string(),
            expected: "a non-negative 32-bit integer".to_string(),
            value: raw.to_string(),
        })
}

fn parse_env_bool(env_var: &str, field: &str, raw: &str) -> Result<bool, ConfigError> {
    // Accept the operator-familiar spellings AND fail-fast on anything
    // else — the ADR §Decision 1 explicitly rules out TOML's own
    // `no`/`off`/`on`, so we don't accept them here either.
    match raw {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(ConfigError::EnvOverrideParse {
            env_var: env_var.to_string(),
            field: field.to_string(),
            expected: "`true` or `false` (lowercase)".to_string(),
            value: raw.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::env_lock;
    use std::io::Write;

    // Absolute-path fixtures split per OS: `Path::is_absolute` on Windows
    // rejects Unix-style `/etc/…`, and the load-time validation checks
    // several paths for absoluteness, so the fixture has to match the host.
    #[cfg(target_os = "windows")]
    const FIXTURE_MTLS_CERT: &str = r"C:\ProgramData\Synthaea\certs\client.crt";
    #[cfg(target_os = "windows")]
    const FIXTURE_MTLS_KEY: &str = r"C:\ProgramData\Synthaea\certs\client.key";
    #[cfg(target_os = "windows")]
    const FIXTURE_LOG_DIR: &str = r"C:\ProgramData\Synthaea\logs";
    #[cfg(target_os = "windows")]
    const FIXTURE_STATE_DIR: &str = r"C:\ProgramData\Synthaea\state";
    #[cfg(target_os = "windows")]
    const FIXTURE_IPC_ENDPOINT: &str = r"\\.\pipe\synthaea-agent";

    #[cfg(not(target_os = "windows"))]
    const FIXTURE_MTLS_CERT: &str = "/etc/synthaea/certs/client.crt";
    #[cfg(not(target_os = "windows"))]
    const FIXTURE_MTLS_KEY: &str = "/etc/synthaea/certs/client.key";
    #[cfg(not(target_os = "windows"))]
    const FIXTURE_LOG_DIR: &str = "/var/log/synthaea";
    #[cfg(not(target_os = "windows"))]
    const FIXTURE_STATE_DIR: &str = "/var/lib/synthaea";
    #[cfg(not(target_os = "windows"))]
    const FIXTURE_IPC_ENDPOINT: &str = "/var/run/synthaea/agent.sock";

    fn valid_toml() -> String {
        // TOML strings interpret `\` as an escape character, so Windows
        // paths (`C:\…`, `\\.\pipe\…`) need every backslash doubled when
        // emitted into the file. Do that once here.
        let escape = |s: &str| s.replace('\\', "\\\\");
        format!(
            r#"schema_version = {v}

[server]
control_plane_url = "https://cp.example"
mtls_cert = "{cert}"
mtls_key = "{key}"
mtls_passphrase = "envvar:SYNTHAEA_MTLS_PASSPHRASE"

[log]
dir = "{log_dir}"
level = "info"
max_mb = 1024

[storage]
state_dir = "{state_dir}"
spool_max_mb = 4096

[ipc]
endpoint = "{ipc}"

[resources]
worker_threads = 0
max_reconnect_backoff_ms = 60000
"#,
            v = SCHEMA_VERSION,
            cert = escape(FIXTURE_MTLS_CERT),
            key = escape(FIXTURE_MTLS_KEY),
            log_dir = escape(FIXTURE_LOG_DIR),
            state_dir = escape(FIXTURE_STATE_DIR),
            ipc = escape(FIXTURE_IPC_ENDPOINT),
        )
    }

    fn write_tmp(contents: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::Builder::new()
            .suffix(".toml")
            .tempfile()
            .expect("tempfile");
        f.write_all(contents.as_bytes()).unwrap();
        f
    }

    #[test]
    fn loads_a_valid_file() {
        let f = write_tmp(&valid_toml());
        let cfg = load_from(f.path()).expect("valid config should load");
        assert_eq!(cfg.schema_version, SCHEMA_VERSION);
        assert_eq!(cfg.server.control_plane_url, "https://cp.example");
        assert_eq!(cfg.log.level, "info");
        assert_eq!(cfg.storage.spool_max_mb, 4096);
        assert_eq!(cfg.resources.worker_threads, 0);
        assert_eq!(cfg.resources.max_reconnect_backoff().as_secs(), 60);
    }

    #[test]
    fn missing_file_at_explicit_path_is_io_not_notfound() {
        // Behaviour contract: an explicit --config or SYNTHAEA_CONFIG that
        // points at a missing file is Io (operator typo'd it), not
        // NotFound (which is reserved for the "install-time never
        // provisioned" case at the default path).
        let _guard = env_lock();
        // SAFETY: env access serialized by ENV_LOCK.
        unsafe {
            std::env::remove_var("SYNTHAEA_CONFIG");
        }
        let err = load(Some(Path::new("/tmp/definitely-not-there-xyz.toml"))).unwrap_err();
        assert!(matches!(err, ConfigError::Io { .. }));
    }

    #[test]
    fn schema_version_mismatch_is_a_specific_variant() {
        let bad = valid_toml().replace(
            &format!("schema_version = {}", SCHEMA_VERSION),
            &format!("schema_version = {}", SCHEMA_VERSION + 42),
        );
        let f = write_tmp(&bad);
        let err = load_from(f.path()).unwrap_err();
        match err {
            ConfigError::SchemaVersionMismatch {
                found, expected, ..
            } => {
                assert_eq!(found, SCHEMA_VERSION + 42);
                assert_eq!(expected, SCHEMA_VERSION);
            }
            other => panic!("expected SchemaVersionMismatch, got {other:?}"),
        }
    }

    #[test]
    fn missing_schema_version_is_a_parse_error() {
        // If the top-level `schema_version` field is absent, the probe
        // fails at the deserialize step (SchemaProbe.schema_version is a
        // required u32). The operator's fix is the same as any other
        // "missing required field": add it.
        let f = write_tmp(
            r#"[server]
control_plane_url = "https://cp.example"
"#,
        );
        let err = load_from(f.path()).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn unknown_top_level_field_is_parse_error() {
        // deny_unknown_fields prevents a config file from silently
        // carrying a mistyped field name; catches `[serverr]` typos.
        let bad = valid_toml() + "\n[typo_section]\nfoo = 1\n";
        let f = write_tmp(&bad);
        let err = load_from(f.path()).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn non_https_url_fails_validation() {
        let bad = valid_toml().replace("https://cp.example", "http://cp.example");
        let f = write_tmp(&bad);
        let err = load_from(f.path()).unwrap_err();
        match err {
            ConfigError::Invalid { field, .. } => {
                assert_eq!(field, "server.control_plane_url");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn zero_log_max_mb_fails_validation() {
        let bad = valid_toml().replace("max_mb = 1024", "max_mb = 0");
        let f = write_tmp(&bad);
        let err = load_from(f.path()).unwrap_err();
        match err {
            ConfigError::Invalid { field, .. } => assert_eq!(field, "log.max_mb"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn cleartext_secret_is_rejected_at_parse() {
        let bad = valid_toml().replace(
            r#"mtls_passphrase = "envvar:SYNTHAEA_MTLS_PASSPHRASE""#,
            r#"mtls_passphrase = "hunter2""#,
        );
        let f = write_tmp(&bad);
        let err = load_from(f.path()).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
        // The parse error message flows through from the SecretRef
        // deserialize impl; operators see the field name and the offending
        // literal.
        assert!(format!("{err}").contains("hunter2"));
    }

    #[test]
    fn env_override_applies_and_revalidates() {
        let _guard = env_lock();
        // SAFETY: env access serialized by ENV_LOCK.
        unsafe {
            std::env::set_var("SYNTHAEA_LOG_LEVEL", "debug");
            std::env::set_var("SYNTHAEA_SPOOL_MAX_MB", "8192");
        }
        let f = write_tmp(&valid_toml());
        let mut cfg = load_from(f.path()).unwrap();
        apply_env_overrides(&mut cfg, f.path()).unwrap();
        assert_eq!(cfg.log.level, "debug");
        assert_eq!(cfg.storage.spool_max_mb, 8192);
        // SAFETY: as above.
        unsafe {
            std::env::remove_var("SYNTHAEA_LOG_LEVEL");
            std::env::remove_var("SYNTHAEA_SPOOL_MAX_MB");
        }
    }

    #[test]
    fn env_override_bad_type_is_specific_variant() {
        let _guard = env_lock();
        // SAFETY: env access serialized by ENV_LOCK.
        unsafe {
            std::env::set_var("SYNTHAEA_SPOOL_MAX_MB", "not-a-number");
        }
        let f = write_tmp(&valid_toml());
        let mut cfg = load_from(f.path()).unwrap();
        let err = apply_env_overrides(&mut cfg, f.path()).unwrap_err();
        // SAFETY: as above.
        unsafe {
            std::env::remove_var("SYNTHAEA_SPOOL_MAX_MB");
        }
        match err {
            ConfigError::EnvOverrideParse {
                env_var, field, ..
            } => {
                assert_eq!(env_var, "SYNTHAEA_SPOOL_MAX_MB");
                assert_eq!(field, "storage.spool_max_mb");
            }
            other => panic!("expected EnvOverrideParse, got {other:?}"),
        }
    }

    #[test]
    fn env_override_bad_semantic_flags_the_field() {
        // The env value parses to the target type (a String) but violates
        // the log level enum. The overall failure surfaces via
        // validate_semantics, which produces `Invalid` with the field
        // path, not `EnvOverrideParse`.
        let _guard = env_lock();
        // SAFETY: env access serialized by ENV_LOCK.
        unsafe {
            std::env::set_var("SYNTHAEA_LOG_LEVEL", "verbose");
        }
        let f = write_tmp(&valid_toml());
        let mut cfg = load_from(f.path()).unwrap();
        let err = apply_env_overrides(&mut cfg, f.path()).unwrap_err();
        // SAFETY: as above.
        unsafe {
            std::env::remove_var("SYNTHAEA_LOG_LEVEL");
        }
        match err {
            ConfigError::Invalid { field, .. } => assert_eq!(field, "log.level"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }
}
