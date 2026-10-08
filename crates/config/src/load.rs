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

use crate::{
    discovery::{DiscoverySource, discover},
    error::ConfigError,
    schema::{AgentConfig, SCHEMA_VERSION},
};

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
/// Names that run whatever they are given: allowing one exempts every script and command
/// line it executes, so an attacker needs only to start their tool through it. Matched on the
/// file name, by exact name or by family prefix (`python3.12`, `perl5.38`). Not a complete
/// list, a guard against the obvious mistake; the operator still chooses what to trust.
fn is_interpreter(path: &Path) -> bool {
    const EXACT: &[&str] = &[
        "sh",
        "bash",
        "dash",
        "ash",
        "zsh",
        "ksh",
        "csh",
        "tcsh",
        "fish",
        "busybox",
        "env",
        "xargs",
        "find",
        "awk",
        "gawk",
        "mawk",
        "sed",
        "lua",
        "luajit",
        "tclsh",
        "wish",
        "expect",
        "gdb",
        "sudo",
        "su",
        "nsenter",
        "chroot",
        "pwsh",
        "powershell",
    ];
    const FAMILIES: &[&str] = &[
        "python", "perl", "ruby", "node", "php", "java", "bun", "deno",
    ];
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    EXACT.contains(&name.as_str()) || FAMILIES.iter().any(|family| name.starts_with(family))
}

fn validate_semantics(cfg: &AgentConfig, source_path: &Path) -> Result<(), ConfigError> {
    let src = source_path.display().to_string();

    // Secret fields — reject `SecretRef::Invalid` (a bare literal in the TOML
    // that didn't match any provider prefix). Deserialize is deliberately
    // infallible on secrets so the field-path context can be produced here;
    // see `SecretRef`'s docs and the module-level comment above its
    // `Deserialize` impl. Fixes the dead-code defect from issue #281.
    if let crate::secret::SecretRef::Invalid(raw) = &cfg.server.mtls_passphrase {
        return Err(ConfigError::SecretInvalid {
            field: "server.mtls_passphrase".into(),
            value: raw.clone(),
            origin: src.clone(),
        });
    }

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

    // updates.ring — a typo'd ring would otherwise surface as a server-side
    // 404 (or worse, a valid but unintended ring) at the first fetch.
    if let Some(ring) = &cfg.updates.ring
        && !crate::schema::CONTENT_RINGS.contains(&ring.as_str())
    {
        return Err(ConfigError::Invalid {
            field: "updates.ring".into(),
            expected: format!("one of {}", crate::schema::CONTENT_RINGS.join(", ")),
            value: ring.clone(),
            origin: src.clone(),
        });
    }

    // logs.sources — each one is a file the agent tails and a parser fed by
    // attacker-controlled text (ADR-0022): a bounded, absolute, duplicate-free
    // list, so a typo fails at boot instead of silently reading nothing.
    if cfg.logs.sources.len() > crate::schema::MAX_LOG_SOURCES {
        return Err(ConfigError::Invalid {
            field: "logs.sources".into(),
            expected: format!("at most {} sources", crate::schema::MAX_LOG_SOURCES),
            value: format!("{} sources", cfg.logs.sources.len()),
            origin: src.clone(),
        });
    }
    for (i, source) in cfg.logs.sources.iter().enumerate() {
        if !source.path.is_absolute() {
            return Err(ConfigError::Invalid {
                field: format!("logs.sources[{i}].path"),
                expected: "an absolute filesystem path".into(),
                value: source.path.display().to_string(),
                origin: src.clone(),
            });
        }
        if cfg.logs.sources[..i].iter().any(|s| s.path == source.path) {
            return Err(ConfigError::Invalid {
                field: format!("logs.sources[{i}].path"),
                expected: "a path declared once (two parsers on one file would read it twice)"
                    .into(),
                value: source.path.display().to_string(),
                origin: src.clone(),
            });
        }
    }

    // deception.canary_dirs — each one gets files written into it by the agent, so a
    // typo must fail at boot rather than plant under a relative path of the cwd.
    if cfg.deception.canary_dirs.len() > crate::schema::MAX_CANARY_DIRS {
        return Err(ConfigError::Invalid {
            field: "deception.canary_dirs".into(),
            expected: format!("at most {} directories", crate::schema::MAX_CANARY_DIRS),
            value: format!("{} directories", cfg.deception.canary_dirs.len()),
            origin: src.clone(),
        });
    }
    for (i, dir) in cfg.deception.canary_dirs.iter().enumerate() {
        if !dir.is_absolute() {
            return Err(ConfigError::Invalid {
                field: format!("deception.canary_dirs[{i}]"),
                expected: "an absolute directory path".into(),
                value: dir.display().to_string(),
                origin: src.clone(),
            });
        }
        if cfg.deception.canary_dirs[..i].contains(dir) {
            return Err(ConfigError::Invalid {
                field: format!("deception.canary_dirs[{i}]"),
                expected: "a directory listed once".into(),
                value: dir.display().to_string(),
                origin: src.clone(),
            });
        }
    }

    // deception.allow_exe — matched against a resolved executable path, so a relative
    // entry could never match and would silently leave the canary noisy.
    if cfg.deception.allow_exe.len() > crate::schema::MAX_CANARY_ALLOW_EXES {
        return Err(ConfigError::Invalid {
            field: "deception.allow_exe".into(),
            expected: format!(
                "at most {} executables",
                crate::schema::MAX_CANARY_ALLOW_EXES
            ),
            value: format!("{} executables", cfg.deception.allow_exe.len()),
            origin: src.clone(),
        });
    }
    for (i, exe) in cfg.deception.allow_exe.iter().enumerate() {
        if is_interpreter(exe) {
            return Err(ConfigError::Invalid {
                field: format!("deception.allow_exe[{i}]"),
                expected: "a specific indexer or backup binary, not a shell, interpreter or \
                           launcher (every script it runs would be allowed to read the canaries)"
                    .into(),
                value: exe.display().to_string(),
                origin: src.clone(),
            });
        }
        if !exe.is_absolute() {
            return Err(ConfigError::Invalid {
                field: format!("deception.allow_exe[{i}]"),
                expected: "an absolute executable path".into(),
                value: exe.display().to_string(),
                origin: src.clone(),
            });
        }
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

    // server.ca_cert — optional; when given, absolute for the same reason.
    if let Some(ca_cert) = &cfg.server.ca_cert
        && !ca_cert.is_absolute()
    {
        return Err(ConfigError::Invalid {
            field: "server.ca_cert".into(),
            expected: "an absolute filesystem path".into(),
            value: ca_cert.display().to_string(),
            origin: src.clone(),
        });
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
    use std::io::Write;

    use super::*;
    use crate::test_util::env_lock;

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
    fn an_absent_ca_cert_means_the_builtin_roots() {
        let f = write_tmp(&valid_toml());
        let cfg = load_from(f.path()).expect("valid config should load");
        assert_eq!(cfg.server.ca_cert, None);
    }

    #[test]
    fn a_configured_ca_cert_is_loaded() {
        let ca = FIXTURE_MTLS_CERT.replace("client.crt", "ca.pem");
        let toml = valid_toml().replace(
            "mtls_passphrase =",
            &format!(
                "ca_cert = \"{}\"\nmtls_passphrase =",
                ca.replace('\\', "\\\\")
            ),
        );
        let f = write_tmp(&toml);
        let cfg = load_from(f.path()).expect("valid config should load");
        assert_eq!(cfg.server.ca_cert.as_deref(), Some(Path::new(&ca)));
    }

    #[test]
    fn a_relative_ca_cert_is_rejected() {
        let toml = valid_toml().replace(
            "mtls_passphrase =",
            "ca_cert = \"certs/ca.pem\"\nmtls_passphrase =",
        );
        let f = write_tmp(&toml);
        match load_from(f.path()).unwrap_err() {
            ConfigError::Invalid { field, .. } => assert_eq!(field, "server.ca_cert"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn an_absent_updates_section_means_no_ring_is_assigned() {
        let f = write_tmp(&valid_toml());
        let cfg = load_from(f.path()).expect("valid config should load");
        assert_eq!(cfg.updates.ring, None);
    }

    #[test]
    fn a_configured_ring_is_loaded() {
        let f = write_tmp(&format!(
            "{}\n[updates]\nring = \"canary_1\"\n",
            valid_toml()
        ));
        let cfg = load_from(f.path()).expect("valid config should load");
        assert_eq!(cfg.updates.ring.as_deref(), Some("canary_1"));
    }

    #[test]
    fn an_unknown_ring_is_refused_with_the_field_named() {
        let f = write_tmp(&format!("{}\n[updates]\nring = \"canary\"\n", valid_toml()));
        match load_from(f.path()).unwrap_err() {
            ConfigError::Invalid { field, value, .. } => {
                assert_eq!(field, "updates.ring");
                assert_eq!(value, "canary");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
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
    fn cleartext_secret_is_rejected_as_secret_invalid() {
        // A bare cleartext value in a secret field must produce
        // `ConfigError::SecretInvalid`, NOT the generic `Parse` — this is the
        // whole point of the `SecretInvalid` variant, and the fix for
        // issue #281 (before the fix, this test asserted `Parse` and the
        // dedicated variant was dead code).
        let bad = valid_toml().replace(
            r#"mtls_passphrase = "envvar:SYNTHAEA_MTLS_PASSPHRASE""#,
            r#"mtls_passphrase = "hunter2""#,
        );
        let f = write_tmp(&bad);
        let err = load_from(f.path()).unwrap_err();
        match err {
            ConfigError::SecretInvalid { field, value, .. } => {
                assert_eq!(field, "server.mtls_passphrase");
                assert_eq!(value, "hunter2");
            }
            other => panic!("expected SecretInvalid, got {other:?}"),
        }
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
            ConfigError::EnvOverrideParse { env_var, field, .. } => {
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

    /// An absolute path for the host OS, escaped for a TOML basic string.
    fn abs_log(name: &str) -> String {
        if cfg!(windows) {
            format!("C:\\\\logs\\\\{name}")
        } else {
            format!("/var/log/{name}")
        }
    }

    fn source(path: &str, kind: &str) -> String {
        format!("[[logs.sources]]\npath = \"{path}\"\nkind = \"{kind}\"\n\n")
    }

    fn load_with_logs(extra: &str) -> Result<AgentConfig, ConfigError> {
        let f = write_tmp(&format!("{}\n{extra}", valid_toml()));
        load_from(f.path())
    }

    #[test]
    fn no_logs_table_means_no_sources() {
        let cfg = load_with_logs("").unwrap();
        assert!(cfg.logs.sources.is_empty());
    }

    #[test]
    fn loads_declared_log_sources() {
        let extra = source(&abs_log("access.log"), "access_combined")
            + &source(&abs_log("mysql.err"), "mysql_error");
        let cfg = load_with_logs(&extra).unwrap();
        assert_eq!(cfg.logs.sources.len(), 2);
        assert_eq!(
            cfg.logs.sources[0].kind,
            crate::LogSourceKind::AccessCombined
        );
        assert_eq!(cfg.logs.sources[1].kind, crate::LogSourceKind::MysqlError);
    }

    #[test]
    fn a_relative_log_path_is_rejected() {
        match load_with_logs(&source("access.log", "access_common")).unwrap_err() {
            ConfigError::Invalid { field, .. } => assert_eq!(field, "logs.sources[0].path"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn a_duplicate_log_path_is_rejected() {
        let p = abs_log("access.log");
        let extra = source(&p, "access_common") + &source(&p, "access_combined");
        match load_with_logs(&extra).unwrap_err() {
            ConfigError::Invalid { field, .. } => assert_eq!(field, "logs.sources[1].path"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_kind_is_a_parse_error() {
        let err = load_with_logs(&source(&abs_log("a.log"), "postgres")).unwrap_err();
        assert!(!matches!(err, ConfigError::Invalid { .. }), "{err:?}");
    }

    #[test]
    fn too_many_log_sources_are_rejected() {
        let many: String = (0..=crate::MAX_LOG_SOURCES)
            .map(|i| source(&abs_log(&format!("{i}.log")), "access_common"))
            .collect();
        match load_with_logs(&many).unwrap_err() {
            ConfigError::Invalid { field, .. } => assert_eq!(field, "logs.sources"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    fn deception_table(dirs: &[String]) -> String {
        let list: Vec<String> = dirs.iter().map(|d| format!("\"{d}\"")).collect();
        format!("[deception]\ncanary_dirs = [{}]\n", list.join(", "))
    }

    #[test]
    fn no_deception_table_plants_nothing() {
        let cfg = load_with_logs("").unwrap();
        assert!(cfg.deception.canary_dirs.is_empty());
    }

    #[test]
    fn declared_canary_dirs_are_loaded() {
        let dirs = [abs_log("a"), abs_log("b")];
        let cfg = load_with_logs(&deception_table(&dirs)).unwrap();
        assert_eq!(cfg.deception.canary_dirs.len(), 2);
    }

    #[test]
    fn a_relative_canary_dir_is_rejected() {
        match load_with_logs(&deception_table(&["srv/share".into()])).unwrap_err() {
            ConfigError::Invalid { field, .. } => assert_eq!(field, "deception.canary_dirs[0]"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn a_duplicate_canary_dir_is_rejected() {
        let d = abs_log("a");
        match load_with_logs(&deception_table(&[d.clone(), d])).unwrap_err() {
            ConfigError::Invalid { field, .. } => assert_eq!(field, "deception.canary_dirs[1]"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn too_many_canary_dirs_are_rejected() {
        let many: Vec<String> = (0..=crate::MAX_CANARY_DIRS)
            .map(|i| abs_log(&i.to_string()))
            .collect();
        match load_with_logs(&deception_table(&many)).unwrap_err() {
            ConfigError::Invalid { field, .. } => assert_eq!(field, "deception.canary_dirs"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn a_relative_allowed_executable_is_rejected() {
        let extra = "[deception]\nallow_exe = [\"updatedb\"]\n";
        match load_with_logs(extra).unwrap_err() {
            ConfigError::Invalid { field, .. } => assert_eq!(field, "deception.allow_exe[0]"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn a_shell_or_interpreter_is_rejected_as_an_allowed_executable() {
        for exe in [
            "/usr/bin/bash",
            "/bin/sh",
            "/usr/bin/python3.12",
            "/usr/bin/perl",
            "/usr/bin/find",
            "/usr/bin/env",
        ] {
            let extra = format!("[deception]\nallow_exe = [\"{exe}\"]\n");
            match load_with_logs(&extra) {
                Err(ConfigError::Invalid { field, .. }) => {
                    assert_eq!(field, "deception.allow_exe[0]", "{exe}");
                }
                other => panic!("{exe}: expected Invalid, got {other:?}"),
            }
        }
    }

    #[test]
    fn an_indexer_is_accepted_as_an_allowed_executable() {
        if cfg!(windows) {
            return;
        }
        let extra =
            "[deception]\nallow_exe = [\"/usr/bin/updatedb.plocate\", \"/usr/sbin/bacula-fd\"]\n";
        let cfg = load_with_logs(extra).unwrap();
        assert_eq!(cfg.deception.allow_exe.len(), 2);
    }

    #[test]
    fn too_many_allowed_executables_are_rejected() {
        let many: Vec<String> = (0..=crate::MAX_CANARY_ALLOW_EXES)
            .map(|i| format!("\"{}\"", abs_log(&i.to_string())))
            .collect();
        let extra = format!("[deception]\nallow_exe = [{}]\n", many.join(", "));
        match load_with_logs(&extra).unwrap_err() {
            ConfigError::Invalid { field, .. } => assert_eq!(field, "deception.allow_exe"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }
}
