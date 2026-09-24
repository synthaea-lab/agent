//! The committed default configuration template, and the one operation that
//! puts it on disk (`cli config init`).
//!
//! Per ADR-0013 §5 the template is a hand-written committed file
//! (`data/default-agent.toml`), not generated from Rust literals: this module
//! only embeds it verbatim and writes it out. `tests/default_template.rs`
//! keeps it loadable against the current schema.
//!
//! Linux only for now: the template carries Linux paths and a Unix domain
//! socket (`ipc.endpoint`), so writing it on Windows/macOS would install a
//! file the agent then rejects. Those targets get an explicit error until a
//! per-OS template exists.

use std::path::Path;

use crate::error::ConfigError;

/// The committed default template, byte for byte.
pub const DEFAULT_TEMPLATE: &str = include_str!("../data/default-agent.toml");

/// Writes [`DEFAULT_TEMPLATE`] to `path`, creating missing parent directories.
///
/// Refuses to replace an existing file unless `force` is set: an installed
/// config is operator state, and silently resetting it to placeholder values
/// is exactly the kind of silent misconfiguration ADR-0013 exists to prevent.
/// Without `force` the file is created with `create_new`, so a file appearing
/// between the check and the write is still never clobbered. With `force` the
/// template goes to a sibling temp file first and is renamed over `path`, so a
/// crash mid-write never leaves a truncated config behind.
///
/// The file is created `0644`: it holds no secrets (secret fields are
/// `envvar:`/`file:` references, ADR-0013 §7), and `cli`, which reads it for
/// `ipc.endpoint`, may run as a non-root admin.
///
/// # Errors
///
/// - [`ConfigError::AlreadyExists`] if `path` exists and `force` is false.
/// - [`ConfigError::Write`] if a parent directory or the file cannot be
///   created or written.
/// - [`ConfigError::UnsupportedPlatform`] outside Linux (see module doc).
#[cfg(target_os = "linux")]
pub fn write_default_template(path: &Path, force: bool) -> Result<(), ConfigError> {
    use std::{
        fs::{self, OpenOptions},
        io::Write as _,
        os::unix::fs::OpenOptionsExt as _,
    };

    let write_err = |source| ConfigError::Write {
        path: path.to_path_buf(),
        source,
    };

    if !force && path.exists() {
        return Err(ConfigError::AlreadyExists {
            path: path.to_path_buf(),
        });
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(write_err)?;
    }

    let open = |p: &Path, create_new: bool| {
        let mut opts = OpenOptions::new();
        opts.write(true).mode(0o644);
        if create_new {
            opts.create_new(true);
        } else {
            opts.create(true).truncate(true);
        }
        opts.open(p)
    };

    if force {
        let mut tmp_name = path.as_os_str().to_owned();
        tmp_name.push(".init.tmp");
        let tmp = Path::new(&tmp_name);
        let result = open(tmp, false)
            .and_then(|mut f| {
                f.write_all(DEFAULT_TEMPLATE.as_bytes())?;
                f.sync_all()
            })
            .and_then(|()| fs::rename(tmp, path));
        if result.is_err() {
            let _ = fs::remove_file(tmp);
        }
        result.map_err(write_err)
    } else {
        let mut f = open(path, true).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                ConfigError::AlreadyExists {
                    path: path.to_path_buf(),
                }
            } else {
                write_err(e)
            }
        })?;
        f.write_all(DEFAULT_TEMPLATE.as_bytes())
            .and_then(|()| f.sync_all())
            .map_err(write_err)
    }
}

/// Stub outside Linux — see the module doc.
///
/// # Errors
///
/// Always [`ConfigError::UnsupportedPlatform`].
#[cfg(not(target_os = "linux"))]
pub fn write_default_template(path: &Path, _force: bool) -> Result<(), ConfigError> {
    Err(ConfigError::UnsupportedPlatform {
        path: path.to_path_buf(),
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    #[test]
    fn writes_the_committed_template_and_creates_parents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("etc/synthaea/agent.toml");
        write_default_template(&path, false).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), DEFAULT_TEMPLATE);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o022, 0, "never group/world-writable, got {mode:o}");
        // What it wrote must be a config the agent accepts.
        let cfg = crate::load_from(&path).unwrap();
        assert_eq!(cfg.schema_version, crate::SCHEMA_VERSION);
    }

    #[test]
    fn refuses_to_overwrite_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        std::fs::write(&path, "operator = \"state\"\n").unwrap();
        let err = write_default_template(&path, false).unwrap_err();
        assert!(matches!(err, ConfigError::AlreadyExists { .. }), "{err}");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "operator = \"state\"\n",
            "an existing config must be left untouched"
        );
    }

    #[test]
    fn force_replaces_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        std::fs::write(&path, "stale").unwrap();
        write_default_template(&path, true).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), DEFAULT_TEMPLATE);
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, vec![std::ffi::OsString::from("agent.toml")]);
    }

    #[test]
    fn unwritable_parent_is_a_write_error() {
        let dir = tempfile::tempdir().unwrap();
        // A regular file where a directory is expected: create_dir_all fails
        // even as root, unlike a permission-based setup.
        let blocker = dir.path().join("not-a-dir");
        std::fs::write(&blocker, "").unwrap();
        let err = write_default_template(&blocker.join("agent.toml"), false).unwrap_err();
        assert!(matches!(err, ConfigError::Write { .. }), "{err}");
    }
}
