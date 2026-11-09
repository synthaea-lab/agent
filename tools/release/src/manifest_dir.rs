//! Building an unsigned release manifest from a directory of release files.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, bail};
use updater::{ReleaseManifest, hash::hash_file};

/// Hashes every regular file under `dir` into an unsigned manifest for
/// `release_version`. Entry paths are relative to `dir` with forward slashes.
///
/// A symlink or any other non-regular file is refused: the updater writes each entry
/// as a plain file, so a manifest must not describe anything else.
///
/// # Errors
///
/// `dir` is unreadable or empty, holds a symlink or special file or a non-UTF-8
/// name, or yields an entry path the updater would refuse (`validate_entry_paths`).
pub(crate) fn build(dir: &Path, release_version: u64) -> anyhow::Result<ReleaseManifest> {
    let mut entries = BTreeMap::new();
    walk(dir, Path::new(""), &mut entries)?;
    if entries.is_empty() {
        bail!("{} holds no files", dir.display());
    }
    let manifest = ReleaseManifest::new(release_version, entries);
    manifest.validate_entry_paths()?;
    Ok(manifest)
}

fn walk(
    root: &Path,
    relative: &Path,
    entries: &mut BTreeMap<PathBuf, String>,
) -> anyhow::Result<()> {
    let here = root.join(relative);
    for item in
        std::fs::read_dir(&here).with_context(|| format!("cannot read {}", here.display()))?
    {
        let item = item?;
        let name = item.file_name();
        let name = name
            .to_str()
            .with_context(|| format!("{} holds a non-UTF-8 name", here.display()))?;
        let child = relative.join(name);
        let file_type = item.file_type()?;
        if file_type.is_dir() {
            walk(root, &child, entries)?;
        } else if file_type.is_file() {
            let digest = hash_file(&root.join(&child))
                .with_context(|| format!("cannot hash {}", child.display()))?;
            // Forward slashes whatever the host: the manifest is read on Linux.
            let key = child.to_str().map(|p| PathBuf::from(p.replace('\\', "/")));
            entries.insert(key.context("non-UTF-8 path")?, digest);
        } else {
            bail!(
                "{} is a symlink or special file; a release holds plain files only",
                child.display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, bytes: &[u8]) {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn every_file_is_hashed_under_its_forward_slash_relative_path() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "agent", b"agent bytes");
        write(dir.path(), "lib/helper.so", b"helper bytes");

        let manifest = build(dir.path(), 7).unwrap();

        assert_eq!(manifest.release_version, 7);
        assert_eq!(manifest.signature, "");
        let keys: Vec<_> = manifest
            .entries
            .keys()
            .map(|k| k.to_str().unwrap())
            .collect();
        assert_eq!(keys, ["agent", "lib/helper.so"]);
        assert_eq!(
            manifest.entries[Path::new("agent")],
            updater::hash::hash_bytes(b"agent bytes")
        );
    }

    #[test]
    fn an_empty_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let err = build(dir.path(), 1).unwrap_err().to_string();
        assert!(err.contains("holds no files"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_is_refused_rather_than_followed() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "agent", b"agent bytes");
        std::os::unix::fs::symlink("/etc/passwd", dir.path().join("passwd")).unwrap();
        let err = build(dir.path(), 1).unwrap_err().to_string();
        assert!(err.contains("symlink or special file"), "{err}");
    }
}
