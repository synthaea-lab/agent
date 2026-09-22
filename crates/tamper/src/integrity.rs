//! Self-integrity — the EDR verifying its own binaries and config have not been
//! swapped for a neutered build (`docs/architecture/threat-model.md`, §3).
//!
//! An adversary with admin rights who cannot beat the detections at runtime may
//! instead replace `agent`/`watchdog` on disk with a build that reports clean, or
//! edit the config to disable rules and restart into it. This module hashes the
//! protected paths against the SHA-256 baseline recorded in the signed manifest the
//! `updater` installed, and reports every mismatch as a violation — a high-severity
//! tamper detection, never a silent log.
//!
//! ## Trust and scope
//!
//! The manifest is the root of trust: its authenticity is the `updater`'s job
//! (signed distribution, ADR-0015), not this module's — here it is already-trusted
//! input. Verification runs in user mode, so a kernel-level adversary can forge the
//! result; that ceiling is named in the threat model. What this closes is the
//! same-privilege on-disk swap: the swap changes the hash, and the changed hash is
//! the alert.
//!
//! ## Guards (the enrich lesson)
//!
//! A path is hashed only when it is a regular file — a FIFO or device planted at a
//! protected path would otherwise block the check forever or feed it an endless
//! stream. A file that has grown past [`MAX_VERIFY_BYTES`] is itself a violation (a
//! 12 KB launcher that is now 300 MB is exactly the tampering we are looking for),
//! not something we read to the end.

use std::{
    collections::BTreeMap,
    io::Read as _,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

/// Upper bound on a protected file's size (256 MiB). Larger is treated as a
/// violation rather than read — protected artifacts (binaries, config) are small,
/// and an oversized file at a protected path is tampering, not telemetry.
pub const MAX_VERIFY_BYTES: u64 = 256 * 1024 * 1024;

/// The expected state of the protected artifacts: path → lowercase-hex SHA-256.
/// Produced by the `updater` from the signed release manifest; consumed here as
/// already-trusted input.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manifest {
    entries: BTreeMap<PathBuf, String>,
}

impl Manifest {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a manifest from `(path, expected_sha256)` pairs. The hash is lowercased
    /// so comparison is case-insensitive regardless of how the manifest was written.
    pub fn from_entries(entries: impl IntoIterator<Item = (PathBuf, String)>) -> Self {
        Self {
            entries: entries
                .into_iter()
                .map(|(p, h)| (p, h.to_ascii_lowercase()))
                .collect(),
        }
    }

    /// Adds one protected path and its expected hash.
    pub fn insert(&mut self, path: impl Into<PathBuf>, expected_sha256: impl Into<String>) {
        self.entries
            .insert(path.into(), expected_sha256.into().to_ascii_lowercase());
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Verifies every protected path against its expected hash, returning one
    /// [`IntegrityViolation`] per path that is missing, unreadable, oversized, or
    /// whose content has changed. An empty result means every protected artifact is
    /// byte-for-byte what the manifest recorded.
    #[must_use]
    pub fn verify(&self) -> Vec<IntegrityViolation> {
        self.entries
            .iter()
            .filter_map(|(path, expected)| {
                verify_one(path, expected).map(|kind| IntegrityViolation {
                    path: path.clone(),
                    kind,
                })
            })
            .collect()
    }
}

/// What is wrong with one protected path (each variant is one failed check).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViolationKind {
    /// The file exists and was hashed, but the hash does not match the manifest —
    /// the artifact was replaced or edited.
    Modified { expected: String, actual: String },
    /// The protected path is gone — an uninstall or a move as a prelude to a swap.
    Missing,
    /// The path exists but could not be read as a regular file (a FIFO/device
    /// planted at the path, a permissions change, an I/O error).
    Unreadable,
    /// The file grew past [`MAX_VERIFY_BYTES`] — suspicious in its own right.
    Oversized { size: u64 },
}

/// One protected path that failed verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityViolation {
    pub path: PathBuf,
    pub kind: ViolationKind,
}

impl IntegrityViolation {
    /// A ready-to-log line; the caller decides severity and destination (this crate
    /// stays free of the detection/sink types — it is a LEAF crate).
    #[must_use]
    pub fn message(&self) -> String {
        let p = self.path.display();
        match &self.kind {
            ViolationKind::Modified { expected, actual } => format!(
                "protected artifact `{p}` was modified (expected {expected}, found {actual}) \
                 — possible neutered-build swap"
            ),
            ViolationKind::Missing => {
                format!("protected artifact `{p}` is missing — removed or moved")
            }
            ViolationKind::Unreadable => {
                format!("protected artifact `{p}` is present but unreadable as a regular file")
            }
            ViolationKind::Oversized { size } => format!(
                "protected artifact `{p}` is {size} bytes, past the {MAX_VERIFY_BYTES}-byte \
                 verification bound — treated as tampered"
            ),
        }
    }
}

/// Verifies one path against `expected` (lowercase hex). `None` when it matches.
fn verify_one(path: &Path, expected: &str) -> Option<ViolationKind> {
    // A manifest entry whose path no longer exists is Missing, not clean.
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(_) => return Some(ViolationKind::Missing),
    };
    if !meta.is_file() {
        return Some(ViolationKind::Unreadable);
    }
    if meta.len() > MAX_VERIFY_BYTES {
        return Some(ViolationKind::Oversized { size: meta.len() });
    }
    match hash_file(path) {
        Some(actual) if actual == expected => None,
        Some(actual) => Some(ViolationKind::Modified {
            expected: expected.to_string(),
            actual,
        }),
        None => Some(ViolationKind::Unreadable),
    }
}

/// Streaming SHA-256 of a regular file, bounded by [`MAX_VERIFY_BYTES`] via
/// `Read::take` so a file that grows under us cannot exceed the budget.
fn hash_file(path: &Path) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let mut reader = file.take(MAX_VERIFY_BYTES);
    let mut hasher = Sha256::new();
    // `sha2` 0.11 dropped `impl Write for Sha256` (it never guaranteed the
    // infallible-write contract `io::Write` implies), so `io::copy` no longer
    // applies here — read into a buffer and feed `Digest::update` by hand.
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str, content: &[u8]) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("tamper-integrity-{}-{name}", std::process::id()));
        std::fs::write(&p, content).unwrap();
        p
    }

    fn sha256_hex(content: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(content);
        let d = h.finalize();
        let mut out = String::new();
        for b in d {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
        }
        out
    }

    #[test]
    fn an_unmodified_artifact_verifies_clean() {
        let p = tmp("clean", b"the real agent binary");
        let mut m = Manifest::new();
        m.insert(p.clone(), sha256_hex(b"the real agent binary"));
        assert!(m.verify().is_empty());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn a_swapped_binary_is_reported_modified() {
        let p = tmp("swapped", b"neutered build");
        let mut m = Manifest::new();
        // Manifest records the ORIGINAL hash; the file on disk is the swap.
        m.insert(p.clone(), sha256_hex(b"original build"));
        let v = m.verify();
        assert_eq!(v.len(), 1);
        assert!(matches!(v[0].kind, ViolationKind::Modified { .. }));
        assert!(v[0].message().contains("neutered-build swap"));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn a_missing_artifact_is_reported_missing() {
        let mut m = Manifest::new();
        m.insert(
            std::env::temp_dir().join("tamper-integrity-does-not-exist"),
            sha256_hex(b"anything"),
        );
        let v = m.verify();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].kind, ViolationKind::Missing);
    }

    #[test]
    fn hash_case_does_not_matter() {
        let p = tmp("case", b"payload");
        let mut m = Manifest::new();
        m.insert(p.clone(), sha256_hex(b"payload").to_ascii_uppercase());
        assert!(
            m.verify().is_empty(),
            "uppercase manifest hash must still match"
        );
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn multiple_paths_report_independently() {
        let ok = tmp("multi-ok", b"good");
        let bad = tmp("multi-bad", b"tampered");
        let mut m = Manifest::from_entries([
            (ok.clone(), sha256_hex(b"good")),
            (bad.clone(), sha256_hex(b"good")), // expects "good", finds "tampered"
        ]);
        m.insert(
            std::env::temp_dir().join("tamper-integrity-multi-gone"),
            sha256_hex(b"x"),
        );
        let v = m.verify();
        assert_eq!(v.len(), 2, "the good file must not be reported");
        assert!(
            v.iter()
                .any(|x| x.path == bad && matches!(x.kind, ViolationKind::Modified { .. }))
        );
        assert!(v.iter().any(|x| x.kind == ViolationKind::Missing));
        std::fs::remove_file(&ok).ok();
        std::fs::remove_file(&bad).ok();
    }
}
