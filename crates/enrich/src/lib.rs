//! # enrich
//!
//! Cross-platform enrichment shared by detection: SHA-256 file hashing with a
//! validity-checked cache, and code-signature verification (Authenticode on Windows,
//! `codesign` on macOS, `Unsupported` on Linux — no standard scheme). One
//! implementation feeding rules, YARA triggers, IOC matching, and ML features — not
//! three platform copies.
//!
//! ## Latency budget
//!
//! Enrichment runs on the agent's event path, so it is budgeted, not best-effort:
//! - Cache hit (same path, mtime, size): a metadata stat — microseconds.
//! - Cache miss: one streaming SHA-256 read, refused above [`MAX_HASH_BYTES`]
//!   (result: hash absent, reason logged) so a multi-GB binary can never stall the
//!   pipeline.
//! - Signature verification runs only on cache misses and its verdict is cached with
//!   the hash. Windows verification is forced offline (no revocation-network calls).

mod sig;

use std::path::Path;

use schema::Signature;
use sha2::{Digest, Sha256};
use store::BoundedMap;

/// Files larger than this are not hashed on the event path (64 MiB).
pub const MAX_HASH_BYTES: u64 = 64 * 1024 * 1024;

/// Hash+signature cache entries — pids churn, images repeat.
const CACHE_CAP: usize = 16_384;

/// What enrichment knows about one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEnrichment {
    /// Lowercase hex SHA-256; `None` when the file was unreadable or over budget.
    pub sha256: Option<String>,
    pub signature: Signature,
}

#[derive(Clone, PartialEq, Eq)]
struct CacheEntry {
    mtime_ns: u128,
    size: u64,
    /// Unix: (dev, inode) — an attacker can set mtime and size at will
    /// (`touch -r`), but cannot keep them while swapping the underlying inode
    /// without the pair changing (review finding: mtime+size alone made the
    /// cached verdict spoofable). Windows: 0 (no cheap stable id via metadata).
    file_id: (u64, u64),
    enrichment: FileEnrichment,
}

#[cfg(unix)]
fn file_id(meta: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (meta.dev(), meta.ino())
}

#[cfg(not(unix))]
fn file_id(_meta: &std::fs::Metadata) -> (u64, u64) {
    (0, 0)
}

/// The enrichment engine: owns the cache. One instance per agent, behind whatever
/// synchronization the host uses (methods take `&mut self`).
pub struct Enricher {
    cache: BoundedMap<std::path::PathBuf, CacheEntry>,
}

impl Default for Enricher {
    fn default() -> Self {
        Self::new()
    }
}

impl Enricher {
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: BoundedMap::new(CACHE_CAP),
        }
    }

    /// Enriches one file. Cached by (path, mtime, size): an unchanged file is a
    /// metadata stat; a changed or unknown file is one bounded hash + one signature
    /// verification.
    pub fn enrich(&mut self, path: &Path) -> FileEnrichment {
        let Ok(meta) = std::fs::metadata(path) else {
            return FileEnrichment {
                sha256: None,
                signature: Signature::Unsupported,
            };
        };
        // FIFOs, device nodes, sockets: opening one can block forever (a named
        // pipe with no writer) or read an endless stream — the event path must
        // never touch them (review finding).
        if !meta.is_file() {
            return FileEnrichment {
                sha256: None,
                signature: Signature::Unsupported,
            };
        }
        let mtime_ns = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let size = meta.len();

        let id = file_id(&meta);
        if let Some(entry) = self.cache.get(&path.to_path_buf())
            && entry.mtime_ns == mtime_ns
            && entry.size == size
            && entry.file_id == id
        {
            return entry.enrichment.clone();
        }

        let sha256 = if size <= MAX_HASH_BYTES {
            hash_file(path)
        } else {
            log::debug!(
                "enrich: {} over hash budget ({size} bytes), skipping",
                path.display()
            );
            None
        };
        let enrichment = FileEnrichment {
            sha256,
            signature: sig::verify(path),
        };
        self.cache.insert(
            path.to_path_buf(),
            CacheEntry {
                mtime_ns,
                size,
                file_id: id,
                enrichment: enrichment.clone(),
            },
        );
        enrichment
    }
}

fn hash_file(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).ok()?;
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

    fn tmp_file(name: &str, content: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("enrich-test-{}-{name}", std::process::id()));
        std::fs::write(&p, content).unwrap();
        p
    }

    #[test]
    fn hashes_known_vector() {
        let p = tmp_file("abc", b"abc");
        let mut e = Enricher::new();
        assert_eq!(
            e.enrich(&p).sha256.as_deref(),
            // SHA-256("abc") — FIPS 180-2 test vector.
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    #[test]
    fn cache_invalidates_on_change() {
        let p = tmp_file("change", b"one");
        let mut e = Enricher::new();
        let first = e.enrich(&p).sha256;
        // Ensure the mtime moves even on coarse filesystem clocks.
        std::thread::sleep(std::time::Duration::from_millis(30));
        std::fs::write(&p, b"two").unwrap();
        let second = e.enrich(&p).sha256;
        assert_ne!(first, second, "changed content must re-hash");
    }

    #[test]
    fn missing_file_is_not_fatal() {
        let mut e = Enricher::new();
        let got = e.enrich(Path::new("/nonexistent/enrich-test"));
        assert_eq!(got.sha256, None);
        assert_eq!(got.signature, Signature::Unsupported);
    }

    /// Real platform coverage in CI: a known system binary must verify as signed on
    /// Windows (Authenticode) and macOS (codesign); Linux reports Unsupported.
    #[test]
    fn platform_signature_of_system_binary() {
        let mut e = Enricher::new();
        // pwsh.exe carries an EMBEDDED Authenticode signature (System32 binaries are
        // catalog-signed, which this stage does not resolve yet — see sig.rs).
        #[cfg(windows)]
        let (path, expected) = (
            Path::new("C:\\Program Files\\PowerShell\\7\\pwsh.exe"),
            Signature::Valid,
        );
        #[cfg(target_os = "macos")]
        let (path, expected) = (Path::new("/bin/ls"), Signature::Valid);
        #[cfg(target_os = "linux")]
        let (path, expected) = (Path::new("/bin/ls"), Signature::Unsupported);
        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        return;
        #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
        {
            if !path.exists() {
                eprintln!("skipping: {} not present on this host", path.display());
                return;
            }
            assert_eq!(e.enrich(path).signature, expected, "{}", path.display());
        }
    }

    #[test]
    fn unsigned_scratch_file() {
        // On Windows the extension picks the SIP: a .ps1 is a signable type, so an
        // unsigned one reads Unsigned; an extensionless blob has no SIP and reads
        // Unsupported (asserted separately below).
        let p = tmp_file("unsigned.ps1", b"Write-Host hi\n");
        let mut e = Enricher::new();
        let got = e.enrich(&p).signature;
        #[cfg(any(windows, target_os = "macos"))]
        assert_eq!(got, Signature::Unsigned);
        #[cfg(target_os = "linux")]
        assert_eq!(got, Signature::Unsupported);
        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        let _ = got;
    }

    #[cfg(windows)]
    #[test]
    fn non_signable_file_is_unsupported_not_invalid() {
        // CI regression: SUBJECT_FORM_UNKNOWN must not read as a broken signature.
        let p = tmp_file("blob", b"just data");
        let mut e = Enricher::new();
        assert_eq!(e.enrich(&p).signature, Signature::Unsupported);
    }
}
