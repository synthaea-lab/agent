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
//! - Cache hit (same path, mtime, size, file identity): a stat, an open and a
//!   metadata query on the handle — microseconds.
//! - Cache miss: one streaming SHA-256 read, refused above [`MAX_HASH_BYTES`]
//!   (result: hash absent, reason logged) so a multi-GB binary can never stall the
//!   pipeline.
//! - Signature verification runs only on cache misses and its verdict is cached with
//!   the hash. Windows verification is forced offline (no revocation-network calls).
//!   On Windows, an embedded-signature miss additionally tries a catalog-membership
//!   lookup (see `sig.rs`) before settling on `Unsigned` — a handful of extra Win32
//!   calls, but only on that one path, and only once per cache miss.

mod sig;

use std::{
    fs::File,
    io::{Read as _, Seek as _},
    path::Path,
};

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
    /// Unix: (dev, inode). Windows: (volume serial, 128-bit file id). An attacker
    /// can set mtime and size at will (`touch -r`, `SetFileTime`), but cannot keep
    /// them while swapping the underlying file without the identity changing
    /// (review finding: mtime+size alone made the cached verdict spoofable; #688
    /// for Windows, where it was a constant until then). `None`: the file system
    /// gave no identity, and the entry is never trusted.
    file_id: Option<FileId>,
    enrichment: FileEnrichment,
}

/// Which file object an entry describes: (volume or device, file id or inode).
type FileId = (u64, u128);

#[cfg(unix)]
fn file_id(_file: &File, meta: &std::fs::Metadata) -> Option<FileId> {
    use std::os::unix::fs::MetadataExt;
    Some((meta.dev(), u128::from(meta.ino())))
}

#[cfg(windows)]
fn file_id(file: &File, _meta: &std::fs::Metadata) -> Option<FileId> {
    sig::file_identity(file)
}

#[cfg(not(any(unix, windows)))]
fn file_id(_file: &File, _meta: &std::fs::Metadata) -> Option<FileId> {
    None
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

    /// Enriches one file. Cached by (path, mtime, size, file identity): an unchanged
    /// file is a stat and an open; a changed or unknown file is one bounded hash + one
    /// signature verification.
    ///
    /// The file is opened once, and its metadata, identity, signature and hash all come
    /// from that handle (#688). Whatever the path points at after the open (a rename,
    /// a replacement), the verdict and the hash describe the same file object, and the
    /// cache key is that object's identity.
    pub fn enrich(&mut self, path: &Path) -> FileEnrichment {
        self.enrich_with(path, true)
    }

    /// [`Self::enrich`] without trusting a cache hit: always hashes and verifies,
    /// then refreshes the entry. For a caller whose decision rests on the verdict
    /// (#441: a `Valid` signature silences T1204.002). On Windows the cache key has
    /// no file identity, so a same-size replacement with its mtime restored would
    /// hit an entry describing the file it replaced.
    pub fn enrich_uncached(&mut self, path: &Path) -> FileEnrichment {
        self.enrich_with(path, false)
    }

    fn enrich_with(&mut self, path: &Path, trust_cache: bool) -> FileEnrichment {
        let unsupported = FileEnrichment {
            sha256: None,
            signature: Signature::Unsupported,
        };
        // FIFOs, device nodes, sockets: opening one can block forever (a named
        // pipe with no writer) or read an endless stream — the event path must
        // never touch them (review finding). Checked by path before the open.
        if !std::fs::metadata(path).is_ok_and(|meta| meta.is_file()) {
            return unsupported;
        }
        let Ok(mut file) = File::open(path) else {
            return unsupported;
        };
        // Checked again on the handle: the path may have been swapped since.
        let Ok(meta) = file.metadata() else {
            return unsupported;
        };
        if !meta.is_file() {
            return unsupported;
        }
        let mtime_ns = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let size = meta.len();

        let id = file_id(&file, &meta);
        if trust_cache
            && let Some(id) = id
            && let Some(entry) = self.cache.get(&path.to_path_buf())
            && entry.mtime_ns == mtime_ns
            && entry.size == size
            && entry.file_id == Some(id)
        {
            return entry.enrichment.clone();
        }

        // Verified before hashing: the verifier reads the handle itself, and the
        // hash then starts again from offset 0.
        let signature = sig::verify(path, &file);
        let sha256 = if size <= MAX_HASH_BYTES {
            file.rewind().ok().and_then(|()| hash_file(&mut file))
        } else {
            tracing::debug!(path = %path.display(), size, "enrich: over hash budget, skipping");
            None
        };
        let enrichment = FileEnrichment { sha256, signature };
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

fn hash_file(file: &mut File) -> Option<String> {
    let mut hasher = Sha256::new();
    // `sha2` 0.11 dropped `impl Write for Sha256` (it never guaranteed the
    // infallible-write contract `io::Write` implies), so `io::copy` no longer
    // applies here — read into a buffer and feed `Digest::update` by hand.
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).ok()?;
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

    /// #688: before it, Windows keyed the cache on (path, mtime, size) only, the file
    /// identity being a constant. A same-size file renamed over the original, with
    /// the original's mtime set on it, then hit the old entry and reported the old
    /// hash. Unix caught it by inode already.
    #[test]
    fn a_same_size_replacement_with_the_mtime_restored_is_rehashed() {
        let p = tmp_file("swap-target", b"one");
        let decoy = tmp_file("swap-decoy", b"two");
        let mut e = Enricher::new();
        let first = e.enrich(&p).sha256;
        let mtime = std::fs::metadata(&p).unwrap().modified().unwrap();
        File::options()
            .write(true)
            .open(&decoy)
            .unwrap()
            .set_modified(mtime)
            .unwrap();
        std::fs::rename(&decoy, &p).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().modified().unwrap(), mtime);
        assert_eq!(std::fs::metadata(&p).unwrap().len(), 3);

        let second = e.enrich(&p).sha256;
        assert_ne!(second, first, "a replaced file must not hit the old entry");
        assert_eq!(
            second.as_deref(),
            // SHA-256("two").
            Some("3fc4ccfe745870e2c0d99f71f30ff0656c8dedd41cc1d7d3d376b0dbe685e2f3")
        );
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn file_identity_is_stable_for_one_file_and_differs_between_two() {
        let a = tmp_file("id-a", b"a");
        let b = tmp_file("id-b", b"b");
        let id = |p: &Path| {
            let file = File::open(p).unwrap();
            let meta = file.metadata().unwrap();
            file_id(&file, &meta)
        };
        #[cfg(any(unix, windows))]
        {
            assert!(
                id(&a).is_some(),
                "a local NTFS/ext4/APFS file has an identity"
            );
            assert_eq!(id(&a), id(&a));
            assert_ne!(id(&a), id(&b));
        }
        std::fs::remove_file(&a).ok();
        std::fs::remove_file(&b).ok();
    }

    #[test]
    fn enrich_uncached_sees_a_same_size_rewrite_with_its_mtime_restored() {
        let p = tmp_file("respoof", b"one");
        let mut e = Enricher::new();
        let first = e.enrich(&p).sha256;
        let mtime = std::fs::metadata(&p).unwrap().modified().unwrap();
        std::fs::write(&p, b"two").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&p)
            .unwrap()
            .set_modified(mtime)
            .unwrap();
        // The attack the cached path cannot see: same path, size and mtime, and
        // on Unix the same inode (rewritten in place).
        assert_eq!(e.enrich(&p).sha256, first, "the cached path is fooled");
        let fresh = e.enrich_uncached(&p).sha256;
        assert_ne!(fresh, first, "an uncached enrichment must re-hash");
        assert_eq!(e.enrich(&p).sha256, fresh, "and refresh the cache entry");
        std::fs::remove_file(&p).ok();
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
        // pwsh.exe carries an EMBEDDED Authenticode signature — this exercises the
        // embedded-signature path (sig.rs's `verify_wide`) in isolation; the
        // catalog-lookup fallback is exercised separately by
        // `catalog_signed_system_binary_verifies` below.
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

    /// The exact regression #21's closing comment flagged: notepad.exe (like most
    /// System32 binaries) has no EMBEDDED Authenticode signature, only catalog
    /// membership — `verify_wide` alone reports Unsigned; the catalog-lookup
    /// fallback (`sig.rs::windows_impl::catalog_verify`) must resolve it to Valid.
    /// See `docs/adr/0007-windows-catalog-signed-binary-verification.md`.
    #[cfg(windows)]
    #[test]
    fn catalog_signed_system_binary_verifies() {
        let path = Path::new(r"C:\Windows\System32\notepad.exe");
        if !path.exists() {
            eprintln!("skipping: {} not present on this host", path.display());
            return;
        }
        let mut e = Enricher::new();
        assert_eq!(
            e.enrich(path).signature,
            Signature::Valid,
            "{}",
            path.display()
        );
    }
}
