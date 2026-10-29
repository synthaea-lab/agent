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

mod pe_info;
mod sig;

use std::{
    fs::File,
    io::{Read as _, Seek as _},
    path::Path,
};

pub use pe_info::PeInfo;
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
    /// PE version-resource metadata (issue #983): empty (every field `None`) on
    /// every platform but Windows, and on Windows too when the image has none,
    /// enrichment could not read it, or the image was over [`MAX_HASH_BYTES`] —
    /// same budget as the hash, see `pe_info`'s module doc for why reading it
    /// costs comparably little once the file is already open for the other two.
    pub pe_info: PeInfo,
    /// [`image_identity`] of the file the verdict and the hash were read from, taken
    /// from the same handle (#688); `None` when the file system gave no identity.
    pub file_id: Option<String>,
}

/// The identity of the file at `path` as a token: `"{volume:016x}:{id:032x}"`.
/// Unix: (device, inode); Windows: (volume serial, 128-bit file id). Two opens of
/// the same file give the same token; a different file at the same path gives a
/// different one. `None` when the file cannot be opened or has no identity.
#[must_use]
pub fn path_identity(path: &Path) -> Option<String> {
    let file = File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    file_id(&file, &meta).map(identity_token)
}

fn identity_token((volume, id): FileId) -> String {
    format!("{volume:016x}:{id:032x}")
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
            pe_info: PeInfo::default(),
            file_id: None,
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
        // Same budget as the hash (#983): a multi-GB binary must never stall this
        // path for four cosmetic strings either. `pe_info::read` is a no-op on
        // every platform but Windows regardless (see its module doc), so this
        // check only ever skips real work there.
        let pe_info = if size <= MAX_HASH_BYTES {
            pe_info::read(path)
        } else {
            PeInfo::default()
        };
        let enrichment = FileEnrichment {
            sha256,
            signature,
            pe_info,
            file_id: id.map(identity_token),
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
    fn path_identity_follows_the_file_not_its_path() {
        let dir = std::env::temp_dir().join(format!("enrich-identity-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (a, moved, b) = (dir.join("a"), dir.join("moved"), dir.join("b"));
        std::fs::write(&a, b"image").unwrap();
        std::fs::write(&b, b"decoy").unwrap();
        let ran = path_identity(&a).expect("a regular file has an identity");
        // The dropper's move: the image goes aside, a decoy takes its path.
        std::fs::rename(&a, &moved).unwrap();
        std::fs::rename(&b, &a).unwrap();
        assert_ne!(
            path_identity(&a),
            Some(ran.clone()),
            "the path now holds another file"
        );
        assert_eq!(path_identity(&moved), Some(ran.clone()));
        // And enrichment reports the identity of the file it read.
        assert_eq!(
            Enricher::new().enrich_uncached(&a).file_id,
            path_identity(&a)
        );
        assert_eq!(path_identity(&dir.join("missing")), None);
        std::fs::remove_dir_all(&dir).ok();
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
        assert!(got.pe_info.is_empty());
    }

    /// #983: `Enricher::enrich` wires `pe_info::read` through the same cache as the
    /// hash and signature — a plain data file (no PE version resource, any platform)
    /// must come back with every field `None` rather than erroring.
    #[test]
    fn non_pe_file_has_empty_pe_info() {
        let p = tmp_file("pe-info-plain", b"not a PE file");
        let mut e = Enricher::new();
        assert!(e.enrich(&p).pe_info.is_empty());
        std::fs::remove_file(&p).ok();
    }

    /// Real platform coverage in CI, like `platform_signature_of_system_binary`:
    /// `cmd.exe`'s `OriginalFilename` must come back through the full cache path,
    /// not just `pe_info::read` in isolation (see `pe_info`'s own test, including
    /// why the exact string is only checked loosely: it is build/locale-dependent).
    #[cfg(windows)]
    #[test]
    fn enrich_fills_pe_info_for_a_windows_system_binary() {
        let path = Path::new(r"C:\Windows\System32\cmd.exe");
        if !path.exists() {
            eprintln!("skipping: {} not present on this host", path.display());
            return;
        }
        let mut e = Enricher::new();
        let info = e.enrich(path).pe_info;
        assert!(
            info.original_file_name
                .as_deref()
                .is_some_and(|n| n.to_lowercase().starts_with("cmd.exe")),
            "{info:?}"
        );
        // A second, cached call must return the same value, not re-derive it from a
        // stale or absent cache entry.
        assert_eq!(e.enrich(path).pe_info, info);
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
