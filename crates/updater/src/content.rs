//! The signed content manifest (ADR-0016): detection rules, ML models, and
//! policy distributed via canary rings, independent of a binary release. Same
//! Ed25519 signing/verification discipline as [`crate::manifest::ReleaseManifest`]
//! — a distinct type, not a variant of it, because the two manifests carry
//! genuinely different shapes: content entries need a `ring`, a `type`, and
//! optional `metadata` that a binary release's flat `(path, sha256)` map has no
//! use for.
//!
//! This module covers verification only — fetching the manifest over the
//! network (`crates/transport`) and reloading rules/models into a running agent
//! are composed by the binary that uses this crate (`updater` stays a LEAF crate
//! per `tools/check-deps.py`; see [`crate`]'s module doc for why).

use std::collections::BTreeMap;

use ring::signature::{self, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use crate::{error::UpdaterError, hash::hex_decode, key::UPDATER_PUBLIC_KEY};

/// The only `schema_version` this build accepts — same anti-drift stance as
/// [`crate::manifest::MANIFEST_SCHEMA_VERSION`], a separate constant because the
/// two manifest kinds version independently.
pub const CONTENT_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// One artifact in a content manifest (ADR-0016 §1).
///
/// Field order is alphabetical and fixed by declaration, same reasoning as
/// [`ContentManifest`] — canonicalization depends on it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentEntry {
    /// Free-form key/value metadata (e.g. `{"technique": "T1071.001"}`) —
    /// carried through, never interpreted by this crate. Absent rather than
    /// `null` when empty, matching the server's `.optional()` Zod field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
    /// Path relative to the content root (e.g. `rules/beacon.sigma`). Forward-slash
    /// strings regardless of host OS — content paths are a server-defined
    /// namespace, not a filesystem path on either side.
    pub path: String,
    /// Lowercase-hex SHA-256 of the artifact's bytes.
    pub sha256: String,
    /// Size in bytes — lets a caller budget a download before fetching it.
    pub size: u64,
    /// `rule` | `model` | `policy` (ADR-0016 §1). Kept as a plain string, not a
    /// Rust enum: this crate only ever forwards the value to a caller that
    /// decides what to do with each type, and a string can't fail to
    /// deserialize just because the server added a fourth type this build
    /// doesn't know the name of yet.
    #[serde(rename = "type")]
    pub content_type: String,
}

/// Windows device names reserved regardless of extension (`NUL.txt` is just
/// as reserved as `NUL`) — checked against a segment's stem, case-insensitively.
const WINDOWS_RESERVED_NAMES: &[&str] = &[
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
    // Superscript-digit variants and the console handles also resolve to devices.
    "COM\u{b9}",
    "COM\u{b2}",
    "COM\u{b3}",
    "LPT\u{b9}",
    "LPT\u{b2}",
    "LPT\u{b3}",
    "CONIN$",
    "CONOUT$",
];

/// True if `segment` is safe as one path component on every platform this
/// agent targets — not just "no `..`". A `:` starts a drive prefix
/// (`C:\Windows\...`) or an NTFS alternate data stream (`file.txt:stream`)
/// on Windows, either of which lets a signed path escape the content root or
/// write to a stream `content_type`/`sha256` checks never see (PR #520
/// review: `rules/C:/Windows/evil.sigma` and `rules/a.sigma:stream` both
/// passed the pre-#520-review-round-1 version of this check). A segment
/// ending in `.` or a space is silently trimmed by the Win32 API, so
/// `"evil. "` and `"evil"` can address the same file — reject the form that
/// makes that ambiguity possible in the first place. Windows device names
/// are reserved regardless of extension.
#[must_use]
pub(crate) fn is_safe_path_segment(segment: &str) -> bool {
    if segment.is_empty() || segment == "." || segment == ".." || segment.contains(':') {
        return false;
    }
    if segment.ends_with('.') || segment.ends_with(' ') {
        return false;
    }
    let stem = segment.split('.').next().unwrap_or(segment);
    !WINDOWS_RESERVED_NAMES
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
}

impl ContentEntry {
    /// True if [`Self::path`] is safe to join onto a local content root on
    /// every platform this agent targets: non-empty, relative,
    /// forward-slash-only, and every component passes
    /// [`is_safe_path_segment`]. A signed path only proves who signed the
    /// manifest, not that it's safe to write — checked before any download
    /// happens (PR #509 review), not deferred to write time.
    #[must_use]
    pub fn is_safe_relative_path(&self) -> bool {
        !self.path.is_empty()
            && !self.path.starts_with('/')
            && !self.path.contains('\\')
            && !self.path.contains('\0')
            && self.path.split('/').all(is_safe_path_segment)
    }
}

/// A signed content manifest for one ring (ADR-0016 §1).
///
/// Field order is alphabetical and fixed by declaration — canonicalization
/// relies on it, exactly like [`crate::manifest::ReleaseManifest`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentManifest {
    pub entries: Vec<ContentEntry>,
    /// Monotone, strictly increasing per `ring`. See [`Self::check_release_version`].
    pub release_version: u64,
    /// ISO 8601 UTC timestamp, e.g. `2026-09-23T16:00:00Z`. Kept as the raw
    /// string the server sent — this crate never computes with it, only a
    /// caller displaying "last updated" would parse it.
    pub released_at: String,
    /// Target ring (`canary_0`/`canary_1`/`canary_2`/`prod`). A plain string for
    /// the same reason as [`ContentEntry::content_type`] — this crate compares
    /// it, never branches on an exhaustive match.
    pub ring: String,
    /// Must equal [`CONTENT_MANIFEST_SCHEMA_VERSION`] or the manifest is
    /// rejected before any other check runs.
    pub schema_version: u32,
    /// Lowercase-hex Ed25519 signature over [`Self::canonical_bytes`] computed
    /// with this field forced to `""`.
    pub signature: String,
}

impl ContentManifest {
    /// The canonical bytes this manifest signs and verifies over: 2-space-indented
    /// JSON with `signature` forced to `""`, fields in the alphabetical order
    /// they are declared in the struct. Same scheme as
    /// [`crate::manifest::ReleaseManifest::canonical_bytes`] (ADR-0015 Decision 2,
    /// reused by ADR-0016 for consistency) — kept as a private, independent
    /// implementation rather than shared code, since the two manifest shapes
    /// differ and a shared helper would need to take the signature-bearing
    /// struct by trait object for no real savings.
    fn canonical_bytes(&self) -> Vec<u8> {
        let unsigned = Self {
            signature: String::new(),
            ..self.clone()
        };
        serde_json::to_vec_pretty(&unsigned)
            .expect("ContentManifest has no non-serializable content")
    }

    /// Verifies this manifest's `schema_version` and Ed25519 signature against
    /// [`UPDATER_PUBLIC_KEY`] — the same embedded key that verifies binary
    /// release manifests. Does not check `release_version` monotonicity,
    /// `ring` assignment, or per-entry hashes — see [`Self::check_release_version`]
    /// and the caller's own per-artifact hash check after download.
    ///
    /// # Errors
    ///
    /// [`UpdaterError::SchemaVersionUnsupported`] if `schema_version` does not
    /// match [`CONTENT_MANIFEST_SCHEMA_VERSION`]; [`UpdaterError::SignatureInvalid`]
    /// if the signature is malformed or does not verify.
    pub fn verify_signature(&self) -> Result<(), UpdaterError> {
        if self.schema_version != CONTENT_MANIFEST_SCHEMA_VERSION {
            return Err(UpdaterError::SchemaVersionUnsupported {
                found: self.schema_version,
                expected: CONTENT_MANIFEST_SCHEMA_VERSION,
            });
        }
        let sig_bytes = hex_decode(&self.signature).ok_or(UpdaterError::SignatureInvalid)?;
        let msg = self.canonical_bytes();
        let public_key = UnparsedPublicKey::new(&signature::ED25519, UPDATER_PUBLIC_KEY.as_slice());
        public_key
            .verify(&msg, &sig_bytes)
            .map_err(|_| UpdaterError::SignatureInvalid)
    }

    /// Rejects a manifest whose `ring` does not match `requested` — a valid
    /// signature only proves the server signed this manifest, not that it is
    /// the manifest for the ring the caller actually asked for. Without this,
    /// a validly-signed manifest for a different ring (e.g. a less-vetted
    /// canary release replayed against a prod agent) would still verify.
    /// Callers must check this before, or alongside,
    /// [`Self::check_release_version`] — see `agent::content::plan`.
    ///
    /// # Errors
    ///
    /// [`UpdaterError::RingMismatch`] if `self.ring != requested`.
    pub fn check_ring(&self, requested: &str) -> Result<(), UpdaterError> {
        if self.ring != requested {
            return Err(UpdaterError::RingMismatch {
                requested: requested.to_string(),
                found: self.ring.clone(),
            });
        }
        Ok(())
    }

    /// Anti-rollback-attack check, same shape as
    /// [`crate::manifest::ReleaseManifest::check_release_version`]: rejects a
    /// manifest whose `release_version` is not strictly greater than `current`.
    /// `current` is per-`ring` — a caller tracks the last-applied version for
    /// each ring it has ever fetched, not one counter shared across rings.
    ///
    /// # Errors
    ///
    /// [`UpdaterError::ReleaseNotNewer`] if `release_version <= current`.
    pub fn check_release_version(&self, current: Option<u64>) -> Result<(), UpdaterError> {
        match current {
            Some(current) if self.release_version <= current => {
                Err(UpdaterError::ReleaseNotNewer {
                    offered: self.release_version,
                    current,
                })
            }
            _ => Ok(()),
        }
    }

    /// Entries this manifest carries that are missing from, or whose hash
    /// disagrees with, `have` (the caller's map of already-applied
    /// `path -> sha256`). Empty means the caller is already fully up to date
    /// with this manifest's content — a legitimate outcome (e.g. re-fetching
    /// the same ring's manifest after a restart with no new release).
    #[must_use]
    pub fn entries_to_fetch<'a>(
        &'a self,
        have: &BTreeMap<String, String>,
    ) -> Vec<&'a ContentEntry> {
        self.entries
            .iter()
            .filter(|e| have.get(&e.path) != Some(&e.sha256))
            .collect()
    }

    /// Rejects the whole manifest if any entry's path is not safe to join
    /// onto a local content root ([`ContentEntry::is_safe_relative_path`]) —
    /// checked once, before anything is downloaded, rather than skipping the
    /// one bad entry and applying the rest.
    ///
    /// # Errors
    ///
    /// [`UpdaterError::UnsafeContentPath`] naming the first offending entry.
    pub fn validate_entry_paths(&self) -> Result<(), UpdaterError> {
        for entry in &self.entries {
            if !entry.is_safe_relative_path() {
                return Err(UpdaterError::UnsafeContentPath(entry.path.clone()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::test_key_pair;

    fn entry(path: &str, sha256: &str) -> ContentEntry {
        ContentEntry {
            metadata: None,
            path: path.to_string(),
            sha256: sha256.to_string(),
            size: 1234,
            content_type: "rule".to_string(),
        }
    }

    fn signed_manifest(release_version: u64) -> ContentManifest {
        let mut m = ContentManifest {
            entries: vec![entry("rules/beacon.sigma", &"a".repeat(64))],
            released_at: "2026-09-23T16:00:00Z".to_string(),
            release_version,
            ring: "canary_0".to_string(),
            schema_version: CONTENT_MANIFEST_SCHEMA_VERSION,
            signature: String::new(),
        };
        let msg = m.canonical_bytes();
        let sig = test_key_pair().sign(&msg);
        m.signature = crate::hash::hex_encode(sig.as_ref());
        m
    }

    #[test]
    fn a_freshly_signed_manifest_verifies() {
        assert!(signed_manifest(1).verify_signature().is_ok());
    }

    #[test]
    fn tampering_with_entries_after_signing_breaks_verification() {
        let mut m = signed_manifest(1);
        m.entries.push(entry("rules/other.sigma", &"b".repeat(64)));
        assert!(matches!(
            m.verify_signature(),
            Err(UpdaterError::SignatureInvalid)
        ));
    }

    #[test]
    fn tampering_with_ring_after_signing_breaks_verification() {
        // A signed canary_0 manifest replayed as a prod manifest must not verify
        // — the ring is part of what's signed, not a side channel the server
        // could swap after the fact.
        let mut m = signed_manifest(1);
        m.ring = "prod".to_string();
        assert!(matches!(
            m.verify_signature(),
            Err(UpdaterError::SignatureInvalid)
        ));
    }

    #[test]
    fn an_unsigned_manifest_fails_verification() {
        let m = ContentManifest {
            entries: vec![],
            released_at: "2026-09-23T16:00:00Z".to_string(),
            release_version: 1,
            ring: "canary_0".to_string(),
            schema_version: CONTENT_MANIFEST_SCHEMA_VERSION,
            signature: String::new(),
        };
        assert!(matches!(
            m.verify_signature(),
            Err(UpdaterError::SignatureInvalid)
        ));
    }

    #[test]
    fn unsupported_schema_version_is_rejected_before_checking_the_signature() {
        let mut m = signed_manifest(1);
        m.schema_version = CONTENT_MANIFEST_SCHEMA_VERSION + 1;
        assert!(matches!(
            m.verify_signature(),
            Err(UpdaterError::SchemaVersionUnsupported { found, expected })
                if found == CONTENT_MANIFEST_SCHEMA_VERSION + 1
                    && expected == CONTENT_MANIFEST_SCHEMA_VERSION
        ));
    }

    #[test]
    fn check_ring_accepts_a_matching_ring() {
        let m = signed_manifest(1);
        assert!(m.check_ring("canary_0").is_ok());
    }

    #[test]
    fn check_ring_rejects_a_correctly_signed_manifest_for_another_ring() {
        // A validly-signed canary_0 manifest must not pass as a prod manifest
        // just because the signature verifies — the signature proves who
        // signed it, not that it's the manifest for the ring asked for.
        let m = signed_manifest(1);
        assert!(matches!(
            m.check_ring("prod"),
            Err(UpdaterError::RingMismatch { requested, found })
                if requested == "prod" && found == "canary_0"
        ));
    }

    #[test]
    fn release_version_must_exceed_the_installed_one() {
        let m = signed_manifest(5);
        assert!(m.check_release_version(Some(4)).is_ok());
        assert!(matches!(
            m.check_release_version(Some(5)),
            Err(UpdaterError::ReleaseNotNewer {
                offered: 5,
                current: 5
            })
        ));
    }

    #[test]
    fn no_installed_release_always_accepts_day_zero() {
        let m = signed_manifest(1);
        assert!(m.check_release_version(None).is_ok());
    }

    #[test]
    fn entries_to_fetch_skips_files_already_at_the_right_hash() {
        let mut m = signed_manifest(1);
        m.entries.push(entry("rules/other.sigma", &"b".repeat(64)));

        let mut have = BTreeMap::new();
        have.insert("rules/beacon.sigma".to_string(), "a".repeat(64));
        // Stale hash for this one — must still be reported.
        have.insert("rules/other.sigma".to_string(), "c".repeat(64));

        let missing = m.entries_to_fetch(&have);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].path, "rules/other.sigma");
    }

    #[test]
    fn entries_to_fetch_is_empty_when_fully_up_to_date() {
        let m = signed_manifest(1);
        let mut have = BTreeMap::new();
        have.insert("rules/beacon.sigma".to_string(), "a".repeat(64));
        assert!(m.entries_to_fetch(&have).is_empty());
    }

    #[test]
    fn canonical_bytes_are_stable_regardless_of_the_signature_field() {
        let mut a = signed_manifest(3);
        let mut b = a.clone();
        b.signature = "not-the-real-signature".into();
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
        a.signature.clear();
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    }

    #[test]
    fn ordinary_content_paths_are_safe() {
        assert!(entry("rules/beacon.sigma", &"a".repeat(64)).is_safe_relative_path());
        assert!(
            entry(
                "models/cmdline-iforest-linux/0.3.0/model.pkl",
                &"a".repeat(64)
            )
            .is_safe_relative_path()
        );
    }

    #[test]
    fn a_dot_dot_component_is_unsafe() {
        // The concrete attack the PR #509 review named: a signed
        // `rules/../../etc/cron.d/x` must not be treated as safe.
        assert!(!entry("rules/../../etc/cron.d/x", &"a".repeat(64)).is_safe_relative_path());
        assert!(!entry("..", &"a".repeat(64)).is_safe_relative_path());
    }

    #[test]
    fn an_absolute_path_is_unsafe() {
        assert!(!entry("/etc/passwd", &"a".repeat(64)).is_safe_relative_path());
    }

    #[test]
    fn a_backslash_is_unsafe() {
        // Content paths are forward-slash-only by contract (the field's own
        // doc comment) — a backslash could mean something different to a
        // Windows path join than it does to the manifest's namespace.
        assert!(!entry("rules\\..\\evil.sigma", &"a".repeat(64)).is_safe_relative_path());
    }

    #[test]
    fn an_empty_path_is_unsafe() {
        assert!(!entry("", &"a".repeat(64)).is_safe_relative_path());
    }

    #[test]
    fn a_windows_drive_prefix_segment_is_unsafe() {
        // PR #520 review: `PathBuf::push` of a segment carrying a drive
        // prefix replaces the whole buffer on Windows instead of joining,
        // so `root.join("rules").join("C:").join("Windows").join("evil.sigma")`
        // does not end up under `root` at all.
        assert!(!entry("rules/C:/Windows/evil.sigma", &"a".repeat(64)).is_safe_relative_path());
        assert!(!entry("C:evil.sigma", &"a".repeat(64)).is_safe_relative_path());
    }

    #[test]
    fn an_ntfs_alternate_data_stream_segment_is_unsafe() {
        // `rules/a.sigma:stream` writes to a hidden NTFS stream on the same
        // file, past whatever `content_type`/`sha256` checks ever see.
        assert!(!entry("rules/a.sigma:stream", &"a".repeat(64)).is_safe_relative_path());
    }

    #[test]
    fn a_segment_ending_in_dot_or_space_is_unsafe() {
        // Win32 silently trims a trailing `.`/` ` from a path component, so
        // "evil." and "evil" can address the same file — an ambiguity a
        // hash/hash-mismatch check downstream never sees.
        assert!(!entry("rules/evil.", &"a".repeat(64)).is_safe_relative_path());
        assert!(!entry("rules/evil ", &"a".repeat(64)).is_safe_relative_path());
    }

    #[test]
    fn a_windows_reserved_device_name_is_unsafe_regardless_of_extension() {
        assert!(!entry("rules/NUL", &"a".repeat(64)).is_safe_relative_path());
        assert!(!entry("rules/nul.sigma", &"a".repeat(64)).is_safe_relative_path());
        assert!(!entry("rules/COM1.txt", &"a".repeat(64)).is_safe_relative_path());
        // Superscript digits and console handles also reach devices.
        for name in [
            "rules/COM\u{b9}.sigma",
            "rules/LPT\u{b3}",
            "rules/CONIN$",
            "rules/CONOUT$",
        ] {
            assert!(
                !entry(name, &"a".repeat(64)).is_safe_relative_path(),
                "{name}"
            );
        }
    }

    #[test]
    fn an_ordinary_dotted_filename_is_still_safe() {
        // The reserved-name/trailing-dot checks above must not turn into a
        // blanket ban on periods in filenames.
        assert!(
            entry(
                "models/cmdline-iforest-linux/0.3.0/model.pkl",
                &"a".repeat(64)
            )
            .is_safe_relative_path()
        );
        assert!(entry("rules/console-host.sigma", &"a".repeat(64)).is_safe_relative_path());
    }

    #[test]
    fn validate_entry_paths_rejects_the_whole_manifest_for_one_bad_entry() {
        let mut m = signed_manifest(1);
        m.entries.push(entry("../escape.sigma", &"b".repeat(64)));
        assert!(matches!(
            m.validate_entry_paths(),
            Err(UpdaterError::UnsafeContentPath(path)) if path == "../escape.sigma"
        ));
    }

    #[test]
    fn validate_entry_paths_accepts_a_clean_manifest() {
        assert!(signed_manifest(1).validate_entry_paths().is_ok());
    }
}

/// Parity-seam golden fixture (CLAUDE.md): one real, signed manifest checked
/// in once at `server/tests/fixtures/content-manifest-golden.json` and
/// verified by both this crate's tests and the server's TS unit tests
/// (`server/tests/unit/content-manifest-golden.test.ts`), so a canonicalization
/// mismatch between the two sides (PR #509 review) can't silently reappear.
#[cfg(test)]
mod golden_fixture {
    use super::*;

    const GOLDEN_FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../server/tests/fixtures/content-manifest-golden.json"
    ));

    #[test]
    fn golden_fixture_verifies_against_the_embedded_key() {
        let manifest: ContentManifest = serde_json::from_str(GOLDEN_FIXTURE).unwrap();
        manifest.verify_signature().unwrap();
    }

    #[test]
    fn golden_fixture_bytes_are_the_canonical_form() {
        // The fixture file itself is `serde_json::to_string_pretty` of the
        // signed manifest — asserts the checked-in bytes haven't drifted from
        // what this crate would itself produce, so a hand-edit of the fixture
        // can't silently break the cross-language comparison it exists for.
        // `.gitattributes` pins this file to `eol=lf`, but normalize `\r\n` on
        // both sides anyway rather than depend on that alone — a Windows
        // checkout that reintroduces CRLF here should fail on real content
        // drift, not on line endings (this crate's own CI caught exactly that
        // once, before this normalization existed).
        let manifest: ContentManifest = serde_json::from_str(GOLDEN_FIXTURE).unwrap();
        let regenerated = serde_json::to_string_pretty(&manifest).unwrap();
        assert_eq!(
            GOLDEN_FIXTURE.trim_end().replace("\r\n", "\n"),
            regenerated.trim_end().replace("\r\n", "\n")
        );
    }
}
