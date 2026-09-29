//! Errors this crate returns. Every rejection is a named variant — no
//! `anyhow`-style string swallowing, so a caller can tell a banned release apart
//! from a corrupt download without parsing a message.

use std::path::PathBuf;

use thiserror::Error;

/// Everything that can go wrong staging, verifying, or promoting a release.
#[derive(Debug, Error)]
pub enum UpdaterError {
    /// The manifest's `schema_version` is not one this build understands
    /// (ADR-0015 Decision 2: readers reject an unknown value outright).
    #[error("manifest schema_version {found} is not supported (expected {expected})")]
    SchemaVersionUnsupported { found: u32, expected: u32 },

    /// The manifest's Ed25519 signature does not verify against the embedded
    /// public key.
    #[error("manifest signature does not verify")]
    SignatureInvalid,

    /// `release_version` is not strictly greater than the currently installed
    /// one (ADR-0015 Decision 2: anti-rollback-attack check).
    #[error("release {offered} is not newer than the installed release {current}")]
    ReleaseNotNewer { offered: u64, current: u64 },

    /// A content manifest's `ring` does not match the ring the caller actually
    /// requested. A valid signature only proves "we signed this manifest", not
    /// "this is the manifest for the ring you asked for" — without this check a
    /// correctly-signed manifest for a different (e.g. less-vetted canary) ring
    /// would still verify and be accepted.
    #[error("manifest is for ring `{found}`, expected `{requested}`")]
    RingMismatch { requested: String, found: String },

    /// `release_version` is on the local ban list — a previous install of this
    /// exact release failed its health check (ADR-0015 Decision 6).
    #[error("release {0} is banned on this install (failed a previous health check)")]
    ReleaseBanned(u64),

    /// A content manifest entry's `path` would escape a local content root —
    /// contains a `..` component, is absolute, or uses a backslash. A valid
    /// signature only proves who signed the manifest, not that every entry's
    /// path is safe to write; checked before any download starts, not at
    /// write time (PR #509 review).
    #[error("content entry path `{0}` is not a safe relative path")]
    UnsafeContentPath(String),

    /// A file the manifest lists is missing from the staged release directory.
    #[error("staged release is missing manifest entry `{path}`")]
    StagedFileMissing { path: PathBuf },

    /// A staged file's content does not match the manifest's recorded hash.
    #[error("staged file `{path}` hash mismatch (expected {expected}, found {actual})")]
    StagedFileMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },

    /// Filesystem I/O failed — the underlying [`std::io::Error`] carries the
    /// specifics (missing permissions, disk full, etc).
    #[error("I/O error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// A persisted manifest file exists but is not valid JSON, or does not
    /// deserialize as a [`crate::ReleaseManifest`] — a corrupt or truncated write,
    /// never expected from this crate's own [`crate::layout::Layout::persist_manifest`].
    #[error("manifest at {path} is corrupt: {source}")]
    ManifestCorrupt {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}
