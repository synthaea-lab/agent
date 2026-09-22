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

    /// `release_version` is on the local ban list — a previous install of this
    /// exact release failed its health check (ADR-0015 Decision 6).
    #[error("release {0} is banned on this install (failed a previous health check)")]
    ReleaseBanned(u64),

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
}
