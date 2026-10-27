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

    /// This build embeds no production signing key for the manifest's kind, so nothing can
    /// be verified (ADR-0027: the key files under `crates/updater/keys/` are unprovisioned).
    #[error("this build embeds no production signing key for this manifest (ADR-0027)")]
    SigningKeyUnprovisioned,

    /// `release_version` is not strictly greater than the currently installed
    /// one (ADR-0015 Decision 2: anti-rollback-attack check).
    #[error("release {offered} is not newer than the installed release {current}")]
    ReleaseNotNewer { offered: u64, current: u64 },

    /// A content manifest lists nothing while the agent has applied content: applying it
    /// would delete every recorded file and leave the agent with no rules. A release that
    /// really withdraws everything must be a deliberate, separate decision; an empty or
    /// mis-globbed build must not be able to do it by accident.
    #[error("the manifest lists no content but {would_remove} applied file(s) would be removed")]
    EmptyContentManifest { would_remove: usize },

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

    /// A release manifest entry's path would escape the release directory (same
    /// rules as [`Self::UnsafeContentPath`]): checked before any download starts.
    #[error("release entry path `{0}` is not a safe relative path")]
    UnsafeReleasePath(String),

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

    /// A snapshot manifest's `kind` is not one this build knows (ADR-0033: only `common-set`).
    #[error("snapshot manifest kind `{found}` is not supported")]
    SnapshotKindUnsupported { found: String },

    /// A snapshot manifest's `built_at` is not later than the snapshot in force: a replay or a
    /// rollback of the server's own state. The snapshot in force stays (ADR-0033 decision 3).
    #[error("snapshot built at {offered} is not newer than the one in force ({current})")]
    SnapshotNotNewer { offered: u64, current: u64 },

    /// A snapshot manifest claims to be built further in the future than the clock-skew
    /// tolerance allows: a wrong server clock, or a manifest made to outlive its maximum age.
    #[error("snapshot built at {built_at} is dated beyond now ({now}) plus the tolerance")]
    SnapshotFromFuture { built_at: u64, now: u64 },

    /// The artifact does not match the signed manifest that names it (size, hash, or a header
    /// that disagrees with the manifest).
    #[error("snapshot artifact does not match its manifest: {0}")]
    SnapshotArtifactMismatch(String),

    /// A key-rotation manifest is not well formed (ADR-0027): it names no key, half a pair, a key
    /// that is not canonical hex, a window that is empty or too long, or its result would break
    /// the split between roles. Checked before its signature is trusted for anything.
    #[error("key-rotation manifest is malformed: {0}")]
    RotationMalformed(&'static str),

    /// A key-rotation manifest retires a key that is not the one this install trusts for `role`:
    /// a replay, or a manifest written for another key state.
    #[error(
        "key-rotation manifest does not apply: it retires a {role} key this install does not trust"
    )]
    RotationDoesNotApply { role: &'static str },

    /// A key-rotation manifest is past its `expires_at`.
    #[error("key-rotation manifest expired at {expires_at} (now {now})")]
    RotationExpired { expires_at: u64, now: u64 },

    /// A key-rotation manifest is dated beyond now plus the clock-skew tolerance.
    #[error(
        "key-rotation manifest issued at {issued_at} is dated beyond now ({now}) plus the tolerance"
    )]
    RotationNotYetValid { issued_at: u64, now: u64 },

    /// The file that records the applied key rotations exists but cannot be trusted: it does not
    /// parse, one of its rotations does not verify under the embedded `recovery` key, they are not
    /// in increasing `release_version` order, or they do not lead from this build's embedded keys.
    /// Refused rather than ignored: a file that exists proves a rotation happened, and falling
    /// back to the embedded keys could re-trust a key that was rotated away from.
    #[error("the key-rotation record is not trustworthy: {reason}")]
    TrustStateCorrupt { reason: String },

    /// The install already holds [`crate::trust_state::MAX_ROTATIONS`] rotations.
    #[error("this install already holds the maximum of {0} recorded key rotations")]
    TrustStateFull(usize),

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
