//! Error type returned by every operation in this crate.
//!
//! Every variant carries enough context for a review-time reader to know
//! which document, which field, and what expectation failed — matching the
//! "precise errors" contract [ADR-0010 §8] borrows from ADR-0013.

/// Anything that can go wrong loading, parsing, verifying, or merging a
/// [`crate::Policy`] document.
///
/// Variants are stable: `agent` and (later) the control plane both
/// pattern-match on them to decide the exit code / API response.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The document's `schema_version` is unknown to this build. Readers
    /// reject rather than parse-strict-with-drop (ADR-0010 §Deferred:
    /// today's decision on cross-version co-existence is "reject").
    #[error("unsupported schema_version {found}: this build only accepts {expected}")]
    SchemaVersionMismatch {
        /// Version literally present in the document.
        found: u32,
        /// Version this build supports (currently [`crate::SCHEMA_VERSION`]).
        expected: u32,
    },

    /// The document is not valid JSON, or does not match the shape this
    /// crate's [`crate::Policy`] type expects.
    #[error("failed to parse policy document: {0}")]
    Parse(#[from] serde_json::Error),

    /// The document parses, its `schema_version` matches, but the Ed25519
    /// signature over its canonical form does not verify against the
    /// caller-supplied public key. Never reveals cryptographic detail
    /// beyond the fact of failure — timing-neutral by construction of the
    /// underlying `ring::signature::UnparsedPublicKey::verify`.
    #[error("policy signature verification failed")]
    SignatureInvalid,

    /// The signature field itself is not a valid lowercase-hex string of
    /// the expected length (128 chars for a 64-byte Ed25519 signature).
    /// Distinguished from [`Self::SignatureInvalid`] so an operator can
    /// tell "signature is malformed" from "signature does not match" —
    /// the two have different remediations.
    #[error(
        "signature field is malformed (expected 128 lowercase-hex chars for \
         a 64-byte Ed25519 signature, got {found_len} chars)"
    )]
    SignatureMalformed {
        /// Number of characters the signature field actually contains.
        found_len: usize,
    },

    /// The caller-supplied public key is not the 32 bytes an Ed25519
    /// public key requires. Distinguished from a runtime `SignatureInvalid`
    /// so callers whose key material is misconfigured see it named.
    #[error("public key must be exactly 32 bytes, got {found_len}")]
    PublicKeyMalformed {
        /// Byte length of the supplied key.
        found_len: usize,
    },

    /// An override document contains a partial version of a sub-object
    /// that [ADR-0011] declared safety-critical (present in the hardcoded
    /// [`crate::SAFETY_CRITICAL_PATHS`] list). The override is refused at
    /// parse time; the agent keeps its current effective policy.
    ///
    /// [ADR-0011]: ../../../docs/adr/0011-policy-override-granularity.md
    #[error(
        "safety-critical sub-object `{path}` in an override is incomplete: \
         missing field(s) {missing:?}. A safety-critical sub-object must be \
         supplied in full or omitted entirely — partial override is refused \
         to prevent silent disabling of the omitted fields."
    )]
    SafetyCriticalPartial {
        /// Dot-path of the offending sub-object (e.g.
        /// `sensors.windows_eventlog.redaction`).
        path: String,
        /// The subset of fields the schema declares that the override
        /// omits.
        missing: Vec<String>,
    },

    /// The `signature` field contains anything other than lowercase-hex
    /// (spaces, uppercase, non-hex characters). Distinguished from
    /// [`Self::SignatureMalformed`] because the length is right but the
    /// alphabet is wrong.
    #[error("signature field contains non-hex characters (expected [0-9a-f])")]
    SignatureNotHex,
}
