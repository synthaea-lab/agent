//! The signing logic the four signed documents share (#149): [`crate::manifest::ReleaseManifest`],
//! [`crate::content::ContentManifest`], [`crate::snapshot::SnapshotManifest`] and
//! [`crate::rotation::KeyRotationManifest`].
//!
//! All four sign the same way (ADR-0015 decision 2, reused by ADR-0016): the document as
//! 2-space-indented JSON with `signature` forced to `""`, fields in the alphabetical order they are
//! declared in the struct, an Ed25519 signature over those bytes, lowercase hex in `signature`. The
//! trait is crate-private: each document keeps its own public `sign`, `sign_with`,
//! `verify_signature` and `verify_signature_with`, which add what is specific to it (the
//! `schema_version` and `kind` checks, which key verifies, whether `sign` exists outside tests) and
//! call the methods here for the rest.

use ring::signature::{self, Ed25519KeyPair, UnparsedPublicKey};
use serde::Serialize;

use crate::{
    error::UpdaterError,
    hash::{hex_decode, hex_encode},
};

pub(crate) trait SignedDocument: Serialize + Clone {
    /// The lowercase-hex signature field.
    fn signature(&self) -> &str;

    /// The same field, mutably.
    fn signature_mut(&mut self) -> &mut String;

    /// Whether [`Self::verify_against`] looks for the key before it decodes the signature. It
    /// decides which refusal a document with a malformed signature and no key to verify against
    /// returns: `SignatureInvalid` (the default) or `SigningKeyUnprovisioned`. The two orders are
    /// what the documents did when each had its own copy, kept as they were.
    const KEY_BEFORE_SIGNATURE: bool = false;

    /// The bytes signed and verified: 2-space-indented JSON with `signature` forced to `""`.
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut unsigned = self.clone();
        unsigned.signature_mut().clear();
        // A signed document holds only strings, integers, options, vectors and maps with string
        // keys, which `serde_json` always serializes: the call cannot fail.
        serde_json::to_vec_pretty(&unsigned)
            .expect("a signed document has no non-serializable content")
    }

    /// Signs in place with `key_pair`, replacing whatever `signature` holds.
    fn sign_with_key_pair(&mut self, key_pair: &Ed25519KeyPair) {
        self.signature_mut().clear();
        let sig = key_pair.sign(&self.canonical_bytes());
        *self.signature_mut() = hex_encode(sig.as_ref());
    }

    /// Signs in place with `sign`, which receives the canonical bytes and returns the 64-byte
    /// signature over them: for a key that cannot leave its device. `signature` is left empty if
    /// `sign` fails.
    ///
    /// # Errors
    ///
    /// Whatever `sign` returns.
    fn sign_via<E>(&mut self, sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, E>) -> Result<(), E> {
        self.signature_mut().clear();
        let sig = sign(&self.canonical_bytes())?;
        *self.signature_mut() = hex_encode(&sig);
        Ok(())
    }

    /// Checks the Ed25519 signature over [`Self::canonical_bytes`] against `key`; `None` is a build
    /// with no key to verify against. The checks that are specific to a document come before this
    /// in its own `verify_signature_with`.
    ///
    /// # Errors
    ///
    /// [`UpdaterError::SignatureInvalid`] if the signature is malformed or does not verify,
    /// [`UpdaterError::SigningKeyUnprovisioned`] if `key` is `None`.
    fn verify_against(&self, key: Option<&[u8; 32]>) -> Result<(), UpdaterError> {
        let (sig_bytes, key) = if Self::KEY_BEFORE_SIGNATURE {
            let key = key.ok_or(UpdaterError::SigningKeyUnprovisioned)?;
            (
                hex_decode(self.signature()).ok_or(UpdaterError::SignatureInvalid)?,
                key,
            )
        } else {
            let sig_bytes = hex_decode(self.signature()).ok_or(UpdaterError::SignatureInvalid)?;
            (sig_bytes, key.ok_or(UpdaterError::SigningKeyUnprovisioned)?)
        };
        UnparsedPublicKey::new(&signature::ED25519, key.as_slice())
            .verify(&self.canonical_bytes(), &sig_bytes)
            .map_err(|_| UpdaterError::SignatureInvalid)
    }
}
