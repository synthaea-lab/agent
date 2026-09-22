//! Ed25519 signing and verification for [`crate::Policy`] documents.
//!
//! Uses `ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey}` —
//! the algorithm from ADR-0010 §3, the crate substitution from ADR-0015
//! §Decision 3 (`ring` chosen over `ed25519-dalek` because `ring` is already
//! a transitive dep via `rustls`, avoiding a second Ed25519 implementation
//! in the workspace).
//!
//! ## Scope of this module
//!
//! Two functions:
//! - [`sign`] — takes a mutable `Policy` and a keypair, writes the signature
//!   into `metadata.signature`. **Test-only in v1**: production signing
//!   happens in the (future) control plane, in a language and process this
//!   crate deliberately does not know about. Kept here so the crate's own
//!   round-trip test can exercise both sides without inventing a mock.
//! - [`verify`] — takes a `Policy` and a public key, returns `Ok(())` iff
//!   the signature matches the canonical form of the document. **The
//!   production path** — every agent boot and every policy update ends here.
//!
//! ## What this module does NOT do
//!
//! - Key management. Where the public key comes from (compiled-in constant?
//!   file on disk? env variable?), how it rotates, how a compromised key is
//!   revoked — all deferred by ADR-0010's own Deferred section. This crate
//!   is the verification mechanism; the caller supplies the key.
//! - Key generation. `ring` can generate keypairs; that lives in whatever
//!   test binary needs a keypair (see the `#[cfg(test)]` helper below).

use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
// `KeyPair` is only referenced by the test-only helper below; scoped
// accordingly to keep it out of the production build's imports.
#[cfg(test)]
use ring::signature::KeyPair;

use crate::canonical::to_canonical_bytes;
use crate::document::Policy;
use crate::error::PolicyError;

/// Length of an Ed25519 signature in bytes.
pub const SIGNATURE_LEN_BYTES: usize = 64;

/// Length of an Ed25519 public key in bytes.
pub const PUBLIC_KEY_LEN_BYTES: usize = 32;

/// Sign `policy` in place: writes `metadata.signature` as the lowercase-hex
/// encoding of the Ed25519 signature over its canonical form. Test-only in
/// v1 — production signing happens in the control plane, not in this crate.
///
/// # Errors
///
/// Only fails if canonicalization itself fails, which for the concrete
/// [`Policy`] type is unreachable (all fields are serde-supported).
pub fn sign(policy: &mut Policy, keypair: &Ed25519KeyPair) -> Result<(), PolicyError> {
    let bytes = to_canonical_bytes(policy)?;
    let sig = keypair.sign(&bytes);
    policy.metadata.signature = hex_lowercase(sig.as_ref());
    Ok(())
}

/// Verify `policy.metadata.signature` against the caller-supplied Ed25519
/// public key. `public_key` must be exactly 32 bytes; the signature field
/// must be exactly 128 lowercase-hex characters.
///
/// The production entry point. See the module doc for what this crate does
/// and does not own on the way to a verified policy.
///
/// # Errors
///
/// - [`PolicyError::PublicKeyMalformed`] — `public_key` is not 32 bytes.
/// - [`PolicyError::SignatureMalformed`] — `signature` field is not 128
///   chars.
/// - [`PolicyError::SignatureNotHex`] — `signature` field contains
///   non-hex characters.
/// - [`PolicyError::SignatureInvalid`] — the signature does not match the
///   canonical form of the document under `public_key`. Timing-neutral by
///   construction of the underlying `ring` verify.
pub fn verify(policy: &Policy, public_key: &[u8]) -> Result<(), PolicyError> {
    if public_key.len() != PUBLIC_KEY_LEN_BYTES {
        return Err(PolicyError::PublicKeyMalformed {
            found_len: public_key.len(),
        });
    }

    let sig_hex = &policy.metadata.signature;
    let expected_hex_len = SIGNATURE_LEN_BYTES * 2;
    if sig_hex.len() != expected_hex_len {
        return Err(PolicyError::SignatureMalformed {
            found_len: sig_hex.len(),
        });
    }
    let sig_bytes = decode_hex_lowercase(sig_hex).ok_or(PolicyError::SignatureNotHex)?;

    let canonical = to_canonical_bytes(policy)?;

    // `ring::signature::UnparsedPublicKey::verify` is timing-neutral —
    // no early-exit based on where the signature diverges. That property
    // is what we get from `ring`, not something this wrapper adds.
    let pubkey = UnparsedPublicKey::new(&ED25519, public_key);
    pubkey
        .verify(&canonical, &sig_bytes)
        .map_err(|_| PolicyError::SignatureInvalid)
}

/// Encode `bytes` as a lowercase-hex string. Length of the output is
/// exactly `2 * bytes.len()`.
fn hex_lowercase(bytes: &[u8]) -> String {
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_LOWER[(b >> 4) as usize] as char);
        s.push(HEX_LOWER[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode a lowercase-hex string of even length. Returns `None` if any
/// character is not in `[0-9a-f]`. Rejects uppercase — the format contract
/// is lowercase, and accepting both would let two different valid
/// serializations of "the same" signature disagree at the byte level.
fn decode_hex_lowercase(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = from_hex_nibble(pair[0])?;
        let lo = from_hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn from_hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(10 + c - b'a'),
        _ => None,
    }
}

/// Test-only helper: generates a fresh Ed25519 keypair for round-trip tests
/// AND returns its public key bytes. Kept here (behind `#[cfg(test)]`) so
/// every downstream test that wants a signed document has one call site,
/// not its own copy of the ring boilerplate.
#[cfg(test)]
pub(crate) fn test_keypair() -> (Ed25519KeyPair, Vec<u8>) {
    use ring::rand::SystemRandom;
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate_pkcs8");
    let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("from_pkcs8");
    let public_key = keypair.public_key().as_ref().to_vec();
    (keypair, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::{PolicyMetadata, PolicyPayload, SCHEMA_VERSION};

    fn empty_doc() -> Policy {
        Policy {
            metadata: PolicyMetadata {
                schema_version: SCHEMA_VERSION,
                policy_version: 1,
                issued_at_ns: 0,
                signature: String::new(),
            },
            payload: PolicyPayload::default(),
        }
    }

    #[test]
    fn sign_then_verify_succeeds() {
        let (kp, pk) = test_keypair();
        let mut doc = empty_doc();
        sign(&mut doc, &kp).unwrap();
        assert_eq!(doc.metadata.signature.len(), SIGNATURE_LEN_BYTES * 2);
        verify(&doc, &pk).unwrap();
    }

    #[test]
    fn signature_survives_serde_round_trip() {
        // Sign, serialize to JSON, parse back — signature must still
        // verify. This is the actual production shape (control plane
        // signs and serializes; agent parses and verifies).
        let (kp, pk) = test_keypair();
        let mut doc = empty_doc();
        sign(&mut doc, &kp).unwrap();
        let json = serde_json::to_string(&doc).unwrap();
        let parsed: Policy = serde_json::from_str(&json).unwrap();
        verify(&parsed, &pk).unwrap();
    }

    #[test]
    fn tamper_in_payload_breaks_verification() {
        let (kp, pk) = test_keypair();
        let mut doc = empty_doc();
        sign(&mut doc, &kp).unwrap();
        // Change policy_version — anything covered by the canonical bytes
        // must invalidate the signature.
        doc.metadata.policy_version = 999;
        assert!(matches!(
            verify(&doc, &pk),
            Err(PolicyError::SignatureInvalid)
        ));
    }

    #[test]
    fn wrong_public_key_breaks_verification() {
        let (kp, _pk) = test_keypair();
        let (_kp2, other_pk) = test_keypair();
        let mut doc = empty_doc();
        sign(&mut doc, &kp).unwrap();
        assert!(matches!(
            verify(&doc, &other_pk),
            Err(PolicyError::SignatureInvalid)
        ));
    }

    #[test]
    fn malformed_signature_length_is_reported_as_such() {
        let (_kp, pk) = test_keypair();
        let mut doc = empty_doc();
        doc.metadata.signature = "abc".to_string(); // 3 chars, way too short
        match verify(&doc, &pk) {
            Err(PolicyError::SignatureMalformed { found_len }) => {
                assert_eq!(found_len, 3);
            }
            other => panic!("expected SignatureMalformed, got {other:?}"),
        }
    }

    #[test]
    fn uppercase_signature_is_rejected() {
        let (_kp, pk) = test_keypair();
        let mut doc = empty_doc();
        // 128 chars, but uppercase — format contract is lowercase.
        doc.metadata.signature = "F".repeat(128);
        assert!(matches!(verify(&doc, &pk), Err(PolicyError::SignatureNotHex)));
    }

    #[test]
    fn malformed_public_key_is_reported_as_such() {
        let mut doc = empty_doc();
        doc.metadata.signature = "0".repeat(128);
        // Only 16 bytes instead of 32.
        let short_pk = vec![0u8; 16];
        match verify(&doc, &short_pk) {
            Err(PolicyError::PublicKeyMalformed { found_len }) => {
                assert_eq!(found_len, 16);
            }
            other => panic!("expected PublicKeyMalformed, got {other:?}"),
        }
    }

    #[test]
    fn hex_round_trip() {
        let bytes = [0x00u8, 0x01, 0x7f, 0xff, 0xab, 0xcd];
        let s = hex_lowercase(&bytes);
        assert_eq!(s, "00017fffabcd");
        assert_eq!(decode_hex_lowercase(&s).unwrap(), bytes);
    }
}
