//! Who signs. A [`Signer`] holds a key that can sign the canonical bytes of a manifest and
//! name its public half; the tool never needs the private half itself, which is what lets the
//! production key live on a token (ADR-0027 decision 2, [`crate::pkcs11`]).
//!
//! [`FileKey`] is the other implementation: the 32-byte seed in a file, for the public test key
//! and for lab releases.

use anyhow::Context as _;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};
use updater::hash::hex_encode;

/// An Ed25519 signing key whose private half may be out of reach.
pub(crate) trait Signer {
    /// The 32-byte public key.
    fn public_key(&self) -> Vec<u8>;

    /// The 64-byte Ed25519 signature of `message`.
    ///
    /// # Errors
    ///
    /// The key could not sign (a token refused, was removed, ...).
    fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>>;
}

/// The public half as lowercase hex, the form to embed in `updater::key`.
pub(crate) fn public_key_hex(signer: &dyn Signer) -> String {
    hex_encode(&signer.public_key())
}

/// Signs `message` and checks the signature against the signer's own public key before it is
/// used: a token that answers with the wrong length, the wrong key or garbage must not end up
/// in a manifest that looks signed.
///
/// # Errors
///
/// The signer failed, or its signature does not verify under its public key.
pub(crate) fn sign_checked(signer: &dyn Signer, message: &[u8]) -> anyhow::Result<Vec<u8>> {
    let signature = signer.sign(message)?;
    UnparsedPublicKey::new(&ED25519, signer.public_key())
        .verify(message, &signature)
        .map_err(|_| {
            anyhow::anyhow!("the signature does not verify under the signing key's own public key")
        })
        .context("refusing to use it")?;
    Ok(signature)
}

/// A key held in memory: from a seed file or the test key.
pub(crate) struct FileKey(Ed25519KeyPair);

impl FileKey {
    pub(crate) fn new(key_pair: Ed25519KeyPair) -> Self {
        Self(key_pair)
    }
}

impl Signer for FileKey {
    fn public_key(&self) -> Vec<u8> {
        self.0.public_key().as_ref().to_vec()
    }

    fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(self.0.sign(message).as_ref().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A signer that answers with whatever it was given: the shape of a faulty token.
    struct Fixed {
        public: Vec<u8>,
        signature: Vec<u8>,
    }

    impl Signer for Fixed {
        fn public_key(&self) -> Vec<u8> {
            self.public.clone()
        }
        fn sign(&self, _message: &[u8]) -> anyhow::Result<Vec<u8>> {
            Ok(self.signature.clone())
        }
    }

    fn key(seed: u8) -> FileKey {
        FileKey::new(Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap())
    }

    #[test]
    fn a_file_key_signs_and_its_signature_checks() {
        let signer = key(7);
        let signature = sign_checked(&signer, b"message").unwrap();
        assert_eq!(signature.len(), 64);
        assert_eq!(public_key_hex(&signer).len(), 64);
    }

    #[test]
    fn a_signature_from_another_key_is_refused() {
        let signer = Fixed {
            public: key(7).public_key(),
            signature: key(8).sign(b"message").unwrap(),
        };
        assert!(sign_checked(&signer, b"message").is_err());
    }

    #[test]
    fn a_short_or_empty_signature_is_refused() {
        for signature in [vec![], vec![0; 63], vec![0; 64]] {
            let signer = Fixed {
                public: key(7).public_key(),
                signature,
            };
            assert!(sign_checked(&signer, b"message").is_err());
        }
    }
}
