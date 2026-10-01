//! Loading the signing key: a file holding the 32-byte Ed25519 seed as 64 hex
//! characters (`openssl rand -hex 32 > release.key`).
//!
//! The tool never generates, stores or transports a key; where the production key
//! lives and who may use it is ADR-0015's open question, not this tool's. It only
//! refuses the obvious mistake of a key file other users can read.

use std::path::Path;

use anyhow::{Context as _, bail};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use updater::hash::{hex_decode, hex_encode};

/// Parses a seed file's text: 64 hex characters, surrounding whitespace ignored.
pub(crate) fn parse_seed(text: &str) -> anyhow::Result<Ed25519KeyPair> {
    let seed = hex_decode(text.trim())
        .filter(|bytes| bytes.len() == 32)
        .context("the key file must hold exactly 64 hex characters (a 32-byte Ed25519 seed)")?;
    Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|e| anyhow::anyhow!("invalid seed: {e}"))
}

/// Loads the key pair from `path`.
///
/// # Errors
///
/// The file is unreadable, is readable by group or others (Unix), or does not hold
/// a 32-byte hex seed.
pub(crate) fn load(path: &Path) -> anyhow::Result<Ed25519KeyPair> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path)
            .with_context(|| format!("cannot read {}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            bail!(
                "{} is readable by group or others (mode {:o}); run `chmod 600` on it",
                path.display(),
                mode & 0o777
            );
        }
    }
    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    parse_seed(&text)
}

/// The public half as lowercase hex, the form to embed in `updater::key`.
pub(crate) fn public_key_hex(key_pair: &Ed25519KeyPair) -> String {
    hex_encode(key_pair.public_key().as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = "4242424242424242424242424242424242424242424242424242424242424242";

    #[test]
    fn a_seed_with_surrounding_whitespace_parses_to_the_matching_public_key() {
        let key = parse_seed(&format!("  {SEED}\n")).unwrap();
        assert_eq!(
            public_key_hex(&key),
            hex_encode(updater::key::UPDATER_PUBLIC_KEY.as_slice())
        );
    }

    #[test]
    fn a_seed_of_the_wrong_length_or_not_hex_is_refused() {
        for text in [
            "",
            "42",
            &SEED[..62],
            &format!("{SEED}00"),
            &"zz".repeat(32),
        ] {
            assert!(parse_seed(text).is_err(), "{text:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_key_file_other_users_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("release.key");
        std::fs::write(&path, SEED).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load(&path).unwrap_err().to_string();
        assert!(err.contains("readable by group or others"), "{err}");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load(&path).is_ok());
    }
}
