//! Loading the signing key: a file holding the 32-byte Ed25519 seed as 64 hex
//! characters (`openssl rand -hex 32 > release.key`).
//!
//! The tool never generates, stores or transports a key; where the production key
//! lives and who may use it is ADR-0015's open question, not this tool's. It refuses the
//! obvious mistake of a key file other users can read, and, per ADR-0027, a key file that does
//! not hold one of the public test keys: a key that can be read from a file is not a production
//! key, so the file path signs the test set and nothing else (production signs from a PKCS#11
//! token).

use std::path::Path;

use anyhow::Context as _;
use ring::signature::Ed25519KeyPair;
use updater::hash::hex_decode;

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
            anyhow::bail!(
                "{} is readable by group or others (mode {:o}); run `chmod 600` on it",
                path.display(),
                mode & 0o777
            );
        }
    }
    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let key = parse_seed(&text)?;
    ensure_test_key(&key, path)?;
    Ok(key)
}

/// ADR-0027 decision 2: `--key-file` stays reserved to the public test keys. Anything else is a
/// key that sat in a file, which is what custody exists to prevent, and a lab that wants a
/// throwaway key of its own generates it on a `SoftHSM` token and signs with `--pkcs11`.
#[cfg(feature = "test-key")]
fn ensure_test_key(key: &Ed25519KeyPair, path: &Path) -> anyhow::Result<()> {
    use ring::signature::KeyPair as _;
    let public = key.public_key().as_ref();
    let is_test_key = [
        updater::key::test_key_pair(),
        updater::key::test_recovery_key_pair(),
        updater::key::test_snapshot_key_pair(),
    ]
    .iter()
    .any(|test| test.public_key().as_ref() == public);
    anyhow::ensure!(
        is_test_key,
        "{} does not hold one of the public test keys: --key-file is reserved to them \
         (ADR-0027); sign from a PKCS#11 token with --pkcs11 (a SoftHSM token for a lab)",
        path.display()
    );
    Ok(())
}

/// A build without the `test-key` feature has no test key to allow: no key file at all.
#[cfg(not(feature = "test-key"))]
fn ensure_test_key(_key: &Ed25519KeyPair, path: &Path) -> anyhow::Result<()> {
    anyhow::bail!(
        "{}: this build has no test key, so --key-file is not accepted (ADR-0027); sign from a \
         PKCS#11 token with --pkcs11",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = "4242424242424242424242424242424242424242424242424242424242424242";

    #[test]
    fn a_seed_with_surrounding_whitespace_parses_to_the_matching_public_key() {
        let key = parse_seed(&format!("  {SEED}\n")).unwrap();
        assert_eq!(
            crate::signer::public_key_hex(&crate::signer::FileKey::new(key)),
            updater::hash::hex_encode(
                updater::key::RELEASE_PUBLIC_KEY
                    .as_ref()
                    .expect("the test set is embedded in tests")
                    .as_slice()
            )
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

    #[cfg(all(unix, feature = "test-key"))]
    #[test]
    fn a_key_file_holds_a_public_test_key_or_it_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        let write = |seed: &str| {
            std::fs::write(&path, seed).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        // The release/content, recovery and snapshot test seeds.
        for byte in ["42", "43", "44"] {
            write(&byte.repeat(32));
            assert!(load(&path).is_ok(), "test seed {byte}");
        }
        // Any other seed is a key that sat in a file.
        for byte in ["07", "41", "ff"] {
            write(&byte.repeat(32));
            let err = load(&path).unwrap_err().to_string();
            assert!(err.contains("reserved to them"), "{err}");
            assert!(err.contains("--pkcs11"), "{err}");
        }
    }
}
