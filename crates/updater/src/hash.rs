//! SHA-256 hashing shared by manifest verification and staged-file checking.
//!
//! Deliberately independent of `tamper::integrity`'s equivalent (`hash_file`) even
//! though the logic is similar — `updater` and `tamper` are both leaf crates and
//! may not depend on each other (`tools/check-deps.py`); the `agent` binary is
//! where their outputs meet.

use std::{fs::File, io::Read as _, path::Path};

use sha2::{Digest, Sha256};

/// Streaming SHA-256 of a file's full contents, lowercase hex.
///
/// # Errors
///
/// Propagates any [`std::io::Error`] opening or reading `path`.
pub fn hash_file(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_encode(&hasher.finalize()))
}

/// Lowercase-hex encoding, used for both file hashes and the manifest signature.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Decodes a lowercase- or uppercase-hex string. `None` on odd length or a
/// non-hex-digit character.
#[must_use]
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let bytes = [0x00, 0x0f, 0xab, 0xff];
        let encoded = hex_encode(&bytes);
        assert_eq!(encoded, "000fabff");
        assert_eq!(hex_decode(&encoded).unwrap(), bytes);
    }

    #[test]
    fn hex_decode_rejects_odd_length() {
        assert!(hex_decode("abc").is_none());
    }

    #[test]
    fn hex_decode_rejects_non_hex() {
        assert!(hex_decode("zz").is_none());
    }

    #[test]
    fn hash_file_matches_independently_computed_sha256() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.bin");
        std::fs::write(&path, b"hello updater").unwrap();

        let mut hasher = Sha256::new();
        hasher.update(b"hello updater");
        let expected = hex_encode(&hasher.finalize());

        assert_eq!(hash_file(&path).unwrap(), expected);
    }

    #[test]
    fn hash_file_detects_content_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.bin");
        std::fs::write(&path, b"original").unwrap();
        let original_hash = hash_file(&path).unwrap();

        std::fs::write(&path, b"tampered").unwrap();
        assert_ne!(hash_file(&path).unwrap(), original_hash);
    }
}
