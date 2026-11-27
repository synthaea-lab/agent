//! Streaming SHA-256 of a file or reader.
//!
//! One implementation for every crate that hashes a file: the updater checking a staged
//! release, `tamper` checking the installed binaries, the watchdog pinning the agent it
//! starts, `enrich` hashing an executed image, `response` hashing what it quarantines.
//! They sit in tiers that may not depend on each other, so each had its own copy of the
//! same read loop; this crate depends on no workspace crate, and any of them may use it.

use std::{
    fmt::Write as _,
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

use sha2::{Digest, Sha256};

/// A SHA-256 digest.
pub type Sha256Digest = [u8; 32];

/// Copies `from` to `to` and returns the SHA-256 of exactly the bytes copied.
///
/// # Errors
///
/// Propagates the first I/O error reading `from` or writing `to`.
pub fn sha256_copy(from: &mut impl Read, to: &mut impl Write) -> io::Result<Sha256Digest> {
    let mut hasher = Sha256::new();
    // `sha2` 0.11 dropped `impl Write for Sha256`, so `io::copy` into the hasher is gone:
    // read into a buffer and feed `Digest::update` by hand.
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = from.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        to.write_all(&buf[..n])?;
    }
    Ok(hasher.finalize().into())
}

/// The SHA-256 of everything `reader` yields until its end.
///
/// # Errors
///
/// Propagates the first I/O error reading `reader`.
pub fn sha256_reader(reader: &mut impl Read) -> io::Result<Sha256Digest> {
    sha256_copy(reader, &mut io::sink())
}

/// The SHA-256 of a file's full contents.
///
/// # Errors
///
/// Propagates any I/O error opening or reading `path`.
pub fn sha256_file(path: &Path) -> io::Result<Sha256Digest> {
    sha256_reader(&mut File::open(path)?)
}

/// Lowercase hexadecimal, two characters per byte: the form digests take in manifests,
/// events and file names.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a `String` cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    /// SHA-256 of the empty input, and of "abc" (FIPS 180-4 test vectors).
    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn a_reader_hashes_to_the_published_test_vectors() {
        assert_eq!(hex(&sha256_reader(&mut Cursor::new(b"")).unwrap()), EMPTY);
        assert_eq!(hex(&sha256_reader(&mut Cursor::new(b"abc")).unwrap()), ABC);
    }

    #[test]
    fn input_longer_than_the_buffer_hashes_like_one_piece() {
        let data = vec![0x5a_u8; 64 * 1024 * 3 + 17];
        let expected: Sha256Digest = Sha256::digest(&data).into();
        assert_eq!(sha256_reader(&mut Cursor::new(&data)).unwrap(), expected);
    }

    #[test]
    fn a_copy_writes_every_byte_it_hashed() {
        let data = vec![7_u8; 100_000];
        let mut copied = Vec::new();
        let digest = sha256_copy(&mut Cursor::new(&data), &mut copied).unwrap();
        assert_eq!(copied, data);
        assert_eq!(digest, sha256_reader(&mut Cursor::new(&data)).unwrap());
    }

    #[test]
    fn a_file_hashes_like_its_bytes() {
        let path = std::env::temp_dir().join(format!("file-hash-test-{}", std::process::id()));
        std::fs::write(&path, b"abc").unwrap();
        let digest = sha256_file(&path);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(hex(&digest.unwrap()), ABC);
    }

    #[test]
    fn a_missing_file_is_an_error() {
        let missing = std::env::temp_dir().join("file-hash-test-no-such-file");
        assert!(sha256_file(&missing).is_err());
    }

    #[test]
    fn hex_is_lowercase_and_zero_padded() {
        assert_eq!(hex(&[0x00, 0x0f, 0xab, 0xff]), "000fabff");
    }
}
