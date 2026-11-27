//! The sidecar that records where a quarantined file came from.

use super::invalid;
use std::path::{Path, PathBuf};

/// A NUL-prefixed header cannot be a legacy path because Unix paths and Windows paths cannot
/// contain NUL. The four-byte mode uses `u32::MAX` when no Unix mode was recorded.
pub(super) const ORIGIN_RECORD_MAGIC: &[u8] = b"\0synthaea-origin-v1\0";

pub(super) struct OriginRecord {
    pub(super) original: PathBuf,
    #[cfg(unix)]
    pub(super) mode: Option<u32>,
}

pub(super) fn encode_origin_record(original: &Path, mode: Option<u32>) -> Vec<u8> {
    let mut record = Vec::with_capacity(ORIGIN_RECORD_MAGIC.len() + 4 + original.as_os_str().len());
    record.extend_from_slice(ORIGIN_RECORD_MAGIC);
    record.extend_from_slice(&mode.unwrap_or(u32::MAX).to_le_bytes());
    record.extend_from_slice(original.to_string_lossy().as_bytes());
    record
}

pub(super) fn decode_origin_record(bytes: &[u8]) -> std::io::Result<OriginRecord> {
    let (path, mode) = if let Some(encoded) = bytes.strip_prefix(ORIGIN_RECORD_MAGIC) {
        let mode_bytes: [u8; 4] = encoded
            .get(..4)
            .ok_or_else(|| invalid("truncated quarantine origin record"))?
            .try_into()
            .map_err(|_| invalid("truncated quarantine origin record"))?;
        let raw_mode = u32::from_le_bytes(mode_bytes);
        let mode = if raw_mode == u32::MAX {
            None
        } else if raw_mode & !0o7777 == 0 {
            Some(raw_mode)
        } else {
            return Err(invalid("invalid mode in quarantine origin record"));
        };
        (&encoded[4..], mode)
    } else {
        // Compatibility with the original sidecar format: the complete contents were a path.
        (bytes, None)
    };
    let path = String::from_utf8(path.to_vec())
        .map_err(|_| invalid("quarantine origin path is not valid UTF-8"))?;
    if path.is_empty() {
        return Err(invalid("quarantine origin path is empty"));
    }
    #[cfg(not(unix))]
    let _ = mode;
    Ok(OriginRecord {
        original: PathBuf::from(path),
        #[cfg(unix)]
        mode,
    })
}

#[cfg(test)]
pub(super) fn origin_sidecar_path(quarantine_dir: &Path, sha256_hex: &str) -> PathBuf {
    quarantine_dir.join(format!("{sha256_hex}.origin"))
}
