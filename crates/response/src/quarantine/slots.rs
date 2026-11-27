//! How quarantined files are named: a SHA-256 and a slot number.

use std::path::{Path, PathBuf};

use super::invalid;

pub(super) fn slot_stem(sha256_hex: &str, slot: u64) -> String {
    if slot == 0 {
        sha256_hex.to_owned()
    } else {
        format!("{sha256_hex}.{slot}")
    }
}

pub(super) fn quarantine_slots(
    quarantine_dir: &Path,
    sha256_hex: &str,
) -> std::io::Result<Vec<(PathBuf, PathBuf)>> {
    let mut slots = Vec::new();
    for entry in std::fs::read_dir(quarantine_dir)? {
        let path = entry?.path();
        let Some((digest, slot)) = sidecar_slot(&path) else {
            continue;
        };
        if digest == sha256_hex {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_suffix(".origin"))
                .ok_or_else(|| invalid("invalid quarantine sidecar name"))?;
            slots.push((slot, quarantine_dir.join(name), path));
        }
    }
    slots.sort_by_key(|(slot, _, _)| *slot);
    Ok(slots
        .into_iter()
        .map(|(_, stored, sidecar)| (stored, sidecar))
        .collect())
}

pub(super) fn sidecar_slot(path: &Path) -> Option<(String, u64)> {
    let stem = path.file_name()?.to_str()?.strip_suffix(".origin")?;
    parse_slot_stem(stem)
}

pub(super) fn payload_slot(path: &Path) -> Option<(String, u64)> {
    let stem = path.file_name()?.to_str()?;
    parse_slot_stem(stem)
}

pub(super) fn parse_slot_stem(stem: &str) -> Option<(String, u64)> {
    if let Some((digest, suffix)) = stem.split_once('.') {
        let slot = suffix.parse::<u64>().ok()?;
        return (slot > 0 && suffix == slot.to_string() && is_sha256_hex(digest))
            .then(|| (digest.to_owned(), slot));
    }
    is_sha256_hex(stem).then(|| (stem.to_owned(), 0))
}

pub(super) fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
