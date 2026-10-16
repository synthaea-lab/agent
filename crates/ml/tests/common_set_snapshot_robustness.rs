//! Never-panic suite for the common-set snapshot reader (CLAUDE.md: byte parsers get one). The
//! snapshot arrives signed through the content manifest, but a reader that panics on a bad file
//! turns a corrupt download into a crashed agent, so every input here must return a value:
//! `Ok` or `Err`, never a panic and never an allocation sized by an untrusted header field.

use ml::features::{common_set::CommonSetSnapshot, rarity::CommonSet};
use serde_json::Value;

const GOLDEN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../ml/tests/fixtures/common_set_snapshot_golden.json"
));

fn reference_blobs() -> Vec<Vec<u8>> {
    let doc: Value = serde_json::from_str(GOLDEN).expect("fixture parses");
    doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            let hex = c["bytes_hex"].as_str().unwrap();
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect()
        })
        .collect()
}

/// Parses, and when that works, queries too: a parse that succeeds must also be safe to use.
fn exercise(bytes: &[u8]) {
    if let Ok(snapshot) = CommonSetSnapshot::parse(bytes) {
        let _ = snapshot.contains(&"ab".repeat(32));
        let _ = snapshot.contains("");
        let _ = snapshot.hosts_covered();
    }
}

#[test]
fn every_prefix_of_a_valid_snapshot() {
    for blob in reference_blobs() {
        for len in 0..=blob.len() {
            exercise(&blob[..len]);
        }
    }
}

#[test]
fn every_single_byte_changed_in_a_valid_snapshot() {
    for blob in reference_blobs().iter().take(3) {
        for i in 0..blob.len() {
            for value in [0x00, 0x01, 0x7f, 0x80, 0xff] {
                let mut mutated = blob.clone();
                mutated[i] = value;
                exercise(&mutated);
            }
        }
    }
}

#[test]
fn a_header_claiming_a_huge_filter_over_a_tiny_body_is_refused_without_allocating() {
    let mut header = reference_blobs()[0][..32].to_vec();
    header[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(CommonSetSnapshot::parse(&header).is_err());
    header[20..24].copy_from_slice(&0xffff_fff8_u32.to_le_bytes());
    assert!(CommonSetSnapshot::parse(&header).is_err());
}

#[test]
fn pseudo_random_bytes_of_every_small_length() {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for len in 0..300 {
        for _ in 0..40 {
            let mut bytes: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
            // Half of them start like a real snapshot so the field checks are reached.
            if len >= 8 && next() % 2 == 0 {
                bytes[..4].copy_from_slice(b"SYCS");
                bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
            }
            exercise(&bytes);
        }
    }
}
