//! Cross-language golden test for the common-set snapshot wire format (ADR-0020, #76).
//!
//! Consumes `ml/tests/fixtures/common_set_snapshot_golden.json`, written by
//! `ml/tests/fixtures/gen_common_set_snapshot_golden.py` from the spec in
//! `docs/detection/common-set-snapshot-format.md`. The TypeScript writer
//! (`server/tests/unit/common-set-snapshot.test.ts`) must produce these exact bytes; this reader
//! must parse them and answer membership the same way.
//!
//! If this breaks, the reader has drifted from the format the server writes: the agent would
//! read a snapshot as different from what was published. Fix the divergence, or, if the format
//! changed on purpose, bump `format_version` and regenerate the file.

use ml::features::{
    common_set::{CommonSetSnapshot, SnapshotError},
    rarity::CommonSet,
};
use serde_json::Value;

const GOLDEN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../ml/tests/fixtures/common_set_snapshot_golden.json"
));

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("fixture hex"))
        .collect()
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .expect("array")
        .iter()
        .map(|x| x.as_str().expect("string").to_owned())
        .collect()
}

fn cases() -> Vec<Value> {
    let doc: Value = serde_json::from_str(GOLDEN).expect("fixture parses");
    doc["cases"].as_array().expect("cases").clone()
}

#[test]
fn reads_the_header_the_reference_writer_wrote() {
    for case in cases() {
        let params = &case["params"];
        let snapshot = CommonSetSnapshot::parse(&unhex(case["bytes_hex"].as_str().unwrap()))
            .unwrap_or_else(|e| panic!("{}: {e}", case["name"]));
        let header = snapshot.header();
        assert_eq!(header.format_version, 1, "{}", case["name"]);
        assert_eq!(
            u64::from(header.min_hosts),
            params["min_hosts"].as_u64().unwrap()
        );
        assert_eq!(
            snapshot.hosts_covered(),
            params["hosts_covered"].as_u64().unwrap()
        );
        assert_eq!(header.built_at, params["built_at"].as_u64().unwrap());
        let distinct = strings(&params["hashes"]).len() as u64;
        assert_eq!(u64::from(header.entry_count), distinct, "{}", case["name"]);
    }
}

#[test]
fn every_member_reads_as_a_member_and_pinned_non_members_do_not() {
    for case in cases() {
        let snapshot =
            CommonSetSnapshot::parse(&unhex(case["bytes_hex"].as_str().unwrap())).unwrap();
        for member in strings(&case["params"]["hashes"]) {
            assert!(
                snapshot.contains(&member),
                "{}: lost member {member}",
                case["name"]
            );
        }
        for absent in strings(&case["non_members"]) {
            assert!(!snapshot.contains(&absent), "{}: {absent}", case["name"]);
        }
    }
}

#[test]
fn a_hash_that_is_not_a_normalized_sha256_is_never_a_member() {
    let case = &cases()[2];
    let snapshot = CommonSetSnapshot::parse(&unhex(case["bytes_hex"].as_str().unwrap())).unwrap();
    let member = strings(&case["members"])[0].clone();
    assert!(snapshot.contains(&member));
    assert!(
        !snapshot.contains(&member.to_uppercase()),
        "the trait takes normalized hashes"
    );
    assert!(!snapshot.contains(&member[..63]));
    assert!(!snapshot.contains(""));
    assert!(!snapshot.contains(&format!("{member}0")));
    assert!(!snapshot.contains(&"zz".repeat(32)));
}

#[test]
fn rejects_what_it_does_not_understand() {
    let good = unhex(cases()[2]["bytes_hex"].as_str().unwrap());
    let with = |edit: &dyn Fn(&mut Vec<u8>)| {
        let mut b = good.clone();
        edit(&mut b);
        CommonSetSnapshot::parse(&b).err()
    };
    assert_eq!(with(&|b| b[0] = b'X'), Some(SnapshotError::BadMagic));
    assert_eq!(with(&|b| b[4] = 2), Some(SnapshotError::UnknownVersion(2)));
    assert_eq!(
        with(&|b| b[6] = 0),
        Some(SnapshotError::HashCountOutOfRange(0))
    );
    assert_eq!(
        with(&|b| b[6] = 17),
        Some(SnapshotError::HashCountOutOfRange(17))
    );
    assert!(matches!(
        with(&|b| b[20] += 1),
        Some(SnapshotError::BitCountOutOfRange(_))
    ));
    assert_eq!(with(&|b| b.truncate(31)), Some(SnapshotError::TooShort));
    assert_eq!(
        with(&|b| b.truncate(b.len() - 1)),
        Some(SnapshotError::LengthMismatch)
    );
    assert_eq!(with(&|b| b.push(0)), Some(SnapshotError::LengthMismatch));
}
