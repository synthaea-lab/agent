//! Backward-compatibility check for the `SCHEMA_VERSION` 1 → 2 bump (#94,
//! [`Event::Auth`]): the frozen fixtures under `tests/fixtures/v1/` must still
//! deserialize successfully under the *current* types. Unlike `tests/golden.rs`,
//! this does not assert equality against hand-built values or round-trip the
//! result — it only proves that data written by the old schema version is not
//! rejected by readers running the new one (a new enum variant is additive:
//! `Event` is `#[non_exhaustive]`, and no existing field changed shape).
//!
//! `tests/fixtures/v1/*.json` are never edited (see `schema` crate docs) —
//! `tests/fixtures/v2/` holds the current snapshot instead, exercised by
//! `tests/golden.rs`.

use schema::{Event, detection::Detection};

fn v1_fixture(name: &str) -> String {
    let path = format!(
        "{}/tests/fixtures/v1/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&path).expect(&path)
}

#[test]
fn v1_events_still_deserialize() {
    for name in [
        "exec",
        "exec_windows",
        "exec_lineage",
        "exec_enriched",
        "connect",
        "file_open",
    ] {
        let raw = v1_fixture(name);
        let result: Result<Event, _> = serde_json::from_str(&raw);
        assert!(
            result.is_ok(),
            "v1 fixture {name} no longer deserializes as Event: {:?}",
            result.err()
        );
    }
}

#[test]
fn v1_detection_still_deserializes() {
    let raw = v1_fixture("detection_ml");
    let result: Result<Detection, _> = serde_json::from_str(&raw);
    assert!(
        result.is_ok(),
        "v1 fixture detection_ml no longer deserializes as Detection: {:?}",
        result.err()
    );
}
