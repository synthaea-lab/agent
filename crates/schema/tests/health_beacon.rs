//! The health beacon's wire shape beyond what the transport test pins (ADR-0020, issue #76):
//! the rarity counters are additive, so a beacon from an agent that predates them still parses.

use schema::HealthBeacon;

fn beacon_json(extra: &str) -> String {
    format!(
        r#"{{"timestamp_ns":1790756620574604200,"agent_version":"0.1.0","sensors":[],
        "spool_bytes":1024,"spool_dropped":0,"enrich_dropped":3{extra}}}"#
    )
}

#[test]
fn a_beacon_from_an_agent_without_the_rarity_counters_parses_with_zeros() {
    let beacon: HealthBeacon = serde_json::from_str(&beacon_json("")).unwrap();
    assert_eq!(
        (
            beacon.rarity_applied,
            beacon.rarity_withheld,
            beacon.rarity_unapplied
        ),
        (0, 0, 0)
    );
    assert_eq!(beacon.enrich_dropped, 3);
}

#[test]
fn the_rarity_counters_round_trip() {
    let beacon: HealthBeacon = serde_json::from_str(&beacon_json(
        r#","rarity_applied":7,"rarity_withheld":11,"rarity_unapplied":2"#,
    ))
    .unwrap();
    assert_eq!(
        (
            beacon.rarity_applied,
            beacon.rarity_withheld,
            beacon.rarity_unapplied
        ),
        (7, 11, 2)
    );
    let back: HealthBeacon =
        serde_json::from_str(&serde_json::to_string(&beacon).unwrap()).unwrap();
    assert_eq!(back, beacon);
}
