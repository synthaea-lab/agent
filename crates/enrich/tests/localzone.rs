//! The platform's zone conversion at fixed instants either side of a daylight-saving change
//! (#1088). Unix only: Windows reads the machine's zone setting, which a test cannot change.
//!
//! One test in this binary, on purpose: it sets `TZ`, which is process-wide, so a second test
//! running beside it would race. POSIX `TZ` rules are used instead of zoneinfo names so the
//! result does not depend on the host's tzdata.
#![cfg(unix)]

use enrich::localzone::{configured, utc_offset_minutes_at};

// 2026 transitions. Europe (CET/CEST): UTC 01:00 on 29 March and on 25 October.
// US Eastern: 07:00 UTC on 8 March (02:00 local), 06:00 UTC on 1 November.
const EU_SPRING: i64 = 1_774_746_000;
const EU_AUTUMN: i64 = 1_792_890_000;
const US_SPRING: i64 = 1_772_953_200;

fn set_tz(rule: &str) {
    // SAFETY: the only test in this binary, so nothing reads or writes the environment
    // concurrently.
    unsafe { std::env::set_var("TZ", rule) };
}

#[test]
fn the_offset_follows_the_zones_daylight_saving_rules_at_each_instant() {
    set_tz("CET-1CEST,M3.5.0,M10.5.0/3");
    assert!(configured());
    assert_eq!(
        utc_offset_minutes_at(EU_SPRING - 1),
        Some(60),
        "last second of winter time"
    );
    assert_eq!(
        utc_offset_minutes_at(EU_SPRING),
        Some(120),
        "first second of summer time"
    );
    assert_eq!(
        utc_offset_minutes_at(EU_AUTUMN - 1),
        Some(120),
        "last second of summer time"
    );
    assert_eq!(
        utc_offset_minutes_at(EU_AUTUMN),
        Some(60),
        "first second of winter time"
    );
    // A past instant is judged by that instant's rules, not today's.
    assert_eq!(utc_offset_minutes_at(0), Some(60));

    // The platform is re-read on every call: the zone changes under a running agent.
    set_tz("EST5EDT,M3.2.0,M11.1.0");
    assert_eq!(utc_offset_minutes_at(US_SPRING - 1), Some(-300));
    assert_eq!(utc_offset_minutes_at(US_SPRING), Some(-240));

    // A zone with no daylight saving and a half-hour offset (India).
    set_tz("IST-5:30");
    assert_eq!(utc_offset_minutes_at(EU_SPRING), Some(330));

    set_tz("UTC0");
    assert_eq!(utc_offset_minutes_at(EU_SPRING), Some(0));
}
