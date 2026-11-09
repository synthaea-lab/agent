//! `<TimeCreated SystemTime>` as Unix nanoseconds, with the civil-date arithmetic it needs.

use crate::xml::scan::extract_between;

/// The event's own time, `<TimeCreated SystemTime='2026-09-21T13:29:23.0286360Z'/>`,
/// as nanoseconds since the Unix epoch (the unit of `EventMeta::timestamp_ns`).
/// `None` when the attribute is absent or not exactly `YYYY-MM-DDTHH:MM:SS[.f]Z`
/// with a fraction of one to nine digits and a real calendar date from 1970 on.
///
/// The pollers read each channel on its own thread, so an event is *processed*
/// some seconds after it happened, and two channels do not agree on that delay.
/// A rule that joins events from two channels needs when they happened, not when
/// they arrived (the RDP success-after-failures join, #285).
#[must_use]
pub fn time_created_ns(block: &str) -> Option<u64> {
    let text = extract_between(block, "<TimeCreated SystemTime='", "'")
        .or_else(|| extract_between(block, "<TimeCreated SystemTime=\"", "\""))?;
    system_time_ns(text.trim())
}

fn digits(text: &str, from: usize, to: usize) -> Option<u32> {
    let part = text.get(from..to)?;
    if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    part.parse().ok()
}

fn is_leap(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if is_leap(year) => 29,
        _ => 28,
    }
}

/// Days from 1970-01-01 to the given civil date (proleptic Gregorian; the
/// standard "days from civil" computation, valid for every date from 1970).
fn days_from_civil(year: u32, month: u32, day: u32) -> u64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_from_march = i64::from((month + 9) % 12);
    let day_of_year = (153 * month_from_march + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    u64::try_from(era * 146_097 + day_of_era - 719_468).unwrap_or(0)
}

fn system_time_ns(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || *bytes.last()? != b'Z'
    {
        return None;
    }
    let year = digits(text, 0, 4)?;
    let month = digits(text, 5, 7)?;
    let day = digits(text, 8, 10)?;
    let hour = digits(text, 11, 13)?;
    let minute = digits(text, 14, 16)?;
    let second = digits(text, 17, 19)?;
    if year < 1970
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let fraction_ns = if bytes.len() == 20 {
        0
    } else {
        // `.` then one to nine digits, then `Z`.
        let fraction_len = bytes.len() - 21;
        if bytes[19] != b'.' || !(1..=9).contains(&fraction_len) {
            return None;
        }
        let value = u64::from(digits(text, 20, bytes.len() - 1)?);
        value * 10_u64.pow(u32::try_from(9 - fraction_len).ok()?)
    };
    let seconds = days_from_civil(year, month, day) * 86_400
        + u64::from(hour) * 3_600
        + u64::from(minute) * 60
        + u64::from(second);
    seconds.checked_mul(1_000_000_000)?.checked_add(fraction_ns)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn time_created_reads_wevtutil_timestamps_exactly() {
        let at = |t: &str| time_created_ns(&format!("<TimeCreated SystemTime='{t}'/>"));
        assert_eq!(at("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            at("2026-09-21T13:29:23.0286360Z"),
            Some(1789997363028636000)
        );
        assert_eq!(
            at("2024-02-29T23:59:59.999999999Z"),
            Some(1709251199999999999)
        );
        assert_eq!(
            at("2000-03-01T00:00:00.000000000Z"),
            Some(951868800000000000)
        );
    }

    #[test]
    fn time_created_rejects_what_is_not_a_real_timestamp() {
        let at = |t: &str| time_created_ns(&format!("<TimeCreated SystemTime='{t}'/>"));
        assert_eq!(time_created_ns("<Event/>"), None, "no attribute");
        for bad in [
            "",
            "2026-09-21",
            "2026-09-21T13:29:23",
            "2026-09-21 13:29:23Z",
            "2026-13-01T00:00:00Z",
            "2026-00-10T00:00:00Z",
            "2026-02-30T00:00:00Z",
            "2023-02-29T00:00:00Z",
            "2026-09-21T24:00:00Z",
            "2026-09-21T13:60:00Z",
            "2026-09-21T13:29:60Z",
            "1969-12-31T23:59:59Z",
            "2026-09-21T13:29:23.Z",
            "2026-09-21T13:29:23.1234567891Z",
            "2026-09-21T13:29:23,5Z",
            "2026-09-21T13:29:23+01:00",
            "20x6-09-21T13:29:23Z",
        ] {
            assert_eq!(at(bad), None, "{bad:?}");
        }
    }

    proptest! {
        #[test]
        fn time_created_round_trips_against_time_crate(
            // `time_created_ns` returns u64 nanoseconds, so cap the reference
            // generator below u64::MAX / 1e9; a separate boundary case covers
            // the overflow edge.
            seconds in 0_u64..18_446_744_073,
            nanos in 0_u32..1_000_000_000,
        ) {
            let reference = time::OffsetDateTime::from_unix_timestamp(seconds as i64)
                .unwrap()
                .replace_nanosecond(nanos)
                .unwrap();
            let date = reference.date();
            let clock = reference.time();
            let timestamp = format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
                date.year(),
                u8::from(date.month()),
                date.day(),
                clock.hour(),
                clock.minute(),
                clock.second(),
                clock.nanosecond(),
            );
            let event = format!("<TimeCreated SystemTime='{timestamp}'/>");
            prop_assert_eq!(
                time_created_ns(&event),
                Some(reference.unix_timestamp_nanos() as u64),
            );
        }
    }

    #[test]
    fn time_created_handles_gregorian_century_leap_years() {
        let at = |text: &str| time_created_ns(&format!("<TimeCreated SystemTime='{text}'/>"));
        assert_eq!(at("2000-02-29T00:00:00Z"), Some(951_782_400_000_000_000));
        assert_eq!(at("1900-02-29T00:00:00Z"), None);
        assert_eq!(at("2100-02-29T00:00:00Z"), None);
        assert_eq!(at("2100-03-01T00:00:00Z"), Some(4_107_542_400_000_000_000));
    }

    #[test]
    fn time_created_rejects_nanoseconds_beyond_u64() {
        assert_eq!(
            time_created_ns("<TimeCreated SystemTime='2554-07-21T23:34:33.709551616Z'/>"),
            None,
        );
    }

    #[test]
    fn time_created_accepts_both_attribute_quote_styles_and_rejects_hostile_text() {
        assert_eq!(
            time_created_ns("<TimeCreated SystemTime=\"2026-01-02T03:04:05.000000006Z\"/>"),
            Some(1_767_323_045_000_000_006),
        );
        assert_eq!(
            time_created_ns("<TimeCreated SystemTime='2026-01-02T03:04:05.000000006Z'/>"),
            Some(1_767_323_045_000_000_006),
        );
        for hostile in [
            "2026-0é-02T03:04:05Z",
            "2026-01-02T03:04:é5Z",
            "2026-01-02T03:04:05\"Z",
            "2026-01-02T03:04:05'Z",
        ] {
            let event = format!("<TimeCreated SystemTime='{hostile}'/>");
            assert_eq!(time_created_ns(&event), None, "{hostile:?}");
        }
        let million_digits = format!(
            "<TimeCreated SystemTime='2026-01-02T03:04:05.{}Z'/>",
            "7".repeat(1_000_000),
        );
        assert_eq!(time_created_ns(&million_digits), None);
    }

    #[test]
    fn time_created_rejects_each_required_delimiter_when_only_it_is_wrong() {
        for malformed in [
            "2026/01-02T03:04:05Z",
            "2026-01/02T03:04:05Z",
            "2026-01-02t03:04:05Z",
            "2026-01-02T03.04:05Z",
            "2026-01-02T03:04.05Z",
            "2026-01-02T03:04:05X",
        ] {
            let event = format!("<TimeCreated SystemTime='{malformed}'/>");
            assert_eq!(time_created_ns(&event), None, "{malformed}");
        }
    }
}
