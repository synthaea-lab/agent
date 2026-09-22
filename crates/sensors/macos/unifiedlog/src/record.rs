//! Parses one line of `log stream --style ndjson` output into the subset of
//! fields [`classify`](crate::classify) needs.
//!
//! Same defensive field-by-field extraction as `sensor-linux-journal`'s
//! `record.rs` (via [`serde_json::Value`], not a derived struct): one odd
//! record — a null `eventMessage` on `timesync`/`stateEvent` records, a shape
//! this crate's author has actually observed in live captures — skips that
//! record, never the whole stream.

use crate::UnifiedLogError;

/// The fields of a `log stream --style ndjson` record this crate needs. Not
/// exhaustive — the unified log carries ~30 fields per record; add more as a
/// category needs them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRecord {
    /// `eventMessage` — required: a record with no message string cannot be
    /// classified. `log`'s NDJSON emits null/absent for non-log records
    /// (`timesync`, `activityCreateEvent` transitions) — treated as
    /// unparseable, not an error.
    pub message: String,
    /// `subsystem` — `com.apple.TCC` & co.; empty string when the logger
    /// didn't declare one (sudo).
    pub subsystem: String,
    /// `processImagePath` — full path of the logging process.
    pub process_image_path: String,
    /// `processID`.
    pub pid: Option<u32>,
    /// `userID` — uid of the logging process, when present.
    pub uid: Option<u32>,
    /// `timestamp` (wall clock) normalized to ns since the UNIX epoch.
    pub timestamp_ns: u64,
    /// `eventType` — only `logEvent` records carry classifiable messages.
    pub event_type: String,
}

/// Short process name from `process_image_path` (`.../Support/tccd` → `tccd`).
#[must_use]
pub(crate) fn image_basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Parses one NDJSON line. `Err(UnifiedLogError::MissingField)` marks the
/// "expected, recoverable" shape misses (see module doc) — callers skip those.
///
/// # Errors
///
/// [`UnifiedLogError::Json`] when the line isn't JSON at all;
/// [`UnifiedLogError::MissingField`] when a required field is absent or the
/// wrong shape.
pub fn parse_record(line: &str) -> Result<LogRecord, UnifiedLogError> {
    let value: serde_json::Value = serde_json::from_str(line)?;

    let message = value
        .get("eventMessage")
        .and_then(|v| v.as_str())
        .ok_or(UnifiedLogError::MissingField("eventMessage"))?
        .to_string();
    let event_type = value
        .get("eventType")
        .and_then(|v| v.as_str())
        .ok_or(UnifiedLogError::MissingField("eventType"))?
        .to_string();
    let timestamp = value
        .get("timestamp")
        .and_then(|v| v.as_str())
        .ok_or(UnifiedLogError::MissingField("timestamp"))?;
    let timestamp_ns = parse_log_timestamp(timestamp).ok_or(UnifiedLogError::MissingField(
        "timestamp (unrecognized format)",
    ))?;

    Ok(LogRecord {
        message,
        subsystem: value
            .get("subsystem")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        process_image_path: value
            .get("processImagePath")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        pid: value
            .get("processID")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| u32::try_from(v).ok()),
        uid: value
            .get("userID")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| u32::try_from(v).ok()),
        timestamp_ns,
        event_type,
    })
}

/// Parses `log`'s wall-clock format — `"2026-09-22 11:12:25.248383+0200"` —
/// to ns since the UNIX epoch. Hand-rolled for exactly this fixed layout
/// rather than pulling a date crate into a sensor: the format is emitted by
/// one tool this crate also spawns, not arbitrary user input.
///
/// Returns `None` on any deviation (fail the record, never guess a time).
fn parse_log_timestamp(s: &str) -> Option<u64> {
    let bytes = s.as_bytes();
    // "YYYY-MM-DD HH:MM:SS.ffffff±HHMM" = 31 bytes exactly.
    if bytes.len() != 31 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b' ' {
        return None;
    }
    let num = |range: std::ops::Range<usize>| -> Option<u64> { s.get(range)?.parse().ok() };
    let year = num(0..4)?;
    let month = num(5..7)?;
    let day = num(8..10)?;
    let hour = num(11..13)?;
    let minute = num(14..16)?;
    let second = num(17..19)?;
    if bytes[16] != b':' || bytes[13] != b':' || bytes[19] != b'.' {
        return None;
    }
    let micros = num(20..26)?;
    let tz_sign = match bytes[26] {
        b'+' => 1i64,
        b'-' => -1i64,
        _ => return None,
    };
    let tz_hours = i64::try_from(num(27..29)?).ok()?;
    let tz_minutes = i64::try_from(num(29..31)?).ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59
        // Leap seconds don't occur in this format (CLOCK_REALTIME).
        || second > 59
    {
        return None;
    }

    // Days since the UNIX epoch, Howard Hinnant's civil-days algorithm.
    let y = i64::try_from(year).ok()? - i64::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let m = i64::try_from(month).ok()?;
    let d = i64::try_from(day).ok()?;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days = era * 146_097 + doe - 719_468;

    let local_secs = days * 86_400
        + i64::try_from(hour).ok()? * 3_600
        + i64::try_from(minute).ok()? * 60
        + i64::try_from(second).ok()?;
    let utc_secs = local_secs - tz_sign * (tz_hours * 3_600 + tz_minutes * 60);
    let ns = utc_secs
        .checked_mul(1_000_000_000)?
        .checked_add(i64::try_from(micros).ok()?.checked_mul(1_000)?)?;
    u64::try_from(ns).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_real_log_stream_record() {
        // Verbatim shape from a live `log show --style ndjson` capture on this
        // dev machine (2026-09-22), trimmed to the fields we read.
        let line = r#"{"timezoneName":"","messageType":"Default","eventType":"logEvent","subsystem":"com.apple.TCC","category":"access","processID":427,"userID":0,"processImagePath":"/System/Library/PrivateFrameworks/TCC.framework/Support/tccd","timestamp":"2026-09-22 11:12:25.248383+0200","eventMessage":"AUTHREQ_RESULT: msgID=438.631, authValue=0, authReason=12, authVersion=1, desired_auth=0, error=(null),"}"#;
        let record = parse_record(line).expect("must parse");
        assert_eq!(record.pid, Some(427));
        assert_eq!(record.uid, Some(0));
        assert_eq!(record.subsystem, "com.apple.TCC");
        assert_eq!(image_basename(&record.process_image_path), "tccd");
        assert!(record.message.starts_with("AUTHREQ_RESULT"));
    }

    #[test]
    fn null_event_message_is_a_recoverable_miss() {
        // `timesync`/state records carry no eventMessage — skip, don't fail.
        let line = r#"{"eventType":"timesyncEvent","eventMessage":null,"timestamp":"2026-09-22 11:12:25.248383+0200"}"#;
        assert!(matches!(
            parse_record(line),
            Err(UnifiedLogError::MissingField("eventMessage"))
        ));
    }

    #[test]
    fn non_json_line_is_a_hard_error() {
        assert!(matches!(
            parse_record("Filtering the log data using ..."),
            Err(UnifiedLogError::Json(_))
        ));
    }

    #[test]
    fn timestamp_converts_to_epoch_ns() {
        // 2026-09-22 11:12:25.248383 at UTC+2 == 09:12:25.248383 UTC.
        // Cross-checked with `date -j -u -f "%Y-%m-%d %H:%M:%S" "2026-09-22 09:12:25" +%s`.
        let ns = parse_log_timestamp("2026-09-22 11:12:25.248383+0200").unwrap();
        assert_eq!(ns, 1_790_068_345_000_000_000 + 248_383_000);
    }

    #[test]
    fn negative_utc_offset_adds_to_utc() {
        let plus = parse_log_timestamp("2026-09-22 11:12:25.000000+0200").unwrap();
        let minus = parse_log_timestamp("2026-09-22 11:12:25.000000-0200").unwrap();
        assert_eq!(minus - plus, 4 * 3_600 * 1_000_000_000);
    }

    #[test]
    fn malformed_timestamps_fail_rather_than_guess() {
        for bad in [
            "2026-09-22T11:12:25.248383+0200", // ISO 'T' separator — not log's format
            "2026-09-22 11:12:25+0200",        // no fractional part
            "2026-13-22 11:12:25.248383+0200", // month out of range
            "garbage",
        ] {
            assert_eq!(parse_log_timestamp(bad), None, "{bad}");
        }
    }
}
