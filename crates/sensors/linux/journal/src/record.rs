//! Parses one line of `journalctl -o json` output into the subset of fields
//! [`classify`](crate::classify) needs.
//!
//! Deliberately field-by-field via [`serde_json::Value`] rather than a single
//! `#[derive(Deserialize)]` struct: journald's JSON export represents a field whose
//! value contains invalid UTF-8 (or an embedded NUL) as a JSON array of byte values
//! instead of a string — rare, but a `MESSAGE` line from something that logs raw
//! binary would hit it. A derived struct would fail the whole line; extracting each
//! field defensively (`as_str()`, `None` on a shape mismatch) means that one odd
//! record is skipped, not fatal to the entire tail. See `JournalError::MissingField`
//! at the call site — a record we can't extract `MESSAGE`/`__CURSOR`/
//! `__REALTIME_TIMESTAMP` from is treated as unparseable, not as an error worth
//! surfacing to the caller.

use crate::JournalError;

/// The fields of a `journalctl -o json` record that [`classify`](crate::classify)
/// and its callers need. Not exhaustive — journald records carry dozens of `_`-
/// prefixed trusted fields; add more here as a category needs them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalRecord {
    /// `__CURSOR` — opaque resume token for `journalctl --after-cursor`.
    pub cursor: String,
    /// `__REALTIME_TIMESTAMP` — microseconds since the Unix epoch.
    pub realtime_us: u64,
    /// `_BOOT_ID` — which boot produced this record (absent only if journald itself
    /// is misbehaving; kept `Option` rather than asserted, since nothing here
    /// depends on it yet).
    pub boot_id: Option<String>,
    /// `SYSLOG_IDENTIFIER` — the program name as it identified itself to the log
    /// (`"sshd"`, `"sudo"`, `"su"`, ...). Absent on structured-only sources.
    pub syslog_identifier: Option<String>,
    /// `_UID` — numeric UID of the process that emitted the record (the logger, not
    /// necessarily the account being authenticated — that's parsed from `message`
    /// by [`classify`](crate::classify) instead).
    pub uid: Option<String>,
    /// `MESSAGE` — required: a record with no usable message string can't be
    /// classified, so [`parse_record`] treats its absence as unparseable.
    pub message: String,
    /// `JOB_TYPE` — present on systemd job-completion records (`"start"`,
    /// `"stop"`, ...). Paired with `job_result` for unit lifecycle classification;
    /// see the module doc on [`crate::classify`] for why fields rather than the
    /// opaque `MESSAGE_ID` catalog constant.
    pub job_type: Option<String>,
    /// `JOB_RESULT` — `"done"`, `"failed"`, `"canceled"`, ...
    pub job_result: Option<String>,
    /// The unit a job record is about: `UNIT` on the system manager, `USER_UNIT` on
    /// a user manager (this dev sandbox only ever produced the latter — see the
    /// crate doc's Status section).
    pub unit: Option<String>,
}

/// Parses one `journalctl -o json` line.
///
/// # Errors
///
/// Returns [`JournalError::Json`] if the line is not valid JSON at all, or
/// [`JournalError::MissingField`] if `__CURSOR`, `__REALTIME_TIMESTAMP` or
/// `MESSAGE` is absent or not a plain JSON string (see the module doc for when that
/// happens). Both are expected, recoverable conditions for a caller iterating a
/// live stream — see [`crate::ClassifiedJournal`], which skips the latter rather
/// than propagating it.
pub fn parse_record(line: &str) -> Result<JournalRecord, JournalError> {
    let value: serde_json::Value = serde_json::from_str(line)?;
    let get_str = |key: &str| -> Option<String> {
        value.get(key).and_then(|v| v.as_str()).map(str::to_string)
    };

    let cursor = get_str("__CURSOR").ok_or(JournalError::MissingField("__CURSOR"))?;
    let message = get_str("MESSAGE").ok_or(JournalError::MissingField("MESSAGE"))?;
    let realtime_us = get_str("__REALTIME_TIMESTAMP")
        .and_then(|s| s.parse().ok())
        .ok_or(JournalError::MissingField("__REALTIME_TIMESTAMP"))?;

    Ok(JournalRecord {
        cursor,
        realtime_us,
        boot_id: get_str("_BOOT_ID"),
        syslog_identifier: get_str("SYSLOG_IDENTIFIER"),
        uid: get_str("_UID"),
        message,
        job_type: get_str("JOB_TYPE"),
        job_result: get_str("JOB_RESULT"),
        unit: get_str("UNIT").or_else(|| get_str("USER_UNIT")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real capture from this dev machine's own journal (`journalctl -o json`),
    // machine/boot IDs included verbatim — they're local-machine identifiers, not
    // secrets.
    const REAL_SUDO_COMMAND_LINE: &str = r#"{"__CURSOR":"s=3df6ac98b05349d194455aa7a1167fef;i=1a626;b=e397e6127ad54b2f82bd4d85f39e8bba;m=3c0b782fe;t=65b3349fb99bb;x=4ef703b3a49edbe2","__REALTIME_TIMESTAMP":"1789125702949307","_BOOT_ID":"e397e6127ad54b2f82bd4d85f39e8bba","SYSLOG_IDENTIFIER":"sudo","_UID":"1001","MESSAGE":"     lab : TTY=pts/0 ; PWD=/mnt/d/projets persos ; USER=root ; COMMAND=/bin/echo hi"}"#;

    #[test]
    fn parses_a_real_sudo_command_line() {
        let record = parse_record(REAL_SUDO_COMMAND_LINE).unwrap();
        assert_eq!(record.syslog_identifier.as_deref(), Some("sudo"));
        assert_eq!(record.uid.as_deref(), Some("1001"));
        assert!(record.message.contains("COMMAND=/bin/echo hi"));
        assert_eq!(record.realtime_us, 1_789_125_702_949_307);
        assert!(record.job_type.is_none());
    }

    #[test]
    fn parses_a_real_unit_job_line() {
        // Real capture: user-manager job completion (see the crate doc — the
        // system-manager `UNIT=` path is standard systemd behavior but wasn't
        // exercised in this sandbox).
        let line = r#"{"__CURSOR":"s=dec1e171761a423fa8cf4153b39d1058;i=1a13d","__REALTIME_TIMESTAMP":"1789125634179641","JOB_TYPE":"start","JOB_RESULT":"done","USER_UNIT":"default.target","MESSAGE":"Reached target default.target - Main User Target."}"#;
        let record = parse_record(line).unwrap();
        assert_eq!(record.job_type.as_deref(), Some("start"));
        assert_eq!(record.job_result.as_deref(), Some("done"));
        assert_eq!(record.unit.as_deref(), Some("default.target"));
    }

    #[test]
    fn missing_cursor_is_a_missing_field_error() {
        let line = r#"{"__REALTIME_TIMESTAMP":"1","MESSAGE":"hi"}"#;
        assert!(matches!(
            parse_record(line),
            Err(JournalError::MissingField("__CURSOR"))
        ));
    }

    #[test]
    fn message_as_byte_array_is_a_missing_field_not_a_hard_error() {
        // journald's binary-safe representation for a non-UTF8 MESSAGE: an array of
        // byte values instead of a string. This must not be a JSON parse error —
        // it's valid JSON, just not a shape `classify` can use.
        let line = r#"{"__CURSOR":"c","__REALTIME_TIMESTAMP":"1","MESSAGE":[104,105,0,255]}"#;
        assert!(matches!(
            parse_record(line),
            Err(JournalError::MissingField("MESSAGE"))
        ));
    }

    #[test]
    fn malformed_json_is_a_json_error() {
        assert!(matches!(
            parse_record("not json"),
            Err(JournalError::Json(_))
        ));
    }

    #[test]
    fn non_numeric_realtime_timestamp_is_a_missing_field_error() {
        let line = r#"{"__CURSOR":"c","__REALTIME_TIMESTAMP":"not-a-number","MESSAGE":"hi"}"#;
        assert!(matches!(
            parse_record(line),
            Err(JournalError::MissingField("__REALTIME_TIMESTAMP"))
        ));
    }
}
