//! Coverage-guided fuzzing for the service-log parsers (ADR-0022). Log lines are
//! attacker-controlled text; same contract as the other targets: an `Err` is fine,
//! a panic is a bug.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sensor_linux_logs::{AccessFormat, parse_access_line, parse_mysql_error_line};

fuzz_target!(|data: &[u8]| {
    let Ok(line) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse_access_line(line, AccessFormat::Common);
    let _ = parse_access_line(line, AccessFormat::Combined);
    let _ = parse_mysql_error_line(line);
});
