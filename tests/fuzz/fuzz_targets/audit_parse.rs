//! Coverage-guided fuzzing for the audit netlink parser — the deeper sibling of
//! the deterministic robustness suite (`crates/sensors/linux/audit/tests/`):
//! libFuzzer mutates toward new branches instead of sampling blindly. The
//! contract under test is the same: any byte input may fail, none may panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sensor_linux_audit::parse_audit_message(data);
});
