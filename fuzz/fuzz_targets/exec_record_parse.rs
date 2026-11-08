//! Coverage-guided fuzzing for the variable-length exec record (<https://github.com/synthaea-lab/edr-agent/issues/48>, ADR-0045): the lengths
//! it carries describe bytes a process chose. Same contract as the deterministic suite in
//! `crates/sensors/linux/wire/tests/exec_record.rs`: an `Err` is fine, a panic is a bug, and an
//! accepted record never reaches past its end.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sensor_linux_wire::{ARGV_WINDOW_BYTES, ExecEvent, parse_exec_record};

fuzz_target!(|data: &[u8]| {
    if let Ok((_, argv)) = parse_exec_record(data) {
        let used = argv.head.len() + argv.tail.len();
        assert!(used <= ARGV_WINDOW_BYTES);
        assert!(core::mem::size_of::<ExecEvent>() + used <= data.len());
    }
});
