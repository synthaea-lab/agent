//! Coverage-guided fuzzing for the netlink decoders. One target for all three:
//! they share the input domain (bytes off a netlink socket) and libFuzzer
//! explores each parser's branches from the same corpus. Same contract as the
//! deterministic robustness suite: failure is fine, panic is a bug.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sensor_linux_netlink::{ConntrackFlow, DiagMsg, ProcEvent};

fuzz_target!(|data: &[u8]| {
    let _ = DiagMsg::parse(data);
    let _ = ProcEvent::parse(data);
    let _ = ConntrackFlow::parse(data);
});
