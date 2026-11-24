//! Coverage-guided fuzzing for the netlink framing and decoders. One target for all of them:
//! they share the input domain (bytes off a netlink socket) and libFuzzer
//! explores each parser's branches from the same corpus. Same contract as the
//! deterministic robustness suite: failure is fine, panic is a bug.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sensor_linux_netlink::{ConntrackFlow, DiagMsg, ProcEvent, netlink_messages};

fuzz_target!(|data: &[u8]| {
    let _ = DiagMsg::parse(data);
    let _ = ProcEvent::parse(data);
    let _ = ConntrackFlow::parse(data);
    // The framing every socket reader walks its buffer with; the walk must end.
    for _ in netlink_messages(data) {}
});
