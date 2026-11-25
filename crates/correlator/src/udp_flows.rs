//! The UDP flow gate: at most one `UdpSend` per flow per second reaches the bus.
//!
//! A datagram is an event (Windows Kernel-Network 42/58, Linux `sendto(2)`), so a QUIC
//! transfer or a UDP loop would otherwise put thousands of events per second on the bus,
//! which keeps every event of its window and is scanned per pid. The rules only ask
//! whether a process sent to a peer within the window, so one datagram per flow per
//! re-admission interval answers them.
//!
//! The interval is short on purpose (#253 review). Re-admitting only once a full window
//! had passed made the gate a reset bucket: the admitted datagram left the bus exactly
//! when suppression ended, so a datagram sent late in the window never existed for the
//! rules, and a sender could hide its real exchange behind one throwaway datagram.
//! With a one-second interval the blind spot is that second, and an active flow keeps
//! at most `window / interval` events on the bus.

use std::net::IpAddr;

use schema::UdpSendEvent;
use store::BoundedMap;

/// Flows remembered at once. Past it the least recently admitted flow is forgotten, and
/// its next datagram is admitted again: more bus entries, never a missed flow.
const FLOW_CAP: usize = 16_384;

/// How long after an admission a flow's datagrams stay off the bus.
const READMISSION_INTERVAL_NS: u64 = 1_000_000_000;

/// A flow: the sending process (pid and incarnation) and the destination.
type Flow = (u32, Option<u64>, IpAddr, u16);

/// What the gate kept off the bus since start, for the health surface.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UdpSendShedding {
    /// Datagrams of a flow already admitted within the re-admission interval.
    pub repeats_suppressed: u64,
    /// Flows forgotten at the cap while still remembered as recently admitted.
    pub flows_evicted: u64,
}

/// Admits the first `UdpSend` of each flow, then the first one a re-admission interval
/// after the last admission.
pub(crate) struct UdpFlowGate {
    admitted_at_ns: BoundedMap<Flow, u64>,
    repeats_suppressed: u64,
}

impl UdpFlowGate {
    pub(crate) fn new() -> Self {
        Self {
            admitted_at_ns: BoundedMap::new(FLOW_CAP),
            repeats_suppressed: 0,
        }
    }

    /// Whether `send` goes on the bus; a datagram kept off it is counted.
    pub(crate) fn admit(&mut self, send: &UdpSendEvent) -> bool {
        let flow = (
            send.meta.pid,
            send.meta.process_generation,
            send.daddr,
            send.dport,
        );
        let now_ns = send.meta.timestamp_ns;
        let repeat = self.admitted_at_ns.peek(&flow).is_some_and(|&admitted_ns| {
            now_ns.saturating_sub(admitted_ns) < READMISSION_INTERVAL_NS
        });
        if repeat {
            self.repeats_suppressed += 1;
            return false;
        }
        self.admitted_at_ns.insert(flow, now_ns);
        true
    }

    pub(crate) fn shedding(&self) -> UdpSendShedding {
        UdpSendShedding {
            repeats_suppressed: self.repeats_suppressed,
            flows_evicted: self.admitted_at_ns.evicted(),
        }
    }
}
