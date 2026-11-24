//! The UDP flow gate: one `UdpSend` per flow per window reaches the bus.
//!
//! A datagram is an event (Windows Kernel-Network 42/58, Linux `sendto(2)`), so a QUIC
//! transfer or a UDP loop would otherwise put thousands of events per second on the bus,
//! which keeps every event of its window and is scanned per pid. The rules only ask
//! whether a process sent to a peer, which the first datagram of a flow answers.

use std::net::IpAddr;

use schema::UdpSendEvent;
use store::BoundedMap;

/// Flows remembered at once. Past it the least recently admitted flow is forgotten, and
/// its next datagram is admitted again: more bus entries, never a missed flow.
const FLOW_CAP: usize = 16_384;

/// A flow: the sending process (pid and incarnation) and the destination.
type Flow = (u32, Option<u64>, IpAddr, u16);

/// What the gate kept off the bus since start, for the health surface.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UdpSendShedding {
    /// Datagrams of a flow already admitted within the window.
    pub repeats_suppressed: u64,
    /// Flows forgotten at the cap before their window ended.
    pub flows_evicted: u64,
}

/// Admits the first `UdpSend` of each flow, then the first one a full window after the
/// last admission: each flow keeps one event on the bus while it is active.
pub(crate) struct UdpFlowGate {
    window_ns: u64,
    admitted_at_ns: BoundedMap<Flow, u64>,
    repeats_suppressed: u64,
}

impl UdpFlowGate {
    pub(crate) fn new(window_ns: u64) -> Self {
        Self {
            window_ns,
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
        let repeat = self
            .admitted_at_ns
            .peek(&flow)
            .is_some_and(|&admitted_ns| now_ns.saturating_sub(admitted_ns) < self.window_ns);
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
