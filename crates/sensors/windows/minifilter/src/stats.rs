//! What the agent knows about the event channel's health (milestone 2c, #136).
//!
//! Loss is visible from two sides, as the design asks. The driver counts what it could not
//! queue or send, and carries the cumulative counters in every message. The agent sees a gap
//! in the per-connection sequence number, and counts what it could not decode. Neither side
//! alone is enough: a record lost between the queue and `FilterGetMessage` shows only as a
//! sequence gap, and a record never queued shows only in the driver's counters.
//!
//! Platform-independent: tested on every OS.

use crate::wire::{Counters, Message};

/// Cumulative figures for one agent run, across reconnects.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChannelStats {
    /// Messages decoded, heartbeats included.
    pub received: u64,
    /// Heartbeats among them.
    pub heartbeats: u64,
    /// Messages refused by the decoder (counted, never forwarded).
    pub decode_errors: u64,
    /// Records missing between two received sequence numbers.
    pub lost_by_sequence: u64,
    /// Connections made (the first one included): more than one means the driver was
    /// reloaded or the connection dropped.
    pub connections: u64,
    /// The driver's own counters, as of its latest message.
    pub driver: Counters,
    /// Sequence number of the latest message on the current connection; 0 before the first.
    last_seq: u64,
}

impl ChannelStats {
    /// A new connection: sequence numbers restart at 1 on the driver's side.
    pub fn on_connect(&mut self) {
        self.connections += 1;
        self.last_seq = 0;
    }

    /// One decoded message. Returns how many records were lost just before it (0 when the
    /// sequence is contiguous). A sequence number that goes backwards on the same connection
    /// cannot come from the driver; it is not counted as loss, and tracking restarts from it.
    pub fn on_message(&mut self, message: &Message) -> u64 {
        self.received += 1;
        if matches!(message.body, crate::wire::Body::Heartbeat) {
            self.heartbeats += 1;
        }
        self.driver = message.counters;
        let expected = self.last_seq + 1;
        let lost = message.seq.saturating_sub(expected);
        self.lost_by_sequence += lost;
        self.last_seq = message.seq;
        lost
    }

    /// A message the decoder refused.
    pub fn on_decode_error(&mut self) {
        self.decode_errors += 1;
    }

    /// Everything known to be lost so far: the driver's three counters plus the gaps the agent
    /// saw. The two do not overlap: a record the driver dropped never got a sequence number.
    #[must_use]
    pub fn total_lost(&self) -> u64 {
        self.lost_by_sequence
            + self.driver.dropped_queue_full
            + self.driver.dropped_send_failed
            + self.driver.not_connected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Body;

    fn msg(seq: u64, body: Body, counters: Counters) -> Message {
        Message {
            seq,
            timestamp_ns: 1,
            pid: 4,
            tid: 8,
            counters,
            body,
        }
    }

    fn delete() -> Body {
        Body::Delete {
            path: "x".into(),
            on_close: false,
            truncated: false,
        }
    }

    #[test]
    fn a_contiguous_sequence_loses_nothing() {
        let mut s = ChannelStats::default();
        s.on_connect();
        for seq in 1..=5 {
            assert_eq!(s.on_message(&msg(seq, delete(), Counters::default())), 0);
        }
        assert_eq!(s.lost_by_sequence, 0);
        assert_eq!(s.received, 5);
    }

    #[test]
    fn a_gap_counts_the_missing_records() {
        let mut s = ChannelStats::default();
        s.on_connect();
        s.on_message(&msg(1, delete(), Counters::default()));
        assert_eq!(s.on_message(&msg(5, delete(), Counters::default())), 3);
        assert_eq!(s.lost_by_sequence, 3);
    }

    #[test]
    fn the_first_message_after_connect_may_not_be_one() {
        // Records queued before the agent's first FilterGetMessage and lost count from 1.
        let mut s = ChannelStats::default();
        s.on_connect();
        assert_eq!(s.on_message(&msg(3, delete(), Counters::default())), 2);
    }

    #[test]
    fn a_reconnect_restarts_the_sequence_without_counting_loss() {
        let mut s = ChannelStats::default();
        s.on_connect();
        s.on_message(&msg(40, delete(), Counters::default()));
        s.on_connect();
        assert_eq!(
            s.on_message(&msg(1, Body::Heartbeat, Counters::default())),
            0
        );
        assert_eq!(s.connections, 2);
        assert_eq!(s.heartbeats, 1);
        assert_eq!(s.lost_by_sequence, 39);
    }

    #[test]
    fn a_sequence_going_backwards_is_not_loss() {
        let mut s = ChannelStats::default();
        s.on_connect();
        s.on_message(&msg(10, delete(), Counters::default()));
        let lost_before = s.lost_by_sequence;
        assert_eq!(s.on_message(&msg(4, delete(), Counters::default())), 0);
        assert_eq!(s.lost_by_sequence, lost_before);
        assert_eq!(s.on_message(&msg(5, delete(), Counters::default())), 0);
    }

    #[test]
    fn total_lost_adds_the_driver_counters_and_the_gaps() {
        let mut s = ChannelStats::default();
        s.on_connect();
        s.on_message(&msg(1, delete(), Counters::default()));
        s.on_message(&msg(
            4,
            delete(),
            Counters {
                dropped_queue_full: 10,
                dropped_send_failed: 1,
                not_connected: 100,
            },
        ));
        s.on_decode_error();
        assert_eq!(s.total_lost(), 2 + 10 + 1 + 100);
        assert_eq!(s.decode_errors, 1);
    }
}
