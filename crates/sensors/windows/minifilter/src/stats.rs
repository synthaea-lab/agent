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
    /// Decoded file messages not forwarded because at least one path was cut.
    pub truncated_paths: u64,
    /// Records missing between two received sequence numbers.
    pub lost_by_sequence: u64,
    /// Failed sends reconciled with sequence gaps per received message.
    send_loss: u64,
    /// Connections made (the first one included): more than one means the driver was
    /// reloaded or the connection dropped.
    pub connections: u64,
    /// The driver's own counters, as of its latest message.
    pub driver: Counters,
    /// Driver counter increases observed after this agent's first message. A decrease is treated
    /// as a driver reload, so the new value belongs to this run.
    driver_deltas: Counters,
    /// Previous driver snapshot, including the initial baseline from the first message.
    previous_driver: Option<Counters>,
    /// Sequence number of the latest message on the current connection; 0 before the first.
    last_seq: u64,
}

impl ChannelStats {
    /// A new connection: the driver restarts its sequence numbers at 1 (it resets the counter
    /// when a client connects), so the next message is checked against 1, not against the last
    /// number of the previous connection. Records the driver numbered and failed to send before
    /// the agent's first read are real losses and show up as a gap from 1: the driver also
    /// takes back the number of a heartbeat it could not send, so a quiet period with no read
    /// pending leaves no gap.
    pub fn on_connect(&mut self) {
        self.connections = self.connections.saturating_add(1);
        self.last_seq = 0;
    }

    /// One decoded message. Returns how many records were lost just before it (0 when the
    /// sequence is contiguous). A sequence number that goes backwards on the same connection
    /// cannot come from the driver; it is not counted as loss, and tracking restarts from it.
    pub fn on_message(&mut self, message: &Message) -> u64 {
        self.received = self.received.saturating_add(1);
        if matches!(message.body, crate::wire::Body::Heartbeat) {
            self.heartbeats = self.heartbeats.saturating_add(1);
        }
        let mut send_failed_delta = 0;
        if let Some(previous) = self.previous_driver {
            let delta = |current: u64, old: u64| {
                if current >= old {
                    current - old
                } else {
                    current
                }
            };
            self.driver_deltas.dropped_queue_full =
                self.driver_deltas.dropped_queue_full.saturating_add(delta(
                    message.counters.dropped_queue_full,
                    previous.dropped_queue_full,
                ));
            send_failed_delta = delta(
                message.counters.dropped_send_failed,
                previous.dropped_send_failed,
            );
            self.driver_deltas.not_connected = self.driver_deltas.not_connected.saturating_add(
                delta(message.counters.not_connected, previous.not_connected),
            );
            self.driver_deltas.dropped_capture_failed = self
                .driver_deltas
                .dropped_capture_failed
                .saturating_add(delta(
                    message.counters.dropped_capture_failed,
                    previous.dropped_capture_failed,
                ));
        }
        self.previous_driver = Some(message.counters);
        self.driver = message.counters;
        let expected = self.last_seq.saturating_add(1);
        let lost = message.seq.saturating_sub(expected);
        self.lost_by_sequence = self.lost_by_sequence.saturating_add(lost);
        self.send_loss = self.send_loss.saturating_add(lost.max(send_failed_delta));
        self.last_seq = message.seq;
        lost
    }

    /// A message the decoder refused.
    pub fn on_decode_error(&mut self) {
        self.decode_errors = self.decode_errors.saturating_add(1);
    }

    /// A decoded message with a cut path is counted but not forwarded to rules.
    pub fn on_truncated_path(&mut self) {
        self.truncated_paths = self.truncated_paths.saturating_add(1);
    }

    /// Aggregate loss indicator since the first message of this run. It reconciles failed sends
    /// and sequence gaps per snapshot, without counting the same send twice. It can overstate
    /// loss because `not_connected` includes attempts that later
    /// failed, and understate it because the first snapshot is only a baseline: its counters
    /// may predate this run, and losses before that snapshot cannot be attributed here. The raw
    /// driver snapshot remains in [`Self::driver`] for observation.
    ///
    /// The sender numbers a record when it takes it off the queue, so a failed send normally
    /// leaves a gap and raises `dropped_send_failed` (the #857 lab saw both rise by 16). A
    /// disconnect can hide the gap when the sequence resets; the counter still exposes it.
    /// Records dropped
    /// before the sender (queue full, no agent connected, capture failed) never get a number,
    /// so their counters add to the gaps without overlap.
    #[must_use]
    pub fn total_lost(&self) -> u64 {
        self.send_loss
            .saturating_add(self.driver_deltas.dropped_queue_full)
            .saturating_add(self.driver_deltas.not_connected)
            .saturating_add(self.driver_deltas.dropped_capture_failed)
            .saturating_add(self.truncated_paths)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

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
        for seq in 1..=40 {
            assert_eq!(s.on_message(&msg(seq, delete(), Counters::default())), 0);
        }
        s.on_connect();
        assert_eq!(
            s.on_message(&msg(1, Body::Heartbeat, Counters::default())),
            0
        );
        assert_eq!(s.connections, 2);
        assert_eq!(s.heartbeats, 1);
        // Nothing was lost: the second connection starts again at 1 after a clean first one.
        assert_eq!(s.lost_by_sequence, 0);
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
    fn total_lost_counts_each_loss_once() {
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
                dropped_capture_failed: 7,
            },
        ));
        s.on_decode_error();
        // The gap of 2 already includes the one failed send: it is not counted twice.
        assert_eq!(s.total_lost(), 2 + 10 + 100 + 7);
        assert_eq!(s.decode_errors, 1);
    }

    #[test]
    fn a_cut_path_counts_as_one_unforwarded_event() {
        let mut s = ChannelStats::default();
        s.on_connect();
        s.on_message(&msg(1, delete(), Counters::default()));
        s.on_truncated_path();
        assert_eq!(s.truncated_paths, 1);
        assert_eq!(s.total_lost(), 1);
    }

    #[test]
    fn historical_driver_counters_are_not_reported_as_new_agent_loss() {
        let mut s = ChannelStats::default();
        s.on_connect();
        s.on_message(&msg(
            1,
            delete(),
            Counters {
                dropped_queue_full: 10,
                dropped_send_failed: 0,
                not_connected: 100,
                dropped_capture_failed: 7,
            },
        ));
        assert_eq!(s.total_lost(), 0);
        s.on_message(&msg(
            2,
            delete(),
            Counters {
                dropped_queue_full: 12,
                dropped_send_failed: 0,
                not_connected: 100,
                dropped_capture_failed: 8,
            },
        ));
        assert_eq!(s.total_lost(), 3);
    }

    #[test]
    fn a_driver_reload_starts_new_counter_deltas_without_losing_the_old_ones() {
        let mut s = ChannelStats::default();
        s.on_connect();
        s.on_message(&msg(
            1,
            delete(),
            Counters {
                dropped_queue_full: 10,
                ..Counters::default()
            },
        ));
        s.on_message(&msg(
            2,
            delete(),
            Counters {
                dropped_queue_full: 12,
                ..Counters::default()
            },
        ));
        s.on_connect();
        s.on_message(&msg(
            1,
            delete(),
            Counters {
                dropped_queue_full: 1,
                ..Counters::default()
            },
        ));
        assert_eq!(s.total_lost(), 3);
    }

    #[test]
    fn a_failed_send_before_reconnect_is_visible_without_a_sequence_gap() {
        let mut s = ChannelStats::default();
        s.on_connect();
        s.on_message(&msg(1, delete(), Counters::default()));
        s.on_connect();
        s.on_message(&msg(
            1,
            delete(),
            Counters {
                dropped_send_failed: 1,
                ..Counters::default()
            },
        ));
        assert_eq!(s.lost_by_sequence, 0);
        assert_eq!(s.total_lost(), 1);
    }

    #[test]
    fn a_failed_send_and_its_sequence_gap_count_once() {
        let mut s = ChannelStats::default();
        s.on_connect();
        s.on_message(&msg(1, delete(), Counters::default()));
        s.on_message(&msg(
            3,
            delete(),
            Counters {
                dropped_send_failed: 1,
                ..Counters::default()
            },
        ));
        assert_eq!(s.lost_by_sequence, 1);
        assert_eq!(s.total_lost(), 1);
    }

    proptest! {
        #[test]
        fn arbitrary_sequences_and_counter_snapshots_never_panic(
            snapshots in prop::collection::vec(any::<(u64, u64, u64, u64)>(), 0..32)
        ) {
            let mut s = ChannelStats::default();
            s.on_connect();
            let mut previous_total = 0;
            for (seq, queue_full, not_connected, capture_failed) in snapshots {
                s.on_message(&msg(
                    seq,
                    delete(),
                    Counters {
                        dropped_queue_full: queue_full,
                        not_connected,
                        dropped_capture_failed: capture_failed,
                        ..Counters::default()
                    },
                ));
                s.on_truncated_path();
                let total = s.total_lost();
                prop_assert!(total >= previous_total);
                previous_total = total;
            }
        }
    }
}
