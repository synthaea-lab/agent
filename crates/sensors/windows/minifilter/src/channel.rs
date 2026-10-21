//! The receive loop: connect, read, decode, forward, reconnect (milestone 2c, #136; Windows).
//!
//! One thread runs [`run`] for the agent's lifetime. It connects to the driver, forwards each
//! delete and rename to the sink as `FileDelete`/`FileRename`, calls `on_alive` for every
//! message (heartbeats included, so a wedged driver or sender thread becomes a silence alert,
//! #71), and keeps [`ChannelStats`] current. Loss that the driver's counters or a sequence
//! gap reveal is logged at most once a minute ([`LOSS_REPORT_INTERVAL`]).
//!
//! When a connection cannot be made, or breaks, the loop waits and retries with a capped
//! backoff (1 s doubling to 30 s). The backoff is reset only once a connection has delivered a
//! message, so a driver that accepts the connection but fails every read is retried at the
//! capped rate, never in a tight loop. While the driver is absent nothing is forwarded and
//! `on_alive` is not called, which is exactly the silence the monitor is for.

use std::{
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use schema::sensor::EventSink;

use crate::{
    DriverPort,
    events::{VolumeMap, to_event},
    port::ReceiveBuffer,
    stats::ChannelStats,
    wire,
};

/// First reconnect delay; doubled after each failed attempt up to [`MAX_BACKOFF`].
const MIN_BACKOFF: Duration = Duration::from_secs(1);
/// Longest wait between two connection attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Shortest interval between two volume-map refreshes on a normalisation miss (a newly
/// mounted volume appears without a restart, but a burst of misses rereads the table once).
const VOLUME_REFRESH: Duration = Duration::from_secs(30);
/// Granularity of the stop check while waiting to reconnect.
const STOP_SLICE: Duration = Duration::from_millis(250);
/// Shortest interval between two reports of lost events (a flood is one line a minute, not one
/// line per message).
const LOSS_REPORT_INTERVAL: Duration = Duration::from_secs(60);

/// Runs until `stop` is set. See the module doc.
pub fn run(
    sink: &dyn EventSink,
    stop: &AtomicBool,
    on_alive: &dyn Fn(),
    stats: &Mutex<ChannelStats>,
) {
    let mut backoff = MIN_BACKOFF;
    let mut failures: u64 = 0;
    let mut buffer = ReceiveBuffer::new();
    let mut loss = LossReport::new();
    while !stop.load(Ordering::Relaxed) {
        let port = match DriverPort::connect() {
            Ok(port) => port,
            Err(error) => {
                failures += 1;
                if failures.is_power_of_two() {
                    tracing::warn!(%error, attempts = failures, "minifilter: cannot connect to the driver");
                }
                sleep_unless_stopped(backoff, stop);
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        };
        tracing::info!(
            after_attempts = failures + 1,
            "minifilter: connected to the driver"
        );
        lock(stats).on_connect();
        let mut volumes = VolumeMap::from_system();
        let mut last_refresh = Instant::now();
        // The backoff and the failure count are reset by the first message of a connection, not
        // by the connect: a connection that never delivers anything is still a failed attempt.
        let mut delivered = false;
        loop {
            // `port.receive` only notices `stop` on a wait timeout; while messages keep
            // arriving before the timeout elapses (a delete/rename storm), it never times
            // out and `stop` is never read there. Check it here too, so a continuous
            // stream of messages cannot delay shutdown (#853 review).
            if stop.load(Ordering::Relaxed) {
                return;
            }
            match port.receive(&mut buffer, stop) {
                Ok(None) => return,
                Ok(Some(payload)) => {
                    if !delivered {
                        delivered = true;
                        failures = 0;
                        backoff = MIN_BACKOFF;
                    }
                    match wire::decode(payload) {
                        Ok(message) => {
                            on_alive();
                            let lost = lock(stats).on_message(&message);
                            if lost > 0 {
                                tracing::warn!(
                                    lost,
                                    seq = message.seq,
                                    "minifilter: records missing before this one"
                                );
                            }
                            if needs_refresh(&message) && last_refresh.elapsed() >= VOLUME_REFRESH {
                                volumes = VolumeMap::from_system();
                                last_refresh = Instant::now();
                            }
                            if let Some(event) = to_event(&message, &volumes) {
                                sink.on_event(event);
                            }
                        }
                        Err(error) => {
                            let mut stats = lock(stats);
                            stats.on_decode_error();
                            if stats.decode_errors.is_power_of_two() {
                                tracing::warn!(%error, refused = stats.decode_errors, "minifilter: message refused by the decoder");
                            }
                        }
                    }
                    loss.report_if_due(&lock(stats));
                }
                Err(error) => {
                    tracing::warn!(%error, "minifilter: connection lost, reconnecting");
                    break;
                }
            }
        }
        // The connection broke. Wait before the next attempt in every case: a driver that
        // accepts the connection and then fails every read must not be retried in a tight loop.
        // A connection that delivered something restarts the schedule at the shortest wait; one
        // that did not keeps doubling it.
        failures += u64::from(!delivered);
        sleep_unless_stopped(backoff, stop);
        if !delivered {
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }
}

/// Reports lost events at most once per [`LOSS_REPORT_INTERVAL`], and only when the figures
/// rose since the previous report: the loss is counted by the driver and by the sequence
/// numbers, and this is where an operator reads it (the health beacon does not carry it yet).
struct LossReport {
    last: Instant,
    lost: u64,
    decode_errors: u64,
}

impl LossReport {
    fn new() -> Self {
        Self {
            last: Instant::now(),
            lost: 0,
            decode_errors: 0,
        }
    }

    fn report_if_due(&mut self, stats: &ChannelStats) {
        if self.last.elapsed() < LOSS_REPORT_INTERVAL {
            return;
        }
        self.last = Instant::now();
        let lost = stats.total_lost();
        if lost <= self.lost && stats.decode_errors <= self.decode_errors {
            return;
        }
        tracing::warn!(
            lost_total = lost,
            lost_since_last_report = lost.saturating_sub(self.lost),
            sequence_gaps = stats.lost_by_sequence,
            queue_full = stats.driver.dropped_queue_full,
            send_failed = stats.driver.dropped_send_failed,
            not_connected = stats.driver.not_connected,
            capture_failed = stats.driver.dropped_capture_failed,
            decode_errors = stats.decode_errors,
            "minifilter: file events were lost (driver counters and sequence gaps)"
        );
        self.lost = lost;
        self.decode_errors = stats.decode_errors;
    }
}

/// Whether a message carries a device path the current map did not translate: the only case
/// worth rereading the drive table for.
fn needs_refresh(message: &wire::Message) -> bool {
    let unmapped = |path: &str| {
        path.get(..8)
            .is_some_and(|head| head.eq_ignore_ascii_case(r"\Device\"))
    };
    match &message.body {
        wire::Body::Delete { path, .. } => unmapped(path),
        wire::Body::Rename {
            old_path, new_path, ..
        } => unmapped(old_path) || unmapped(new_path),
        wire::Body::Heartbeat => false,
    }
}

fn sleep_unless_stopped(total: Duration, stop: &AtomicBool) {
    let deadline = Instant::now() + total;
    while !stop.load(Ordering::Relaxed) {
        let now = Instant::now();
        if now >= deadline {
            return;
        }
        std::thread::sleep((deadline - now).min(STOP_SLICE));
    }
}

/// The stats lock: a poisoned lock still holds valid counters (plain integers), so it is used
/// rather than propagating a panic into the receive thread.
fn lock(stats: &Mutex<ChannelStats>) -> std::sync::MutexGuard<'_, ChannelStats> {
    stats
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
