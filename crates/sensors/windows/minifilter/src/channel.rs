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
    events::VolumeMap,
    port::ReceiveBuffer,
    session::{Backoff, Session, lock},
    stats::ChannelStats,
};

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
    let mut backoff = Backoff::new();
    let mut buffer = ReceiveBuffer::new();
    let mut loss = LossReport::new();
    while !stop.load(Ordering::Relaxed) {
        let port = match DriverPort::connect() {
            Ok(port) => port,
            Err(error) => {
                let wait = backoff.on_failure();
                if backoff.failures().is_power_of_two() {
                    tracing::warn!(%error, attempts = backoff.failures(), "minifilter: cannot connect to the driver");
                }
                sleep_unless_stopped(wait, stop);
                continue;
            }
        };
        tracing::info!(
            after_attempts = backoff.failures() + 1,
            "minifilter: connected to the driver"
        );
        lock(stats).on_connect();
        let mut session = Session::new(sink, on_alive, stats, &VolumeMap::from_system);
        let broken = receive_until_broken(&port, &mut buffer, stop, &mut |payload| {
            backoff.on_delivery();
            session.on_payload(payload);
            loss.report_if_due(&lock(stats));
        });
        if !broken {
            return;
        }
        // A connection that never delivered anything is still a failed attempt, so a driver
        // that accepts the connection and then fails every read is not retried in a tight loop.
        let wait = if session.delivered() {
            backoff.wait()
        } else {
            backoff.on_failure()
        };
        sleep_unless_stopped(wait, stop);
    }
}

/// Hands each payload to `on_payload` until the connection breaks (`true`) or `stop` is set
/// (`false`).
fn receive_until_broken(
    port: &DriverPort,
    buffer: &mut ReceiveBuffer,
    stop: &AtomicBool,
    on_payload: &mut dyn FnMut(&[u8]),
) -> bool {
    loop {
        // `port.receive` only notices `stop` on a wait timeout, which a continuous stream of
        // messages never reaches: checking here keeps a delete/rename storm from delaying
        // shutdown (#853 review).
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        match port.receive(buffer, stop) {
            Ok(None) => return false,
            Ok(Some(payload)) => on_payload(payload),
            Err(error) => {
                tracing::warn!(%error, "minifilter: connection lost, reconnecting");
                return true;
            }
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
            truncated_paths = stats.truncated_paths,
            "minifilter: file event loss indicators increased"
        );
        self.lost = lost;
        self.decode_errors = stats.decode_errors;
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
