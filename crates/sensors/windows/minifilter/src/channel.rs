//! The receive loop: connect, read, decode, forward, reconnect (milestone 2c, #136; Windows).
//!
//! One thread runs [`run`] for the agent's lifetime. It connects to the driver, forwards each
//! delete and rename to the sink as `FileDelete`/`FileRename`, calls `on_alive` for every
//! message (heartbeats included, so a wedged driver or sender thread becomes a silence alert,
//! #71), and keeps [`ChannelStats`] current. When the connection breaks (driver unloaded or
//! reloaded) it reconnects with a capped backoff; while the driver is absent nothing is
//! forwarded and `on_alive` is not called, which is exactly the silence the monitor is for.

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
        failures = 0;
        backoff = MIN_BACKOFF;
        lock(stats).on_connect();
        let mut volumes = VolumeMap::from_system();
        let mut last_refresh = Instant::now();
        loop {
            match port.receive(&mut buffer, stop) {
                Ok(None) => return,
                Ok(Some(payload)) => match wire::decode(payload) {
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
                },
                Err(error) => {
                    tracing::warn!(%error, "minifilter: connection lost, reconnecting");
                    break;
                }
            }
        }
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
