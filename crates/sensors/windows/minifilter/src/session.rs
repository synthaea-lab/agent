//! What the receive loop does between a connect and a disconnect, and how long it waits
//! before the next attempt (milestone 2c, #136).
//!
//! Portable apart from the drive-table read, which the caller injects, so the per-message
//! accounting and the backoff schedule are tested on every OS.

use std::{
    sync::{Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use schema::sensor::EventSink;

use crate::{
    events::{VolumeMap, to_event},
    stats::ChannelStats,
    wire::{self, Counters, Message},
};

/// First reconnect delay; doubled after each failed attempt up to [`MAX_BACKOFF`].
const MIN_BACKOFF: Duration = Duration::from_secs(1);
/// Longest wait between two connection attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Shortest interval between two volume-map refreshes on a normalisation miss (a newly
/// mounted volume appears without a restart, but a burst of misses rereads the table once).
const VOLUME_REFRESH: Duration = Duration::from_secs(30);

/// The reconnect schedule. A failed attempt (no connection, or a connection that broke before
/// delivering anything) doubles the wait; a delivered message resets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Backoff {
    delay: Duration,
    failures: u64,
}

impl Backoff {
    pub(crate) fn new() -> Self {
        Self {
            delay: MIN_BACKOFF,
            failures: 0,
        }
    }

    /// Counts a failed attempt and returns how long to wait before the next one; the wait
    /// after that is twice as long, up to [`MAX_BACKOFF`].
    pub(crate) fn on_failure(&mut self) -> Duration {
        self.failures += 1;
        let wait = self.delay;
        self.delay = (self.delay * 2).min(MAX_BACKOFF);
        wait
    }

    /// A connection delivered a message: the schedule restarts at the shortest wait.
    pub(crate) fn on_delivery(&mut self) {
        self.failures = 0;
        self.delay = MIN_BACKOFF;
    }

    /// The wait before the next attempt, without counting a failure.
    pub(crate) fn wait(&self) -> Duration {
        self.delay
    }

    /// Failed attempts since the last delivered message.
    pub(crate) fn failures(&self) -> u64 {
        self.failures
    }
}

/// One connection's receive state: decodes each payload, keeps the stats, forwards the event.
pub(crate) struct Session<'a> {
    sink: &'a dyn EventSink,
    on_alive: &'a dyn Fn(),
    stats: &'a Mutex<ChannelStats>,
    load_volumes: &'a dyn Fn() -> VolumeMap,
    volumes: VolumeMap,
    last_refresh: Instant,
    delivered: bool,
}

/// What one decoded message changed in the stats, read under the lock and logged after it.
struct Accounted {
    lost: u64,
    truncated_paths: Option<u64>,
    baseline: Option<Counters>,
}

impl<'a> Session<'a> {
    /// A new connection: reads the drive table once with `load_volumes`.
    pub(crate) fn new(
        sink: &'a dyn EventSink,
        on_alive: &'a dyn Fn(),
        stats: &'a Mutex<ChannelStats>,
        load_volumes: &'a dyn Fn() -> VolumeMap,
    ) -> Self {
        Self {
            sink,
            on_alive,
            stats,
            load_volumes,
            volumes: load_volumes(),
            last_refresh: Instant::now(),
            delivered: false,
        }
    }

    /// Whether this connection delivered at least one payload, decodable or not.
    pub(crate) fn delivered(&self) -> bool {
        self.delivered
    }

    /// One payload from the driver: a decoded message calls `on_alive` and reaches the sink
    /// unless it is a heartbeat or has a cut path; a refused one is only counted.
    pub(crate) fn on_payload(&mut self, payload: &[u8]) {
        self.delivered = true;
        match wire::decode(payload) {
            Ok(message) => self.on_message(&message),
            Err(error) => {
                let mut stats = lock(self.stats);
                stats.on_decode_error();
                if stats.decode_errors.is_power_of_two() {
                    tracing::warn!(%error, refused = stats.decode_errors, "minifilter: message refused by the decoder");
                }
            }
        }
    }

    fn on_message(&mut self, message: &Message) {
        (self.on_alive)();
        let accounted = self.account(message);
        if let Some(counters) = accounted.baseline {
            log_driver_baseline(&counters);
        }
        if accounted.lost > 0 {
            tracing::warn!(
                lost = accounted.lost,
                seq = message.seq,
                "minifilter: records missing before this one"
            );
        }
        if let Some(count) = accounted.truncated_paths.filter(|n| n.is_power_of_two()) {
            tracing::warn!(
                truncated_paths = count,
                "minifilter: event with a cut path was not forwarded"
            );
        }
        self.refresh_volumes_if_due(message, Instant::now());
        if let Some(event) = to_event(message, &self.volumes) {
            self.sink.on_event(event);
        }
    }

    fn account(&self, message: &Message) -> Accounted {
        let mut stats = lock(self.stats);
        let first_message = stats.received == 0;
        let lost = stats.on_message(message);
        let truncated_paths = message.body.has_truncated_path().then(|| {
            stats.on_truncated_path();
            stats.truncated_paths
        });
        Accounted {
            lost,
            truncated_paths,
            baseline: first_message.then_some(stats.driver),
        }
    }

    /// Rereads the drive table when `message` has a path the map did not translate, at most
    /// once per [`VOLUME_REFRESH`].
    fn refresh_volumes_if_due(&mut self, message: &Message, now: Instant) {
        if needs_refresh(message) && now.duration_since(self.last_refresh) >= VOLUME_REFRESH {
            self.volumes = (self.load_volumes)();
            self.last_refresh = now;
        }
    }
}

/// The driver's counters at the agent's first message: a baseline, since they count from the
/// driver's load and may predate this agent.
fn log_driver_baseline(counters: &Counters) {
    tracing::info!(
        queue_full = counters.dropped_queue_full,
        send_failed = counters.dropped_send_failed,
        not_connected = counters.not_connected,
        capture_failed = counters.dropped_capture_failed,
        "minifilter: driver counters at first message (may predate this agent)"
    );
}

/// Whether a message carries a device path the current map did not translate: the only case
/// worth rereading the drive table for.
fn needs_refresh(message: &Message) -> bool {
    let unmapped = |path: &str| {
        path.get(..8)
            .is_some_and(|head| head.eq_ignore_ascii_case(r"\Device\"))
    };
    match &message.body {
        wire::Body::Delete { path, .. } => unmapped(path),
        wire::Body::Rename {
            old_path, new_path, ..
        } => unmapped(old_path) || unmapped(new_path),
        wire::Body::SetTime { path, .. } => unmapped(path),
        wire::Body::RawVolumeOpen { volume, .. } => unmapped(volume),
        wire::Body::Heartbeat => false,
    }
}

/// The stats lock: a poisoned lock still holds valid counters (plain integers), so it is used
/// rather than propagating a panic into the receive thread.
pub(crate) fn lock(stats: &Mutex<ChannelStats>) -> MutexGuard<'_, ChannelStats> {
    stats.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, sync::Mutex as StdMutex};

    use schema::Event;

    use super::*;
    use crate::wire::Body;

    #[derive(Default)]
    struct Collect(StdMutex<Vec<Event>>);

    impl EventSink for Collect {
        fn on_event(&self, event: Event) {
            self.0.lock().unwrap().push(event);
        }
    }

    impl Collect {
        fn paths(&self) -> Vec<String> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .map(|event| match event {
                    Event::FileDelete(d) => d.path.clone(),
                    other => panic!("unexpected event {other:?}"),
                })
                .collect()
        }
    }

    fn volumes() -> VolumeMap {
        VolumeMap::from_pairs([(r"\Device\HarddiskVolume1".to_owned(), "C:".to_owned())])
    }

    fn message(seq: u64, body: Body) -> Message {
        Message {
            seq,
            timestamp_ns: 0,
            pid: 4,
            tid: 8,
            counters: Counters::default(),
            body,
        }
    }

    fn delete(path: &str, truncated: bool) -> Body {
        Body::Delete {
            path: path.into(),
            on_close: false,
            truncated,
        }
    }

    fn payload(seq: u64, body: Body) -> Vec<u8> {
        wire::encode(&message(seq, body), 116_444_736_000_000_000)
    }

    #[test]
    fn the_backoff_doubles_on_each_failure_up_to_the_cap() {
        let mut backoff = Backoff::new();
        let waits: Vec<u64> = (0..7).map(|_| backoff.on_failure().as_secs()).collect();
        assert_eq!(waits, [1, 2, 4, 8, 16, 30, 30]);
        assert_eq!(backoff.failures(), 7);
        assert_eq!(backoff.wait(), MAX_BACKOFF);
    }

    #[test]
    fn a_delivery_restarts_the_backoff_at_the_shortest_wait() {
        let mut backoff = Backoff::new();
        backoff.on_failure();
        backoff.on_failure();
        backoff.on_delivery();
        assert_eq!(backoff, Backoff::new());
        assert_eq!(backoff.wait(), MIN_BACKOFF);
        assert_eq!(backoff.on_failure(), MIN_BACKOFF);
    }

    #[test]
    fn a_decoded_delete_is_forwarded_normalised_and_counted() {
        let sink = Collect::default();
        let alive = Cell::new(0);
        let on_alive = || alive.set(alive.get() + 1);
        let stats = Mutex::new(ChannelStats::default());
        let mut session = Session::new(&sink, &on_alive, &stats, &volumes);
        assert!(!session.delivered());
        session.on_payload(&payload(1, delete(r"\Device\HarddiskVolume1\a.txt", false)));
        session.on_payload(&payload(2, Body::Heartbeat));
        assert!(session.delivered());
        assert_eq!(sink.paths(), [r"C:\a.txt"]);
        assert_eq!(alive.get(), 2);
        let stats = *lock(&stats);
        assert_eq!((stats.received, stats.heartbeats), (2, 1));
    }

    #[test]
    fn a_cut_path_is_counted_but_not_forwarded() {
        let sink = Collect::default();
        let stats = Mutex::new(ChannelStats::default());
        let mut session = Session::new(&sink, &|| {}, &stats, &volumes);
        session.on_payload(&payload(1, delete(r"\Device\HarddiskVolume1\a.txt", true)));
        assert!(sink.paths().is_empty());
        assert_eq!(lock(&stats).truncated_paths, 1);
    }

    #[test]
    fn a_refused_payload_is_counted_without_calling_on_alive() {
        let sink = Collect::default();
        let alive = Cell::new(0);
        let on_alive = || alive.set(alive.get() + 1);
        let stats = Mutex::new(ChannelStats::default());
        let mut session = Session::new(&sink, &on_alive, &stats, &volumes);
        session.on_payload(&[0u8; 3]);
        assert!(session.delivered());
        assert_eq!(alive.get(), 0);
        let stats = *lock(&stats);
        assert_eq!((stats.decode_errors, stats.received), (1, 0));
        assert!(sink.paths().is_empty());
    }

    #[test]
    fn an_unmapped_device_path_rereads_the_drive_table_at_most_once_per_interval() {
        let sink = Collect::default();
        let stats = Mutex::new(ChannelStats::default());
        let loads = Cell::new(0);
        let load = || {
            loads.set(loads.get() + 1);
            volumes()
        };
        let mut session = Session::new(&sink, &|| {}, &stats, &load);
        assert_eq!(loads.get(), 1);
        let unmapped = message(1, delete(r"\Device\HarddiskVolume9\a.txt", false));
        let start = session.last_refresh;
        session.refresh_volumes_if_due(&unmapped, start + VOLUME_REFRESH / 2);
        assert_eq!(loads.get(), 1);
        session.refresh_volumes_if_due(&unmapped, start + VOLUME_REFRESH);
        assert_eq!(loads.get(), 2);
        session.refresh_volumes_if_due(&unmapped, start + VOLUME_REFRESH + VOLUME_REFRESH / 2);
        assert_eq!(loads.get(), 2);
        let mapped = message(2, delete(r"C:\a.txt", false));
        session.refresh_volumes_if_due(&mapped, start + 3 * VOLUME_REFRESH);
        assert_eq!(loads.get(), 2);
    }
}
