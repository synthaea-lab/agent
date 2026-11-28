//! Puts a sensor's events back in the order they happened.
//!
//! The Linux sensor reads one ring buffer per event type, so events reach the pipeline in
//! the order their buffers were drained, not in the order the kernel stamped them: in the
//! lab about one event in thirteen arrives after a later one, by up to 34 ms. Detection
//! reads state an earlier event set (which image a pid runs, whether it has connected), so an
//! `open` judged before the `exec` that precedes it is judged against the process's previous
//! image. That is wrong in both directions: a false alert on `sudo` reading `/etc/shadow`,
//! and a missed one when the previous image was a trusted program.
//!
//! [`ReorderingSink`] holds each event for [`HOLD`] and releases them by timestamp. An event
//! that arrives later than that behind the newest one is passed on as it is and counted.

use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use schema::{Event, sensor::EventSink};
use workers::sync::LockExt as _;

/// How long an event waits for an earlier one to arrive. Three times the largest lateness
/// measured in the lab (34 ms over 12,000 events, Debian 12, 2026-11-28): **provisional**
/// until it is measured on a loaded host. It is also the latency this stage adds.
pub const HOLD: Duration = Duration::from_millis(100);

/// Most events held at once. Past it the oldest is released early and counted: a burst must
/// cost ordering, never memory.
const CAPACITY: usize = 65_536;

/// One held event. Ordered by timestamp, then by arrival, so two events with one timestamp
/// leave in the order they came.
struct Held {
    timestamp_ns: u64,
    arrival: u64,
    event: Event,
}

impl PartialEq for Held {
    fn eq(&self, other: &Self) -> bool {
        (self.timestamp_ns, self.arrival) == (other.timestamp_ns, other.arrival)
    }
}
impl Eq for Held {}
impl PartialOrd for Held {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Held {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.timestamp_ns, self.arrival).cmp(&(other.timestamp_ns, other.arrival))
    }
}

struct Window {
    held: BinaryHeap<Reverse<Held>>,
    /// The newest timestamp seen: what "old enough to release" is measured against.
    newest_ns: u64,
    /// The newest timestamp already passed on. An arrival older than it is late.
    released_ns: u64,
    arrivals: u64,
    last_arrival: Instant,
}

/// What the stage could not put in order, cumulative. Cloned to whoever reports it: the
/// health beacon is built before the sink that counts.
#[derive(Debug, Clone, Default)]
pub struct ReorderCounters {
    late: Arc<AtomicU64>,
    forced: Arc<AtomicU64>,
}

impl ReorderCounters {
    /// Events that arrived more than the hold behind a later one, and were passed on out of
    /// order.
    #[must_use]
    pub fn late(&self) -> u64 {
        self.late.load(Ordering::Relaxed)
    }

    /// Events released early because the window was full.
    #[must_use]
    pub fn forced(&self) -> u64 {
        self.forced.load(Ordering::Relaxed)
    }
}

/// An [`EventSink`] that passes events to `inner` in timestamp order, [`HOLD`] later.
pub struct ReorderingSink<S> {
    inner: S,
    hold_ns: u64,
    window: Mutex<Window>,
    counters: ReorderCounters,
    stopped: AtomicBool,
}

impl<S: EventSink> ReorderingSink<S> {
    /// Wraps `inner` with the default [`HOLD`].
    pub fn new(inner: S) -> Self {
        Self::holding(inner, HOLD)
    }

    /// Wraps `inner`, holding each event for `hold`.
    pub fn holding(inner: S, hold: Duration) -> Self {
        Self {
            inner,
            hold_ns: u64::try_from(hold.as_nanos()).unwrap_or(u64::MAX),
            window: Mutex::new(Window {
                held: BinaryHeap::new(),
                newest_ns: 0,
                released_ns: 0,
                arrivals: 0,
                last_arrival: Instant::now(),
            }),
            counters: ReorderCounters::default(),
            stopped: AtomicBool::new(false),
        }
    }

    /// Counts into `counters` instead of counters of its own, so a reporter that was built
    /// first reads the same numbers.
    #[must_use]
    pub fn counting_into(mut self, counters: ReorderCounters) -> Self {
        self.counters = counters;
        self
    }

    /// Events that arrived more than the hold behind a later one, and were passed on out of
    /// order.
    pub fn late(&self) -> u64 {
        self.counters.late()
    }

    /// Events released early because the window was full.
    pub fn forced(&self) -> u64 {
        self.counters.forced()
    }

    /// Releases every held event, in order. Called when the stream ends, and by the
    /// flusher when it goes quiet: the newest events have nothing later to push them out.
    pub fn flush(&self) {
        let mut window = self.window.lock_recovering();
        self.release(&mut window, |_| true);
    }

    /// Releases, in order and under the lock, the held events `ready` accepts, stopping at
    /// the first it refuses. Emitting under the lock is what keeps two callers (the sensor
    /// and the flusher) from interleaving their releases.
    fn release(&self, window: &mut Window, ready: impl Fn(&Held) -> bool) {
        while window.held.peek().is_some_and(|Reverse(next)| ready(next)) {
            if let Some(Reverse(next)) = window.held.pop() {
                window.released_ns = window.released_ns.max(next.timestamp_ns);
                self.inner.on_event(next.event);
            }
        }
    }
}

impl<S: EventSink + 'static> ReorderingSink<S> {
    /// Starts the thread that releases what a quiet stream leaves held, and returns the sink
    /// to hand to the sensor. Without it the last events before a pause would wait for the
    /// next event to arrive.
    ///
    /// # Errors
    ///
    /// When the thread cannot be spawned.
    pub fn start(self) -> std::io::Result<Arc<Self>> {
        let sink = Arc::new(self);
        let flusher = Arc::downgrade(&sink);
        let pause = Duration::from_nanos(sink.hold_ns);
        workers::spawn::spawn_named("event-reorder", move || {
            loop {
                std::thread::sleep(pause);
                let Some(sink) = flusher.upgrade() else {
                    return;
                };
                if sink.stopped.load(Ordering::Relaxed) {
                    return;
                }
                let quiet = sink.window.lock_recovering().last_arrival.elapsed() >= pause;
                if quiet {
                    sink.flush();
                }
            }
        })?;
        Ok(sink)
    }

    /// Stops the flusher and releases what is held. For the end of the sensor's run.
    pub fn finish(&self) {
        self.stopped.store(true, Ordering::Relaxed);
        self.flush();
    }
}

impl<S: EventSink> EventSink for ReorderingSink<S> {
    fn on_event(&self, event: Event) {
        let timestamp_ns = event.meta().timestamp_ns;
        let mut window = self.window.lock_recovering();
        window.last_arrival = Instant::now();
        if timestamp_ns < window.released_ns {
            // Later than the hold: its place in the order is already gone.
            self.counters.late.fetch_add(1, Ordering::Relaxed);
            self.inner.on_event(event);
            return;
        }
        window.arrivals += 1;
        let arrival = window.arrivals;
        window.newest_ns = window.newest_ns.max(timestamp_ns);
        window.held.push(Reverse(Held {
            timestamp_ns,
            arrival,
            event,
        }));
        if let Some(horizon) = window.newest_ns.checked_sub(self.hold_ns) {
            self.release(&mut window, |held| held.timestamp_ns <= horizon);
        }
        while window.held.len() > CAPACITY {
            self.counters.forced.fetch_add(1, Ordering::Relaxed);
            let oldest = window.held.peek().map(|Reverse(held)| held.timestamp_ns);
            self.release(&mut window, |held| Some(held.timestamp_ns) == oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder(Mutex<Vec<u64>>);

    impl EventSink for Recorder {
        fn on_event(&self, event: Event) {
            self.0.lock().unwrap().push(event.meta().timestamp_ns);
        }
    }

    fn at(timestamp_ns: u64) -> Event {
        let mut exec = schema::fixtures::exec();
        exec.meta.timestamp_ns = timestamp_ns;
        Event::Exec(exec)
    }

    const MS: u64 = 1_000_000;

    fn sink() -> (Arc<Recorder>, ReorderingSink<Arc<Recorder>>) {
        let recorder = Arc::new(Recorder::default());
        (
            recorder.clone(),
            ReorderingSink::holding(recorder, Duration::from_millis(100)),
        )
    }

    fn seen(recorder: &Recorder) -> Vec<u64> {
        recorder.0.lock().unwrap().clone()
    }

    #[test]
    fn an_event_that_arrives_after_a_later_one_is_passed_on_before_it() {
        let (recorder, sink) = sink();
        sink.on_event(at(50 * MS));
        sink.on_event(at(20 * MS));
        sink.flush();
        assert_eq!(seen(&recorder), vec![20 * MS, 50 * MS]);
    }

    #[test]
    fn an_event_is_held_until_the_stream_has_moved_past_the_hold() {
        let (recorder, sink) = sink();
        sink.on_event(at(10 * MS));
        sink.on_event(at(90 * MS));
        assert!(seen(&recorder).is_empty(), "nothing is 100 ms old yet");
        sink.on_event(at(115 * MS));
        assert_eq!(seen(&recorder), vec![10 * MS], "only the first is");
    }

    #[test]
    fn events_with_one_timestamp_keep_their_arrival_order() {
        let recorder = Arc::new(Mutex::new(Vec::new()));
        struct Comms(Arc<Mutex<Vec<String>>>);
        impl EventSink for Comms {
            fn on_event(&self, event: Event) {
                self.0.lock().unwrap().push(event.meta().comm.clone());
            }
        }
        let sink = ReorderingSink::holding(Comms(recorder.clone()), Duration::from_millis(100));
        for comm in ["first", "second", "third"] {
            let mut exec = schema::fixtures::exec();
            exec.meta.timestamp_ns = 7 * MS;
            exec.meta.comm = comm.into();
            sink.on_event(Event::Exec(exec));
        }
        sink.flush();
        assert_eq!(*recorder.lock().unwrap(), ["first", "second", "third"]);
    }

    #[test]
    fn an_event_later_than_the_hold_is_passed_on_at_once_and_counted() {
        let (recorder, sink) = sink();
        sink.on_event(at(10 * MS));
        sink.on_event(at(300 * MS));
        assert_eq!(seen(&recorder), vec![10 * MS]);
        sink.on_event(at(5 * MS));
        assert_eq!(seen(&recorder), vec![10 * MS, 5 * MS]);
        assert_eq!(sink.late(), 1);
    }

    #[test]
    fn a_full_window_releases_its_oldest_event_and_counts_it() {
        let (recorder, sink) = sink();
        for i in 0..=CAPACITY as u64 {
            // All inside one hold: nothing is released by age.
            sink.on_event(at(i));
        }
        assert_eq!(seen(&recorder), vec![0]);
        assert_eq!(sink.forced(), 1);
    }

    #[test]
    fn counters_handed_in_first_read_what_the_sink_counts() {
        let counters = ReorderCounters::default();
        let recorder = Arc::new(Recorder::default());
        let sink = ReorderingSink::holding(recorder, Duration::from_millis(100))
            .counting_into(counters.clone());
        sink.on_event(at(10 * MS));
        sink.on_event(at(300 * MS));
        sink.on_event(at(5 * MS));
        assert_eq!((counters.late(), counters.forced()), (1, 0));
    }

    #[test]
    fn the_flusher_releases_what_a_quiet_stream_left_held() {
        let recorder = Arc::new(Recorder::default());
        let sink = ReorderingSink::holding(recorder.clone(), Duration::from_millis(20))
            .start()
            .unwrap();
        sink.on_event(at(10 * MS));
        let deadline = Instant::now() + Duration::from_secs(5);
        while seen(&recorder).is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(seen(&recorder), vec![10 * MS]);
        sink.finish();
    }
}
