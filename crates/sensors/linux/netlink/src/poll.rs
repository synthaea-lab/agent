//! [`NetlinkPollSensor`]: the periodic `sock_diag` + conntrack poll as a [`Sensor`].
//! Cadence, failure logging and the heartbeat rule are described in
//! `docs/sensors/linux/netlink.md#the-poller`.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
use schema::sensor::{Capabilities, Sensor, SensorError};
use schema::{Event, sensor::EventSink};

/// Time between two polls. The beacon rule needs three distinct flows inside its 60 s
/// window, so this leaves room for that without dumping the kernel tables every tick.
pub const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// How quickly a stop interrupts the sleep between two polls.
const STOP_CHECK_SLICE: Duration = Duration::from_millis(50);

/// One kernel query of a poll tick, with its own failure streak.
struct PollSource<E> {
    name: &'static str,
    poll: fn(u64) -> Result<Vec<Event>, E>,
    warned: bool,
}

impl<E: std::fmt::Display> PollSource<E> {
    fn new(name: &'static str, poll: fn(u64) -> Result<Vec<Event>, E>) -> Self {
        Self {
            name,
            poll,
            warned: false,
        }
    }

    /// Forwards one poll's events, or logs the error once per failure streak (an
    /// unprivileged agent would otherwise log the same `EPERM` every tick). A
    /// successful poll calls `on_poll_ok` whatever its event count: the poll is the
    /// canary, so silence means the poll fails or the thread is stuck.
    fn poll_once(&mut self, ts: u64, sink: &dyn EventSink, on_poll_ok: &mut dyn FnMut()) {
        match (self.poll)(ts) {
            Ok(events) => {
                self.warned = false;
                on_poll_ok();
                for event in events {
                    sink.on_event(event);
                }
            }
            Err(e) => {
                if !self.warned {
                    self.warned = true;
                    tracing::warn!(
                        source = self.name,
                        error = %e,
                        "netlink poll failed — further identical errors this run are suppressed"
                    );
                }
            }
        }
    }
}

/// The poll loop, generic over the error type so it can be tested off-Linux with
/// fake sources.
struct PollLoop<E> {
    sources: Vec<PollSource<E>>,
    interval: Duration,
    stop: Arc<AtomicBool>,
    on_poll_ok: Box<dyn FnMut() + Send>,
}

impl<E: std::fmt::Display> PollLoop<E> {
    fn run(&mut self, sink: &dyn EventSink) {
        while !self.stop.load(Ordering::SeqCst) {
            let ts = schema::time::now_ns();
            for source in &mut self.sources {
                source.poll_once(ts, sink, &mut *self.on_poll_ok);
            }
            sleep_unless_stopped(&self.stop, self.interval);
        }
    }
}

fn sleep_unless_stopped(stop: &AtomicBool, total: Duration) {
    let deadline = Instant::now() + total;
    while !stop.load(Ordering::SeqCst) {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return;
        }
        thread::sleep(left.min(STOP_CHECK_SLICE));
    }
}

/// Stops a running [`NetlinkPollSensor`] from another thread.
#[derive(Clone)]
pub struct PollStopHandle(Arc<AtomicBool>);

impl PollStopHandle {
    /// Makes `run` return within one stop-check slice.
    pub fn stop(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Polls [`crate::listen_port_events`] then [`crate::conntrack_flow_events`] every
/// [`POLL_INTERVAL`] and forwards the events to the sink.
#[cfg(target_os = "linux")]
pub struct NetlinkPollSensor {
    inner: PollLoop<crate::NetlinkError>,
}

#[cfg(target_os = "linux")]
impl NetlinkPollSensor {
    /// A sensor that calls `on_poll_ok` after each successful kernel query (twice per
    /// tick when both succeed), whether or not the query returned events.
    #[must_use]
    pub fn new(on_poll_ok: impl FnMut() + Send + 'static) -> Self {
        Self {
            inner: PollLoop {
                sources: vec![
                    PollSource::new("listen-port", crate::listen_port_events),
                    PollSource::new("conntrack", crate::conntrack_flow_events),
                ],
                interval: POLL_INTERVAL,
                stop: Arc::new(AtomicBool::new(false)),
                on_poll_ok: Box::new(on_poll_ok),
            },
        }
    }

    /// A handle that stops this sensor while another thread is inside `run`.
    #[must_use]
    pub fn stop_handle(&self) -> PollStopHandle {
        PollStopHandle(Arc::clone(&self.inner.stop))
    }
}

#[cfg(target_os = "linux")]
impl Sensor for NetlinkPollSensor {
    fn name(&self) -> &str {
        "linux-netlink"
    }

    /// `ListenPort` and `NetworkFlow` only; both carry the socket owner's uid and gid.
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            user_attribution: true,
            ..Capabilities::default()
        }
    }

    /// Never fails: a failing query is logged and retried on the next tick.
    fn run(&mut self, sink: Box<dyn EventSink>) -> Result<(), SensorError> {
        self.inner.run(sink.as_ref());
        Ok(())
    }

    fn stop(&mut self) {
        self.stop_handle().stop();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    #[derive(Default)]
    struct Collect(Mutex<Vec<Event>>);

    impl EventSink for Collect {
        fn on_event(&self, event: Event) {
            self.0.lock().unwrap().push(event);
        }
    }

    fn two_listeners(_ts: u64) -> Result<Vec<Event>, String> {
        Ok(vec![
            Event::ListenPort(schema::fixtures::listen_port()),
            Event::ListenPort(schema::fixtures::listen_port()),
        ])
    }

    fn nothing(_ts: u64) -> Result<Vec<Event>, String> {
        Ok(Vec::new())
    }

    fn eperm(_ts: u64) -> Result<Vec<Event>, String> {
        Err("EPERM".into())
    }

    #[test]
    fn a_successful_poll_forwards_every_event_and_pulses_once() {
        let sink = Collect::default();
        let mut pulses = 0;
        PollSource::new("listen-port", two_listeners).poll_once(1, &sink, &mut || pulses += 1);
        assert_eq!(sink.0.lock().unwrap().len(), 2);
        assert_eq!(pulses, 1);
    }

    #[test]
    fn an_empty_poll_still_pulses() {
        let sink = Collect::default();
        let mut pulses = 0;
        PollSource::new("conntrack", nothing).poll_once(1, &sink, &mut || pulses += 1);
        assert!(sink.0.lock().unwrap().is_empty());
        assert_eq!(pulses, 1);
    }

    #[test]
    fn a_failing_poll_does_not_pulse_and_warns_once_per_streak() {
        let sink = Collect::default();
        let mut pulses = 0;
        let mut source = PollSource::new("conntrack", eperm);
        source.poll_once(1, &sink, &mut || pulses += 1);
        assert!(source.warned);
        source.poll_once(2, &sink, &mut || pulses += 1);
        assert!(source.warned);
        assert_eq!(pulses, 0);

        source.poll = nothing;
        source.poll_once(3, &sink, &mut || pulses += 1);
        assert!(!source.warned, "a good poll ends the streak");
        assert_eq!(pulses, 1);
    }

    #[test]
    fn the_loop_polls_every_source_each_tick_and_returns_once_stopped() {
        let sink = Arc::new(Collect::default());
        let pulses = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let counted = Arc::clone(&pulses);
        let mut poll_loop = PollLoop {
            sources: vec![
                PollSource::new("listen-port", two_listeners),
                PollSource::new("conntrack", eperm),
            ],
            interval: Duration::from_secs(60),
            stop: Arc::clone(&stop),
            on_poll_ok: Box::new(move || {
                counted.fetch_add(1, Ordering::SeqCst);
            }),
        };
        let fed = Arc::clone(&sink);
        let worker = thread::spawn(move || poll_loop.run(fed.as_ref()));
        while sink.0.lock().unwrap().len() < 2 {
            thread::sleep(Duration::from_millis(5));
        }
        let started = Instant::now();
        PollStopHandle(stop).stop();
        worker.join().unwrap();

        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(sink.0.lock().unwrap().len(), 2, "one tick before the stop");
        assert_eq!(
            pulses.load(Ordering::SeqCst),
            1,
            "the failing source never pulses"
        );
    }
}
