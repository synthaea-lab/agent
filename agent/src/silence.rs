//! Sensor-silence detection (issue #71) — wires `tamper::heartbeat`'s already-tested
//! primitives into the agent: each sensor pulses a [`SensorHeartbeat`] as it
//! processes events, a dedicated thread polls a shared [`SilenceMonitor`] and turns
//! every stall it confirms into a real alert (not just a health-beacon metric), and
//! [`SilenceHealthSource`] feeds the same monitor's live snapshot to the existing
//! health beacon (#134) in place of `health::NoopSensorHealth`.
//!
//! "Silence is a detection": an attacker who detaches a sensor (stops an eBPF
//! program, kills the netlink poller thread's ability to make progress) without
//! killing the agent process leaves no crash for the watchdog to catch — this is
//! what catches that instead. See `tamper::heartbeat`'s own doc for the F-2 lesson
//! this generalizes and the honest limitation repeated on [`PulsingSink`] below.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use schema::{Event, sensor::EventSink};
use tamper::heartbeat::{SensorHeartbeat, SilenceMonitor};

use crate::{health::SensorHealthSource, sink::DetectionSink};

/// How often the dedicated monitor thread checks every registered heartbeat against
/// its deadline. Independent of the health beacon's own (much longer) cadence —
/// silence should turn into an alert quickly, not wait for the next beacon tick.
pub(crate) const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Wraps an inner [`EventSink`], pulsing `heartbeat` before forwarding every event.
///
/// Honest limitation (matches `tamper::heartbeat`'s own doc): the eBPF sensor has
/// no self-generated canary the way the Windows ETW sensor's periodic temp-file
/// write does (audit F-2), so this can only prove "this sensor produced nothing for
/// a whole deadline window" — on a genuinely idle host that is indistinguishable
/// from a detached probe. Real hosts are not perfectly idle (cron, the agent's own
/// activity, incidental network traffic), so the deadline is set generously rather
/// than tightened with a synthetic canary, which is tracked as a gap, not solved
/// here.
pub(crate) struct PulsingSink<S> {
    inner: S,
    heartbeat: SensorHeartbeat,
}

impl<S> PulsingSink<S> {
    pub(crate) fn new(inner: S, heartbeat: SensorHeartbeat) -> Self {
        Self { inner, heartbeat }
    }
}

impl<S: EventSink> EventSink for PulsingSink<S> {
    fn on_event(&self, event: Event) {
        self.heartbeat.pulse();
        self.inner.on_event(event);
    }
}

/// Feeds a shared [`SilenceMonitor`]'s current snapshot to the health beacon
/// (#134) — a real replacement for `health::NoopSensorHealth`.
pub(crate) struct SilenceHealthSource(Arc<Mutex<SilenceMonitor>>);

impl SilenceHealthSource {
    pub(crate) fn new(monitor: Arc<Mutex<SilenceMonitor>>) -> Self {
        Self(monitor)
    }
}

impl SensorHealthSource for SilenceHealthSource {
    fn sensor_health(&self) -> Vec<schema::SensorHealth> {
        self.0.lock().unwrap().sensor_health()
    }
}

/// Spawns the thread that polls `monitor` on [`POLL_INTERVAL`] and turns every
/// newly confirmed [`tamper::heartbeat::SilenceVerdict`] into a real alert through
/// `sink.emit` — the same `alerts.ndjson` line shape as any rule/correlator/Sigma
/// finding (issue #71's "Done when: stopping a sensor... produces a local alert").
/// Runs until the process exits, same as every other background worker in
/// `commands::linux` (no `Sensor::stop`-style shutdown exists for `agent run` today).
pub(crate) fn spawn_monitor(monitor: Arc<Mutex<SilenceMonitor>>, sink: Arc<DetectionSink>) {
    std::thread::Builder::new()
        .name("sensor-silence".into())
        .spawn(move || {
            loop {
                std::thread::sleep(POLL_INTERVAL);
                let verdicts = monitor.lock().unwrap().poll(schema::time::now_ns());
                for verdict in verdicts {
                    sink.emit("T1562", &verdict.message());
                }
            }
        })
        .expect("spawning the sensor-silence monitor thread");
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct CountingSink(Arc<AtomicUsize>);

    impl EventSink for CountingSink {
        fn on_event(&self, _event: Event) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn exec_event() -> Event {
        Event::Exec(schema::ExecEvent {
            meta: schema::EventMeta {
                pid: 1,
                ppid: 0,
                user: schema::User::Unknown,
                timestamp_ns: 0,
                comm: String::new(),
                container: None,
            },
            image_path: String::new(),
            cmdline: String::new(),
            argv: vec![],
            parent_comm: None,
            parent_image_path: None,
            sha256: None,
            signature: None,
        })
    }

    #[test]
    fn pulsing_sink_pulses_and_forwards() {
        let count = Arc::new(AtomicUsize::new(0));
        let heartbeat = SensorHeartbeat::new("test-sensor");
        let pulsing = PulsingSink::new(CountingSink(count.clone()), heartbeat.clone());

        pulsing.on_event(exec_event());
        pulsing.on_event(exec_event());

        assert_eq!(
            count.load(Ordering::Relaxed),
            2,
            "events must still reach the inner sink"
        );
        assert_eq!(
            heartbeat.pulse_count(),
            2,
            "each event must pulse the heartbeat"
        );
    }

    #[test]
    fn silence_health_source_reflects_the_shared_monitor() {
        let monitor = Arc::new(Mutex::new(SilenceMonitor::new()));
        let hb = SensorHeartbeat::new("linux-ebpf");
        monitor.lock().unwrap().register(hb.clone(), 1, 0);
        hb.pulse();

        let source = SilenceHealthSource::new(monitor);
        let health = source.sensor_health();
        assert_eq!(health.len(), 1);
        assert_eq!(health[0].name, "linux-ebpf");
        assert_eq!(health[0].pulse_count, 1);
    }
}
