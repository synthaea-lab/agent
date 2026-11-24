//! Sensor-silence detection — the enforcement of the self-protection invariant
//! "silence is a detection" (`docs/architecture/threat-model.md`, §2).
//!
//! An adversary who cannot beat the detections tries to switch a sensor off instead:
//! stop the ETW session, detach an eBPF program, suspend the agent so it is alive
//! (no respawn fires) but frozen. Each of those produces the same observable —
//! telemetry stops — and this module turns that observable into an alert.
//!
//! ## Shape
//!
//! - Each sensor holds a [`SensorHeartbeat`] and [`pulse`](SensorHeartbeat::pulse)es
//!   it as events flow. A pulse is one relaxed atomic increment: cheap enough to sit
//!   on the hot event path.
//! - A [`SilenceMonitor`] — run from the **watchdog** or a thread not subject to the
//!   same freeze as the sensor it watches — polls the shared counters. A counter that
//!   has not advanced within its deadline is a [`SilenceVerdict`]: that sensor has
//!   gone dark.
//!
//! ## Determinism (the F-2 lesson)
//!
//! A healthy sensor on an *idle* host produces no events, which is indistinguishable
//! from a blinded one. The Windows sensor solved this (audit F-2) with a canary: it
//! writes its own temp file every interval, which *must* produce a Kernel-File event,
//! so a healthy sensor pulses even when the host is quiet. This module is the
//! platform-agnostic half — the counting and the deadline — and expects each sensor
//! to keep its heartbeat live by whatever canary its platform needs. Where a sensor
//! cannot self-generate traffic, the monitor still catches a *total* stall; the
//! canary is what tightens "no events" into "no events despite guaranteed activity".

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

/// A sensor's liveness counter. Cloneable: the sensor keeps one and pulses it, the
/// [`SilenceMonitor`] keeps another and reads it. Reads and writes are `Relaxed` —
/// the monitor only needs the value to *eventually* reflect a live sensor, and a
/// pulse must be as close to free as possible on the event path.
#[derive(Clone)]
pub struct SensorHeartbeat {
    name: &'static str,
    counter: Arc<AtomicU64>,
}

impl SensorHeartbeat {
    /// Creates a heartbeat for a sensor named `name` (stable, e.g. `"linux-ebpf"`,
    /// `"windows-etw"` — the string that will name it in a [`SilenceVerdict`]).
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            counter: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Wraps a liveness counter a sensor already owns, for a sensor crate that
    /// may not depend on `tamper` (`sensor-*` crates depend only on `schema`,
    /// see `tools/check-deps.py`): the sensor exposes a plain `Arc<AtomicU64>` it
    /// increments, and the binary — the one place both crates are in scope —
    /// turns it into a heartbeat here. Same semantics as [`Self::pulse`]: every
    /// increment of `counter` is a pulse.
    #[must_use]
    pub fn from_counter(name: &'static str, counter: Arc<AtomicU64>) -> Self {
        Self { name, counter }
    }

    /// Records liveness — call it as events are produced (and from the canary tick,
    /// so an idle-but-healthy sensor still advances). One relaxed atomic add.
    pub fn pulse(&self) {
        self.counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Records `n` units of liveness at once — for a sensor that drains a batch and
    /// would rather pulse once per batch than once per event.
    pub fn pulse_n(&self, n: u64) {
        self.counter.fetch_add(n, Ordering::Relaxed);
    }

    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the current pulse count. Used by the health beacon (#134) to report
    /// per-sensor liveness to the control plane.
    #[must_use]
    pub fn pulse_count(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
    }

    fn count(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
    }
}

/// One sensor's watch state inside the monitor.
struct Watched {
    heartbeat: SensorHeartbeat,
    /// A stall longer than this is silence.
    deadline_ns: u64,
    /// Count observed at the last poll where it had advanced.
    last_count: u64,
    /// Timestamp of that last advance — the clock the deadline runs against.
    last_change_ns: u64,
    /// One verdict per silence episode: set when we report, cleared when the sensor
    /// recovers, so a persistently dark sensor does not re-alert every poll.
    alerted: bool,
}

/// A sensor confirmed silent: its counter has not advanced within its deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SilenceVerdict {
    /// The sensor's stable name (from [`SensorHeartbeat::new`]).
    pub sensor: &'static str,
    /// How long it had been silent when the verdict fired.
    pub silent_for_ns: u64,
    /// The deadline it breached — included so the consumer can log both.
    pub deadline_ns: u64,
}

impl SilenceVerdict {
    /// A ready-to-log line; the caller decides the severity and destination (this
    /// crate stays free of the detection/sink types by design — it is a LEAF crate).
    #[must_use]
    pub fn message(&self) -> String {
        format!(
            "sensor `{}` produced no telemetry for {:.1}s (deadline {:.1}s) — \
             stopped, detached, or the agent is frozen",
            self.sensor,
            self.silent_for_ns as f64 / 1e9,
            self.deadline_ns as f64 / 1e9,
        )
    }
}

/// Watches a set of sensor heartbeats and reports the ones that have gone dark.
///
/// Intended to be driven by the **watchdog**, or by a dedicated agent thread that a
/// suspend of the sensor threads would not also freeze — a monitor sharing the fate
/// of what it watches cannot report on it. Poll it on a fixed cadence; feed it a
/// monotonic clock in nanoseconds.
pub struct SilenceMonitor {
    watched: Vec<Watched>,
}

impl SilenceMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            watched: Vec::new(),
        }
    }

    /// Registers a heartbeat with the deadline past which a stall is silence.
    /// `now_ns` seeds the stall clock, so a sensor that never pulses is caught one
    /// deadline after registration rather than never.
    pub fn register(&mut self, heartbeat: SensorHeartbeat, deadline_ns: u64, now_ns: u64) {
        let last_count = heartbeat.count();
        self.watched.push(Watched {
            heartbeat,
            deadline_ns,
            last_count,
            last_change_ns: now_ns,
            alerted: false,
        });
    }

    /// Polls every watched sensor and returns a verdict for each one newly confirmed
    /// silent. A sensor whose counter advanced since the last poll resets its clock
    /// (and clears any prior alert); one that has been static past its deadline
    /// reports **once** per silence episode.
    pub fn poll(&mut self, now_ns: u64) -> Vec<SilenceVerdict> {
        let mut verdicts = Vec::new();
        for w in &mut self.watched {
            let count = w.heartbeat.count();
            if count != w.last_count {
                w.last_count = count;
                w.last_change_ns = now_ns;
                w.alerted = false;
                continue;
            }
            let silent_for = now_ns.saturating_sub(w.last_change_ns);
            if silent_for > w.deadline_ns && !w.alerted {
                w.alerted = true;
                verdicts.push(SilenceVerdict {
                    sensor: w.heartbeat.name(),
                    silent_for_ns: silent_for,
                    deadline_ns: w.deadline_ns,
                });
            }
        }
        verdicts
    }

    /// True while any watched sensor is currently in a reported-silent state — a
    /// cheap health gate for the watchdog to consult before deciding to restart.
    #[must_use]
    pub fn any_silent(&self) -> bool {
        self.watched.iter().any(|w| w.alerted)
    }

    /// Returns the health status of each registered sensor. Used by the health
    /// beacon (#134) to report per-sensor state to the control plane.
    #[must_use]
    pub fn sensor_health(&self) -> Vec<schema::SensorHealth> {
        self.watched
            .iter()
            .map(|w| schema::SensorHealth {
                name: w.heartbeat.name().to_string(),
                pulse_count: w.heartbeat.pulse_count(),
                silent: w.alerted,
            })
            .collect()
    }
}

impl Default for SilenceMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: u64 = 1_000_000_000;

    #[test]
    fn a_heartbeat_from_an_external_counter_sees_its_increments() {
        let counter = Arc::new(AtomicU64::new(0));
        let hb = SensorHeartbeat::from_counter("windows-eventlog:logon", Arc::clone(&counter));
        let mut mon = SilenceMonitor::new();
        mon.register(hb.clone(), 30 * SEC, 0);
        counter.fetch_add(1, Ordering::Relaxed);
        assert!(mon.poll(40 * SEC).is_empty(), "the increment is a pulse");
        assert_eq!(hb.pulse_count(), 1);
        assert_eq!(mon.poll(80 * SEC).len(), 1, "no further increment: silent");
    }

    #[test]
    fn a_pulsing_sensor_is_never_silent() {
        let hb = SensorHeartbeat::new("linux-ebpf");
        let mut mon = SilenceMonitor::new();
        mon.register(hb.clone(), 30 * SEC, 0);
        // Pulse and poll across several deadlines.
        for t in (0..120 * SEC).step_by(10 * SEC as usize) {
            hb.pulse();
            assert!(mon.poll(t).is_empty(), "healthy sensor flagged at t={t}");
        }
    }

    #[test]
    fn a_stalled_sensor_is_reported_once_per_episode() {
        let hb = SensorHeartbeat::new("windows-etw");
        let mut mon = SilenceMonitor::new();
        hb.pulse();
        mon.register(hb.clone(), 30 * SEC, 0);

        // Within the deadline: quiet.
        assert!(mon.poll(20 * SEC).is_empty());
        // Past the deadline with no pulse: one verdict.
        let v = mon.poll(31 * SEC);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].sensor, "windows-etw");
        assert!(v[0].silent_for_ns > 30 * SEC);
        // Still silent: no repeat.
        assert!(
            mon.poll(60 * SEC).is_empty(),
            "must not re-alert every poll"
        );
    }

    #[test]
    fn recovery_clears_the_alert_and_re_arms() {
        let hb = SensorHeartbeat::new("s");
        let mut mon = SilenceMonitor::new();
        mon.register(hb.clone(), 10 * SEC, 0);

        // Go silent → reported.
        assert_eq!(mon.poll(11 * SEC).len(), 1);
        assert!(mon.any_silent());
        // Sensor recovers.
        hb.pulse();
        assert!(mon.poll(12 * SEC).is_empty());
        assert!(!mon.any_silent(), "recovery must clear the silent state");
        // A second silence episode is reported again.
        assert_eq!(mon.poll(23 * SEC).len(), 1, "must re-arm after recovery");
    }

    #[test]
    fn a_sensor_that_never_pulses_is_caught_after_registration() {
        // A sensor blinded before it ever produced an event: registered at count 0,
        // never advances → silent one deadline after registration, not never.
        let hb = SensorHeartbeat::new("dead-on-arrival");
        let mut mon = SilenceMonitor::new();
        mon.register(hb, 30 * SEC, 5 * SEC);
        assert!(mon.poll(30 * SEC).is_empty(), "still within deadline");
        assert_eq!(
            mon.poll(36 * SEC).len(),
            1,
            "caught one deadline after start"
        );
    }

    #[test]
    fn independent_sensors_are_tracked_independently() {
        let live = SensorHeartbeat::new("live");
        let dark = SensorHeartbeat::new("dark");
        let mut mon = SilenceMonitor::new();
        mon.register(live.clone(), 30 * SEC, 0);
        mon.register(dark, 30 * SEC, 0);

        live.pulse();
        let v = mon.poll(31 * SEC);
        assert_eq!(v.len(), 1, "only the dark sensor is reported");
        assert_eq!(v[0].sensor, "dark");
    }

    #[test]
    fn verdict_message_names_the_sensor_and_durations() {
        let v = SilenceVerdict {
            sensor: "windows-etw",
            silent_for_ns: 31 * SEC,
            deadline_ns: 30 * SEC,
        };
        let m = v.message();
        assert!(m.contains("windows-etw"));
        assert!(m.contains("31.0s"));
        assert!(m.contains("30.0s"));
    }
}
