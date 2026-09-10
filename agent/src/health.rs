//! Agent health beacon — periodic self-diagnostics emitted to the control plane.
//!
//! Not yet wired into the agent main loop — integration pending transport (#24)
//! and spool availability. The module compiles and tests pass; `#[allow(dead_code)]`
//! until the main loop calls `HealthCollector::spawn`.

#![allow(dead_code)]
//!
//! A background thread collects counters from sensors, spool, and enrichment queue,
//! then emits a [`schema::HealthBeacon`] at a fixed cadence. The beacon flows through
//! the normal event pipeline (spool → transport) so it benefits from at-least-once
//! delivery and the server can detect silent agents.
//!
//! "Silence is a detection": an agent that stops beaconing is as suspicious as one
//! that stops sending events.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use schema::{Event, HealthBeacon, SensorHealth};

/// Default beacon interval (30 seconds).
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);

/// Reads the current dropped count from an enrichment queue (or similar bounded queue).
/// The health collector calls this periodically to report backpressure loss.
pub trait DroppedCounter: Send + Sync {
    fn dropped(&self) -> u64;
}

/// A simple atomic counter implementing `DroppedCounter`.
#[derive(Default)]
pub struct AtomicDroppedCounter(AtomicU64);

impl AtomicDroppedCounter {
    pub fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }
}

impl DroppedCounter for AtomicDroppedCounter {
    fn dropped(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Snapshot of sensor health for the beacon.
#[derive(Clone)]
pub struct SensorSnapshot {
    pub name: String,
    pub pulse_count: u64,
    pub silent: bool,
}

/// Reads sensor health snapshots. Implementations may wrap a `SilenceMonitor` or
/// provide mock data for testing.
pub trait SensorHealthSource: Send + Sync {
    fn sensor_health(&self) -> Vec<SensorSnapshot>;
}

/// Reads spool statistics. Implementations may wrap an `EventSpool` or provide
/// mock data for testing.
pub trait SpoolStatsSource: Send + Sync {
    fn spool_bytes(&self) -> u64;
    fn spool_dropped(&self) -> u64;
}

/// A no-op spool stats source for when the spool is not yet available.
pub struct NoopSpoolStats;

impl SpoolStatsSource for NoopSpoolStats {
    fn spool_bytes(&self) -> u64 {
        0
    }
    fn spool_dropped(&self) -> u64 {
        0
    }
}

/// A no-op sensor health source for when sensors are not yet registered.
pub struct NoopSensorHealth;

impl SensorHealthSource for NoopSensorHealth {
    fn sensor_health(&self) -> Vec<SensorSnapshot> {
        Vec::new()
    }
}

/// Configuration for the health collector.
pub struct HealthCollectorConfig {
    /// Interval between beacon emissions.
    pub interval: Duration,
    /// Agent version string.
    pub agent_version: String,
}

impl Default for HealthCollectorConfig {
    fn default() -> Self {
        Self {
            interval: DEFAULT_INTERVAL,
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// Collects health metrics and emits beacons at a fixed cadence.
///
/// The collector runs in a dedicated thread to avoid blocking the sensor drain
/// thread. It reads from various sources (sensors, spool, enrich queue) and
/// emits `Event::HealthBeacon` via the provided callback.
pub struct HealthCollector {
    config: HealthCollectorConfig,
    sensors: Arc<dyn SensorHealthSource>,
    spool: Arc<dyn SpoolStatsSource>,
    enrich_dropped: Arc<dyn DroppedCounter>,
    emit: Box<dyn Fn(Event) + Send>,
    stop: Arc<AtomicBool>,
}

impl HealthCollector {
    /// Creates a new health collector with the given sources.
    pub fn new(
        config: HealthCollectorConfig,
        sensors: Arc<dyn SensorHealthSource>,
        spool: Arc<dyn SpoolStatsSource>,
        enrich_dropped: Arc<dyn DroppedCounter>,
        emit: impl Fn(Event) + Send + 'static,
    ) -> Self {
        Self {
            config,
            sensors,
            spool,
            enrich_dropped,
            emit: Box::new(emit),
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Spawns the collector thread. Returns a handle that can be used to stop
    /// the collector and a `StopHandle` to signal shutdown.
    pub fn spawn(self) -> (JoinHandle<()>, StopHandle) {
        let stop = self.stop.clone();
        let handle = thread::Builder::new()
            .name("health-beacon".into())
            .spawn(move || self.run())
            .expect("spawning the health beacon thread");
        (handle, StopHandle(stop))
    }

    fn run(self) {
        log::info!(
            "health beacon started (interval: {:?})",
            self.config.interval
        );
        while !self.stop.load(Ordering::Relaxed) {
            thread::sleep(self.config.interval);
            if self.stop.load(Ordering::Relaxed) {
                break;
            }
            let beacon = self.collect();
            (self.emit)(Event::HealthBeacon(beacon));
            log::debug!("health beacon emitted");
        }
        log::info!("health beacon stopped");
    }

    fn collect(&self) -> HealthBeacon {
        let sensors: Vec<SensorHealth> = self
            .sensors
            .sensor_health()
            .into_iter()
            .map(|s| SensorHealth {
                name: s.name,
                pulse_count: s.pulse_count,
                silent: s.silent,
            })
            .collect();

        HealthBeacon {
            timestamp_ns: now_ns(),
            agent_version: self.config.agent_version.clone(),
            sensors,
            spool_bytes: self.spool.spool_bytes(),
            spool_dropped: self.spool.spool_dropped(),
            enrich_dropped: self.enrich_dropped.dropped(),
        }
    }
}

/// Handle to stop the health collector.
pub struct StopHandle(Arc<AtomicBool>);

impl StopHandle {
    /// Signals the collector to stop after its current sleep.
    pub fn stop(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Returns the current time in nanoseconds since the UNIX epoch.
fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct MockSensors(Vec<SensorSnapshot>);

    impl SensorHealthSource for MockSensors {
        fn sensor_health(&self) -> Vec<SensorSnapshot> {
            self.0.clone()
        }
    }

    struct MockSpool {
        bytes: u64,
        dropped: u64,
    }

    impl SpoolStatsSource for MockSpool {
        fn spool_bytes(&self) -> u64 {
            self.bytes
        }
        fn spool_dropped(&self) -> u64 {
            self.dropped
        }
    }

    #[test]
    fn collects_health_beacon() {
        let sensors = Arc::new(MockSensors(vec![SensorSnapshot {
            name: "linux-ebpf".into(),
            pulse_count: 1234,
            silent: false,
        }]));
        let spool = Arc::new(MockSpool {
            bytes: 5000,
            dropped: 10,
        });
        let enrich = Arc::new(AtomicDroppedCounter::new());
        enrich.add(5);

        let collected: Arc<Mutex<Vec<Event>>> = Arc::new(Mutex::new(Vec::new()));
        let collected_clone = collected.clone();

        let collector = HealthCollector::new(
            HealthCollectorConfig {
                interval: Duration::from_millis(10),
                agent_version: "0.1.0-test".into(),
            },
            sensors,
            spool,
            enrich,
            move |e| collected_clone.lock().unwrap().push(e),
        );

        let (handle, stop) = collector.spawn();

        // Wait for at least one beacon
        thread::sleep(Duration::from_millis(50));
        stop.stop();
        handle.join().unwrap();

        let events = collected.lock().unwrap();
        assert!(
            !events.is_empty(),
            "should have collected at least one beacon"
        );

        let Event::HealthBeacon(beacon) = &events[0] else {
            panic!("expected HealthBeacon");
        };
        assert_eq!(beacon.agent_version, "0.1.0-test");
        assert_eq!(beacon.sensors.len(), 1);
        assert_eq!(beacon.sensors[0].name, "linux-ebpf");
        assert_eq!(beacon.sensors[0].pulse_count, 1234);
        assert!(!beacon.sensors[0].silent);
        assert_eq!(beacon.spool_bytes, 5000);
        assert_eq!(beacon.spool_dropped, 10);
        assert_eq!(beacon.enrich_dropped, 5);
    }
}
