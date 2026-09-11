#![allow(dead_code)]
//! Agent health beacon — periodic self-diagnostics emitted to the control plane.
//!
//! A background thread collects counters from sensors, spool, and enrichment queue,
//! then emits a [`schema::HealthBeacon`] at a fixed cadence. The beacon flows through
//! a separate channel (not the Event pipeline) so it doesn't pollute telemetry
//! consumers that expect process metadata.
//!
//! "Silence is a detection": an agent that stops beaconing is as suspicious as one
//! that stops sending events.
//!
//! Not yet wired into the agent main loop — integration pending transport (#24).

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use schema::{HealthBeacon, SensorHealth};

/// Default beacon interval (30 seconds).
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);

/// Reads the current dropped count from an enrichment queue (or similar bounded queue).
/// The health collector calls this periodically to report backpressure loss.
pub trait DroppedCounter: Send + Sync {
    fn dropped(&self) -> u64;
}

/// Reads sensor health snapshots. Implementations may wrap a `SilenceMonitor` or
/// provide mock data for testing.
pub trait SensorHealthSource: Send + Sync {
    fn sensor_health(&self) -> Vec<SensorHealth>;
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
    fn sensor_health(&self) -> Vec<SensorHealth> {
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
/// emits `HealthBeacon` via the provided callback.
///
/// Note: Beacons are emitted separately from telemetry events — they flow through
/// a different channel at the transport layer.
pub struct HealthCollector {
    config: HealthCollectorConfig,
    sensors: Arc<dyn SensorHealthSource>,
    spool: Arc<dyn SpoolStatsSource>,
    enrich_dropped: Arc<dyn DroppedCounter>,
    emit: Box<dyn Fn(HealthBeacon) + Send>,
    stop: Arc<StopFlag>,
}

/// Shared stop flag with condvar for interruptible sleep.
struct StopFlag {
    flag: AtomicBool,
    condvar: std::sync::Condvar,
    mutex: std::sync::Mutex<()>,
}

impl StopFlag {
    fn new() -> Self {
        Self {
            flag: AtomicBool::new(false),
            condvar: std::sync::Condvar::new(),
            mutex: std::sync::Mutex::new(()),
        }
    }

    fn stop(&self) {
        self.flag.store(true, Ordering::SeqCst);
        self.condvar.notify_all();
    }

    fn is_stopped(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Sleeps for the given duration, but wakes early if `stop()` is called.
    fn sleep_interruptible(&self, duration: Duration) {
        let guard = self.mutex.lock().unwrap();
        let _ = self.condvar.wait_timeout(guard, duration);
    }
}

impl HealthCollector {
    /// Creates a new health collector with the given sources.
    pub fn new(
        config: HealthCollectorConfig,
        sensors: Arc<dyn SensorHealthSource>,
        spool: Arc<dyn SpoolStatsSource>,
        enrich_dropped: Arc<dyn DroppedCounter>,
        emit: impl Fn(HealthBeacon) + Send + 'static,
    ) -> Self {
        Self {
            config,
            sensors,
            spool,
            enrich_dropped,
            emit: Box::new(emit),
            stop: Arc::new(StopFlag::new()),
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
        while !self.stop.is_stopped() {
            self.stop.sleep_interruptible(self.config.interval);
            if self.stop.is_stopped() {
                break;
            }
            let beacon = self.collect();
            (self.emit)(beacon);
            log::debug!("health beacon emitted");
        }
        log::info!("health beacon stopped");
    }

    fn collect(&self) -> HealthBeacon {
        HealthBeacon {
            timestamp_ns: crate::time::now_ns(),
            agent_version: self.config.agent_version.clone(),
            sensors: self.sensors.sensor_health(),
            spool_bytes: self.spool.spool_bytes(),
            spool_dropped: self.spool.spool_dropped(),
            enrich_dropped: self.enrich_dropped.dropped(),
        }
    }
}

/// Handle to stop the health collector.
pub struct StopHandle(Arc<StopFlag>);

impl StopHandle {
    /// Signals the collector to stop and wakes it from sleep immediately.
    pub fn stop(&self) {
        self.0.stop();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct MockSensors(Vec<SensorHealth>);

    impl SensorHealthSource for MockSensors {
        fn sensor_health(&self) -> Vec<SensorHealth> {
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

    struct MockDropped(u64);

    impl DroppedCounter for MockDropped {
        fn dropped(&self) -> u64 {
            self.0
        }
    }

    #[test]
    fn collects_health_beacon() {
        let sensors = Arc::new(MockSensors(vec![SensorHealth {
            name: "linux-ebpf".into(),
            pulse_count: 1234,
            silent: false,
        }]));
        let spool = Arc::new(MockSpool {
            bytes: 5000,
            dropped: 10,
        });
        let enrich = Arc::new(MockDropped(5));

        let collected: Arc<Mutex<Vec<HealthBeacon>>> = Arc::new(Mutex::new(Vec::new()));
        let collected_clone = collected.clone();

        let collector = HealthCollector::new(
            HealthCollectorConfig {
                interval: Duration::from_millis(10),
                agent_version: "0.1.0-test".into(),
            },
            sensors,
            spool,
            enrich,
            move |b| collected_clone.lock().unwrap().push(b),
        );

        let (handle, stop) = collector.spawn();

        // Wait for at least one beacon
        thread::sleep(Duration::from_millis(50));
        stop.stop();
        handle.join().unwrap();

        let beacons = collected.lock().unwrap();
        assert!(
            !beacons.is_empty(),
            "should have collected at least one beacon"
        );

        let beacon = &beacons[0];
        assert_eq!(beacon.agent_version, "0.1.0-test");
        assert_eq!(beacon.sensors.len(), 1);
        assert_eq!(beacon.sensors[0].name, "linux-ebpf");
        assert_eq!(beacon.sensors[0].pulse_count, 1234);
        assert!(!beacon.sensors[0].silent);
        assert_eq!(beacon.spool_bytes, 5000);
        assert_eq!(beacon.spool_dropped, 10);
        assert_eq!(beacon.enrich_dropped, 5);
    }

    #[test]
    fn stop_interrupts_sleep() {
        let sensors = Arc::new(NoopSensorHealth);
        let spool = Arc::new(NoopSpoolStats);
        let enrich = Arc::new(MockDropped(0));

        let collector = HealthCollector::new(
            HealthCollectorConfig {
                interval: Duration::from_secs(60), // Long interval
                agent_version: "test".into(),
            },
            sensors,
            spool,
            enrich,
            |_| {},
        );

        let (handle, stop) = collector.spawn();

        // Stop immediately - should not wait 60 seconds
        thread::sleep(Duration::from_millis(10));
        stop.stop();

        // Join should complete quickly
        let start = std::time::Instant::now();
        handle.join().unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "stop should interrupt sleep"
        );
    }
}
