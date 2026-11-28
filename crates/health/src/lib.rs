//! Agent health beacon — periodic self-diagnostics emitted to the control plane.
//!
//! A background thread collects counters from sensors, spool, and enrichment queue,
//! then emits a [`schema::HealthBeacon`] at a fixed cadence. The beacon flows through
//! a separate channel (not the Event pipeline) so it doesn't pollute telemetry
//! consumers that expect process metadata.
//!
//! "Silence is a detection": an agent that stops beaconing is as suspicious as one
//! that stops sending events.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use schema::{HealthBeacon, SensorHealth};
use workers::sync::{CondvarExt, LockExt};

/// Default beacon interval (30 seconds).
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);

/// Reads the current dropped count from an enrichment queue (or similar bounded queue).
/// The health collector calls this periodically to report backpressure loss.
pub trait DroppedCounter: Send + Sync {
    /// Items dropped since the agent started.
    fn dropped(&self) -> u64;
}

/// Cumulative counts of the rarity evidence (issue #76): what the fleet's common set
/// let the correlator learn about executed images, and what it could not.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RarityCounts {
    /// Evidence added to a process belief.
    pub applied: u64,
    /// Executions the evidence could not judge (no snapshot, too few hosts, no usable hash).
    pub withheld: u64,
    /// Rare images whose evidence found no belief to land on.
    pub unapplied: u64,
}

/// Reads the rarity evidence counters. The sink implements it over its own atomics.
pub trait RarityStatsSource: Send + Sync {
    /// The counters as they stand now.
    fn rarity_counts(&self) -> RarityCounts;
}

/// Cumulative counters the beacon takes from outside the sink's rarity statistics, the spool and
/// the silence monitor (#863): see `crate::host_counters` for what each one counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HostCounters {
    /// Times the watchdog restarted the agent since the watchdog started.
    pub watchdog_restarts: u64,
    /// Tamper-class alerts raised since the agent started, plus the watchdog's own events.
    pub tamper_events: u64,
    /// Parent-image cache entries the cap dropped while their process was alive (the loss).
    pub parent_image_evicted_live: u64,
    /// Entries the cap dropped whose process had already exited (nothing lost).
    pub parent_image_evicted_dead: u64,
    /// Indicators in force in the on-device IOC set (a gauge, #60).
    pub ioc_indicators: u64,
    /// IOC matches that raised a finding.
    pub ioc_findings: u64,
    /// IOC matches the per-indicator cooldown absorbed.
    pub ioc_cooled_down: u64,
    /// IOC matches skipped as the agent's own control-plane traffic, by the agent (<https://github.com/synthaea-lab/agent/issues/47>).
    pub ioc_own_skipped: u64,
    /// The same, by a second process on the agent's executable.
    pub ioc_sibling_skipped: u64,
    /// Alerts that could not be written to `alerts.ndjson`.
    pub alerts_dropped: u64,
    /// Events the Linux eBPF probes lost to full ring buffers, every ring (#335).
    pub ring_dropped: u64,
    /// The part of it lost from the exec ring.
    pub exec_ring_dropped: u64,
    /// Events the Linux reordering stage passed on out of order (later than its hold).
    pub reorder_late: u64,
    /// Events that stage released early because its window was full.
    pub reorder_forced: u64,
    /// Windows ETW pid-cache entries the cap dropped (#178).
    pub etw_pid_cache_evicted: u64,
    /// Windows ETW silo-directory entries the cap dropped.
    pub etw_silo_evicted: u64,
    /// `Zone.Identifier` marks the read-back queue dropped.
    pub etw_marks_dropped: u64,
    /// Quarantine paths reported without dedup (the map was full).
    pub etw_quarantine_unremembered: u64,
    /// Windows ETW registry writes reported with their key unresolved (#91).
    pub etw_registry_unresolved_writes: u64,
    /// Windows ETW registry key objects the key table dropped.
    pub etw_registry_keys_evicted: u64,
    /// Windows ETW registry key names cut to the length bound.
    pub etw_registry_names_truncated: u64,
}

/// Reads the [`HostCounters`].
pub trait HostCountersSource: Send + Sync {
    /// The counters as they stand now.
    fn host_counters(&self) -> HostCounters;
}

/// Reads sensor health snapshots. Implementations may wrap a `SilenceMonitor` or
/// provide mock data for testing.
pub trait SensorHealthSource: Send + Sync {
    /// One entry per sensor the agent runs.
    fn sensor_health(&self) -> Vec<SensorHealth>;
}

/// Reads spool statistics. Implementations may wrap an `EventSpool` or provide
/// mock data for testing.
pub trait SpoolStatsSource: Send + Sync {
    /// Bytes the spool holds on disk now.
    fn spool_bytes(&self) -> u64;
    /// Events the spool dropped to stay within its bound.
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
    rarity: Arc<dyn RarityStatsSource>,
    host: Arc<dyn HostCountersSource>,
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
        // Set the flag under the mutex: a sleeper checks it under the same
        // mutex before waiting, so the notification can't fall between its
        // check and its wait (lost wakeup → full-interval sleep).
        {
            let _guard = self.mutex.lock_recovering();
            self.flag.store(true, Ordering::SeqCst);
        }
        self.condvar.notify_all();
    }

    fn is_stopped(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Sleeps until `started` plus `interval`, and returns early if `stop()` is called, including
    /// just before the sleep started.
    fn sleep_until_due(&self, started: Instant, interval: Duration) {
        let mut guard = self.mutex.lock_recovering();
        loop {
            if self.is_stopped() {
                return;
            }
            let due = started + interval;
            let now = Instant::now();
            if now >= due {
                return;
            }
            guard = self.condvar.wait_timeout_recovering(guard, due - now);
        }
    }
}

impl HealthCollector {
    /// Creates a new health collector with the given sources.
    pub fn new(
        config: HealthCollectorConfig,
        sensors: Arc<dyn SensorHealthSource>,
        spool: Arc<dyn SpoolStatsSource>,
        enrich_dropped: Arc<dyn DroppedCounter>,
        rarity: Arc<dyn RarityStatsSource>,
        host: Arc<dyn HostCountersSource>,
        emit: impl Fn(HealthBeacon) + Send + 'static,
    ) -> Self {
        let stop = Arc::new(StopFlag::new());
        Self {
            config,
            sensors,
            spool,
            enrich_dropped,
            rarity,
            host,
            emit: Box::new(emit),
            stop,
        }
    }

    /// Spawns the collector thread. Returns a handle that can be used to stop
    /// the collector and a `StopHandle` to signal shutdown.
    ///
    /// # Errors
    ///
    /// The OS refused the thread (see [`workers::spawn::spawn_named`]).
    pub fn spawn(self) -> std::io::Result<(JoinHandle<()>, StopHandle)> {
        let stop = self.stop.clone();
        let handle = workers::spawn::spawn_named("health-beacon", move || self.run())?;
        Ok((handle, StopHandle(stop)))
    }

    fn run(self) {
        tracing::info!(interval = ?self.config.interval, "health beacon started");
        while !self.stop.is_stopped() {
            self.stop
                .sleep_until_due(Instant::now(), self.config.interval);
            if self.stop.is_stopped() {
                break;
            }
            let beacon = self.collect();
            (self.emit)(beacon);
            tracing::debug!("health beacon emitted");
        }
        tracing::info!("health beacon stopped");
    }

    fn collect(&self) -> HealthBeacon {
        let rarity = self.rarity.rarity_counts();
        let host = self.host.host_counters();
        HealthBeacon {
            timestamp_ns: schema::time::now_ns(),
            agent_version: self.config.agent_version.clone(),
            sensors: self.sensors.sensor_health(),
            spool_bytes: self.spool.spool_bytes(),
            spool_dropped: self.spool.spool_dropped(),
            enrich_dropped: self.enrich_dropped.dropped(),
            rarity_applied: rarity.applied,
            rarity_withheld: rarity.withheld,
            rarity_unapplied: rarity.unapplied,
            watchdog_restarts: host.watchdog_restarts,
            tamper_events: host.tamper_events,
            parent_image_evicted_live: host.parent_image_evicted_live,
            parent_image_evicted_dead: host.parent_image_evicted_dead,
            ioc_indicators: host.ioc_indicators,
            ioc_findings: host.ioc_findings,
            ioc_cooled_down: host.ioc_cooled_down,
            ioc_own_skipped: host.ioc_own_skipped,
            ioc_sibling_skipped: host.ioc_sibling_skipped,
            alerts_dropped: host.alerts_dropped,
            ring_dropped: host.ring_dropped,
            exec_ring_dropped: host.exec_ring_dropped,
            reorder_late: host.reorder_late,
            reorder_forced: host.reorder_forced,
            etw_pid_cache_evicted: host.etw_pid_cache_evicted,
            etw_silo_evicted: host.etw_silo_evicted,
            etw_marks_dropped: host.etw_marks_dropped,
            etw_quarantine_unremembered: host.etw_quarantine_unremembered,
            etw_registry_unresolved_writes: host.etw_registry_unresolved_writes,
            etw_registry_keys_evicted: host.etw_registry_keys_evicted,
            etw_registry_names_truncated: host.etw_registry_names_truncated,
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
    use std::{sync::mpsc, thread};

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

    struct MockRarity(RarityCounts);

    impl RarityStatsSource for MockRarity {
        fn rarity_counts(&self) -> RarityCounts {
            self.0
        }
    }

    struct MockHost(HostCounters);

    impl HostCountersSource for MockHost {
        fn host_counters(&self) -> HostCounters {
            self.0
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
        let rarity = Arc::new(MockRarity(RarityCounts {
            applied: 7,
            withheld: 11,
            unapplied: 2,
        }));

        let host = Arc::new(MockHost(HostCounters {
            watchdog_restarts: 3,
            tamper_events: 5,
            parent_image_evicted_live: 13,
            parent_image_evicted_dead: 209_000,
            ioc_indicators: 12_000,
            ioc_findings: 4,
            ioc_cooled_down: 31,
            ioc_own_skipped: 6,
            ioc_sibling_skipped: 2,
            alerts_dropped: 8,
            ring_dropped: 51_064_213,
            exec_ring_dropped: 7,
            reorder_late: 31,
            reorder_forced: 32,
            etw_pid_cache_evicted: 21,
            etw_silo_evicted: 22,
            etw_marks_dropped: 23,
            etw_quarantine_unremembered: 24,
            etw_registry_unresolved_writes: 25,
            etw_registry_keys_evicted: 26,
            etw_registry_names_truncated: 27,
        }));

        let (tx, rx) = mpsc::channel();

        let collector = HealthCollector::new(
            HealthCollectorConfig {
                interval: Duration::from_millis(10),
                agent_version: "0.1.0-test".into(),
            },
            sensors,
            spool,
            enrich,
            rarity,
            host,
            move |b| {
                let _ = tx.send(b);
            },
        );

        let (handle, stop) = collector.spawn().unwrap();

        // Wait for the first beacon instead of sleeping a fixed time: a fixed
        // 50 ms sleep failed on slow CI runners (macOS) before the thread had
        // emitted anything.
        let beacon = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("should have collected at least one beacon");
        stop.stop();
        handle.join().unwrap();

        assert_eq!(beacon.agent_version, "0.1.0-test");
        assert_eq!(beacon.sensors.len(), 1);
        assert_eq!(beacon.sensors[0].name, "linux-ebpf");
        assert_eq!(beacon.sensors[0].pulse_count, 1234);
        assert!(!beacon.sensors[0].silent);
        assert_eq!(beacon.spool_bytes, 5000);
        assert_eq!(beacon.spool_dropped, 10);
        assert_eq!(beacon.enrich_dropped, 5);
        assert_eq!(
            (
                beacon.rarity_applied,
                beacon.rarity_withheld,
                beacon.rarity_unapplied
            ),
            (7, 11, 2),
            "the rarity evidence counters ride the beacon (#76)"
        );
        assert_eq!(
            (
                beacon.watchdog_restarts,
                beacon.tamper_events,
                beacon.parent_image_evicted_live,
                beacon.parent_image_evicted_dead
            ),
            (3, 5, 13, 209_000),
            "the watchdog, tamper and eviction counters ride the beacon (#863)"
        );
        assert_eq!(
            (
                beacon.ioc_indicators,
                beacon.ioc_findings,
                beacon.ioc_cooled_down
            ),
            (12_000, 4, 31),
            "the IOC engine counters ride the beacon (#60)"
        );
        assert_eq!(
            (beacon.ioc_own_skipped, beacon.ioc_sibling_skipped),
            (6, 2),
            "the own-traffic skips ride the beacon (#1061)"
        );
        assert_eq!(
            beacon.alerts_dropped, 8,
            "the alerts the log file refused ride the beacon (#167)"
        );
        assert_eq!(
            (beacon.ring_dropped, beacon.exec_ring_dropped),
            (51_064_213, 7),
            "the eBPF ring losses ride the beacon (#335)"
        );
        assert_eq!(
            (beacon.reorder_late, beacon.reorder_forced),
            (31, 32),
            "what the reordering stage could not order rides the beacon"
        );
        assert_eq!(
            (
                beacon.etw_pid_cache_evicted,
                beacon.etw_silo_evicted,
                beacon.etw_marks_dropped,
                beacon.etw_quarantine_unremembered,
                beacon.etw_registry_unresolved_writes,
                beacon.etw_registry_keys_evicted,
                beacon.etw_registry_names_truncated
            ),
            (21, 22, 23, 24, 25, 26, 27),
            "what the Windows ETW sensor sheds rides the beacon (#178)"
        );
    }

    #[test]
    fn stop_interrupts_sleep() {
        let sensors = Arc::new(MockSensors(Vec::new()));
        let spool = Arc::new(NoopSpoolStats);
        let enrich = Arc::new(MockDropped(0));
        let rarity = Arc::new(MockRarity(RarityCounts::default()));
        let host = Arc::new(MockHost(HostCounters::default()));

        let collector = HealthCollector::new(
            HealthCollectorConfig {
                interval: Duration::from_secs(60), // Long interval
                agent_version: "test".into(),
            },
            sensors,
            spool,
            enrich,
            rarity,
            host,
            |_| {},
        );

        let (handle, stop) = collector.spawn().unwrap();

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

    #[test]
    fn stop_before_sleep_is_not_lost() {
        // A stop that lands before the sleeper starts waiting must still cut
        // the sleep short, instead of the notification being lost.
        let flag = StopFlag::new();
        flag.stop();
        let start = std::time::Instant::now();
        flag.sleep_until_due(Instant::now(), Duration::from_secs(60));
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "a stop issued before the sleep should not be lost"
        );
    }

    #[test]
    fn a_stop_flag_whose_mutex_was_poisoned_still_stops_and_wakes_a_sleeper() {
        let stop = Arc::new(StopFlag::new());
        let held = Arc::clone(&stop);
        let _ = std::thread::spawn(move || {
            let _guard = held.mutex.lock().unwrap();
            panic!("poison the stop flag mutex while holding it");
        })
        .join();
        assert!(stop.mutex.is_poisoned());
        stop.stop();
        // The flag is set, so the sleep returns at once instead of panicking on the poison.
        stop.sleep_until_due(Instant::now(), Duration::from_secs(3600));
        assert!(stop.is_stopped());
    }
}
