//! Agent health beacon — periodic self-diagnostics emitted to the control plane.
//!
//! A background thread collects counters from sensors, spool, and enrichment queue,
//! then emits a [`schema::HealthBeacon`] at a fixed cadence. The beacon flows through
//! a separate channel (not the Event pipeline) so it doesn't pollute telemetry
//! consumers that expect process metadata.
//!
//! "Silence is a detection": an agent that stops beaconing is as suspicious as one
//! that stops sending events.

// Wired on Linux and Windows (`commands::common::health_collector`, #317); macOS
// has no silence monitor to feed it yet.
#![cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use schema::{HealthBeacon, SensorHealth};

/// Default beacon interval (30 seconds).
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);

/// The shortest interval a live overlay may ask the beacon for (ADR-0035). A floor compiled
/// into the agent, so a posture document can heighten the cadence but never turn the beacon into
/// a flood: whatever it asks for is raised to this.
pub const MIN_WIDENED_INTERVAL: Duration = Duration::from_secs(5);

/// The beacon cadence, adjustable at run time in one direction only (ADR-0035 decision 2: a
/// posture overlay may heighten, never lower). It starts at the configured interval and can be
/// **shortened** with [`Self::widen_to`], down to a compiled floor, and put back with
/// [`Self::reset`]. Nothing in this API can make it longer than the configured value, so a
/// caller holding it cannot quiet the beacon: "silence is a detection".
///
/// Cloning gives another handle on the same value. A shortened interval takes effect at once, not
/// after the sleep in progress: the collector is woken and recomputes when the next beacon is due.
#[derive(Clone)]
pub struct BeaconInterval(Arc<IntervalState>);

// Written and read by the posture overlay (#62, slice 3), which does not exist yet: until then
// only the tests use the setters.
#[cfg_attr(not(test), allow(dead_code))]
struct IntervalState {
    configured: Duration,
    floor: Duration,
    current_ms: AtomicU64,
    /// The collector's wake-up, once it is attached (`HealthCollector::new`).
    waker: Mutex<Option<Arc<StopFlag>>>,
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

#[cfg_attr(not(test), allow(dead_code))]
impl BeaconInterval {
    #[must_use]
    pub fn new(configured: Duration) -> Self {
        Self::with_floor(configured, MIN_WIDENED_INTERVAL)
    }

    fn with_floor(configured: Duration, floor: Duration) -> Self {
        Self(Arc::new(IntervalState {
            configured,
            floor,
            current_ms: AtomicU64::new(millis(configured)),
            waker: Mutex::new(None),
        }))
    }

    /// The interval in force now.
    #[must_use]
    pub fn get(&self) -> Duration {
        Duration::from_millis(self.0.current_ms.load(Ordering::SeqCst))
    }

    /// Shortens the interval to `target`, raised to the floor, and never lengthens it: a
    /// `target` longer than what is in force changes nothing.
    pub fn widen_to(&self, target: Duration) {
        let wanted = millis(target.max(self.0.floor));
        if self.0.current_ms.fetch_min(wanted, Ordering::SeqCst) > wanted {
            self.wake();
        }
    }

    /// Puts the configured interval back, when no overlay asks for a shorter one any more.
    pub fn reset(&self) {
        self.0
            .current_ms
            .store(millis(self.0.configured), Ordering::SeqCst);
        self.wake();
    }

    fn attach(&self, stop: Arc<StopFlag>) {
        *self.0.waker.lock().unwrap() = Some(stop);
    }

    fn wake(&self) {
        if let Some(stop) = self.0.waker.lock().unwrap().clone() {
            stop.wake();
        }
    }
}

/// Reads the current dropped count from an enrichment queue (or similar bounded queue).
/// The health collector calls this periodically to report backpressure loss.
pub trait DroppedCounter: Send + Sync {
    fn dropped(&self) -> u64;
}

/// Cumulative counts of the rarity evidence (ADR-0020, issue #76): what the fleet's common set
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
}

/// Reads the [`HostCounters`].
pub trait HostCountersSource: Send + Sync {
    fn host_counters(&self) -> HostCounters;
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
    interval: BeaconInterval,
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

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn stop(&self) {
        // Set the flag under the mutex: a sleeper checks it under the same
        // mutex before waiting, so the notification can't fall between its
        // check and its wait (lost wakeup → full-interval sleep).
        {
            let _guard = self.mutex.lock().unwrap();
            self.flag.store(true, Ordering::SeqCst);
        }
        self.condvar.notify_all();
    }

    fn is_stopped(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    /// Wakes a sleeper so it recomputes how long it still has to wait (the interval changed).
    fn wake(&self) {
        let _guard = self.mutex.lock().unwrap();
        self.condvar.notify_all();
    }

    /// Sleeps until `started` plus the interval in force, however it changes meanwhile, and
    /// returns early if `stop()` is called, including just before the sleep started.
    fn sleep_until_due(&self, started: Instant, interval: &BeaconInterval) {
        let mut guard = self.mutex.lock().unwrap();
        loop {
            if self.is_stopped() {
                return;
            }
            let due = started + interval.get();
            let now = Instant::now();
            if now >= due {
                return;
            }
            guard = self.condvar.wait_timeout(guard, due - now).unwrap().0;
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
        let interval = BeaconInterval::new(config.interval);
        interval.attach(Arc::clone(&stop));
        Self {
            config,
            sensors,
            spool,
            enrich_dropped,
            rarity,
            host,
            emit: Box::new(emit),
            stop,
            interval,
        }
    }

    /// The handle on this collector's cadence, to take before [`Self::spawn`]. It can shorten the
    /// interval and put it back; nothing it offers can lengthen it. Read by the posture overlay
    /// (#62, slice 3), which does not exist yet.
    #[allow(dead_code)]
    #[must_use]
    pub fn interval_handle(&self) -> BeaconInterval {
        self.interval.clone()
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
        tracing::info!(interval = ?self.interval.get(), "health beacon started");
        while !self.stop.is_stopped() {
            self.stop.sleep_until_due(Instant::now(), &self.interval);
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
        }
    }
}

/// Handle to stop the health collector.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct StopHandle(Arc<StopFlag>);

impl StopHandle {
    /// Signals the collector to stop and wakes it from sleep immediately.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn stop(&self) {
        self.0.stop();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

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

        let (handle, stop) = collector.spawn();

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
            "the rarity evidence counters ride the beacon (ADR-0020, #76)"
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

    #[test]
    fn stop_before_sleep_is_not_lost() {
        // A stop that lands before the sleeper starts waiting must still cut
        // the sleep short, instead of the notification being lost.
        let flag = StopFlag::new();
        flag.stop();
        let interval = BeaconInterval::new(Duration::from_secs(60));

        let start = std::time::Instant::now();
        flag.sleep_until_due(Instant::now(), &interval);
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "a stop issued before the sleep should not be lost"
        );
    }

    // ── the beacon cadence, adjustable in one direction (#62, ADR-0035) ─────────

    const FLOOR: Duration = Duration::from_secs(5);

    #[test]
    fn the_interval_starts_at_the_configured_value() {
        assert_eq!(
            BeaconInterval::new(Duration::from_secs(30)).get(),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn widening_shortens_the_interval_and_never_below_the_floor() {
        let interval = BeaconInterval::new(Duration::from_secs(30));
        interval.widen_to(Duration::from_secs(10));
        assert_eq!(interval.get(), Duration::from_secs(10));
        interval.widen_to(Duration::from_millis(1));
        assert_eq!(
            interval.get(),
            FLOOR,
            "a request below the floor is raised to it"
        );
        interval.widen_to(Duration::ZERO);
        assert_eq!(interval.get(), FLOOR);
    }

    #[test]
    fn nothing_the_handle_offers_can_lengthen_the_interval() {
        // The heighten-only rule (ADR-0035 decision 2): whatever sequence of calls is made, the
        // interval is never longer than the configured one, and `widen_to` never makes it longer
        // than it already was.
        let configured = Duration::from_secs(30);
        let interval = BeaconInterval::new(configured);
        let asks = [
            Duration::from_secs(3600),
            Duration::from_secs(20),
            Duration::from_secs(7200),
            Duration::from_secs(8),
            Duration::from_secs(30),
            Duration::MAX,
            Duration::from_secs(12),
        ];
        let mut last = interval.get();
        for ask in asks {
            interval.widen_to(ask);
            assert!(
                interval.get() <= last,
                "widen_to({ask:?}) lengthened {last:?} to {:?}",
                interval.get()
            );
            assert!(interval.get() <= configured);
            last = interval.get();
        }
        interval.reset();
        assert_eq!(
            interval.get(),
            configured,
            "reset goes back to the configured value, not past it"
        );
    }

    #[test]
    fn a_configured_interval_below_the_floor_is_not_raised_by_widening() {
        // Tests and a deliberate configuration may run faster than the floor: widening must not
        // slow them down.
        let interval = BeaconInterval::new(Duration::from_secs(1));
        interval.widen_to(Duration::from_secs(10));
        assert_eq!(interval.get(), Duration::from_secs(1));
    }

    #[test]
    fn handles_share_one_value() {
        let a = BeaconInterval::new(Duration::from_secs(30));
        let b = a.clone();
        a.widen_to(Duration::from_secs(9));
        assert_eq!(b.get(), Duration::from_secs(9));
        b.reset();
        assert_eq!(a.get(), Duration::from_secs(30));
    }

    fn collector_with(
        interval: Duration,
        floor: Duration,
    ) -> (
        mpsc::Receiver<HealthBeacon>,
        BeaconInterval,
        JoinHandle<()>,
        StopHandle,
    ) {
        let (tx, rx) = mpsc::channel();
        let mut collector = HealthCollector::new(
            HealthCollectorConfig {
                interval,
                agent_version: "test".into(),
            },
            Arc::new(MockSensors(Vec::new())),
            Arc::new(NoopSpoolStats),
            Arc::new(MockDropped(0)),
            Arc::new(MockRarity(RarityCounts::default())),
            Arc::new(MockHost(HostCounters::default())),
            move |b| {
                let _ = tx.send(b);
            },
        );
        // A test floor, so the proof does not wait the production minimum.
        let handle = BeaconInterval::with_floor(interval, floor);
        handle.attach(Arc::clone(&collector.stop));
        collector.interval = handle.clone();
        let (join, stop) = collector.spawn();
        (rx, handle, join, stop)
    }

    #[test]
    fn a_shortened_interval_takes_effect_at_once_not_after_the_sleep_in_progress() {
        // Configured 60 s: with no change nothing arrives in the test's time. Shortening to the
        // floor wakes the sleeping collector, which then emits within a moment.
        let (rx, interval, join, stop) =
            collector_with(Duration::from_secs(60), Duration::from_millis(20));
        assert!(
            rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "no beacon yet on a 60 s cadence"
        );

        interval.widen_to(Duration::from_millis(20));
        let got = rx.recv_timeout(Duration::from_secs(10));
        stop.stop();
        join.join().unwrap();
        assert!(
            got.is_ok(),
            "a shortened interval must wake the collector, not wait out the old sleep"
        );
    }

    #[test]
    fn resetting_puts_the_slow_cadence_back() {
        let (rx, interval, join, stop) =
            collector_with(Duration::from_secs(60), Duration::from_millis(20));
        interval.widen_to(Duration::from_millis(20));
        rx.recv_timeout(Duration::from_secs(10))
            .expect("a beacon at the shortened cadence");
        interval.reset();
        // Drain what was emitted before the reset took effect, then expect quiet.
        std::thread::sleep(Duration::from_millis(100));
        while rx.try_recv().is_ok() {}
        assert!(
            rx.recv_timeout(Duration::from_millis(400)).is_err(),
            "back on the 60 s cadence"
        );
        stop.stop();
        join.join().unwrap();
    }

    #[test]
    fn stopping_still_interrupts_a_collector_whose_interval_was_widened() {
        let (_rx, interval, join, stop) =
            collector_with(Duration::from_secs(60), Duration::from_secs(30));
        interval.widen_to(Duration::from_secs(30));
        std::thread::sleep(Duration::from_millis(20));
        let start = Instant::now();
        stop.stop();
        join.join().unwrap();
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
