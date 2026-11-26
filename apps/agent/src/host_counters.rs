//! The health-beacon counters that come from outside the sink's rarity statistics, the spool and
//! the silence monitor (#863): how many times the watchdog restarted the agent, how many
//! tamper-class alerts there were, what the Linux parent-image cache's cap dropped, what the Linux
//! eBPF probes lost to full ring buffers, and how many alerts `alerts.ndjson` did not get.
//!
//! What counts as a tamper event, stated plainly: an alert the agent's own monitors raise through
//! [`crate::sink::DetectionSink::emit_tamper`] (a sensor confirmed silent, a shipped binary or its
//! signed manifest that no longer verifies), plus the self-protection events the watchdog reported
//! (service definition drift, a binary that no longer matches its pinned hash). It does **not**
//! include a rule detecting tampering with a protected resource (that is an ordinary detection),
//! nor a `SIGKILL` of the agent: the agent cannot report its own death, and the restarted agent
//! shows it as one more `watchdog_restarts`.

#![cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]

use std::sync::Arc;

use config::identity::{WATCHDOG_RESTARTS_ENV, WATCHDOG_TAMPER_EVENTS_ENV};

use crate::{
    health::{HostCounters, HostCountersSource},
    sink::DetectionSink,
};

/// What the watchdog told this agent at spawn. Zero when the agent runs without a watchdog, and
/// for a variable that is missing or is not a number: a beacon must not fail over a bad variable.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WatchdogReport {
    pub(crate) restarts: u64,
    pub(crate) tamper_events: u64,
}

impl WatchdogReport {
    pub(crate) fn from_env() -> Self {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let number = |name: &str| {
            get(name)
                .and_then(|value| value.trim().parse::<u64>().ok())
                .unwrap_or(0)
        };
        Self {
            restarts: number(WATCHDOG_RESTARTS_ENV),
            tamper_events: number(WATCHDOG_TAMPER_EVENTS_ENV),
        }
    }
}

/// The Linux eBPF sensor's own loss totals, cumulative since it started.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SensorTotals {
    /// Parent-image cache entries the cap dropped while their process was alive (#863).
    pub(crate) parent_image_evicted_live: u64,
    /// Entries the cap dropped whose process had already exited.
    pub(crate) parent_image_evicted_dead: u64,
    /// Events lost to full ring buffers, every ring (#335).
    pub(crate) ring_dropped: u64,
    /// The part of it lost from the exec ring.
    pub(crate) exec_ring_dropped: u64,
}

/// Reads the [`SensorTotals`]. Linux eBPF only: the audit fallback and other platforms pass none.
pub(crate) type SensorTotalsReader = Box<dyn Fn() -> SensorTotals + Send + Sync>;

/// What the Windows ETW sensor's caches and queues shed (#178). Zero where there is no such
/// sensor.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EtwShedCounts {
    pub(crate) pid_cache_evicted: u64,
    pub(crate) silo_evicted: u64,
    pub(crate) marks_dropped: u64,
    pub(crate) quarantine_unremembered: u64,
}

/// Reads the [`EtwShedCounts`]. Windows only: other platforms pass none.
pub(crate) type EtwShedReader = Box<dyn Fn() -> EtwShedCounts + Send + Sync>;

/// The agent's [`HostCountersSource`]: the sink's tamper count, what the watchdog reported, and
/// the sensor's loss totals when the platform has them.
pub(crate) struct AgentHostCounters {
    sink: Arc<DetectionSink>,
    watchdog: WatchdogReport,
    sensor_totals: Option<SensorTotalsReader>,
    etw_shed: Option<EtwShedReader>,
}

impl AgentHostCounters {
    pub(crate) fn new(
        sink: Arc<DetectionSink>,
        watchdog: WatchdogReport,
        sensor_totals: Option<SensorTotalsReader>,
    ) -> Self {
        Self {
            sink,
            watchdog,
            sensor_totals,
            etw_shed: None,
        }
    }

    /// Reports what `read` says the Windows ETW sensor shed.
    #[cfg(any(windows, test))]
    pub(crate) fn with_etw_shed_reader(mut self, read: EtwShedReader) -> Self {
        self.etw_shed = Some(read);
        self
    }

    /// Reports what the Windows ETW sensor counted into `shedding`.
    #[cfg(windows)]
    pub(crate) fn with_etw_shedding(self, shedding: sensor_windows::EtwShedding) -> Self {
        self.with_etw_shed_reader(Box::new(move || EtwShedCounts {
            pid_cache_evicted: shedding.pid_cache_evicted(),
            silo_evicted: shedding.silo_evicted(),
            marks_dropped: shedding.marks_dropped(),
            quarantine_unremembered: shedding.quarantine_unremembered(),
        }))
    }
}

impl HostCountersSource for AgentHostCounters {
    fn host_counters(&self) -> HostCounters {
        let sensor = self
            .sensor_totals
            .as_ref()
            .map_or_else(SensorTotals::default, |read| read());
        let etw_shed = self
            .etw_shed
            .as_ref()
            .map(|read| read())
            .unwrap_or_default();
        let (ioc_indicators, ioc_findings, ioc_cooled_down) = self.sink.ioc_counts();
        let (ioc_own_skipped, ioc_sibling_skipped) = self.sink.ioc_own_skips();
        HostCounters {
            watchdog_restarts: self.watchdog.restarts,
            tamper_events: self
                .sink
                .tamper_events()
                .saturating_add(self.watchdog.tamper_events),
            parent_image_evicted_live: sensor.parent_image_evicted_live,
            parent_image_evicted_dead: sensor.parent_image_evicted_dead,
            ioc_indicators,
            ioc_findings,
            ioc_cooled_down,
            ioc_own_skipped,
            ioc_sibling_skipped,
            alerts_dropped: self.sink.alert_log().dropped_writes(),
            ring_dropped: sensor.ring_dropped,
            exec_ring_dropped: sensor.exec_ring_dropped,
            etw_pid_cache_evicted: etw_shed.pid_cache_evicted,
            etw_silo_evicted: etw_shed.silo_evicted,
            etw_marks_dropped: etw_shed.marks_dropped,
            etw_quarantine_unremembered: etw_shed.quarantine_unremembered,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn lookup(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |name| map.get(name).cloned()
    }

    #[test]
    fn without_a_watchdog_both_counts_are_zero() {
        assert_eq!(
            WatchdogReport::from_lookup(lookup(&[])),
            WatchdogReport::default()
        );
    }

    #[test]
    fn the_watchdogs_numbers_are_read_whitespace_trimmed() {
        let report = WatchdogReport::from_lookup(lookup(&[
            (WATCHDOG_RESTARTS_ENV, " 3 "),
            (WATCHDOG_TAMPER_EVENTS_ENV, "5"),
        ]));
        assert_eq!(
            report,
            WatchdogReport {
                restarts: 3,
                tamper_events: 5
            }
        );
    }

    #[test]
    fn a_variable_that_is_not_a_number_counts_as_zero_without_touching_the_other() {
        for bad in ["", "abc", "-1", "1.5", "99999999999999999999999"] {
            let report = WatchdogReport::from_lookup(lookup(&[
                (WATCHDOG_RESTARTS_ENV, bad),
                (WATCHDOG_TAMPER_EVENTS_ENV, "7"),
            ]));
            assert_eq!(
                report,
                WatchdogReport {
                    restarts: 0,
                    tamper_events: 7
                },
                "{bad:?}"
            );
        }
    }

    fn sink(name: &str) -> Arc<DetectionSink> {
        let dir = std::env::temp_dir().join(format!("host-counters-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        Arc::new(
            DetectionSink::new(
                rules::RuleState::new(),
                &dir.join("alerts.ndjson"),
                None,
                None,
                None,
                &dir.join("content"),
                &dir.join("ml-registry"),
            )
            .unwrap(),
        )
    }

    #[test]
    fn tamper_events_add_the_agents_own_to_the_watchdogs() {
        let sink = sink("sum");
        sink.emit_tamper("T1562", "sensor silent");
        sink.emit_tamper("T1601", "binary swapped");
        sink.emit("T1059", "an ordinary alert");
        let counters = AgentHostCounters::new(
            sink,
            WatchdogReport {
                restarts: 2,
                tamper_events: 5,
            },
            None,
        )
        .host_counters();

        assert_eq!(
            counters.tamper_events, 7,
            "2 raised here, 5 reported by the watchdog"
        );
        assert_eq!(counters.watchdog_restarts, 2);
    }

    #[test]
    fn the_ioc_counters_follow_the_loaded_set_and_what_it_matched() {
        let dir = std::env::temp_dir().join(format!("host-counters-ioc-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        let feeds = dir.join("content").join("ioc");
        std::fs::create_dir_all(&feeds).unwrap();
        std::fs::write(feeds.join("f.txt"), "ip:203.0.113.9\nip:203.0.113.10\n").unwrap();
        let sink = Arc::new(
            DetectionSink::new(
                rules::RuleState::new(),
                &dir.join("alerts.ndjson"),
                None,
                None,
                None,
                &dir.join("content"),
                &dir.join("ml-registry"),
            )
            .unwrap(),
        );
        use schema::sensor::EventSink as _;
        let counters = AgentHostCounters::new(Arc::clone(&sink), WatchdogReport::default(), None);
        let ioc = |c: HostCounters| (c.ioc_indicators, c.ioc_findings, c.ioc_cooled_down);
        assert_eq!(ioc(counters.host_counters()), (2, 0, 0));

        for ts in [1_000, 2_000] {
            sink.on_event(schema::Event::Connect(schema::ConnectEvent {
                meta: schema::EventMeta {
                    timestamp_ns: ts,
                    ..schema::fixtures::meta()
                },
                daddr: "203.0.113.9".parse().unwrap(),
                dport: 443,
            }));
        }
        assert_eq!(ioc(counters.host_counters()), (2, 1, 1));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_sensor_totals_reach_their_own_fields_and_are_zero_where_the_platform_has_none() {
        let with = AgentHostCounters::new(
            sink("evict"),
            WatchdogReport::default(),
            Some(Box::new(|| SensorTotals {
                parent_image_evicted_live: 13,
                parent_image_evicted_dead: 209_000,
                ring_dropped: 51_064_213,
                exec_ring_dropped: 7,
            })),
        )
        .host_counters();
        assert_eq!(
            (
                with.parent_image_evicted_live,
                with.parent_image_evicted_dead,
                with.ring_dropped,
                with.exec_ring_dropped
            ),
            (13, 209_000, 51_064_213, 7)
        );

        let without =
            AgentHostCounters::new(sink("none"), WatchdogReport::default(), None).host_counters();
        assert_eq!(
            (
                without.parent_image_evicted_live,
                without.parent_image_evicted_dead,
                without.ring_dropped,
                without.exec_ring_dropped
            ),
            (0, 0, 0, 0)
        );
    }

    #[test]
    fn an_alert_log_that_writes_every_alert_reports_none_dropped() {
        let sink = sink("alerts-dropped");
        sink.emit("T1059", "an ordinary alert");
        let counters =
            AgentHostCounters::new(sink, WatchdogReport::default(), None).host_counters();
        assert_eq!(counters.alerts_dropped, 0);
    }

    /// The four ETW shedding counts, in beacon order.
    fn etw_shed(counters: &HostCounters) -> (u64, u64, u64, u64) {
        (
            counters.etw_pid_cache_evicted,
            counters.etw_silo_evicted,
            counters.etw_marks_dropped,
            counters.etw_quarantine_unremembered,
        )
    }

    #[test]
    fn without_an_etw_shed_reader_the_etw_counters_read_zero() {
        let counters =
            AgentHostCounters::new(sink("etw-shed-none"), WatchdogReport::default(), None)
                .host_counters();
        assert_eq!(etw_shed(&counters), (0, 0, 0, 0));
    }

    #[test]
    fn the_etw_shed_reader_feeds_the_counters() {
        let counters = AgentHostCounters::new(sink("etw-shed"), WatchdogReport::default(), None)
            .with_etw_shed_reader(Box::new(|| EtwShedCounts {
                pid_cache_evicted: 1,
                silo_evicted: 2,
                marks_dropped: 3,
                quarantine_unremembered: 4,
            }))
            .host_counters();
        assert_eq!(etw_shed(&counters), (1, 2, 3, 4));
    }

    #[test]
    fn a_sum_that_would_overflow_saturates() {
        let sink = sink("sat");
        sink.emit_tamper("T1562", "x");
        let counters = AgentHostCounters::new(
            sink,
            WatchdogReport {
                restarts: 0,
                tamper_events: u64::MAX,
            },
            None,
        )
        .host_counters();
        assert_eq!(counters.tamper_events, u64::MAX);
    }
}
