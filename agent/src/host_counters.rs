//! The health-beacon counters that come from outside the sink's rarity statistics, the spool and
//! the silence monitor (#863): how many times the watchdog restarted the agent, how many
//! tamper-class alerts there were, and what the Linux parent-image cache's cap dropped.
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

use crate::{
    health::{HostCounters, HostCountersSource},
    sink::DetectionSink,
};

/// The variables the watchdog sets for the agent it spawns. The watchdog has no dependency on this
/// crate, so `watchdog/src/supervise.rs` spells the same two names; a test below checks that it
/// still does.
pub(crate) const WATCHDOG_RESTARTS_ENV: &str = "SYNTHAEA_WATCHDOG_RESTARTS";
pub(crate) const WATCHDOG_TAMPER_EVENTS_ENV: &str = "SYNTHAEA_WATCHDOG_TAMPER_EVENTS";

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

/// Reads the parent-image cache totals as `(live, dead)`. Linux only: other platforms pass none.
pub(crate) type EvictionReader = Box<dyn Fn() -> (u64, u64) + Send + Sync>;

/// The agent's [`HostCountersSource`]: the sink's tamper count, what the watchdog reported, and
/// the eviction totals when the platform has them.
pub(crate) struct AgentHostCounters {
    sink: Arc<DetectionSink>,
    watchdog: WatchdogReport,
    evictions: Option<EvictionReader>,
}

impl AgentHostCounters {
    pub(crate) fn new(
        sink: Arc<DetectionSink>,
        watchdog: WatchdogReport,
        evictions: Option<EvictionReader>,
    ) -> Self {
        Self {
            sink,
            watchdog,
            evictions,
        }
    }
}

impl HostCountersSource for AgentHostCounters {
    fn host_counters(&self) -> HostCounters {
        let (live, dead) = self.evictions.as_ref().map_or((0, 0), |read| read());
        let (ioc_indicators, ioc_findings, ioc_cooled_down) = self.sink.ioc_counts();
        HostCounters {
            watchdog_restarts: self.watchdog.restarts,
            tamper_events: self
                .sink
                .tamper_events()
                .saturating_add(self.watchdog.tamper_events),
            parent_image_evicted_live: live,
            parent_image_evicted_dead: dead,
            ioc_indicators,
            ioc_findings,
            ioc_cooled_down,
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

    #[test]
    fn the_watchdog_spells_the_same_two_variables() {
        // The watchdog does not depend on this crate, so nothing else ties the two spellings.
        let watchdog = include_str!("../../watchdog/src/supervise.rs");
        for name in [WATCHDOG_RESTARTS_ENV, WATCHDOG_TAMPER_EVENTS_ENV] {
            assert!(
                watchdog.contains(&format!("\"{name}\"")),
                "watchdog/src/supervise.rs no longer names {name}"
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
    fn the_eviction_totals_are_live_then_dead_and_zero_where_the_platform_has_none() {
        let with = AgentHostCounters::new(
            sink("evict"),
            WatchdogReport::default(),
            Some(Box::new(|| (13, 209_000))),
        )
        .host_counters();
        assert_eq!(
            (
                with.parent_image_evicted_live,
                with.parent_image_evicted_dead
            ),
            (13, 209_000)
        );

        let without =
            AgentHostCounters::new(sink("none"), WatchdogReport::default(), None).host_counters();
        assert_eq!(
            (
                without.parent_image_evicted_live,
                without.parent_image_evicted_dead
            ),
            (0, 0)
        );
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
