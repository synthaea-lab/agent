//! The engine: receives events from the sensor, feeds the bus, evaluates the
//! co-occurrence rules and the Bayesian belief, and emits alerts.

use std::time::Duration;

use store::BoundedMap;

use schema::Event;

use crate::{
    bayes::{BAYES_THRESHOLD, BeliefState, update_belief},
    behavior::BehaviorVector,
    bus::EventBus,
    event::is_correlated,
    rules::{
        CorrelationAlert, rule_connect_filewrite, rule_respawn_connect, rule_spawn_connect,
        rule_spawn_connect_filewrite,
    },
};

/// Processes excluded from the correlation engine — legitimate system activity that
/// generates noise (spawn + connection) under normal conditions. Same logic as the
/// exclusion lists in `rules`, applied here at the correlation level.
const IGNORED: &[&str] = &[
    "svchost.exe",
    "SearchProtocolHost.exe",
    "MsMpEng.exe",
    "WmiPrvSE.exe",
    "taskhostw.exe",
    "backgroundTaskHost.exe",
    "RuntimeBroker.exe",
    "WindowsPackageManagerServer.exe",
    "SoftLandingTask.exe",
    "msedge.exe",
    "conhost.exe",
    // FPs observed during the NjRAT capture on 2026-08-28:
    "CrossDeviceServ", // CrossDeviceService.exe — Microsoft STUN/WebRTC, legitimate beaconing
    "SecurityHealthH", // SecurityHealthHost.exe — Defender health, frequent respawn
    "System",          // pid=4, Windows kernel — native NetBIOS/NBT
    // FPs observed during the FileOpen test on 2026-08-31:
    "MoUsoCoreWorker", // Windows Update orchestrator — accesses OneSettings/UpdateStore in a loop
    "backgroundTaskH", // backgroundTaskHost.exe truncated by ETW — ContentDelivery/Spotlight
    "nordvpn-service", // NordVPN service — legitimate connections to VPN servers
];

fn is_ignored(comm: &str) -> bool {
    let name = comm.rsplit('\\').next().unwrap_or(comm);
    IGNORED
        .iter()
        .any(|&ignore| name.eq_ignore_ascii_case(ignore))
}

/// Main entry point. Receives events from the sensor, stores them in the bus,
/// and evaluates the co-occurrence rules over the current window.
pub struct CorrelationEngine {
    bus: EventBus,
    window_ns: u64,
    /// Bayesian beliefs per entity (ppid, comm), LRU-bounded (`store::BoundedMap`) —
    /// the old iteration's unbounded `HashMap` was a documented known limitation.
    /// Keyed by (ppid, comm), not pid: survives respawns.
    beliefs: BoundedMap<(u32, String), BeliefState>,
    /// pid → (ppid, comm) mapping populated by `ExecEvents`, LRU-bounded.
    /// Lets `ConnectEvents` (ppid=0) find the right entity key.
    pid_entities: BoundedMap<u32, (u32, String)>,
    /// (technique, pid) → last alert timestamp. A satisfied co-occurrence pattern
    /// stays satisfied for every later event in the window — without this, one
    /// exec+connect pair re-alerted on every subsequent event of that pid (review
    /// finding: identical alert floods from a single pattern).
    fired: BoundedMap<(&'static str, u32), u64>,
    /// Pids whose `ExecEvent` showed an IGNORED-list name running from an
    /// untrusted location — a rename masquerade (`/tmp/svchost.exe`). The
    /// exclusion is name-keyed and would otherwise be a trivial bypass (user
    /// finding); these pids keep full rule evaluation.
    masquerading: BoundedMap<u32, ()>,
}

/// Bounds for a long-lived agent: entities cover the realistic live-pid space with
/// headroom; beliefs are fewer (one per logical entity, not per pid). Evictions are
/// observable via the maps' counters.
const ENTITY_CAP: usize = 65_536;
const BELIEF_CAP: usize = 16_384;

impl CorrelationEngine {
    /// Default window: 60 seconds.
    #[must_use]
    pub fn new() -> Self {
        Self::with_window(Duration::from_secs(60))
    }

    #[must_use]
    pub fn with_window(window: Duration) -> Self {
        Self {
            bus: EventBus::new(window),
            window_ns: window.as_nanos() as u64,
            beliefs: BoundedMap::new(BELIEF_CAP),
            pid_entities: BoundedMap::new(ENTITY_CAP),
            fired: BoundedMap::new(BELIEF_CAP),
            masquerading: BoundedMap::new(ENTITY_CAP),
        }
    }

    /// Records an event and returns the alerts it triggered, if any.
    /// Processes in the IGNORED list are recorded in the bus (for future
    /// parent/child correlation) but do not evaluate the rules — too much system
    /// noise. Event variants this crate does not correlate yet are ignored entirely.
    pub fn on_event(&mut self, event: Event) -> Vec<CorrelationAlert> {
        if !is_correlated(&event) {
            return Vec::new();
        }
        let pid = event.meta().pid;
        let comm = event.meta().comm.clone();
        let ppid = event.meta().ppid;

        // Record pid → (ppid, comm) as soon as the ExecEvent arrives.
        // On Windows (ETW), the sensor does not fill in ppid for ConnectEvent
        // (ppid=0 in EventMeta) — this table compensates. On Linux (eBPF), ppid
        // is filled in on all events, so the table is redundant but harmless.
        if let Event::Exec(exec) = &event {
            if ppid != 0 {
                self.pid_entities.insert(pid, (ppid, comm.clone()));
            }
            if is_ignored(&comm) && !policy::name_exclusion_applies(Some(exec.image_path.as_str()))
            {
                self.masquerading.insert(pid, ());
            }
        }

        self.bus.push(event);

        // Bayesian entity key: (ppid, comm) if known, otherwise (pid, comm).
        // Keying by (ppid, comm) lets the belief survive respawns:
        // fork+exec = new pid, same (ppid, comm) → same BeliefState.
        let entity_key = self
            .pid_entities
            .get(&pid)
            .cloned()
            .unwrap_or_else(|| (pid, comm.clone()));

        // Bayesian update with the pid's current BehaviorVector.
        if let Some(bv) = self.behavior_vector_for_pid(pid) {
            let now_ns = self
                .bus
                .events_for_pid(pid)
                .map(|e| e.meta().timestamp_ns)
                .max()
                .unwrap_or(0);
            let state = self
                .beliefs
                .get_or_insert_with(entity_key.clone(), || BeliefState::new(now_ns));
            update_belief(state, &bv, now_ns);
        }

        if is_ignored(&comm) && self.masquerading.peek(&pid).is_none() {
            return Vec::new();
        }

        let now_ns = self
            .bus
            .events_for_pid(pid)
            .map(|e| e.meta().timestamp_ns)
            .max()
            .unwrap_or(0);
        let mut alerts = self.evaluate(pid, now_ns);
        alerts.extend(self.bayes_alert(pid, &comm, &entity_key));
        alerts
    }

    /// Bayesian alert — only once per threshold crossing.
    /// Reset when `log_odds` drops back below `BAYES_THRESHOLD` (decay).
    fn bayes_alert(
        &mut self,
        pid: u32,
        comm: &str,
        entity_key: &(u32, String),
    ) -> Option<CorrelationAlert> {
        let state = self.beliefs.get_mut(entity_key)?;
        if state.log_odds > BAYES_THRESHOLD && !state.alerted {
            state.alerted = true;
            Some(CorrelationAlert {
                technique: "BAYES",
                message: format!(
                    "pid={pid} comm={comm}: high Bayesian score \
                     (log_odds={:.2}, P={:.0}%)",
                    state.log_odds,
                    state.probability() * 100.0
                ),
            })
        } else {
            if state.log_odds <= BAYES_THRESHOLD && state.alerted {
                // Decay brought the belief back below the threshold — reset the flag.
                state.alerted = false;
            }
            None
        }
    }

    /// Returns the Bayesian belief state for a given PID.
    /// Uses the (ppid, comm) key if the PID has been seen in an `ExecEvent`,
    /// otherwise rebuilds the fallback key (pid, comm) from the bus — consistent
    /// with the fallback used in `on_event`.
    #[must_use]
    pub fn belief_for_pid(&self, pid: u32) -> Option<&BeliefState> {
        if let Some(entity_key) = self.pid_entities.peek(&pid) {
            return self.beliefs.peek(entity_key);
        }
        // Fallback: recover the comm from the bus to rebuild the same key
        // as the one inserted in on_event — (pid, comm.clone()).
        let comm = self.bus.events_for_pid(pid).next()?.meta().comm.clone();
        self.beliefs.peek(&(pid, comm))
    }

    /// Evaluates all the co-occurrence rules for a given pid, emitting each
    /// satisfied pattern once per correlation window rather than on every event.
    fn evaluate(&mut self, pid: u32, now_ns: u64) -> Vec<CorrelationAlert> {
        let mut alerts = Vec::new();
        let window_ns = self.window_ns;

        // Keyed by rule identity, not technique — spawn+connect and
        // respawn+connect share "T1059/T1071" but are distinct findings.
        let mut push_once = |fired: &mut BoundedMap<(&'static str, u32), u64>,
                             rule_id: &'static str,
                             alert: CorrelationAlert| {
            let key = (rule_id, pid);
            let recently = fired
                .get(&key)
                .is_some_and(|&t| now_ns.saturating_sub(t) <= window_ns);
            if !recently {
                fired.insert(key, now_ns);
                alerts.push(alert);
            }
        };

        if let Some(alert) = rule_spawn_connect_filewrite(pid, &self.bus) {
            push_once(&mut self.fired, "spawn_connect_filewrite", alert);
        } else if let Some(alert) = rule_spawn_connect(pid, &self.bus) {
            // Subset of the full chain — only alert if the full chain has not
            // already been reported, to avoid the duplicate.
            push_once(&mut self.fired, "spawn_connect", alert);
        }

        if let Some(alert) = rule_connect_filewrite(pid, &self.bus) {
            push_once(&mut self.fired, "connect_filewrite", alert);
        }

        if let Some(alert) = rule_respawn_connect(pid, &self.bus) {
            push_once(&mut self.fired, "respawn_connect", alert);
        }

        alerts
    }

    /// Computes the behavioral vector for a given PID from the events
    /// currently in the sliding window.
    ///
    /// Returns `None` if the PID has no events in the window.
    #[must_use]
    pub fn behavior_vector_for_pid(&self, pid: u32) -> Option<BehaviorVector> {
        let events: Vec<&Event> = self.bus.events_for_pid(pid).collect();
        BehaviorVector::from_window(&events)
    }
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}
