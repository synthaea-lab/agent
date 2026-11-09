//! LISTENER-DRIFT (T1571) and POLICY-DENIAL-DRIFT (T1562), the [`crate::RuleState`] rules
//! that alert on the first sighting of a listener or a policy-denial shape. See
//! `docs/detection/rules.md#first-seen-shapes` for the keys and the alert budget.

use std::net::IpAddr;

use schema::{
    ListenPortEvent, POLICY_MECHANISM_APPLOCKER, POLICY_MECHANISM_SELINUX, POLICY_MECHANISM_WDAC,
    PolicyDenialEvent, detection::Severity,
};
use store::BoundedMap;

use crate::{
    Alert,
    exclusions::{POLICY_DENIAL_ALERT_CAP, POLICY_DENIAL_SUBJECT_CAP},
    state::COUNTER_CAP,
};

/// `known_policy_denials`' key: (mechanism, subject context, object context, object
/// class, action). Named so clippy's `type_complexity` lint doesn't flag the field
/// declaration.
type PolicyDenialKey = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// One subject type's alert budget for `check_policy_denial_drift` (#840).
#[derive(Default)]
struct PolicyDenialBudget {
    /// Event time (`meta.timestamp_ns`) at which this subject's current window began; `None` until
    /// its first new shape, so the window is anchored on that shape and not on the epoch.
    window_start_ns: Option<u64>,
    /// New-shape alerts raised in the window.
    alerts: u64,
    /// New shapes shed in the window: the warning that the cap was hit is logged when this is 0.
    shed: u64,
}

/// The permission set of an AVC denial in canonical form for the dedup key: whitespace-separated
/// permissions, sorted and deduplicated, so `read write`, `write read` and `read  write` are one
/// shape. The wire value (`PolicyDenialEvent::action`) stays as the kernel wrote it.
fn normalized_permissions(action: &str) -> String {
    let mut permissions: Vec<&str> = action.split_whitespace().collect();
    permissions.sort_unstable();
    permissions.dedup();
    permissions.join(" ")
}

/// The listeners and policy-denial shapes seen this run, and the per-subject alert budgets.
pub(crate) struct DriftState {
    /// (`local_addr`, `local_port`, `protocol`) → seen. `protocol` is the IP protocol number
    /// ([`schema::ListenPortEvent::protocol`]): a TCP and a UDP listener on one port are two
    /// shapes. Pre-filled by [`Self::seed_listen_ports`]. LRU-bounded.
    known_listeners: BoundedMap<(IpAddr, u16, u8), ()>,
    /// [`PolicyDenialKey`] → seen: the shapes that already alerted. The key is per mechanism
    /// (`SELinux` type triple, class and [`normalized_permissions`]; `AppLocker`/WDAC the
    /// lowercased file and collection or loading process). No startup baseline. LRU-bounded.
    known_policy_denials: BoundedMap<PolicyDenialKey, ()>,
    /// Subject type (`user:role:type`, `None` without a subject context) → its alert budget
    /// against [`POLICY_DENIAL_ALERT_CAP`]. One budget per subject, so a noisy domain cannot
    /// spend another's. LRU-bounded by [`POLICY_DENIAL_SUBJECT_CAP`]; an evicted subject starts
    /// a fresh budget.
    policy_denial_budgets: BoundedMap<Option<String>, PolicyDenialBudget>,
    /// `policy_denial_budgets.evicted()` last reported, so each rise is logged once.
    policy_denial_budget_evictions_reported: u64,
    /// New-shape events shed by [`POLICY_DENIAL_ALERT_CAP`] over the whole run, all subjects — counted
    /// instead of silent (#812). A shed shape is *not* remembered in
    /// `known_policy_denials`, so it is still new when it comes back: it can alert in a
    /// later budget window, and every event for it while the budget is spent counts
    /// again (this counts events, not distinct shapes).
    policy_denial_alerts_shed: u64,
    /// `known_policy_denials.evicted()` last reported, so each rise is logged once
    /// (#812): otherwise `known_policy_denials` evicting its oldest eighth at
    /// `COUNTER_CAP` (never a full clear — only the evicted entries can re-alert) and a
    /// shape re-alerting is silent loss (CLAUDE.md: counted, observable shedding).
    policy_denial_evictions_reported: u64,
}

impl DriftState {
    pub(crate) fn new() -> Self {
        Self {
            known_listeners: BoundedMap::new(COUNTER_CAP),
            known_policy_denials: BoundedMap::new(COUNTER_CAP),
            policy_denial_budgets: BoundedMap::new(POLICY_DENIAL_SUBJECT_CAP),
            policy_denial_budget_evictions_reported: 0,
            policy_denial_alerts_shed: 0,
            policy_denial_evictions_reported: 0,
        }
    }

    /// Pre-fills the LISTENER-DRIFT baseline: see [`crate::RuleState::seed_listen_ports`].
    pub(crate) fn seed_listen_ports(&mut self, ports: impl IntoIterator<Item = (IpAddr, u16, u8)>) {
        for key in ports {
            self.known_listeners.insert(key, ());
        }
    }

    /// LISTENER-DRIFT (issue #92, T1571 — non-standard port is the closest
    /// existing tag in this crate; no better precedent for "a new listener
    /// appeared" exists here yet, calibratable later) — a listening socket that
    /// wasn't in the startup baseline ([`Self::seed_listen_ports`]) nor already
    /// alerted on this run. One alert per (`local_addr`, `local_port`, `protocol`): the
    /// second poll to see the same listener is expected (a poll-based source re-reports
    /// it every cycle while it stays open, same reasoning as
    /// [`crate::network_state::NetworkState`]'s BEACON flow dedup), not a second finding — and a TCP and a UDP
    /// listener sharing a port (<https://github.com/synthaea-lab/agent/issues/40>) are different listeners, not one.
    ///
    /// No name/path exclusion list yet — unlike BEACON's `BROWSERS`/
    /// `STANDARD_PORTS`, there is no lab capture here to calibrate one honestly
    /// against (a dev server or `docker-proxy` binding a fresh port after
    /// startup will alert; a documented, known noise source, not a bug).
    pub(crate) fn check_listen_port_drift(&mut self, event: &ListenPortEvent) -> Option<Alert> {
        let key = (event.local_addr, event.local_port, event.protocol);
        if self.known_listeners.get(&key).is_some() {
            return None;
        }
        self.known_listeners.insert(key, ());
        Some(Alert {
            technique: "T1571",
            severity: Severity::Medium,
            message: format!(
                "pid={} comm={} new {} listener on {}:{} — not seen at agent startup",
                event.meta.pid,
                event.meta.comm,
                protocol_label(event.protocol),
                event.local_addr,
                event.local_port,
            ),
        })
    }

    /// POLICY-DENIAL-DRIFT (issue #774, T1562-adjacent): alerts on a new shape, not on every
    /// denial, because an enforcing host denies constantly as part of normal operation (see
    /// `docs/detection/rules.md#first-seen-shapes`). Fires for
    /// `PolicyDenialEvent::enforced` either way (`SELinux` permissive logs the
    /// same fact a managed Enforcing host would act on) — the point is a new
    /// *shape* of denial, not whether this particular one was blocked.
    ///
    /// The key depends on the mechanism (#796), see `known_policy_denials`'s doc. A mechanism
    /// other than `SELinux`, `AppLocker` or WDAC never alerts. Severity is Medium, except Low
    /// for an `AppLocker` or WDAC denial in audit mode (`enforced: false`): a rollout in audit
    /// mode logs every unlisted binary once, and that is routine. `SELinux` stays Medium
    /// either way.
    ///
    /// Inert while the eBPF sensor is selected (#780): `SELinux` AVC denials
    /// only reach the agent through the audit sensor, so silence here does not
    /// mean no denials happened.
    ///
    /// The requested permission is part of the key (#813, recovered by
    /// `sensor-linux-audit`'s AVC parser): a routine `getattr` denial no longer
    /// silences a later, more interesting `read`/`write`/`open` on the same subject,
    /// object and class. `None` (an AppLocker/WDAC denial, or an AVC variant the
    /// parser doesn't recognize) is its own value, same as every other field here.
    ///
    /// Capped at [`POLICY_DENIAL_ALERT_CAP`] new-shape alerts per subject type per
    /// [`crate::exclusions::POLICY_DENIAL_ALERT_WINDOW_NS`] (#812, per subject since #840): a
    /// flood of shapes from one domain past its cap is counted (`policy_denial_alerts_shed`)
    /// rather than alerted, and never touches another domain's budget. A shed shape is not
    /// recorded in `known_policy_denials`, so it is still new — it can alert once its
    /// subject's budget refills in a later window instead of being silenced for the rest of the
    /// run. The cap bounds alert volume; `known_policy_denials` keeps deduplicating
    /// the shapes that did alert.
    ///
    /// The permission set in the key is normalised ([`normalized_permissions`]): `read
    /// write` and `write read` are one shape.
    pub(crate) fn check_policy_denial_drift(&mut self, event: &PolicyDenialEvent) -> Option<Alert> {
        let key: PolicyDenialKey = match event.mechanism.as_str() {
            POLICY_MECHANISM_SELINUX => (
                event.mechanism.clone(),
                selinux_type_triple(event.subject_context.as_deref()),
                selinux_type_triple(event.object_context.as_deref()),
                event.object_class.clone(),
                event.action.as_deref().map(normalized_permissions),
            ),
            // AppLocker: (rule collection, file). The sensor leaves both contexts `None`, so
            // the budget below is one shared by every AppLocker denial.
            POLICY_MECHANISM_APPLOCKER => (
                event.mechanism.clone(),
                None,
                event.object_path.as_deref().map(str::to_lowercase),
                event.object_class.clone(),
                None,
            ),
            // WDAC: (loading process, file, signing scenario), so the budget is per process.
            POLICY_MECHANISM_WDAC => (
                event.mechanism.clone(),
                event.subject_context.as_deref().map(str::to_lowercase),
                event.object_path.as_deref().map(str::to_lowercase),
                event.object_class.clone(),
                None,
            ),
            _ => return None,
        };
        if self.known_policy_denials.get(&key).is_some() {
            return None;
        }
        let now = event.meta.timestamp_ns;
        // The budget is the subject type's (`key.1`, the context without its MLS part), so a noisy
        // domain spends its own and nobody else's.
        let budget = self
            .policy_denial_budgets
            .get_or_insert_with(key.1.clone(), PolicyDenialBudget::default);
        if budget.window_start_ns.is_none_or(|start| {
            now.saturating_sub(start) >= crate::exclusions::POLICY_DENIAL_ALERT_WINDOW_NS
        }) {
            *budget = PolicyDenialBudget {
                window_start_ns: Some(now),
                ..PolicyDenialBudget::default()
            };
        }
        if budget.alerts >= POLICY_DENIAL_ALERT_CAP {
            if budget.shed == 0 {
                tracing::warn!(
                    cap = POLICY_DENIAL_ALERT_CAP,
                    subject = key.1.as_deref().unwrap_or("-"),
                    "policy-denial-drift: alert cap reached for this subject, its further new shapes are counted but not alerted until its budget refills"
                );
            }
            budget.shed += 1;
            self.policy_denial_alerts_shed += 1;
            self.report_policy_denial_evictions();
            return None;
        }
        budget.alerts += 1;
        self.known_policy_denials.insert(key, ());
        self.report_policy_denial_evictions();
        Some(Alert {
            technique: "T1562",
            // A Windows policy in audit mode logs every unlisted binary once during a rollout:
            // routine, not an incident. SELinux keeps Medium either way (see the doc above).
            severity: if event.mechanism != POLICY_MECHANISM_SELINUX && !event.enforced {
                Severity::Low
            } else {
                Severity::Medium
            },
            message: format!(
                "comm={} mechanism={} subject={} object={} class={} action={} path={} enforced={} — new denial shape, not seen this run",
                event.meta.comm,
                event.mechanism,
                event.subject_context.as_deref().unwrap_or("-"),
                event.object_context.as_deref().unwrap_or("-"),
                event.object_class.as_deref().unwrap_or("-"),
                event.action.as_deref().unwrap_or("-"),
                event.object_path.as_deref().unwrap_or("-"),
                event.enforced,
            ),
        })
    }

    /// Logs once per rise in `known_policy_denials`'s eviction count (#812): otherwise
    /// `known_policy_denials` evicting its oldest eighth at `COUNTER_CAP` and a shape
    /// re-alerting is silent loss (CLAUDE.md: counted, observable shedding), the same
    /// idiom as `agent::ransomware_join`'s `report_evictions`. Also carries the running
    /// total of alerts shed by [`POLICY_DENIAL_ALERT_CAP`] (review of #823): this is the
    /// only periodic signal the alert cap gets — once it is reached, the "alert cap
    /// reached" warning fires exactly once, never again, so without this an operator
    /// cannot tell 10 shed shapes from 100,000.
    fn report_policy_denial_evictions(&mut self) {
        let budgets_evicted = self.policy_denial_budgets.evicted();
        if budgets_evicted > self.policy_denial_budget_evictions_reported {
            tracing::warn!(
                budgets_evicted,
                "policy-denial-drift: subject alert budgets forgotten (least recently seen first); those subjects start a fresh budget"
            );
            self.policy_denial_budget_evictions_reported = budgets_evicted;
        }
        let evicted = self.known_policy_denials.evicted();
        if evicted > self.policy_denial_evictions_reported {
            tracing::warn!(
                evicted,
                alerts_shed = self.policy_denial_alerts_shed,
                "policy-denial-drift: tracked denial shapes shed (oldest first)"
            );
            self.policy_denial_evictions_reported = evicted;
        }
    }
}

/// The `user:role:type` prefix of a `SELinux` security context
/// (`user:role:type:sensitivity[:categories]`), dropped from
/// [`PolicyDenialKey`] so a container's own MCS/MLS category pair does not
/// make every denial from it a "new" shape (#781 review: two denials
/// differing only in category gave two alerts). A bounded split, not a
/// split on the last colon: the MLS field itself can contain one
/// (`s0-s0:c0.c1023`). A bare type with no context at all (`httpd_t`)
/// passes through unchanged.
fn selinux_type_triple(context: Option<&str>) -> Option<String> {
    context.map(|c| c.splitn(4, ':').take(3).collect::<Vec<_>>().join(":"))
}

/// `event.protocol`'s IP protocol number, as a word for the LISTENER-DRIFT alert
/// (<https://github.com/synthaea-lab/agent/issues/40>) — `tcp`/`udp` for the two values every snapshot source reports
/// today, the bare number for anything else rather than guessing a name.
fn protocol_label(protocol: u8) -> std::borrow::Cow<'static, str> {
    match protocol {
        schema::IPPROTO_TCP => "tcp".into(),
        schema::IPPROTO_UDP => "udp".into(),
        other => other.to_string().into(),
    }
}
