//! The authentication rules of [`crate::RuleState`]: FIRST-SEEN-LOGON and ODD-HOUR-LOGON
//! (T1078) on a successful logon, the failure burst (T1110), and the two failure-then-success
//! joins, RDP (T1021.001, with the T1563.002 session reconnect) and local `sudo`/`su`
//! (T1548.003 / T1110.001).

use schema::{
    AuthEvent, AuthKind, AuthOutcome, SessionEvent, SessionState, User, detection::Severity,
};
use store::BoundedMap;

use crate::{
    Alert,
    exclusions::{AUTH_FAILURE_THRESHOLD, AUTH_FAILURE_WINDOW_NS},
    logon::{LogonBaseline, Observation, OddHours},
    rdp::RdpSuccessAfterFailures,
    session::SessionHijack,
    sliding::SlidingCounter,
    state::COUNTER_CAP,
    sudo::SudoSuccessAfterFailures,
};

/// The sliding history of the authentication rules, fed by `AuthEvent`s and `SessionEvent`s.
pub(crate) struct AuthState {
    /// (target user, source) → sliding failure counter for T1110 (AUTH-BURST).
    /// LRU-bounded like every other counter: a spray across many fabricated
    /// usernames must not grow this without limit.
    auth_failures: BoundedMap<(String, String), SlidingCounter>,
    /// The accounts seen logging on, for FIRST-SEEN-LOGON (T1078, <https://github.com/synthaea-lab/agent/issues/17>). LRU-bounded.
    logon_baseline: LogonBaseline,
    /// ODD-HOUR-LOGON's clock and quiet period; off until
    /// [`crate::RuleState::set_local_utc_offset_minutes`]. The `RuleState` setters configure it
    /// directly.
    pub(crate) odd_hours: OddHours,
    /// RDP authentication successes joined to the failures from the same address,
    /// by event time (T1021.001, #285); see the `rdp` module.
    rdp_success: RdpSuccessAfterFailures,
    /// Local privilege-escalation successes (`sudo`/`su`) joined to the
    /// authentication failures for the same account, by event time (#381,
    /// T1548.003 for `sudo` / T1110.001 for `su`) — "same account" means the
    /// same invoker uid for `sudo`, the same target name for `su`; see the
    /// `sudo` module's own doc for why they differ.
    sudo_success: SudoSuccessAfterFailures,
    /// Disconnected sessions and the client each was left from, for the
    /// T1563.002 reconnect check (#285).
    session_hijack: SessionHijack,
}

impl AuthState {
    pub(crate) fn new() -> Self {
        Self {
            auth_failures: BoundedMap::new(COUNTER_CAP),
            logon_baseline: LogonBaseline::new(),
            odd_hours: OddHours::new(),
            rdp_success: RdpSuccessAfterFailures::new(),
            sudo_success: SudoSuccessAfterFailures::new(),
            session_hijack: SessionHijack::new(),
        }
    }

    /// To be called for every `AuthEvent` in the stream (issue #377, T1110):
    /// counts failures per (target user, source) on a sliding window and
    /// alerts once per window when the burst threshold is crossed. A success
    /// deliberately doesn't reset the counter — a success right after a burst
    /// is the *stronger* signal, not an all-clear. For a Windows RDP success
    /// that signal is [`Self::rdp_success`] (T1021.001, joined from a separate
    /// `SessionEvent`); for a local `sudo`/`su` success it is
    /// [`Self::sudo_success`] (#381, T1548.003 for `sudo` / T1110.001 for `su`
    /// — see `crate::sudo`'s module doc) below, joined from this same
    /// `AuthEvent` stream. A local `sudo`/`su` failure also counts into the burst
    /// counter below (key: target account, source `"local"`, `sudo` and `su` sharing
    /// one key), so five wrong passwords in the window raise T1110 by themselves,
    /// before and independently of any success (#838).
    ///
    /// A **successful** [`AuthKind::Logon`] also goes through FIRST-SEEN-LOGON
    /// ([`Self::check_first_seen_logon`], T1078); it is the one rule on `main` that fires
    /// on a successful logon.
    pub(crate) fn on_auth(&mut self, event: &AuthEvent) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = self.check_first_seen_logon(event).into_iter().collect();
        alerts.extend(self.check_odd_hour_logon(event));
        alerts.extend(self.on_auth_failures_and_escalations(event));
        alerts
    }

    /// FIRST-SEEN-LOGON (T1078, <https://github.com/synthaea-lab/agent/issues/17>) — a successful logon ([`AuthKind::Logon`], never a
    /// failure, never `su`/`sudo`'s [`AuthKind::ExplicitCredentials`] or
    /// [`AuthKind::PrivilegedSession`]) of an account that did not log on to this host during
    /// the first [`LOGON_LEARNING_NS`](crate::exclusions::LOGON_LEARNING_NS) after the first
    /// one the state saw. One alert per account: it is in the baseline afterwards. Low: a new
    /// colleague, a new service account and a reinstalled host look the same, and nothing
    /// here separates them.
    ///
    /// **This makes the control plane's identity join live** (`server/lib/fleet-case.ts`,
    /// #62, #940): the join reads the event a detection stores, and until this rule no rule
    /// on `main` fired on a successful logon. The limits of that join are this rule's: the
    /// generic accounts are excluded (see `crate::logon`), `vagrant` deliberately is not,
    /// and a `LogonFailure` never counts because its user name is chosen by whoever tries
    /// it.
    ///
    /// The baseline is **in memory**: an agent restart, an update included, begins a new
    /// learning window, and an account that logs on during the window is learned without an
    /// alert, an intruder's included. Expected false positives: a domain controller or file
    /// server, which sees every user's first logon; a new hire; a service account first
    /// used after an install. Odd hours are [`Self::check_odd_hour_logon`], which needs the
    /// host's UTC offset: the event carries a UTC timestamp and nothing else knows the local time.
    fn check_first_seen_logon(&mut self, event: &AuthEvent) -> Option<Alert> {
        if event.outcome != AuthOutcome::Success || event.kind != AuthKind::Logon {
            return None;
        }
        match self.logon_baseline.observe(
            &event.target_user,
            event.target_user_sid.as_deref(),
            event.meta.timestamp_ns,
        ) {
            Observation::FirstSeen => {}
            Observation::Quiet | Observation::Known => return None,
        }
        let source = event
            .source_address
            .map_or_else(String::new, |address| format!(" from {address}"));
        Some(Alert {
            technique: "T1078",
            severity: Severity::Low,
            message: format!(
                "first successful logon of account {}{source} on this host since the baseline began",
                event.target_user,
            ),
        })
    }

    /// ODD-HOUR-LOGON (T1078, <https://github.com/synthaea-lab/agent/issues/17>): a successful [`AuthKind::Logon`] of a non-generic
    /// account whose host-local hour is outside the working hours: [`WORK_HOURS_LOCAL`](crate::exclusions::WORK_HOURS_LOCAL)
    /// unless the operator declared another window ([`crate::RuleState::set_work_hours`]).
    /// Low, once per account per [`ODD_HOUR_QUIET_NS`](crate::exclusions::ODD_HOUR_QUIET_NS).
    /// Same event gate and generic-account list as FIRST-SEEN-LOGON, so the two share the
    /// identity join's limits; they are independent and a first logon at night raises both.
    ///
    /// **Off until the host's local time is known**: the platform's zone (the agent asks it at
    /// startup, [`crate::RuleState::set_local_zone`]) or the operator's fixed UTC offset (`[detection]` in
    /// `agent.toml`, which overrides the zone). The event's timestamp is UTC and nothing else
    /// in the agent knows the local time.
    /// Expected false positives: on-call staff, night shifts, a host in use around the clock,
    /// and on Windows the service and batch logons (4624) of a named account; the operator
    /// answers them with a declared window ([`crate::RuleState::set_work_hours`]) and an exempt list
    /// ([`crate::RuleState::set_odd_hour_exempt_accounts`]).
    fn check_odd_hour_logon(&mut self, event: &AuthEvent) -> Option<Alert> {
        if event.outcome != AuthOutcome::Success || event.kind != AuthKind::Logon {
            return None;
        }
        let hour = self.odd_hours.observe(
            &event.target_user,
            event.target_user_sid.as_deref(),
            event.meta.timestamp_ns,
        )?;
        let source = event
            .source_address
            .map_or_else(String::new, |address| format!(" from {address}"));
        Some(Alert {
            technique: "T1078",
            severity: Severity::Low,
            message: format!(
                "successful logon of account {}{source} at {hour:02}:00 host-local time, outside the working hours",
                event.target_user,
            ),
        })
    }

    /// The failure-burst and `sudo`/`su` joins of [`Self::on_auth`].
    fn on_auth_failures_and_escalations(&mut self, event: &AuthEvent) -> Vec<Alert> {
        let ts = event.meta.timestamp_ns;
        if event.outcome == AuthOutcome::Success {
            // Only a local (Unix) privilege-escalation success joins the sudo/su
            // burst history — a Windows logon success is [`Self::rdp_success`]'s
            // job, fed from the Terminal Services session event instead, not
            // this one (see that field's doc). `PrivilegedSession`/
            // `ExplicitCredentials` are only ever produced for `sudo`/`su`
            // (`auth::to_auth_event`), so `event.meta.comm` is already one of
            // the two here; the explicit match is defense in depth, not a new
            // restriction. `sudo` joins on the trusted uid, not a name, and
            // `su` still joins on the target `AuthEvent::target_user` names —
            // see `crate::sudo`'s module doc for why they differ (review of
            // #838, Sollykhan 2026-10-19, point 1).
            let User::Unix { uid, .. } = event.meta.user else {
                return Vec::new();
            };
            return if matches!(
                event.kind,
                AuthKind::PrivilegedSession | AuthKind::ExplicitCredentials
            ) {
                match event.meta.comm.as_str() {
                    "sudo" => self.sudo_success.on_sudo_success(uid, ts),
                    "su" => self.sudo_success.on_su_success(&event.target_user, ts),
                    _ => Vec::new(),
                }
            } else {
                Vec::new()
            };
        }
        // "local" for console/service logons that legitimately carry no
        // source address (see `AuthEvent::source_address`'s doc) — a distinct
        // key, never a fabricated loopback.
        let source = event
            .source_address
            .map_or_else(|| "local".to_string(), |a| a.to_string());
        let key = (event.target_user.clone(), source.clone());
        // A success can reach the rules before the last failures that precede
        // it (two channels, two poll threads, for RDP's own join): this failure
        // may complete it. Only failures from the Windows Security log feed that
        // join: they carry a Windows identity and are stamped with the event's
        // own time, like the 1149. Application-log failures (`[logs]` sources)
        // are stamped when the line is read, so a restart replaying a backlog
        // would make hours-old failures look current: other clock, not joined.
        let mut alerts: Vec<Alert> = event
            .source_address
            .filter(|_| matches!(event.meta.user, User::Windows { .. }))
            .map(|address| self.rdp_success.on_failure(address, ts))
            .unwrap_or_default();
        // The sudo/su join has no such cross-channel concern (one journal
        // stream feeds both sides of it), but still joins by event time, not
        // arrival order — see the `sudo` module's doc. Gated on `comm`, not
        // just `User::Unix`: an sshd failure (`LogonFailure` from `SshFailed`)
        // is also a Unix identity, and must never reach this join at all —
        // unchanged by the point below. What changed (review of #838,
        // Sollykhan 2026-10-19, point 1): once an event *does* pass this
        // gate, `sudo`'s own side of the join now keys on the trusted uid
        // below, not on anything parsed from the message; `su`'s still keys
        // on the target name, which has its own, narrower residual exposure
        // — see `crate::sudo`'s doc for why the two differ.
        if let User::Unix { uid, .. } = event.meta.user {
            match event.meta.comm.as_str() {
                "sudo" => alerts.extend(self.sudo_success.on_sudo_failure(uid, ts)),
                "su" => alerts.extend(self.sudo_success.on_su_failure(&event.target_user, ts)),
                _ => {}
            }
        }
        let entry = self
            .auth_failures
            .get_or_insert_with(key, SlidingCounter::default);
        let count = entry.record(ts, AUTH_FAILURE_WINDOW_NS);
        if count >= AUTH_FAILURE_THRESHOLD && entry.try_alert(ts, AUTH_FAILURE_WINDOW_NS) {
            alerts.push(Alert {
                technique: "T1110",
                severity: Severity::Medium,
                message: format!(
                    "target={} source={source}: {count} failed authentications in {}s —                      brute-force/spray burst",
                    event.target_user,
                    AUTH_FAILURE_WINDOW_NS / 1_000_000_000,
                ),
            });
        }
        alerts
    }

    /// To be called for every `SessionEvent` in the stream (Windows Terminal
    /// Services, #285): a disconnected session reconnected from another
    /// client, T1563.002 (see the `session` module), or a successful RDP listener
    /// authentication after failures from that source, T1021.001.
    pub(crate) fn on_session(&mut self, event: &SessionEvent) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = self.session_hijack.on_session(event).into_iter().collect();

        if event.state != SessionState::Connect || event.console {
            return alerts;
        }
        if let Some(address) = event.source_address {
            alerts.extend(self.rdp_success.on_success(
                address,
                event.meta.timestamp_ns,
                &event.target_user,
            ));
        }
        alerts
    }
}
