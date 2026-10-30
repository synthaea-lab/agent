//! FIRST-SEEN-LOGON (T1078, #376): the baseline of accounts that have logged on to this host.
//!
//! The rule itself is [`crate::RuleState::check_first_seen_logon`]; this module holds the
//! generic-account list and the bounded baseline it reads.

use store::BoundedMap;

use crate::{
    exclusions::{LOGON_LEARNING_NS, ODD_HOUR_QUIET_NS, WORK_HOURS_LOCAL},
    state::COUNTER_CAP,
};

/// Accounts every host has, whose logon says nothing about who is on the host. Lowercase.
/// Kept in step with `server/lib/fleet-case.ts` (`GENERIC_IDENTITIES`), which draws the same
/// line for the control plane's identity join: a name generic there must not alert here, and
/// the other way round.
///
/// The default logins of cloud and distribution images are generic (every host built from
/// the image has one). **`vagrant` is deliberately not**: the lab VMs are signed in to as
/// `vagrant`, and with it listed no lab run could show the rule or the join it feeds.
const GENERIC_ACCOUNTS: &[&str] = &[
    "root",
    "system",
    "nt authority\\system",
    "nt authority\\local service",
    "nt authority\\network service",
    "administrator",
    "nobody",
    "daemon",
    "ubuntu",
    "ec2-user",
    "debian",
    "fedora",
    "centos",
    "rocky",
    "cloud-user",
    "azureuser",
    "admin",
];

/// Whether `user` (`name` or `DOMAIN\name`, any case) is an account every host has. Only the
/// name counts: `HOST\Administrator` is as generic as `Administrator`. Windows machine
/// accounts (`HOST$`) and the session helpers a Windows host logs on by itself (`DWM-1`,
/// `UMFD-0`, `ANONYMOUS LOGON`, `LOCAL SERVICE`, `NETWORK SERVICE`) are generic too.
pub(crate) fn is_generic_account(user: &str) -> bool {
    let lower = user.to_lowercase();
    let name = lower.rsplit('\\').next().unwrap_or(&lower);
    GENERIC_ACCOUNTS.contains(&lower.as_str())
        || GENERIC_ACCOUNTS.contains(&name)
        || name.ends_with('$')
        || is_session_helper(name)
        || matches!(
            name,
            "anonymous logon" | "local service" | "network service"
        )
}

/// `dwm-<n>` and `umfd-<n>`: the desktop-window-manager and font-driver accounts Windows
/// creates per session.
fn is_session_helper(name: &str) -> bool {
    ["dwm-", "umfd-"].iter().any(|prefix| {
        name.strip_prefix(prefix)
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    })
}

/// What a successful logon of an account is, against the baseline.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Observation {
    /// Inside the learning window, or a generic account: nothing to say.
    Quiet,
    /// Already logged on since the baseline began.
    Known,
    /// First logon of this account after the learning window.
    FirstSeen,
}

/// The accounts seen logging on, and when the baseline began.
pub(crate) struct LogonBaseline {
    /// The timestamp of the first successful logon (of any account) the rule state saw: the learning window
    /// runs from it, not from process start, so a journal replayed after a restart measures
    /// the window in event time.
    started_ns: Option<u64>,
    /// Lowercased account → seen. LRU-bounded: an evicted account is first-seen again.
    known: BoundedMap<String, ()>,
}

impl LogonBaseline {
    pub(crate) fn new() -> Self {
        Self {
            started_ns: None,
            known: BoundedMap::new(COUNTER_CAP),
        }
    }

    /// Records a successful logon of `user` at `ts` and says what it is.
    pub(crate) fn observe(&mut self, user: &str, ts: u64) -> Observation {
        // The clock starts at the first logon of any account, a generic one included: a host
        // only `root` logs on to for days must not leave an intruder's first account inside
        // a window that never began.
        let started = *self.started_ns.get_or_insert(ts);
        if user.is_empty() || is_generic_account(user) {
            return Observation::Quiet;
        }
        let key = user.to_lowercase();
        let known = self.known.get_mut(&key).is_some();
        if !known {
            self.known.insert(key, ());
        }
        if ts.saturating_sub(started) < LOGON_LEARNING_NS {
            Observation::Quiet
        } else if known {
            Observation::Known
        } else {
            Observation::FirstSeen
        }
    }
}

/// Most minutes east of UTC a host's local time can be (UTC+14, Kiribati).
const MAX_UTC_OFFSET_MINUTES: i32 = 14 * 60;
/// Most minutes west of UTC (UTC-12).
const MIN_UTC_OFFSET_MINUTES: i32 = -12 * 60;

/// ODD-HOUR-LOGON's clock: the host's local time as a fixed offset from UTC, and the accounts
/// already reported tonight. With no offset the rule is off: the event's timestamp is UTC
/// and "outside working hours" means nothing without the host's own time.
pub(crate) struct OddHours {
    offset_minutes: Option<i32>,
    /// Lowercased account → timestamp of its last alert.
    last_alert_ns: BoundedMap<String, u64>,
}

impl OddHours {
    pub(crate) fn new() -> Self {
        Self {
            offset_minutes: None,
            last_alert_ns: BoundedMap::new(COUNTER_CAP),
        }
    }

    /// Sets the host's offset from UTC, in minutes. False, and the rule stays as it was, when
    /// the offset is not one a timezone has.
    pub(crate) fn set_offset_minutes(&mut self, minutes: i32) -> bool {
        if !(MIN_UTC_OFFSET_MINUTES..=MAX_UTC_OFFSET_MINUTES).contains(&minutes) {
            return false;
        }
        self.offset_minutes = Some(minutes);
        true
    }

    /// The local hour (0..24) at `ts`, or `None` while no offset is set.
    fn local_hour(&self, ts: u64) -> Option<u32> {
        let offset = i64::from(self.offset_minutes?);
        let secs = i64::try_from(ts / 1_000_000_000).ok()?;
        let local = (secs + offset * 60).rem_euclid(86_400);
        u32::try_from(local / 3_600).ok()
    }

    /// The local hour of a logon of `user` at `ts` when it is outside the working hours and
    /// this account has not been reported within [`ODD_HOUR_QUIET_NS`]; remembers it.
    pub(crate) fn observe(&mut self, user: &str, ts: u64) -> Option<u32> {
        let hour = self.local_hour(ts)?;
        let (start, end) = WORK_HOURS_LOCAL;
        if (start..end).contains(&hour) || user.is_empty() || is_generic_account(user) {
            return None;
        }
        let key = user.to_lowercase();
        if self
            .last_alert_ns
            .get(&key)
            .is_some_and(|last| ts.saturating_sub(*last) < ODD_HOUR_QUIET_NS)
        {
            return None;
        }
        self.last_alert_ns.insert(key, ts);
        Some(hour)
    }
}

#[cfg(test)]
mod tests {
    use super::is_generic_account;

    #[test]
    fn accounts_every_host_has_are_generic_in_any_case_and_with_a_domain() {
        for user in [
            "root",
            "ROOT",
            "SYSTEM",
            "NT AUTHORITY\\SYSTEM",
            "HOST\\Administrator",
            "ubuntu",
            "ec2-user",
            "azureuser",
            "WS01$",
            "CORP\\WS01$",
            "DWM-1",
            "UMFD-0",
            "ANONYMOUS LOGON",
            "NT AUTHORITY\\LOCAL SERVICE",
            "NT AUTHORITY\\NETWORK SERVICE",
        ] {
            assert!(is_generic_account(user), "{user}");
        }
    }

    #[test]
    fn vagrant_and_ordinary_accounts_are_not_generic() {
        for user in [
            "vagrant",
            "alice",
            "CORP\\bob",
            "rootkit",
            "dwm-x",
            "dwm-",
            "umfd",
            "svc-backup",
        ] {
            assert!(!is_generic_account(user), "{user}");
        }
    }
}
