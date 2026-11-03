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

/// The host's zone as a function: minutes east of UTC at an instant (seconds since the Unix
/// epoch), or `None` when it cannot say. Supplied by the agent from the platform
/// (`agent/src/commands/localzone.rs`), so a logon is converted with the zone's rules **at that instant**,
/// daylight saving included.
pub type LocalOffsetAt = fn(i64) -> Option<i32>;

/// Most entries the exempt list keeps, and the longest one: the bounds `config::load` enforces
/// (`MAX_ODD_HOUR_EXEMPT_ACCOUNTS`, 256 bytes), repeated here so that any other caller of the
/// rules API gets a bounded list too. Past them an entry is dropped, not refused.
pub(crate) const MAX_EXEMPT_ACCOUNTS: usize = 64;
pub(crate) const MAX_EXEMPT_ENTRY_BYTES: usize = 256;

/// One entry of the exempt list: an account name, and optionally the SID the logon must carry.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ExemptEntry {
    /// Lowercased account name, exactly as the event reports it.
    name: String,
    /// `None`: the name alone decides. `Some`: the event must also carry a matching SID.
    sid: Option<SidMatch>,
}

/// The SID an exempt entry is bound to: `S-1-5-21-...-1004` exactly, or a prefix written with a
/// trailing `-*` (`S-1-5-21-111-222-333-*`, a domain or a machine) that any SID below it matches.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SidMatch {
    /// Uppercase. For a prefix it ends with `-`.
    value: String,
    prefix: bool,
}

impl SidMatch {
    fn matches(&self, sid: &str) -> bool {
        let sid = sid.to_ascii_uppercase();
        if self.prefix {
            sid.starts_with(&self.value)
        } else {
            sid == self.value
        }
    }
}

/// `NAME` or `NAME|SID`. `|` never occurs in a Windows account name, so it cannot be part of
/// a name. `None` for a blank entry, an over-long one, or a `SID` part that is not a SID or a
/// `-*` prefix: an entry whose SID part is malformed is dropped, never read as the bare name,
/// which would exempt more than the operator wrote.
fn parse_exempt_entry(entry: &str) -> Option<ExemptEntry> {
    let entry = entry.trim();
    if entry.is_empty() || entry.len() > MAX_EXEMPT_ENTRY_BYTES {
        return None;
    }
    let Some((name, sid)) = entry.split_once('|') else {
        return Some(ExemptEntry {
            name: entry.to_lowercase(),
            sid: None,
        });
    };
    let (name, sid) = (name.trim(), sid.trim());
    if name.is_empty() || !is_sid_pattern(sid) {
        return None;
    }
    let (value, prefix) = match sid.strip_suffix('*') {
        Some(head) => (head.to_ascii_uppercase(), true),
        None => (sid.to_ascii_uppercase(), false),
    };
    Some(ExemptEntry {
        name: name.to_lowercase(),
        sid: Some(SidMatch { value, prefix }),
    })
}

/// A SID (`S-1-` then digits and dashes) or such a prefix ending in `-*`.
fn is_sid_pattern(text: &str) -> bool {
    let body = text.strip_suffix("-*").unwrap_or(text);
    let Some(rest) = body
        .strip_prefix("S-1-")
        .or_else(|| body.strip_prefix("s-1-"))
    else {
        return false;
    };
    !rest.is_empty()
        && !rest.starts_with('-')
        && !rest.ends_with('-')
        && !rest.contains("--")
        && rest.bytes().all(|b| b.is_ascii_digit() || b == b'-')
}

/// ODD-HOUR-LOGON's clock: the host's local time, and the accounts already reported tonight.
/// Two sources, the operator's fixed offset first: it is an override, so a host whose platform
/// zone is wrong (or absent) can be corrected. With neither the rule is off: the event's
/// timestamp is UTC and "outside working hours" means nothing without the host's own time.
pub(crate) struct OddHours {
    offset_minutes: Option<i32>,
    zone: Option<LocalOffsetAt>,
    /// The local hours `[start, end)` of an ordinary logon; `start` greater than `end` wraps
    /// midnight. [`WORK_HOURS_LOCAL`] until the operator declares another.
    work_hours: (u32, u32),
    /// The accounts whose odd-hour logons the operator declared expected.
    exempt: Vec<ExemptEntry>,
    /// Lowercased account → timestamp of its last alert.
    last_alert_ns: BoundedMap<String, u64>,
    /// Lowercased account → timestamp of the last odd-hour logon an exemption let through that
    /// was logged (one line per account per [`ODD_HOUR_QUIET_NS`], so a service account that logs
    /// on every minute does not flood the log).
    last_exempt_log_ns: BoundedMap<String, u64>,
    /// Odd-hour logons an exemption suppressed, since the agent started.
    exempt_skips: u64,
}

impl OddHours {
    pub(crate) fn new() -> Self {
        Self {
            offset_minutes: None,
            zone: None,
            work_hours: WORK_HOURS_LOCAL,
            exempt: Vec::new(),
            last_alert_ns: BoundedMap::new(COUNTER_CAP),
            last_exempt_log_ns: BoundedMap::new(COUNTER_CAP),
            exempt_skips: 0,
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

    /// Sets the ordinary local hours `[start, end)`; `start > end` wraps midnight (`22, 6` is a
    /// night shift). False, and nothing changes, unless `start` is 0 to 23, `end` is 1 to 24 and
    /// they differ.
    pub(crate) fn set_work_hours(&mut self, start: u32, end: u32) -> bool {
        if start > 23 || end == 0 || end > 24 || start == end {
            return false;
        }
        self.work_hours = (start, end);
        true
    }

    /// Declares the accounts whose odd-hour logons are expected (on-call, a schedule's service
    /// account). An entry is `NAME`, or `NAME|SID` (a SID such as `S-1-5-21-111-222-333-1004`, or
    /// a prefix ending in `-*` for a whole domain or machine). The name is matched **as the event
    /// reports it**, case aside. The Windows logon reports the bare account name, so a bare entry
    /// exempts any account of that name, including a local one an intruder with local admin
    /// creates under it (checked live on a Windows 11 host, 2026-11-03); a `CORP\svc_backup`
    /// entry matches only an event that reports exactly that string, which no sensor does for a
    /// logon today; a UPN (`svc_backup@corp.com`) or `corp/svc_backup` is another string and a
    /// bare entry does not match it. The SID is the evidence an intruder cannot choose: with
    /// `NAME|SID` the event must carry a matching `target_user_sid`, and an event with none (Linux
    /// and macOS logons have no SID) is **not** exempt.
    ///
    /// Bounded: at most [`MAX_EXEMPT_ACCOUNTS`] entries are kept, and a blank, over-long or
    /// malformed entry is dropped (truncated, not refused). Returns how many were kept. Replaces
    /// the previous list.
    pub(crate) fn set_exempt_accounts(&mut self, accounts: &[String]) -> usize {
        self.exempt = accounts
            .iter()
            .filter_map(|a| parse_exempt_entry(a))
            .take(MAX_EXEMPT_ACCOUNTS)
            .collect();
        self.exempt.len()
    }

    fn is_exempt(&self, user: &str, sid: Option<&str>) -> bool {
        let lower = user.to_lowercase();
        self.exempt.iter().any(|entry| {
            entry.name == lower
                && entry
                    .sid
                    .as_ref()
                    .is_none_or(|want| sid.is_some_and(|got| want.matches(got)))
        })
    }

    /// Odd-hour logons an exemption has suppressed since the agent started.
    pub(crate) fn exempt_skips(&self) -> u64 {
        self.exempt_skips
    }

    fn in_work_hours(&self, hour: u32) -> bool {
        let (start, end) = self.work_hours;
        if start < end {
            (start..end).contains(&hour)
        } else {
            hour >= start || hour < end
        }
    }

    /// Sets the platform's zone, used where no fixed offset is set. False, and nothing changes,
    /// when `zone` cannot convert the present: a source that answers nothing now is not a zone
    /// the rule can rely on, and the rule stays as it was (off, unless an offset is set).
    pub(crate) fn set_zone(&mut self, zone: LocalOffsetAt, now_secs: i64) -> bool {
        if zone(now_secs)
            .is_none_or(|m| !(MIN_UTC_OFFSET_MINUTES..=MAX_UTC_OFFSET_MINUTES).contains(&m))
        {
            return false;
        }
        self.zone = Some(zone);
        true
    }

    /// Minutes east of UTC at `secs`: the operator's offset if set, else the platform zone's at
    /// that instant. `None` when there is neither, or the zone has no answer or one no zone has.
    fn offset_minutes_at(&self, secs: i64) -> Option<i32> {
        if let Some(fixed) = self.offset_minutes {
            return Some(fixed);
        }
        let minutes = (self.zone?)(secs)?;
        (MIN_UTC_OFFSET_MINUTES..=MAX_UTC_OFFSET_MINUTES)
            .contains(&minutes)
            .then_some(minutes)
    }

    /// The local hour (0..24) at `ts`, or `None` while there is no zone.
    fn local_hour(&self, ts: u64) -> Option<u32> {
        let secs = i64::try_from(ts / 1_000_000_000).ok()?;
        let offset = i64::from(self.offset_minutes_at(secs)?);
        let local = (secs + offset * 60).rem_euclid(86_400);
        u32::try_from(local / 3_600).ok()
    }

    /// The local hour of a logon of `user` (carrying `sid`, when the sensor reports one) at `ts`
    /// when it is outside the working hours and this account has not been reported within
    /// [`ODD_HOUR_QUIET_NS`]; remembers it. A logon an exemption suppresses is counted
    /// ([`Self::exempt_skips`]) and logged once per account per quiet period, so a suppression
    /// list leaves a trace.
    pub(crate) fn observe(&mut self, user: &str, sid: Option<&str>, ts: u64) -> Option<u32> {
        let hour = self.local_hour(ts)?;
        if self.in_work_hours(hour) || user.is_empty() || is_generic_account(user) {
            return None;
        }
        if self.is_exempt(user, sid) {
            self.exempt_skips = self.exempt_skips.saturating_add(1);
            let key = user.to_lowercase();
            if !self
                .last_exempt_log_ns
                .get(&key)
                .is_some_and(|last| ts.saturating_sub(*last) < ODD_HOUR_QUIET_NS)
            {
                tracing::info!(
                    account = user,
                    sid = sid.unwrap_or("none"),
                    skips = self.exempt_skips,
                    "odd-hour logon not reported: the account is on the exempt list"
                );
                self.last_exempt_log_ns.insert(key, ts);
            }
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
