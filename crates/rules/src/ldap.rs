//! Rules over LDAP searches (#364): the endpoint's view of directory
//! reconnaissance. The roasting and delegation attacks themselves happen on a
//! domain controller; what the endpoint sees is the search that finds their
//! targets, and the process that sent it.
//!
//! Every rule ignores the built-in service accounts (SYSTEM, LOCAL SERVICE,
//! NETWORK SERVICE): Group Policy, the domain-join machinery and the like
//! query the directory constantly as the machine. Reconnaissance runs as a
//! user, even an administrator.

use schema::{LdapSearchEvent, User};
use store::BoundedMap;

use crate::{Alert, sliding::SlidingDistinct};

/// T1558.003: searching for user accounts that carry a service principal name,
/// the Kerberoasting target list.
const KERBEROAST_RECON: &str = "T1558.003";
/// T1558.004: searching for accounts that do not require Kerberos
/// pre-authentication, the AS-REP roasting target list.
const ASREP_ROAST_RECON: &str = "T1558.004";
/// T1087.002: domain account discovery (privileged accounts, delegation, and
/// the wide-enumeration burst).
const DOMAIN_ACCOUNT_DISCOVERY: &str = "T1087.002";
/// T1482: domain trust discovery.
const DOMAIN_TRUST_DISCOVERY: &str = "T1482";
/// T1552: reading stored credentials out of the directory (LAPS, gMSA).
const DIRECTORY_CREDENTIAL_READ: &str = "T1552";

/// `userAccountControl` bitwise-AND rule (`LDAP_MATCHING_RULE_BIT_AND`) with
/// `DONT_REQUIRE_PREAUTH` (0x400000).
const UAC_DONT_REQUIRE_PREAUTH: &str = "useraccountcontrol:1.2.840.113556.1.4.803:=4194304";
/// Same rule with `TRUSTED_FOR_DELEGATION` (0x80000): unconstrained delegation.
const UAC_TRUSTED_FOR_DELEGATION: &str = "useraccountcontrol:1.2.840.113556.1.4.803:=524288";

/// Filters that restrict a search to user accounts, as roasting tools write
/// them (`samAccountType=805306368` is `SAM_USER_OBJECT`).
const USER_SCOPES: &[&str] = &[
    "samaccounttype=805306368",
    "objectcategory=user",
    "objectcategory=person",
    "objectclass=user",
];

/// Attributes that hold a readable password: legacy and Windows LAPS, gMSA.
const PASSWORD_ATTRIBUTES: &[&str] = &[
    "ms-mcs-admpwd",
    "mslaps-password",
    "mslaps-encryptedpassword",
    "msds-managedpassword",
];

/// Distinct searches from one process within [`BURST_WINDOW_NS`] that make a
/// collection sweep. `SharpHound` and `ADFind`-style sweeps send dozens to
/// hundreds; an interactive admin tool sends a handful per action.
pub(crate) const BURST_THRESHOLD: u32 = 20;
pub(crate) const BURST_WINDOW_NS: u64 = 60_000_000_000;
/// Processes tracked at once for the burst rule.
const BURST_PIDS_CAP: usize = 4_096;

/// The built-in service accounts, see the module doc.
fn is_service_account(user: &User) -> bool {
    matches!(user, User::Windows { sid, .. } if matches!(sid.as_str(), "S-1-5-18" | "S-1-5-19" | "S-1-5-20"))
}

/// Lowercase, without whitespace: filters are case-insensitive and tools
/// space them freely (`( servicePrincipalName = * )`).
fn normalized(filter: &str) -> String {
    filter
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

/// The single-search rules: each filter shape below has a reconnaissance
/// purpose and little else.
#[must_use]
pub fn evaluate_ldap_search(event: &LdapSearchEvent) -> Vec<Alert> {
    if is_service_account(&event.meta.user) {
        return Vec::new();
    }
    let filter = normalized(&event.filter);
    let alert = |technique: &'static str, what: &str| Alert {
        technique,
        message: format!(
            "pid={} comm={}: LDAP search for {what}: filter={} base={}",
            event.meta.pid, event.meta.comm, event.filter, event.base_dn,
        ),
    };
    let mut alerts = Vec::new();
    if filter.contains("serviceprincipalname=*") && USER_SCOPES.iter().any(|s| filter.contains(s)) {
        alerts.push(alert(
            KERBEROAST_RECON,
            "user accounts with an SPN (Kerberoasting targets)",
        ));
    }
    if filter.contains(UAC_DONT_REQUIRE_PREAUTH) {
        alerts.push(alert(
            ASREP_ROAST_RECON,
            "accounts without Kerberos pre-authentication (AS-REP roasting targets)",
        ));
    }
    if filter.contains("admincount=1") {
        alerts.push(alert(
            DOMAIN_ACCOUNT_DISCOVERY,
            "privileged (adminCount=1) accounts",
        ));
    }
    if filter.contains(UAC_TRUSTED_FOR_DELEGATION)
        || filter.contains("msds-allowedtodelegateto=*")
        || filter.contains("msds-allowedtoactonbehalfofotheridentity=*")
    {
        alerts.push(alert(
            DOMAIN_ACCOUNT_DISCOVERY,
            "Kerberos delegation settings",
        ));
    }
    if filter.contains("objectclass=trusteddomain") {
        alerts.push(alert(DOMAIN_TRUST_DISCOVERY, "domain trusts"));
    }
    // Substring over the joined list, not an exact per-name match: robust to
    // a list the sensor could not split (the provider's `;` separator
    // once hid a LAPS attribute this way, #364 lab).
    let attributes = event.attributes.join(" ").to_ascii_lowercase();
    let reads_password = PASSWORD_ATTRIBUTES.iter().any(|a| attributes.contains(a))
        || PASSWORD_ATTRIBUTES
            .iter()
            .any(|a| filter.contains(&format!("{a}=*")));
    if reads_password {
        alerts.push(alert(
            DIRECTORY_CREDENTIAL_READ,
            "stored passwords (LAPS / gMSA)",
        ));
    }
    alerts
}

/// The burst rule's state: distinct searches per process, sliding window.
pub(crate) struct LdapBurst {
    per_pid: BoundedMap<u32, SlidingDistinct<String>>,
}

impl LdapBurst {
    pub(crate) fn new() -> Self {
        Self {
            per_pid: BoundedMap::new(BURST_PIDS_CAP),
        }
    }

    /// Records the search; one alert per window once a process has sent
    /// [`BURST_THRESHOLD`] distinct searches (filter, base and scope) within
    /// [`BURST_WINDOW_NS`].
    pub(crate) fn observe(&mut self, event: &LdapSearchEvent) -> Option<Alert> {
        if is_service_account(&event.meta.user) {
            return None;
        }
        let ts = event.meta.timestamp_ns;
        let search = format!(
            "{}|{}|{}",
            normalized(&event.filter),
            event.base_dn.to_lowercase(),
            event.scope
        );
        let distinct = self
            .per_pid
            .get_or_insert_with(event.meta.pid, SlidingDistinct::default);
        let count = distinct.record(search, ts, BURST_WINDOW_NS);
        (count >= BURST_THRESHOLD && distinct.try_alert(ts, BURST_WINDOW_NS)).then(|| Alert {
            technique: DOMAIN_ACCOUNT_DISCOVERY,
            message: format!(
                "pid={} comm={}: {count} distinct LDAP searches in {}s — directory enumeration sweep (last: {})",
                event.meta.pid,
                event.meta.comm,
                BURST_WINDOW_NS / 1_000_000_000,
                event.filter,
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use schema::fixtures;

    use super::*;

    fn search(filter: &str, attributes: &[&str]) -> LdapSearchEvent {
        LdapSearchEvent {
            meta: schema::EventMeta {
                pid: 3740,
                comm: "powershell.exe".into(),
                user: User::Windows {
                    sid: "S-1-5-21-1-2-3-1001".into(),
                    integrity_level: Some(0x2000),
                },
                ..fixtures::meta()
            },
            filter: filter.into(),
            base_dn: "DC=lab,DC=local".into(),
            attributes: attributes.iter().map(|a| (*a).to_string()).collect(),
            ..fixtures::ldap_search()
        }
    }

    fn techniques(event: &LdapSearchEvent) -> Vec<&'static str> {
        evaluate_ldap_search(event)
            .iter()
            .map(|a| a.technique)
            .collect()
    }

    #[test]
    fn roasting_target_searches_fire() {
        // Rubeus / PowerView shapes, and the 2026-10-02 lab filter.
        assert_eq!(
            techniques(&search(
                "(&(samAccountType=805306368)(servicePrincipalName=*))",
                &[]
            )),
            [KERBEROAST_RECON]
        );
        assert_eq!(
            techniques(&search(
                "(&(objectCategory=user) ( servicePrincipalName = * ))",
                &[]
            )),
            [KERBEROAST_RECON],
            "spacing and case do not matter"
        );
        assert_eq!(
            techniques(&search(
                "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
                &[]
            )),
            [ASREP_ROAST_RECON]
        );
    }

    #[test]
    fn spn_search_without_a_user_scope_is_quiet() {
        // Computers carry SPNs too; listing all SPNs is routine admin work.
        assert!(techniques(&search("(servicePrincipalName=*)", &[])).is_empty());
    }

    #[test]
    fn privilege_delegation_trust_and_password_searches_fire() {
        assert_eq!(
            techniques(&search("(&(objectClass=user)(adminCount=1))", &[])),
            [DOMAIN_ACCOUNT_DISCOVERY]
        );
        assert_eq!(
            techniques(&search(
                "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
                &[]
            )),
            [DOMAIN_ACCOUNT_DISCOVERY]
        );
        assert_eq!(
            techniques(&search("(msDS-AllowedToDelegateTo=*)", &[])),
            [DOMAIN_ACCOUNT_DISCOVERY]
        );
        assert_eq!(
            techniques(&search("(objectClass=trustedDomain)", &[])),
            [DOMAIN_TRUST_DISCOVERY]
        );
        assert_eq!(
            techniques(&search("(objectClass=computer)", &["cn", "ms-Mcs-AdmPwd"])),
            [DIRECTORY_CREDENTIAL_READ]
        );
        assert_eq!(
            techniques(&search("(msLAPS-Password=*)", &[])),
            [DIRECTORY_CREDENTIAL_READ]
        );
        // An unsplit list (NUL separator) still matches.
        assert_eq!(
            techniques(&search("(objectClass=computer)", &["cn\0ms-Mcs-AdmPwd"])),
            [DIRECTORY_CREDENTIAL_READ]
        );
    }

    #[test]
    fn ordinary_lookups_are_quiet() {
        assert!(
            techniques(&search(
                "(&(objectClass=user)(sAMAccountName=alice))",
                &["memberOf"]
            ))
            .is_empty()
        );
        assert!(techniques(&search("(objectClass=*)", &[])).is_empty());
    }

    #[test]
    fn service_accounts_are_ignored() {
        let mut event = search("(&(samAccountType=805306368)(servicePrincipalName=*))", &[]);
        event.meta.user = User::Windows {
            sid: "S-1-5-18".into(),
            integrity_level: Some(0x4000),
        };
        assert!(techniques(&event).is_empty());
        let mut burst = LdapBurst::new();
        for i in 0..BURST_THRESHOLD * 2 {
            event.filter = format!("(cn=host{i})");
            assert!(burst.observe(&event).is_none());
        }
    }

    #[test]
    fn a_sweep_of_distinct_searches_fires_once_per_window() {
        let mut burst = LdapBurst::new();
        let mut alerts = Vec::new();
        for i in 0..BURST_THRESHOLD + 5 {
            let mut event = search(&format!("(&(objectClass=user)(sAMAccountName=u{i}))"), &[]);
            event.meta.timestamp_ns = u64::from(i) * 1_000_000_000;
            alerts.extend(burst.observe(&event));
        }
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].technique, DOMAIN_ACCOUNT_DISCOVERY);
        assert!(
            alerts[0].message.contains("20 distinct LDAP searches"),
            "{}",
            alerts[0].message
        );
    }

    #[test]
    fn repeating_the_same_search_is_not_a_sweep() {
        // A client polling one query (an Outlook-style address lookup) stays quiet.
        let mut burst = LdapBurst::new();
        for i in 0..BURST_THRESHOLD * 3 {
            let mut event = search("(&(objectClass=user)(sAMAccountName=alice))", &[]);
            event.meta.timestamp_ns = u64::from(i) * 500_000_000;
            assert!(burst.observe(&event).is_none());
        }
    }

    #[test]
    fn a_slow_trickle_is_not_a_sweep() {
        let mut burst = LdapBurst::new();
        for i in 0..BURST_THRESHOLD * 2 {
            let mut event = search(&format!("(cn=host{i})"), &[]);
            event.meta.timestamp_ns = u64::from(i) * 10_000_000_000; // one every 10 s
            assert!(burst.observe(&event).is_none());
        }
    }
}
