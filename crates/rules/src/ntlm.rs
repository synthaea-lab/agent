//! Rules over NTLM authentications (#364). The requesting process is often
//! the kernel (SMB) and is not used; both rules key on the protocol facts the
//! provider does report reliably: where the authentication went, and which
//! NTLM version was negotiated.
//!
//! Both rules are Medium until they have run on real traffic: an on-prem web
//! app reached through a public address, an NTLM proxy or NAS with one, and old
//! printers, scanners and NAS speaking NTLMv1 are legitimate sources of both
//! (review of #744). The lab only ever produced `NTLMv2` over loopback.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use schema::{NtlmAuthEvent, NtlmDirection, detection::Severity};

use crate::Alert;

/// T1187 (Forced Authentication): this host sent an NTLM challenge response
/// to an Internet address, the credential-leak shape of a booby-trapped UNC
/// path or a coerced authentication (the Outlook reminder flaw,
/// CVE-2023-23397). A response captured there can be cracked or relayed.
const NTLM_TO_INTERNET: &str = "T1187";
/// T1557 (Adversary-in-the-Middle): `NTLMv1` or LM negotiated. Both are
/// crackable or relayable outright; a modern Windows host only falls back to
/// them when something forces the downgrade or a legacy peer requires it.
const NTLM_DOWNGRADE: &str = "T1557";

/// Both rules (see the module doc).
#[must_use]
pub fn evaluate_ntlm_auth(event: &NtlmAuthEvent) -> Vec<Alert> {
    let mut alerts = Vec::new();
    let who = |what: &str| {
        format!(
            "{what}: account={} target={} remote={} version={} (process pid={} comm={})",
            if event.user.is_empty() {
                "-"
            } else {
                &event.user
            },
            event.target,
            event
                .remote_address
                .map_or_else(|| "-".to_string(), |a| a.to_string()),
            event.ntlm_version,
            event.meta.pid,
            event.meta.comm,
        )
    };
    if event.direction == NtlmDirection::Outgoing
        && event.remote_address.is_some_and(is_internet_address)
    {
        alerts.push(Alert {
            technique: NTLM_TO_INTERNET,
            severity: Severity::Medium,
            message: who("NTLM authentication sent to an Internet address"),
        });
    }
    if is_weak_version(&event.ntlm_version) {
        let direction = match event.direction {
            NtlmDirection::Outgoing => "outgoing",
            NtlmDirection::Incoming => "incoming",
        };
        alerts.push(Alert {
            technique: NTLM_DOWNGRADE,
            severity: Severity::Medium,
            message: who(&format!(
                "{direction} NTLM authentication with a weak version"
            )),
        });
    }
    alerts
}

/// `NTLMv1` (any variant, e.g. with session security) or `LM`, as the provider
/// spells the negotiated version. `NTLMv2` is not weak.
///
/// Only `NTLMv2` was ever observed, so the other spellings come from the manifest
/// and are matched loosely: case, spaces and punctuation are ignored (`NTLM V1`,
/// `ntlmv1 (ESS)`, `NTLMv1 with ESS`). A spelling this misses makes the rule
/// silent, which is why the sensor logs every version that is not `NTLMv2`.
fn is_weak_version(version: &str) -> bool {
    let tokens: Vec<String> = version
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    let compact = tokens.concat();
    compact.starts_with("ntlmv1") || tokens.first().is_some_and(|t| t == "lm")
}

/// An address that routes over the Internet: not loopback, private,
/// link-local, carrier-grade NAT, multicast, documentation or unspecified.
/// (`IpAddr::is_global` is still unstable.)
fn is_internet_address(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => is_internet_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_internet_v4(v4),
            None => is_internet_v6(v6),
        },
    }
}

fn is_internet_v4(v4: Ipv4Addr) -> bool {
    let [a, b, ..] = v4.octets();
    let carrier_grade_nat = a == 100 && (64..128).contains(&b);
    let benchmarking = a == 198 && (b == 18 || b == 19);
    // 192.0.0.0/24, IETF protocol assignments.
    let ietf_assignments = v4.octets()[..3] == [192, 0, 0];
    !(v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_multicast()
        || v4.is_documentation()
        || v4.is_unspecified()
        || carrier_grade_nat
        || benchmarking
        || ietf_assignments
        || a == 0
        || a >= 240)
}

fn is_internet_v6(v6: Ipv6Addr) -> bool {
    let first = v6.segments()[0];
    let unique_local = first & 0xfe00 == 0xfc00;
    let link_local = first & 0xffc0 == 0xfe80;
    let documentation = first == 0x2001 && v6.segments()[1] == 0x0db8;
    !(v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        || unique_local
        || link_local
        || documentation)
}

#[cfg(test)]
mod tests {
    use schema::fixtures;

    use super::*;

    fn ntlm(direction: NtlmDirection, remote: &str, version: &str) -> NtlmAuthEvent {
        NtlmAuthEvent {
            direction,
            user: "CORP\\alice".into(),
            target: "cifs/files".into(),
            remote_address: remote.parse().ok(),
            ntlm_version: version.into(),
            ..fixtures::ntlm_auth()
        }
    }

    fn techniques(event: &NtlmAuthEvent) -> Vec<&'static str> {
        evaluate_ntlm_auth(event)
            .iter()
            .map(|a| a.technique)
            .collect()
    }

    #[test]
    fn outgoing_ntlm_to_the_internet_fires() {
        assert_eq!(
            techniques(&ntlm(NtlmDirection::Outgoing, "203.0.113.7", "NTLMv2")),
            Vec::<&str>::new(),
            "TEST-NET-3 is documentation space, not the Internet"
        );
        assert_eq!(
            techniques(&ntlm(NtlmDirection::Outgoing, "8.8.8.8", "NTLMv2")),
            [NTLM_TO_INTERNET]
        );
        assert_eq!(
            techniques(&ntlm(
                NtlmDirection::Outgoing,
                "2a00:1450:4007::64",
                "NTLMv2"
            )),
            [NTLM_TO_INTERNET]
        );
        assert_eq!(
            techniques(&ntlm(NtlmDirection::Outgoing, "::ffff:8.8.4.4", "NTLMv2")),
            [NTLM_TO_INTERNET],
            "v4-mapped v6 is judged as v4"
        );
    }

    #[test]
    fn local_and_internal_targets_are_quiet() {
        // The 2026-10-02 lab event: SMB to 127.0.0.1, NTLMv2.
        for remote in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.9",
            "192.168.1.20",
            "169.254.3.4",
            "100.64.0.1",
            "::1",
            "fe80::1",
            "fd12:3456::1",
        ] {
            assert!(
                techniques(&ntlm(NtlmDirection::Outgoing, remote, "NTLMv2")).is_empty(),
                "{remote}"
            );
        }
    }

    #[test]
    fn incoming_from_the_internet_is_not_forced_authentication() {
        // A client authenticating *to* this host from outside is exposure, not
        // a leak of this host's credentials; T1110 covers repeated failures.
        assert!(techniques(&ntlm(NtlmDirection::Incoming, "8.8.8.8", "NTLMv2")).is_empty());
    }

    #[test]
    fn weak_versions_fire_in_both_directions() {
        assert_eq!(
            techniques(&ntlm(NtlmDirection::Outgoing, "10.0.0.5", "NTLMv1")),
            [NTLM_DOWNGRADE]
        );
        assert_eq!(
            techniques(&ntlm(NtlmDirection::Incoming, "10.0.0.5", "LM")),
            [NTLM_DOWNGRADE]
        );
        assert_eq!(
            techniques(&ntlm(
                NtlmDirection::Outgoing,
                "10.0.0.5",
                "NTLMv1 with ESS"
            )),
            [NTLM_DOWNGRADE]
        );
        assert!(techniques(&ntlm(NtlmDirection::Outgoing, "10.0.0.5", "NTLMv2")).is_empty());
    }

    #[test]
    fn both_rules_can_fire_together_at_medium_severity() {
        let alerts = evaluate_ntlm_auth(&ntlm(NtlmDirection::Outgoing, "1.1.1.1", "NTLMv1"));
        assert_eq!(alerts.len(), 2);
        assert!(alerts.iter().all(|a| a.severity == Severity::Medium));
        assert!(alerts[0].message.contains("account=CORP\\alice"));
    }

    #[test]
    fn weak_versions_are_matched_whatever_the_spelling() {
        for spelling in [
            "NTLMv1",
            "ntlmv1",
            "NTLM V1",
            "NTLMv1 (ESS)",
            "NTLMv1 with ESS",
            "NTLMv1-ESS",
            "  NTLMv1  ",
            "LM",
            "lm",
            "LM, NTLMv1",
            "LM with ESS",
        ] {
            assert_eq!(
                techniques(&ntlm(NtlmDirection::Outgoing, "10.0.0.5", spelling)),
                [NTLM_DOWNGRADE],
                "{spelling:?}"
            );
        }
        for strong in [
            "NTLMv2",
            "ntlmv2",
            "NTLM V2",
            "NTLMv2 with MIC",
            "",
            "unknown",
        ] {
            assert!(
                techniques(&ntlm(NtlmDirection::Outgoing, "10.0.0.5", strong)).is_empty(),
                "{strong:?}"
            );
        }
    }

    #[test]
    fn the_ietf_protocol_assignment_range_is_not_the_internet() {
        assert!(techniques(&ntlm(NtlmDirection::Outgoing, "192.0.0.9", "NTLMv2")).is_empty());
        assert_eq!(
            techniques(&ntlm(NtlmDirection::Outgoing, "192.0.1.9", "NTLMv2")),
            [NTLM_TO_INTERNET],
            "192.0.1.0/24 is not part of the reserved /24"
        );
    }

    #[test]
    fn a_missing_address_never_counts_as_the_internet() {
        assert!(techniques(&ntlm(NtlmDirection::Outgoing, "not-an-ip", "NTLMv2")).is_empty());
    }
}
