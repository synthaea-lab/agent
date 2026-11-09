//! Credential Access (TA0006): Kerberos tickets requested outside LSASS or refused for
//! delegation.

use schema::{ConnectEvent, detection::Severity};

use crate::Alert;

/// The Kerberos KDC port (TCP and UDP).
const KERBEROS_PORT: u16 = 88;

/// T1558 (#364): a Windows process other than LSASS talking to a KDC.
///
/// On Windows every Kerberos exchange the OS makes, logon, TGT and service tickets
/// alike, goes through `lsass.exe`: no other process has a reason to open port 88 to a
/// domain controller. Tools that request tickets themselves (Rubeus `asktgs`/`kerberoast`,
/// Impacket's `GetUserSPNs.py`/`GetNPUsers.py` run on Windows, kekeo) open that connection
/// from their own process, so this is the endpoint-side shadow of Kerberoasting,
/// AS-REP roasting and ticket forging. The DC-side events (4768/4769) are not visible here
/// (#364's framing).
///
/// Medium, not High: Java applications bring their own Kerberos client (JGSS), so a
/// `java.exe` single-sign-on or a build tool talking to the KDC is legitimate. No name
/// exclusion is made for it: a name-keyed exclusion needs evidence gating (CLAUDE.md), and
/// a renamed tool is the attack. Kerberos through LSASS (`Invoke-Kerberoast`,
/// .NET `KerberosRequestorSecurityToken`) is not seen here: that needs the Kerberos ETW
/// provider, captured first in the lab.
///
/// Windows only. On Linux every Kerberos-aware program (`kinit`, `sssd`, `sshd` with
/// GSSAPI, `curl --negotiate`) talks to the KDC itself, so the same connection is routine.
/// A Windows event is recognised by its token user or, for a process whose token could
/// not be read, by the `.exe` image name the Windows sensor reports.
#[must_use]
pub(crate) fn check_kerberos_from_non_lsass(event: &ConnectEvent) -> Option<Alert> {
    if event.dport != KERBEROS_PORT || event.daddr.is_loopback() || event.daddr.is_unspecified() {
        return None;
    }
    let comm = event.meta.comm.as_str();
    let is_windows = matches!(event.meta.user, schema::User::Windows { .. })
        || comm
            .get(comm.len().saturating_sub(4)..)
            .is_some_and(|ext| ext.eq_ignore_ascii_case(".exe"));
    if !is_windows || comm.eq_ignore_ascii_case("lsass.exe") {
        return None;
    }
    Some(Alert {
        technique: "T1558",
        severity: Severity::Medium,
        message: format!(
            "pid={} comm={comm}: Kerberos connection to {}:{KERBEROS_PORT} from a process \
             other than LSASS: a tool requesting tickets itself (Kerberoasting, AS-REP \
             roasting, ticket forging) unless it is a Java application with its own Kerberos",
            event.meta.pid, event.daddr,
        ),
    })
}

/// T1558 — Steal or Forge Kerberos Tickets. The local process named by `event.meta` asked its
/// own Kerberos client for either a ticket usable for unconstrained delegation, or its TGT's
/// session key, and the client refused (#364, `KerberosDelegationFailureEvent`, EID 201/202 of
/// `Microsoft-Windows-Kerberos/Operational`). The local process is the actor in both cases —
/// not a remote server reaching into this host, see the event's own struct doc.
///
/// A **refusal**, not a success: this host's Kerberos stack said no, so the request did not go
/// through. Still worth an alert — the small, deliberate allowlist unconstrained delegation and
/// TGT export live behind means a request outside it is rare on a well-run host, and both are
/// textbook steps in domain-admin-ticket theft (a process collecting a delegable ticket to
/// coerce a chain back to an attacker-controlled "service", or pulling a TGT's key straight out
/// of a host that should never give it up — the Rubeus `tgtdeleg` shape). High, not Critical:
/// the refusal is the control already working, and a misconfigured but legitimate caller asking
/// for delegation it was never granted looks identical to this agent — the verdict, not this
/// rule, decides what it adds to.
#[must_use]
pub fn evaluate_kerberos_delegation_failure(
    event: &schema::KerberosDelegationFailureEvent,
) -> Vec<Alert> {
    use schema::KerberosDelegationFailureKind as Kind;
    let what = match event.kind {
        Kind::UnconstrainedDelegationDenied => "a ticket usable for unconstrained delegation",
        Kind::TgtSessionKeyExportDenied => "its TGT session key",
    };
    let supplied = if event.target_user.is_empty() {
        String::new()
    } else if event.target_domain.is_empty() {
        format!(", supplied credentials {}", event.target_user)
    } else {
        format!(
            ", supplied credentials {}\\{}",
            event.target_domain, event.target_user
        )
    };
    let owner = if event.caller_user.is_empty() {
        String::new()
    } else if event.caller_domain.is_empty() {
        format!(" owner={}", event.caller_user)
    } else {
        format!(" owner={}\\{}", event.caller_domain, event.caller_user)
    };
    vec![Alert {
        technique: "T1558",
        severity: Severity::High,
        message: format!(
            "pid={} comm={}: asked for {what} against {}{supplied} — denied{owner}",
            event.meta.pid, event.meta.comm, event.target_server,
        ),
    }]
}
