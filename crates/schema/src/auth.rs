//! Logons, sessions and the authentication protocols behind them.

use super::*;

/// Direction of an [`NtlmAuthEvent`], seen from this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NtlmDirection {
    /// This host authenticated to a remote resource (EIDs 4020/4021/4026/4027).
    Outgoing,
    /// A remote client authenticated to this host (EIDs 4022/4023).
    Incoming,
}

/// An NTLM authentication, from the Microsoft-Windows-NTLM provider (#364):
/// who, to or from where, and with which NTLM version. Windows 11 24H2 emits
/// these by default (lab, 2026-10-02, no audit setting).
///
/// `meta` is the process the provider reports, which in practice is often the
/// kernel (`SYSTEM`, pid 4) for SMB: the requesting process is not reliably
/// available, and rules must not depend on it. Failed incoming logons are
/// deliberately **not** turned into [`AuthEvent`]s here: the Security log's
/// 4625 already reports them, and counting them twice would skew the
/// brute-force burst rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NtlmAuthEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Whether the host was the client or the server of the NTLM exchange.
    pub direction: NtlmDirection,
    /// The account used (`Username`, plus `DomainName` as `DOMAIN\user` when
    /// the provider reports one).
    pub user: String,
    /// What was authenticated to: the target service/SPN when present
    /// (`cifs/host`), else the target machine.
    pub target: String,
    /// The remote end: the target IP for outgoing, the client IP for incoming,
    /// when the provider reports a parseable one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_address: Option<core::net::IpAddr>,
    /// The negotiated version as the provider names it (`NTLMv2`, `NTLMv1`,
    /// `LM`, ...).
    pub ntlm_version: String,
    /// Incoming only: the NTSTATUS of the attempt, hex (`0xc000006d` = bad
    /// user name or password). `None` when the provider gives none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Which Kerberos client operation was denied, in a [`KerberosDelegationFailureEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KerberosDelegationFailureKind {
    /// EID 201: this host's own process asked its local Kerberos client for a ticket it
    /// could present for unconstrained delegation to `target_server` (impersonating
    /// whatever user later authenticates through it to that server), and the client's
    /// own Kerberos stack refused — this host is not on the allowlist that may ask for
    /// that. The Rubeus `tgtdeleg`/delegation-collection shape.
    UnconstrainedDelegationDenied,
    /// EID 202: this host's own process asked to export its TGT's session key, and the
    /// client's own Kerberos stack refused — on a Credential Guard host, a TGT's key can
    /// never leave the isolated LSA, by design (this is the client-side half of the
    /// same protection PKINIT key-export denials, EID 203/204, also report).
    TgtSessionKeyExportDenied,
}

/// A Kerberos client-side operation an attacker would want was denied, from the
/// (off by default; see `docs/sensors/sources.md`) `Microsoft-Windows-Kerberos/Operational`
/// channel's EID 201/202 (#364). **The local process is the actor**: both events report this
/// host's own process asking its own Kerberos client for something (a delegable ticket for
/// `target_server`, or its own TGT session key) and that client refusing — not a remote
/// server using this host as a stepping stone. The provider manifest
/// (`Get-WinEvent -ListProvider Microsoft-Windows-Security-Kerberos`) names `%4 CallerPID` as
/// the *client* process id, and the message text is "unconstrained delegation is not allowed
/// for this user" (fwlink 856824) — the refusal is about the local caller, not a third party.
///
/// Framed as what it is: a **refusal**. Each event means an attempt was made and this host's
/// own Kerberos stack said no — not that delegation succeeded, and not evidence the request
/// was malicious (a misconfigured but legitimate service asking for delegation it was never
/// granted looks identical). High: unconstrained delegation and TGT export are both a small,
/// deliberate allowlist on a well-run host, so a request outside it is rare and worth a look;
/// not Critical, since the client's own refusal is already the control working.
///
/// `meta.pid`/`meta.comm` are the process that made the request (`CallerPID`/`ProcessName`,
/// both 201 and 202 carry them, the same nine-field template). `meta.user` is
/// [`User::Unknown`]: the template gives this process's owner only as a name and a domain
/// (`ClientUserName`/`ClientDomainName`), never a SID, so it cannot become a
/// [`User::Windows`] — [`caller_user`](Self::caller_user) carries it as text instead, the same
/// choice [`LogClearedEvent::subject_user`] makes when a SID isn't the shape the data comes in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KerberosDelegationFailureEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Which delegation failure this is.
    pub kind: KerberosDelegationFailureKind,
    /// The server named in the request (`TargetName`/`Server`): for 201, the server the
    /// requested delegable ticket was for.
    pub target_server: String,
    /// Credentials explicitly supplied to the call (`UserName`), rather than the caller's own
    /// — usually empty, since a call with default credentials supplies none.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target_user: String,
    /// That supplied account's domain (`DomainName`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target_domain: String,
    /// The calling process's own owner account (`ClientUserName`), as text — see the struct
    /// doc for why it is not `meta.user`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub caller_user: String,
    /// That account's domain (`ClientDomainName`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub caller_domain: String,
}

/// A logon/authentication outcome, or a privileged-session assignment — shared
/// across platforms per #94: Windows Security-log logons (events 4624/4625/4648/
/// 4672, `sensor-windows-eventlog`) and Linux authentication (sshd accept/failure,
/// `su`/`sudo`, PAM sessions — `sensor-linux-journal`, not yet implemented) both
/// normalize into this one shape rather than each inventing its own type
///.
///
/// Deliberately narrower than either platform's native audit record: only the
/// fields a cross-platform lateral-movement/privilege-escalation rule can
/// actually use today. Platform-only detail that doesn't generalize (a Windows
/// `LogonType` code, a Linux PAM service name) is left out rather than added
/// speculatively — extend when a rule needs it, per this crate's additive-only
/// discipline (see the top-level docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthEvent {
    /// Identity of the process that reported the logon (e.g. Windows
    /// `winlogon.exe`/`lsass.exe`, the logon subsystem — not necessarily the
    /// account's own process). This is a session/auth-subsystem event, not a
    /// process-lifecycle one; `meta.user` is who is *performing* the action
    /// (the already-logged-on caller for `ExplicitCredentials`/
    /// `PrivilegedSession`), which is not the same as `target_user` below.
    pub meta: EventMeta,
    /// Whether the authentication succeeded or failed.
    pub outcome: AuthOutcome,
    /// Kind of logon or authentication this is.
    pub kind: AuthKind,
    /// The account being authenticated as/into — Windows `TargetUserName`
    /// (`DOMAIN\user` or a local account name), Linux the PAM/sshd target user.
    /// Deliberately distinct from `meta.user`: for `ExplicitCredentials` and
    /// `PrivilegedSession` the two differ by design — that difference is the
    /// whole signal.
    pub target_user: String,
    /// Windows `TargetUserSid`, when the platform resolves one. `None` on Linux
    /// (no SID concept) and when Windows itself could not resolve the account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_user_sid: Option<String>,
    /// Origin address, when the platform reports one for this kind of logon
    /// (network/RDP logons, SSH) — absent for local console/service/batch
    /// logons, which is itself meaningful (do not fabricate a loopback address).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_address: Option<core::net::IpAddr>,
    /// Opaque platform status/result code, kept for forensic completeness
    /// (Windows hex `Status`/`SubStatus` — e.g. the substatus that tells a wrong
    /// password apart from an already-locked-out account) — not interpreted by
    /// rules, which match on `outcome`/`kind` instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<String>,
}

/// Whether an [`AuthEvent`] represents a successful or failed action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthOutcome {
    /// The authentication succeeded.
    Success,
    /// The authentication failed.
    Failure,
}

/// What kind of authentication/session action an [`AuthEvent`] represents.
/// Coarse by design — see each variant for how Windows event IDs and (once
/// implemented) the Linux journal facilities map onto it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    /// A new logon session was created (Windows event 4624; Linux sshd
    /// `Accepted ...`/a PAM session open).
    Logon,
    /// A logon attempt failed (Windows event 4625; Linux sshd `Failed
    /// password ...`/a PAM authentication failure).
    LogonFailure,
    /// Credentials for an account other than the current session's were
    /// explicitly supplied (Windows event 4648 — a classic RunAs/lateral-movement
    /// signal; Linux `su`/`sudo -u other-user`).
    ExplicitCredentials,
    /// Special/elevated privileges were assigned to a logon session (Windows
    /// event 4672, typically alongside a 4624 for administrative accounts; Linux
    /// a successful `sudo`).
    PrivilegedSession,
}

/// Which step in a session's life a [`SessionEvent`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    /// A remote client authenticated to the remote-desktop listener (Windows
    /// `TerminalServices-RemoteConnectionManager` 1149). Comes before the
    /// logon and belongs to no session yet, so `session_id` is `None`.
    Connect,
    /// A session logon completed (`TerminalServices-LocalSessionManager` 21).
    Logon,
    /// A session was disconnected and stays alive on the host, ready to be
    /// reconnected to (24).
    Disconnect,
    /// A client was attached to an existing disconnected session (25).
    Reconnect,
    /// A session was logged off (23). Its `session_id` may be reused.
    Logoff,
}

/// One step in the life of an interactive session (#285): Windows Terminal
/// Services, which covers RDP and the local console alike.
///
/// What [`AuthEvent`] cannot say: whether a session is new or reconnected,
/// when it was disconnected (left alive for later) rather than logged off,
/// and which client a given session was attached to at each step. A
/// disconnected session reconnected from another client is the trace of RDP
/// session hijacking (T1563.002), invisible in the Security channel. A
/// separate type rather than more [`AuthKind`]s: these steps are not
/// authentications, and [`AuthEvent::outcome`] would mean nothing on them.
///
/// `meta` names the reporting service (`pid` from the event, `comm` empty,
/// `user` unknown), not an actor. The account is [`Self::target_user`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Session transition this event reports.
    pub state: SessionState,
    /// The OS session number (Windows `SessionID`). Unique among live
    /// sessions only: reused once a session is logged off. `None` for
    /// [`SessionState::Connect`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<u32>,
    /// The session's account as the OS reports it (`DOMAIN\user`). Empty
    /// when the event names none.
    pub target_user: String,
    /// The remote client's address, when the event reports one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_address: Option<core::net::IpAddr>,
    /// The client is the host's own console (Windows `Address` = `LOCAL`).
    /// `false` with no `source_address` means the event named no client at
    /// all, as a logoff does: not the same thing as the console.
    pub console: bool,
}
