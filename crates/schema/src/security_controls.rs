//! Verdicts of the platform's own security controls.

use super::*;

/// What a [`DefenderEvent`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefenderEventKind {
    /// Defender detected a threat (EID 1116).
    Detection,
    /// Defender acted on a detected threat (EID 1117). Shares
    /// [`DefenderEvent::detection_id`] with the [`Detection`](Self::Detection)
    /// it follows.
    Remediation,
    /// A protection component was turned off (EIDs 5001 real-time protection,
    /// 5010 spyware scanning, 5012 virus scanning): [`DefenderEvent::setting`]
    /// names which.
    ProtectionDisabled,
    /// A security-relevant Defender setting changed (EID 5007): exclusions,
    /// the real-time/behavior/script protection switches, Tamper Protection.
    /// The channel logs every internal state write as a 5007 (42 % of the
    /// Operational channel on a lab host, almost all service start-up
    /// progress), so the sensor forwards only these keys.
    ConfigChanged,
}

/// An event from the Microsoft Defender Antivirus Operational channel (#283):
/// its own verdicts, and the traces of someone weakening it (T1562.001).
///
/// Everything here is as Defender reports it, **not translated**: the channel
/// is localized (a French host writes `Severity Name` as "Élevée" and
/// `Action Name` as "Supprimer"), so identifiers are numeric ids and the
/// component names of [`DefenderEventKind::ProtectionDisabled`] are fixed
/// English labels chosen by the sensor, never Defender's text. `meta` carries
/// no actor: Defender does not say which process changed a setting or which
/// one a detection belongs to, so `pid`/`ppid` are 0 and `comm` is empty.
/// Fields are `None` when the kind does not carry them or the event left them
/// empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefenderEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Which Defender event this is; selects which of the other fields are filled.
    pub kind: DefenderEventKind,
    /// Detection / Remediation: Defender's detection GUID, the same for a
    /// 1116 and the 1117 that follows it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detection_id: Option<String>,
    /// Detection / Remediation: the threat as Defender names it
    /// (`HackTool:Win32/Mimikatz.I`). Not localized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat_name: Option<String>,
    /// Detection / Remediation: Defender's `Severity ID` (1 low, 2 moderate,
    /// 4 high, 5 severe).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity_id: Option<u32>,
    /// Detection / Remediation: Defender's `Category ID`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category_id: Option<u32>,
    /// Remediation: Defender's `Action ID` (1 clean, 2 quarantine, 3 remove,
    /// 4 allow, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<u32>,
    /// Detection / Remediation: the resource, as Defender reports it
    /// (`file:_C:\x.exe`, `CmdLine:_...`, `regkey:_...`). Cut to the sensor's
    /// limit: for a command-line detection it is the whole command line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Detection / Remediation: the process Defender associates with the
    /// resource, when it knows one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    /// Detection / Remediation: the account Defender attributes the detection
    /// to, as a name (`DOMAIN\user`), not a SID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// `ProtectionDisabled`: which component (`real-time protection`,
    /// `spyware scanning`, `virus scanning`). `ConfigChanged`: the registry
    /// value that changed (`HKLM\SOFTWARE\Microsoft\Windows
    /// Defender\Exclusions\Paths\C:\Temp`; for an exclusion the value name
    /// *is* the excluded item).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    /// `ConfigChanged`: the value before, as Defender wrote it (`0x1`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_value: Option<String>,
    /// `ConfigChanged`: the value after. Empty after a removal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_value: Option<String>,
}

/// macOS TCC privacy-permission decision — tccd answered a process's request
/// for a protected capability (screen capture, microphone, Accessibility, full
/// disk access, ...). Emitted by `sensor-macos-unifiedlog` (issue #95) from the
/// `com.apple.TCC` unified-log subsystem, joining tccd's `AUTHREQ_CTX` (which
/// carries the service) with the matching `AUTHREQ_RESULT` (which carries the
/// verdict) on tccd's own message id.
///
/// Detection value: malware granting itself Accessibility/screen-capture (via
/// synthetic clicks or a compromised MDM profile), and the reconnaissance
/// pattern of a fresh binary probing many services. A *denial* is signal too —
/// repeated denials for the same client is a process trying to escalate.
///
/// macOS-only family, same precedent as the Windows-only [`RegistrySetEvent`]/
/// [`WmiActivityEvent`]/[`ScriptBlockEvent`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TccDecisionEvent {
    /// The deciding daemon (`tccd`) — the unified log does not attribute the
    /// requesting process on the result record; `client` below carries what
    /// the log did say about the requester.
    pub meta: EventMeta,
    /// TCC service identifier as logged (e.g. `kTCCServiceScreenCapture`).
    pub service: String,
    /// True when access was granted (including "limited" grants).
    pub allowed: bool,
    /// Raw `authValue` from the log (0 denied, 1 unknown, 2 allowed, 3
    /// limited) — kept for forensic completeness; rules match on `allowed`.
    pub auth_value: u32,
    /// Raw `authReason` code when logged (e.g. 11 = user consent, 12 =
    /// service policy) — uninterpreted, forensic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_reason: Option<u32>,
    /// Requesting client when the joined context carried one (bundle
    /// identifier or binary path). `None` when tccd redacted it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
}

/// macOS Gatekeeper scan verdict — syspolicyd evaluated a target (first
/// launch, quarantine, background scan). Emitted by `sensor-macos-unifiedlog`
/// (issue #95) from syspolicyd's `GK evaluateScanResult` unified-log messages.
///
/// The join keys for putting a verdict next to its exec event on a case are
/// `team_id`/`signing_id` plus time proximity: syspolicyd hash-redacts file
/// paths in the public log stream (they only appear with the private-data
/// logging profile installed — see `docs/sensors/macos.md`), so `target` is
/// honest about possibly being an opaque token rather than a path.
///
/// macOS-only family, same precedent as [`TccDecisionEvent`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatekeeperVerdictEvent {
    /// The scanning daemon (`syspolicyd`).
    pub meta: EventMeta,
    /// Scan target as syspolicyd logged it: the bundle identifier when
    /// present, else syspolicyd's path token (hash-redacted without the
    /// logging profile).
    pub target: String,
    /// Signing team identifier, when the target is signed and logged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    /// Code-signing identifier, when logged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_id: Option<String>,
    /// Raw `evaluateScanResult` code. Deliberately uninterpreted: the values
    /// are undocumented by Apple, so the sensor forwards them for forensics
    /// and fleet-side statistics instead of guessing an allow/deny meaning
    /// that could silently invert on an OS update.
    pub result_code: u32,
}

/// [`PolicyDenialEvent::mechanism`] value for `SELinux` AVC denials
/// (`sensor-linux-audit`, #297).
pub const POLICY_MECHANISM_SELINUX: &str = "selinux";

/// [`PolicyDenialEvent::mechanism`] value for Windows `AppLocker` verdicts
/// (`sensor-windows-eventlog`, #427): event 8004 (blocked, `enforced: true`)
/// and 8003 (audit mode, would have been blocked, `enforced: false`) on the
/// `Microsoft-Windows-AppLocker/EXE and DLL` channel. A new value of an
/// existing `String` field — not a schema version bump (see
/// [`PolicyDenialEvent`]'s doc on why `mechanism` is not a closed enum).
pub const POLICY_MECHANISM_APPLOCKER: &str = "applocker";

/// [`PolicyDenialEvent::mechanism`] value for Windows Defender Application
/// Control (WDAC / App Control for Business) verdicts (`sensor-windows-eventlog`,
/// #283): event 3077 (blocked, `enforced: true`) and 3076 (audit mode, would
/// have been blocked, `enforced: false`) on the
/// `Microsoft-Windows-CodeIntegrity/Operational` channel. A new value of the
/// existing `String` field, not a schema version bump.
pub const POLICY_MECHANISM_WDAC: &str = "wdac";

/// An OS security mechanism denied a subject an action on an object —
/// `SELinux`/`AppArmor` on Linux, AppLocker/WDAC on Windows, TCC/Gatekeeper on
/// macOS all report the same underlying shape (issue #297). A dedicated,
/// generic variant rather than folding this into [`FileOpenEvent`]: unlike
/// #224's persistence reuse of `FileOpenEvent` (where the denied artifact
/// really was a file open), a policy denial's `object_class` ranges over
/// file/process/socket/capability/... — forcing it into a file-shaped event
/// would misrepresent every non-file denial. `mechanism` is a plain `String`,
/// not a closed enum: new platforms' mechanisms (AppLocker/WDAC, TCC/
/// Gatekeeper) are additive data here, not a schema change, matching how
/// [`AuthKind`] stays coarse rather than growing a variant per OS event ID.
///
/// First emitted by `sensor-linux-audit` from `SELinux` AVC records
/// (`type=AVC`). The kernel's AVC message body (`avc: denied { read } for
/// pid=...`) is text, not `key=value`, before the first real field; the
/// shared audit parser's byte scan folds that preamble into its first
/// `key=value` pair and recovers the requested permission set from it (#813)
/// — see `sensor_linux_audit::classify::AuditEvent::PolicyDenial`'s doc.
/// `action` is still `None` for an AVC variant the parser doesn't recognize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDenialEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Which security mechanism denied the action — see
    /// [`POLICY_MECHANISM_SELINUX`] and [`POLICY_MECHANISM_APPLOCKER`] for the
    /// values emitted today.
    pub mechanism: String,
    /// The acting subject's security context (`SELinux` `scontext`, e.g.
    /// `system_u:system_r:httpd_t:s0`). Opaque per-mechanism label syntax —
    /// left as the platform reports it, not parsed into sub-fields, since
    /// Windows/macOS mechanisms don't share `SELinux`'s context-string shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_context: Option<String>,
    /// The target object's security context (`SELinux` `tcontext`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_context: Option<String>,
    /// The kind of object the action targeted (`SELinux` `tclass`: `file`,
    /// `process`, `tcp_socket`, `capability`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_class: Option<String>,
    /// The permission or action that was requested. Mechanism-specific:
    /// `SELinux` `{ read }`, or `{ read write }` space-joined for more than one
    /// (recovered from the AVC record by `sensor-linux-audit`, #813); `AppLocker`/
    /// `WDAC` a verb like `execute`/`load`. `None` for an AVC variant the parser
    /// doesn't recognize.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// `true` when the mechanism actually blocked the action (`SELinux`
    /// enforcing mode); `false` when it only logged what it would have
    /// blocked (`SELinux` permissive mode) — `!permissive` at the source.
    pub enforced: bool,
    /// The object's filesystem path, when the mechanism reported one (issue
    /// #427). On Linux, from the AVC record's `path=` field, or `name=` when
    /// `path=` is absent — the kernel only has what the syscall's arguments
    /// gave it, which for `name=` is often a bare filename rather than a full
    /// path (no `PATH` record correlation here, see
    /// `AuditEvent::PolicyDenial`'s doc on why this sensor treats AVC as
    /// supplementary rather than reassembling `type=PATH` siblings for it).
    /// `None` when neither field is present, e.g. `tclass` values that don't
    /// name a file (`process`, `capability`, `tcp_socket`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_path: Option<String>,
}
