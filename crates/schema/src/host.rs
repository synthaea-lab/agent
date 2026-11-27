//! Changes to the host's configuration: registry, services, packages, logs.

use super::*;

/// A Windows event log was cleared (#799), from the record the Event Log
/// service itself writes as the first entry of the fresh log: Security **1102**
/// ("The audit log was cleared") or System **104** ("The log file was
/// cleared", naming the channel). Windows writes it whatever did the clearing
/// (`wevtutil cl`, the `EvtClearLog` API, .NET `EventLogSession.ClearLog`, a
/// renamed tool), and no audit subcategory gates it.
///
/// `meta.pid` is the process that asked for the clear (`ClientProcessId`,
/// written by Windows 11 26200, lab 2026-10-15), or the Event Log service when
/// an older build leaves it out; `comm` is empty either way. `meta.user` is the
/// account that cleared the log (`SubjectUserSid` for 1102, the event's
/// `Security UserID` for 104), [`User::Unknown`] when the event names none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogClearedEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// The channel cleared, as Windows names it (`Security`, `System`,
    /// `Microsoft-Windows-PowerShell/Operational`, ...).
    pub channel: String,
    /// The clearing account as `DOMAIN\user`, or `user` alone when the event
    /// gives no domain. Empty when it names none.
    pub subject_user: String,
    /// 1102 only: the clearing account's logon session (`0x3e7`), to join with
    /// that session's 4624. `None` for 104, which does not carry it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_logon_id: Option<String>,
    /// 104 only: where the log was saved before it was cleared, when the
    /// clearer asked for a backup (`wevtutil cl <channel> /bu:<file>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_path: Option<String>,
}

/// Registry value write — the primary signal for persistence and configuration
/// manipulation detections.
///
/// Emitted on EID 5 (`SetValueKey`) of the Microsoft-Windows-Kernel-Registry
/// provider. Only writes are emitted; the sensor reads key opens and closes only to
/// name the key a write went to.
///
/// A resolved key path is normalized from NT registry format (`\REGISTRY\MACHINE\...`) to
/// the familiar Win32 hive prefix (`HKLM\...`) by the sensor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrySetEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// The key the value was written under, in full or only in the part the sensor saw.
    pub key: RegistryKey,
    /// Name of the value being written. Empty string means the default value `(Default)`.
    pub value_name: String,
    /// Registry data type (`1=REG_SZ`, `2=REG_EXPAND_SZ`, `3=REG_BINARY`, `4=REG_DWORD`, ...).
    pub data_type: u32,
    /// String representation of the value data for `REG_SZ` / `REG_EXPAND_SZ` types.
    /// `None` for binary or DWORD types where string decoding is not meaningful, and for
    /// every write on Windows 11 26300, whose kernel delivers no captured data: no rule may
    /// depend on it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

/// The key a [`RegistrySetEvent`] wrote under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RegistryKey {
    /// The sensor saw the key's whole name.
    Resolved {
        /// The full key path, hive-prefixed (e.g.
        /// `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`).
        path: String,
    },
    /// The sensor did not see where the key's name starts: the key was opened relative to
    /// a key opened before the sensor started (a process's cached `HKEY_CURRENT_USER` or
    /// `HKEY_LOCAL_MACHINE` root), or the sensor's key table had dropped it. The write is
    /// still reported, so rules on the value, the data and the process keep firing.
    Unresolved {
        /// The name the process opened the key by, below that unknown key (e.g.
        /// `Software\Microsoft\Windows\CurrentVersion\Run`): a rule on a key path can match
        /// its suffix. Empty when the sensor knows no part of the name.
        relative_name: String,
    },
}

/// The stop of a systemd unit of [`SECURITY_SERVICES`] (Linux journald `JOB_TYPE=stop`, #1085,
/// T1562.001). `meta.comm` also carries the unit name, as for the unit start. The journal names
/// no actor, so this says a stop happened, not who asked for it.
///
/// An event of its own, not a flag on a [`FileOpenEvent`]: that event's `flags` are the raw
/// `open(2)` flags on Linux (unknown bits pass through `openat`), so any bit there can be set
/// by an unprivileged open, as `O_TMPFILE` set the first cut of the signal-loss bit (#1114).
/// Only the journal sensor builds this variant, from a record whose writer is the system
/// manager, and no probe produces it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitStopEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// The unit as the journal names it (`auditd.service`).
    pub unit: String,
}

/// What happened to a package between two inventory snapshots (`crates/inventory`'s
/// pure diff, issue #87). `Upgraded` carries both versions so a case shows the actual
/// transition, not just "something changed".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageChangeKind {
    /// A package was installed.
    Added,
    /// A package was removed.
    Removed,
    /// A package changed version in place.
    Upgraded,
}

/// A package was added, removed, or changed version since the agent's last inventory
/// snapshot (issue #87). Not a kernel event: the diff runs periodically against the
/// package manager's own database (`dpkg`/`rpm`/...), so `meta.pid`/`ppid` are 0 and
/// `meta.comm` names the package manager, same convention as [`HttpRequestEvent`].
/// `previous_version` is `None` exactly when [`Self::change`] is `Added`, and `version` is `None`
/// exactly when it is `Removed`; both are `Some` only for `Upgraded`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageChangeEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Name of the package that changed.
    pub package: String,
    /// Whether the package was added, removed or upgraded.
    pub change: PackageChangeKind,
    /// Version before the change; `None` when the package was not installed before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_version: Option<String>,
    /// Version after the change; `None` when the package was removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}
