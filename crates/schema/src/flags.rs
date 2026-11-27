//! Synthetic bits a sensor sets in an event's `flags` to mark what it recognised.

/// Marker set on [`FileOpenEvent::flags`](crate::FileOpenEvent::flags) by `sensor-windows-eventlog` when it
/// reports a Windows **service install** as a persistence artifact (event 7045, "A
/// service was installed in the system" — ATT&CK T1543.003) rather than a real file
/// operation. `rules::check_service_persistence` requires this exact value before
/// applying a suspicious-path filter — see that function's doc for why: applying the
/// filter to the whole Windows file stream unfiltered would alert on every legitimate
/// AppData/Temp write (browser updates, Electron apps, installers...).
///
/// A distinct bit from [`FLAG_PERSISTENCE_TASK_ARTIFACT`] (not shared): the two
/// techniques (T1543.003 vs T1053.005) must not both fire off a single event.
/// `disposition_to_flags` (`sensor-windows`) only ever produces `O_WRONLY` (0o1) /
/// `O_CREAT` (0o100), so this high bit never collides with a real disposition value.
///
/// Not a serialization-visible schema change (no new field, no new [`Event`](crate::Event)
/// variant — `flags` already exists and is already an opaque, per-platform `u32`),
/// so this does not bump [`SCHEMA_VERSION`](crate::SCHEMA_VERSION): consumers that ignore the flag see the
/// event pass through unchanged, and the top bits can never collide with a real
/// open disposition. Pragmatic solution, not the final one (ADR-0004): a dedicated
/// `Persistence`/`Registry` event family stays an option once the schema needs one
/// for other reasons too.
pub const FLAG_PERSISTENCE_ARTIFACT: u32 = 0x1000_0000;

/// Same principle as [`FLAG_PERSISTENCE_ARTIFACT`], for a Windows **scheduled task**
/// creation (event 4698, "A scheduled task was created" — ATT&CK T1053.005) rather
/// than a service (T1543.003). See `check_scheduled_task_persistence` (`rules`).
pub const FLAG_PERSISTENCE_TASK_ARTIFACT: u32 = 0x2000_0000;

/// Set alongside [`FLAG_PERSISTENCE_TASK_ARTIFACT`] when the task definition had no
/// action the sensor could read (no `Exec` with a `Command`, no `ComHandler` with a
/// `ClassId`). The persistence event is still reported, since a task whose action
/// is hidden from us is no less suspicious, but `path` then holds a placeholder
/// instead of an action list. Not serialization-visible (a bit in the existing
/// `flags`), so no [`SCHEMA_VERSION`](crate::SCHEMA_VERSION) bump; same reasoning as
/// [`FLAG_PERSISTENCE_ARTIFACT`].
pub const FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN: u32 = 0x0200_0000;

/// Same principle as [`FLAG_PERSISTENCE_ARTIFACT`], for a Windows **local account
/// creation** (event 4720, "A user account was created" — ATT&CK T1136.001) rather
/// than a service (T1543.003) or scheduled task (T1053.005). See
/// `check_account_creation_persistence` (`rules`).
///
/// Scoped to local SAM accounts on this host: domain account creation (4720 on the
/// domain controller) is out of scope for a userland EDR on member/standalone
/// machines — the sensor never observes it. A `computer` account creation (4741) is
/// a distinct technique (T1136.002) and would take its own bit if we add it later.
pub const FLAG_PERSISTENCE_ACCOUNT_ARTIFACT: u32 = 0x0800_0000;

/// Same principle as [`FLAG_PERSISTENCE_ARTIFACT`], for a Linux **systemd unit**
/// observed starting for the first time since the agent started (ATT&CK T1543.002
/// — Create or Modify System Process: Systemd Service, the Linux sibling of
/// T1543.003) rather than a Windows service. Set by `sensor-linux-journal`'s
/// `persistence::UnitPersistenceTracker` (issue #93), the Linux side of the same
/// "reuse `FileOpenEvent` + a flag" shape rather than a new `Event` variant —
/// see `sensor-linux-journal::auth`'s module doc for why a Linux-only lifecycle
/// shape was deliberately not invented while this decision was open.
///
/// Not the same signal as Windows' 7045: journald's `JOB_TYPE=start`/
/// `JOB_RESULT=done` fires on every start of a unit, install or routine restart
/// alike, unlike the Service Control Manager which only writes 7045 once, at
/// actual registration. This flag is therefore only a "first start observed by
/// this agent process" approximation, not a true install signal — see the
/// tracker's own doc for the full caveat (an agent restart forgets what it had
/// already seen).
///
/// `FileOpenEvent::path` and `FileOpenEvent::meta::comm` both carry the unit name
/// (`sshd.service`) — journald's job-completion record has no image-path
/// equivalent to Windows' 7045, so there is no separate field to put there.
///
/// A distinct bit from every other `FLAG_PERSISTENCE_*` constant, so no two
/// techniques cross-fire off a single event.
pub const FLAG_PERSISTENCE_SYSTEMD_ARTIFACT: u32 = 0x4000_0000;

/// Same principle as [`FLAG_PERSISTENCE_ARTIFACT`], for a macOS **launch item
/// registration** observed by Background Task Management (`EndpointSecurity`'s
/// `BTM_LAUNCH_ITEM_ADD`, macOS 13+) — launch agents/daemons (ATT&CK
/// T1543.001/.004) and login items (T1547.015), set by `sensor-macos` (issue
/// #32). Like Windows' 7045 and unlike the Linux systemd approximation, this
/// is a registration-time fact from the OS itself: BTM emits it when the item
/// is added, whatever the path taken (a plist dropped in `LaunchAgents`, an
/// `SMAppService` registration, MDM).
///
/// `FileOpenEvent::path` carries the persistence *payload* (the executable
/// resolved from the launchd plist) when BTM provides it, else the item URL;
/// `meta` identifies the instigating process when BTM attributes one. A raw
/// plist write additionally surfaces as an ordinary file event and is caught
/// by `rules::check_persistence_write`'s path patterns — two distinct signals,
/// not a duplicate (BTM also fires for registrations that never touch a
/// watched directory).
///
/// A distinct bit from every other `FLAG_PERSISTENCE_*` constant, so no two
/// techniques cross-fire off a single event. Not a serialization-visible
/// schema change (same reasoning as [`FLAG_PERSISTENCE_ARTIFACT`]).
pub const FLAG_PERSISTENCE_BTM_ARTIFACT: u32 = 0x0400_0000;

/// Same principle as [`FLAG_PERSISTENCE_ARTIFACT`], for a Windows **`AppLocker`
/// block** — event 8004 in the `Microsoft-Windows-AppLocker/EXE and DLL`
/// operational channel: an executable was refused execution because it
/// matched a deny rule (or no allow rule, depending on policy mode). ATT&CK
/// T1562.001 covers *disabling* `AppLocker`; a *raised* block is a defensive
/// signal — a known-bad payload was stopped at the OS boundary — that the
/// EDR still forwards so operators see the attempt.
///
/// **No longer emitted** (#427): `sensor-windows-eventlog` now reports 8004
/// (and the 8003 audit-mode twin) as [`Event::PolicyDenial`](crate::Event::PolicyDenial) with
/// [`POLICY_MECHANISM_APPLOCKER`](crate::POLICY_MECHANISM_APPLOCKER). The constant stays so the bit is never
/// reassigned to another technique — a stale reader must not misread it.
///
/// Historically reused [`FileOpenEvent`](crate::FileOpenEvent) like the other Windows persistence
/// flags (see ADR-0004): `path` carried `FilePath` from the event's
/// `RuleAndFileData` section, `meta::comm` its leaf name.
///
/// Not a persistence-family flag — the executable never ran, so nothing was
/// installed — but it lives in the same reserved high-bit space because the
/// underlying reuse trick is identical.
///
/// A distinct bit from every other `FLAG_*` constant, so no two techniques
/// cross-fire off a single event.
pub const FLAG_APPLICATION_BLOCKED: u32 = 0x0100_0000;

/// Same principle as [`FLAG_PERSISTENCE_ARTIFACT`], for a Windows **scheduled task
/// update** (event 4702, "A scheduled task was updated") — still ATT&CK T1053.005,
/// but the task-hijack sub-case: an attacker repoints an *existing*, possibly
/// already-trusted task at a malicious action instead of registering a new one
/// (the 4698 / [`FLAG_PERSISTENCE_TASK_ARTIFACT`] case). Set by
/// `sensor-windows-eventlog`.
///
/// Unlike the other `FLAG_PERSISTENCE_*` bits, the flag alone is **not** the
/// signal: Windows rewrites its own tasks routinely (servicing, maintenance), and
/// `schtasks /create` was observed in lab (2026-09-22) to emit 4702 as part of its
/// own registration too. `rules::check_scheduled_task_update_persistence`
/// therefore also requires a suspicious action path — see that function's doc.
///
/// A distinct bit from every other `FLAG_*` constant, so no two techniques
/// cross-fire off a single event. Not a serialization-visible schema change (same
/// reasoning as [`FLAG_PERSISTENCE_ARTIFACT`]).
pub const FLAG_PERSISTENCE_TASK_UPDATE_ARTIFACT: u32 = 0x0080_0000;

/// Every synthetic `FLAG_*` bit above, checked pairwise-disjoint at compile time.
/// A new flag goes here in the same edit (a unit test fails if a `pub const
/// FLAG_*` is missing). Lives next to the constants, not in a
/// consumer's test: the first cut of [`FLAG_PERSISTENCE_TASK_UPDATE_ARTIFACT`]
/// took `0x0200_0000`, already [`FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN`], and the
/// hardcoded list in `rules`' collision test missed it (#399 review).
pub const SYNTHETIC_FLAGS: [u32; 8] = [
    FLAG_PERSISTENCE_ARTIFACT,
    FLAG_PERSISTENCE_TASK_ARTIFACT,
    FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN,
    FLAG_PERSISTENCE_ACCOUNT_ARTIFACT,
    FLAG_PERSISTENCE_SYSTEMD_ARTIFACT,
    FLAG_PERSISTENCE_BTM_ARTIFACT,
    FLAG_APPLICATION_BLOCKED,
    FLAG_PERSISTENCE_TASK_UPDATE_ARTIFACT,
];

const _: () = {
    let mut i = 0;
    while i < SYNTHETIC_FLAGS.len() {
        assert!(SYNTHETIC_FLAGS[i] != 0, "synthetic flag is zero");
        let mut j = i + 1;
        while j < SYNTHETIC_FLAGS.len() {
            assert!(
                SYNTHETIC_FLAGS[i] & SYNTHETIC_FLAGS[j] == 0,
                "two synthetic FLAG_* constants share a bit"
            );
            j += 1;
        }
        i += 1;
    }
};

#[cfg(test)]
mod synthetic_flag_tests {
    #[test]
    fn every_pub_flag_constant_is_in_synthetic_flags() {
        // The compile-time disjointness check only sees what the list holds; a
        // new `pub const FLAG_*` left out of it would skip the check silently.
        let declared = include_str!("flags.rs")
            .lines()
            .filter(|line| line.starts_with("pub const FLAG_"))
            .count();
        assert_eq!(declared, super::SYNTHETIC_FLAGS.len());
    }
}
