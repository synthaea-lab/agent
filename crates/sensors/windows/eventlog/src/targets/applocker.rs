//! `AppLocker` audit and block records.

use schema::{Event, EventMeta, POLICY_MECHANISM_APPLOCKER, PolicyDenialEvent, User, time::now_ns};

use super::BlockOutcome;
use crate::xml::{self};

// ── Events 8003/8004 — `AppLocker` EXE/DLL audit/block (Microsoft-Windows-AppLocker/EXE and DLL)
//
// `AppLocker`'s operational channel is on by default where `AppLocker` ships, with no
// `auditpol` toggle. A channel disabled by group policy returns nothing: a coverage
// gap the start-up channel check logs.

/// `AppLocker` event id for "blocked" (enforce mode).
pub(crate) const APPLOCKER_EVENT_BLOCKED: u32 = 8004;
/// `AppLocker` event id for "allowed, but would have been blocked" (audit
/// mode). Same payload shape as 8004.
pub(crate) const APPLOCKER_EVENT_AUDITED: u32 = 8003;
pub(crate) const APPLOCKER_MSI_AUDITED: u32 = 8006;
pub(crate) const APPLOCKER_MSI_BLOCKED: u32 = 8007;
pub(crate) const APPLOCKER_PACKAGED_EXEC_AUDITED: u32 = 8021;
pub(crate) const APPLOCKER_PACKAGED_EXEC_BLOCKED: u32 = 8022;
pub(crate) const APPLOCKER_PACKAGED_DEPLOY_AUDITED: u32 = 8024;
pub(crate) const APPLOCKER_PACKAGED_DEPLOY_BLOCKED: u32 = 8025;

/// Normalizes a blocked or audit-only `AppLocker` decision into a
/// [`PolicyDenialEvent`] (#427):
/// 8004/8007/8022/8025 are enforced denials, 8003/8006/8021/8024 are audit
/// decisions (`enforced: false`) —
/// the `SELinux` enforcing/permissive split, which is what lets a rule tell
/// "stopped at the OS boundary" from "ran, and policy only noticed".
///
/// - `object_path`: `FullFilePath` when the event carries it (real path,
///   original case); otherwise `FilePath`, expanded from `AppLocker`'s path
///   variables (`%OSDRIVE%\USERS\...` → `C:\USERS\...`) so path-based rules
///   can still match it.
/// - `object_class`: the rule collection (`EXE`, `DLL`, `MSI`, `SCRIPT`, `APPX`), as reported.
/// - `action`: `install` for packaged-app deployment decisions, `execute` otherwise.
/// - `meta.pid`: `<Execution ProcessID>`, the process that tried to launch
///   the image — the actor. Not `TargetProcessId`, which names the process
///   being created for the image itself (lab-checked for 8003 and 8004, #529).
/// - `meta.user`: `TargetUser`, the SID whose execution was refused.
/// - `meta.comm`: empty. The event carries the launcher's pid but not its
///   name, and the image's leaf name — what the pre-#427 `FileOpenEvent` put
///   there — names the *object*, not the actor.
///
/// Skipped (cursor still advances): a block without `FilePath` or a packaged
/// app's `Package` identity (nothing to attribute), and any event id outside
/// the audit/enforced allowlist that an `XPath` filter let through — don't guess
/// a verdict for an event we haven't seen the shape of.
pub(crate) fn normalize_applocker_block(block: &str) -> BlockOutcome {
    let Some(ev) = xml::parse_applocker_event(block) else {
        return BlockOutcome::Unparseable;
    };
    let record_id = ev.record_id;
    let enforced = match ev.event_id {
        APPLOCKER_EVENT_BLOCKED
        | APPLOCKER_MSI_BLOCKED
        | APPLOCKER_PACKAGED_EXEC_BLOCKED
        | APPLOCKER_PACKAGED_DEPLOY_BLOCKED => true,
        APPLOCKER_EVENT_AUDITED
        | APPLOCKER_MSI_AUDITED
        | APPLOCKER_PACKAGED_EXEC_AUDITED
        | APPLOCKER_PACKAGED_DEPLOY_AUDITED => false,
        _ => return BlockOutcome::Filtered { record_id },
    };
    if ev.file_path.is_empty() {
        return BlockOutcome::Filtered { record_id };
    }
    let path = ev.full_file_path.unwrap_or_else(|| {
        xml::expand_applocker_path(&ev.file_path, |name| std::env::var(name).ok())
    });
    let user = ev.target_user.map_or(User::Unknown, |sid| User::Windows {
        sid,
        integrity_level: None,
    });
    let event = Event::PolicyDenial(PolicyDenialEvent {
        meta: EventMeta {
            pid: ev.pid,
            ppid: 0,
            user,
            timestamp_ns: now_ns(),
            comm: String::new(),
            container: None, // attributed by the ETW sensor only (https://github.com/synthaea-lab/agent/issues/39)
            process_generation: None,
            parent_process_generation: None,
        },
        mechanism: POLICY_MECHANISM_APPLOCKER.into(),
        subject_context: None,
        object_context: None,
        object_class: Some(ev.policy_name).filter(|p| !p.is_empty()),
        action: Some(
            if matches!(
                ev.event_id,
                APPLOCKER_PACKAGED_DEPLOY_AUDITED | APPLOCKER_PACKAGED_DEPLOY_BLOCKED
            ) {
                "install"
            } else {
                "execute"
            }
            .into(),
        ),
        enforced,
        object_path: Some(path),
    });
    BlockOutcome::Event { record_id, event }
}
