//! WDAC (Code Integrity) audit and enforcement records.

use schema::{Event, EventMeta, POLICY_MECHANISM_WDAC, PolicyDenialEvent, User, time::now_ns};

use super::BlockOutcome;
use crate::xml::{self};

// ── WDAC (CodeIntegrity Operational) 3076 / 3077 (#283) ─────────────────────

pub(crate) const WDAC_EVENT_ENFORCED: u32 = 3077;
pub(crate) const WDAC_EVENT_AUDITED: u32 = 3076;

/// Normalizes a WDAC 3077 (blocked) / 3076 (audit mode, would have been
/// blocked) into a [`PolicyDenialEvent`], the shape `AppLocker` verdicts use.
///
/// - `object_path`: `File Name`, as the **NT device path** the event carries
///   (`\Device\HarddiskVolume3\...`): not converted to a drive letter here.
/// - `subject_context`: `Process Name` (also an NT path), the loader.
/// - `object_class`: `kernel-mode` / `user-mode` from `SI Signing Scenario`.
/// - `action`: `load`. `meta.pid` is 0: the event logs the policy engine,
///   not the loader's pid.
///
/// The issue's third id, 3033 (a DLL failed a signing level), is deliberately
/// not subscribed: 584 of them on one lab host in a day, all Chrome loading
/// its own DLLs. Skipped (cursor advances): a block without a file name, and
/// any other event id the filter let through.
pub(crate) fn normalize_wdac_block(block: &str) -> BlockOutcome {
    let Some(ev) = xml::parse_code_integrity_event(block) else {
        return BlockOutcome::Unparseable;
    };
    let record_id = ev.record_id;
    let enforced = match ev.event_id {
        WDAC_EVENT_ENFORCED => true,
        WDAC_EVENT_AUDITED => false,
        _ => return BlockOutcome::Filtered { record_id },
    };
    let Some(file_name) = ev.file_name else {
        return BlockOutcome::Filtered { record_id };
    };
    let object_class = match ev.signing_scenario {
        Some(0) => Some("kernel-mode".to_string()),
        Some(1) => Some("user-mode".to_string()),
        _ => None,
    };
    let event = Event::PolicyDenial(PolicyDenialEvent {
        meta: EventMeta {
            pid: 0,
            ppid: 0,
            user: User::Unknown,
            timestamp_ns: now_ns(),
            comm: String::new(),
            container: None, // attributed by the ETW sensor only (https://github.com/synthaea-lab/agent/issues/39)
            process_generation: None,
            parent_process_generation: None,
        },
        mechanism: POLICY_MECHANISM_WDAC.into(),
        subject_context: ev.process_name,
        object_context: None,
        object_class,
        action: Some("load".into()),
        enforced,
        object_path: Some(file_name),
    });
    BlockOutcome::Event { record_id, event }
}
