//! Microsoft Defender detections and protection changes.

use schema::{DefenderEvent, DefenderEventKind, Event, EventMeta, User, time::now_ns};

use super::BlockOutcome;
use crate::xml::{self};

// ── Microsoft Defender Operational (#283) ──────────────────────────────────
//
// The channel's own verdicts (1116 detected, 1117 action taken) and the traces
// of someone weakening it (5001/5010/5012 protection turned off, 5007 a setting
// changed, T1562.001). Enabled by default on every Windows SKU that ships
// Defender: no audit toggle. The channel is **localized**: only numeric ids and
// the untranslated `Threat Name`/`Path` are read, never the `* Name` texts.

pub(crate) const DEFENDER_DETECTED: u32 = 1116;
pub(crate) const DEFENDER_REMEDIATED: u32 = 1117;
pub(crate) const DEFENDER_REALTIME_DISABLED: u32 = 5001;
pub(crate) const DEFENDER_CONFIG_CHANGED: u32 = 5007;
pub(crate) const DEFENDER_SPYWARE_DISABLED: u32 = 5010;
pub(crate) const DEFENDER_VIRUS_DISABLED: u32 = 5012;

/// A command-line detection's `Path` is the whole command line (lab,
/// 2026-10-02: a multi-line script). The event keeps the start: enough to
/// identify what was caught, bounded so one detection cannot carry a script.
pub(crate) const DEFENDER_PATH_MAX_CHARS: usize = 1024;

/// Registry value names (last path component, lowercase) whose change is a
/// protection being weakened. The rules decide which changes alert; the sensor
/// only has to keep the rest of the 5007 flood (service start-up progress:
/// 42 % of the channel on the lab host) out of the pipeline.
pub(crate) const DEFENDER_SECURITY_VALUES: &[&str] = &[
    "disablerealtimemonitoring",
    "disablebehaviormonitoring",
    "disableonaccessprotection",
    "disableioavprotection",
    "disablescriptscanning",
    "disableantispyware",
    "disableantivirus",
    "tamperprotection",
];

/// Whether a 5007's registry value is one a rule could act on: any
/// exclusion, or one of [`DEFENDER_SECURITY_VALUES`].
pub(crate) fn is_security_relevant_setting(setting: &str) -> bool {
    let lower = setting.to_ascii_lowercase();
    lower.contains("\\exclusions\\")
        || DEFENDER_SECURITY_VALUES
            .iter()
            .any(|value| lower.ends_with(&format!("\\{value}")))
}

/// Defender renders a changed setting as `<registry value path> = <data>`.
pub(crate) fn split_registry_assignment(text: &str) -> (&str, &str) {
    match text.split_once(" = ") {
        Some((path, data)) => (path.trim(), data.trim()),
        None => (text.trim(), ""),
    }
}

pub(crate) fn truncate_chars(text: String, max: usize) -> String {
    if text.chars().count() <= max {
        text
    } else {
        text.chars().take(max).collect()
    }
}

/// A [`DefenderEvent`] of `kind` with nothing filled in. Defender names no
/// actor (which process changed a setting, or owns a detection): pid 0, no
/// comm, no user.
pub(crate) fn defender_base(kind: DefenderEventKind) -> DefenderEvent {
    DefenderEvent {
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
        kind,
        detection_id: None,
        threat_name: None,
        severity_id: None,
        category_id: None,
        action_id: None,
        path: None,
        process_name: None,
        user: None,
        setting: None,
        old_value: None,
        new_value: None,
    }
}

/// Normalizes a Defender Operational event into a [`DefenderEvent`].
///
/// Skipped (cursor still advances): a detection without a threat name, a
/// 5007 about a setting no rule watches, and any event id the `XPath` filter
/// let through that this function has no shape for.
pub(crate) fn normalize_defender_block(block: &str) -> BlockOutcome {
    let Some(ev) = xml::parse_defender_event(block) else {
        return BlockOutcome::Unparseable;
    };
    let record_id = ev.record_id;
    let event = match ev.event_id {
        DEFENDER_DETECTED | DEFENDER_REMEDIATED => {
            let Some(threat_name) = ev.threat_name else {
                return BlockOutcome::Filtered { record_id };
            };
            let kind = if ev.event_id == DEFENDER_DETECTED {
                DefenderEventKind::Detection
            } else {
                DefenderEventKind::Remediation
            };
            DefenderEvent {
                detection_id: ev.detection_id,
                threat_name: Some(threat_name),
                severity_id: ev.severity_id,
                category_id: ev.category_id,
                action_id: ev
                    .action_id
                    .filter(|_| kind == DefenderEventKind::Remediation),
                path: ev.path.map(|p| truncate_chars(p, DEFENDER_PATH_MAX_CHARS)),
                process_name: ev.process_name,
                user: ev.detection_user,
                ..defender_base(kind)
            }
        }
        DEFENDER_REALTIME_DISABLED | DEFENDER_SPYWARE_DISABLED | DEFENDER_VIRUS_DISABLED => {
            // Fixed English labels: the event text is localized.
            let component = match ev.event_id {
                DEFENDER_REALTIME_DISABLED => "real-time protection",
                DEFENDER_SPYWARE_DISABLED => "spyware scanning",
                _ => "virus scanning",
            };
            DefenderEvent {
                setting: Some(component.to_string()),
                ..defender_base(DefenderEventKind::ProtectionDisabled)
            }
        }
        DEFENDER_CONFIG_CHANGED => {
            let old = ev.old_value.as_deref().map(split_registry_assignment);
            let new = ev.new_value.as_deref().map(split_registry_assignment);
            // The path is the same on both sides; after a removal only the
            // old side has one.
            let Some(path) = new
                .map(|(path, _)| path)
                .filter(|p| !p.is_empty())
                .or_else(|| old.map(|(path, _)| path))
            else {
                return BlockOutcome::Filtered { record_id };
            };
            if !is_security_relevant_setting(path) {
                return BlockOutcome::Filtered { record_id };
            }
            let value = |side: Option<(&str, &str)>| {
                side.map(|(_, data)| data.to_string())
                    .filter(|data| !data.is_empty())
            };
            DefenderEvent {
                setting: Some(path.to_string()),
                old_value: value(old),
                new_value: value(new),
                ..defender_base(DefenderEventKind::ConfigChanged)
            }
        }
        _ => return BlockOutcome::Filtered { record_id },
    };
    BlockOutcome::Event {
        record_id,
        event: Event::Defender(event),
    }
}
