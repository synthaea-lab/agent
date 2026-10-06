//! Rules over Microsoft Defender Antivirus events (#283): the traces of someone
//! weakening it, T1562.001 (Impair Defenses: Disable or Modify Tools). Defender
//! logs its own state changes, so turning it off or excluding a path leaves a
//! trace even when the attacker removed every other one.
//!
//! Detections (`Detection`/`Remediation`) raise no alert here: Defender already
//! acted on them, and turning its verdicts into a correlator input needs a
//! host-wide signal (these events name no process, so the per-pid correlator
//! cannot use them yet).
//!
//! The events name no actor either, so alerts cannot say which process did it.
//! Legitimate administration does all of this too (a developer excluding a build
//! directory, a third-party antivirus taking over as the active product), which
//! is why only the clearly risky shapes are High.

use schema::{DefenderEvent, DefenderEventKind, detection::Severity};

use crate::Alert;

/// T1562.001: Impair Defenses, Disable or Modify Tools.
const IMPAIR_DEFENSES: &str = "T1562.001";

/// The registry value names (lowercase) that switch a Defender protection off
/// when set to a non-zero value.
const DISABLE_SWITCHES: &[&str] = &[
    "disablerealtimemonitoring",
    "disablebehaviormonitoring",
    "disableonaccessprotection",
    "disableioavprotection",
    "disablescriptscanning",
    "disableantispyware",
    "disableantivirus",
];

/// `TamperProtection`'s "on" value (Microsoft Learn: 5 on, 4 off). Only the
/// move *away* from it alerts, so the rule does not depend on what "off" is.
const TAMPER_PROTECTION_ON: u64 = 5;

/// Directory markers (lowercase) of places malware stages in and software
/// installs to rarely: an exclusion there is the classic way to let a dropped
/// payload live.
const RISKY_DIRECTORIES: &[&str] = &[
    "\\temp",
    "\\tmp",
    "\\users\\public",
    "\\downloads",
    "\\appdata\\",
    "\\programdata\\",
];

/// Extensions (lowercase, no dot) that are code: excluding one makes every
/// such file invisible.
const CODE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "hta", "scr", "com", "msi", "jar", "lnk",
];

/// Interpreters and proxy-execution binaries (lowercase): excluding the
/// *process* exempts everything it runs.
const RISKY_PROCESSES: &[&str] = &[
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
];

/// Evaluates every Defender rule on one event.
#[must_use]
pub fn evaluate_defender_event(event: &DefenderEvent) -> Vec<Alert> {
    match event.kind {
        DefenderEventKind::ProtectionDisabled => {
            let component = event.setting.as_deref().unwrap_or("a protection");
            vec![alert(
                Severity::High,
                format!("Microsoft Defender {component} was turned off"),
            )]
        }
        DefenderEventKind::ConfigChanged => config_changed(event).into_iter().collect(),
        DefenderEventKind::Detection | DefenderEventKind::Remediation => Vec::new(),
    }
}

fn alert(severity: Severity, what: String) -> Alert {
    Alert {
        technique: IMPAIR_DEFENSES,
        severity,
        message: format!("{what} (Defender Operational channel; the event names no process)"),
    }
}

fn config_changed(event: &DefenderEvent) -> Option<Alert> {
    let setting = event.setting.as_deref()?;
    let lower = setting.to_ascii_lowercase();
    let new = event.new_value.as_deref().and_then(parse_number);
    let old = event.old_value.as_deref().and_then(parse_number);

    if let Some((_, rest)) = lower.split_once("\\exclusions\\") {
        // An exclusion *added* has a value after the change; a removal has none.
        event.new_value.as_deref().filter(|v| !v.is_empty())?;
        // The value name is the excluded item, in its original case.
        let original_rest = &setting[setting.len() - rest.len()..];
        let (kind, item) = original_rest
            .split_once('\\')
            .unwrap_or((original_rest, ""));
        let severity = if exclusion_is_risky(&kind.to_ascii_lowercase(), item) {
            Severity::High
        } else {
            Severity::Medium
        };
        return Some(alert(
            severity,
            format!("Microsoft Defender exclusion added ({kind}): {item}"),
        ));
    }

    let value_name = lower.rsplit('\\').next().unwrap_or("");
    if DISABLE_SWITCHES.contains(&value_name)
        && new.is_some_and(|n| n != 0)
        && old.unwrap_or(0) == 0
    {
        return Some(alert(
            Severity::High,
            format!(
                "Microsoft Defender protection switch {value_name} was turned on (protection off)"
            ),
        ));
    }
    if value_name == "tamperprotection"
        && old == Some(TAMPER_PROTECTION_ON)
        && new.is_some_and(|n| n != TAMPER_PROTECTION_ON)
    {
        return Some(alert(
            Severity::High,
            "Microsoft Defender Tamper Protection was turned off".into(),
        ));
    }
    None
}

/// Whether excluding `item` of exclusion type `kind` (lowercase: `paths`,
/// `extensions`, `processes`, `ipaddresses`, ...) blinds Defender to something
/// attacker-friendly.
fn exclusion_is_risky(kind: &str, item: &str) -> bool {
    let item = item.trim().to_ascii_lowercase();
    match kind {
        "paths" | "temporarypaths" => {
            let bare_root = item == "*" || (item.len() <= 3 && item.contains(':'));
            bare_root || RISKY_DIRECTORIES.iter().any(|d| item.contains(d))
        }
        "extensions" => CODE_EXTENSIONS.contains(&item.trim_start_matches('.')),
        "processes" => {
            let leaf = item.rsplit('\\').next().unwrap_or(&item);
            RISKY_PROCESSES.contains(&leaf)
        }
        _ => false,
    }
}

/// `0x1` or `1` as a number; `None` for anything else (a path, an empty value).
fn parse_number(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    match raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => raw.parse().ok(),
    }
}

#[cfg(test)]
mod tests {
    use schema::fixtures;

    use super::*;

    fn change(setting: &str, old: Option<&str>, new: Option<&str>) -> DefenderEvent {
        DefenderEvent {
            kind: DefenderEventKind::ConfigChanged,
            setting: Some(setting.into()),
            old_value: old.map(str::to_string),
            new_value: new.map(str::to_string),
            ..fixtures::defender()
        }
    }

    fn exclusion(kind: &str, item: &str) -> DefenderEvent {
        change(
            &format!(r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\{kind}\{item}"),
            None,
            Some("0x0"),
        )
    }

    fn severities(event: &DefenderEvent) -> Vec<Severity> {
        evaluate_defender_event(event)
            .iter()
            .map(|a| a.severity)
            .collect()
    }

    #[test]
    fn protection_turned_off_is_high() {
        for component in ["real-time protection", "spyware scanning", "virus scanning"] {
            let event = DefenderEvent {
                kind: DefenderEventKind::ProtectionDisabled,
                setting: Some(component.into()),
                ..fixtures::defender()
            };
            let alerts = evaluate_defender_event(&event);
            assert_eq!(alerts.len(), 1);
            assert_eq!(alerts[0].technique, "T1562.001");
            assert_eq!(alerts[0].severity, Severity::High);
            assert!(
                alerts[0].message.contains(component),
                "{}",
                alerts[0].message
            );
        }
    }

    #[test]
    fn risky_exclusions_are_high_and_ordinary_ones_medium() {
        assert_eq!(
            severities(&exclusion("Paths", r"C:\Users\Public")),
            [Severity::High]
        );
        assert_eq!(
            severities(&exclusion("Paths", r"C:\Users\bob\Downloads\tools")),
            [Severity::High]
        );
        assert_eq!(
            severities(&exclusion("Paths", r"C:\Windows\Temp")),
            [Severity::High]
        );
        assert_eq!(
            severities(&exclusion("Paths", r"C:\")),
            [Severity::High],
            "a drive root"
        );
        assert_eq!(severities(&exclusion("Paths", "*")), [Severity::High]);
        assert_eq!(
            severities(&exclusion("Extensions", ".exe")),
            [Severity::High]
        );
        assert_eq!(
            severities(&exclusion("Extensions", "ps1")),
            [Severity::High]
        );
        assert_eq!(
            severities(&exclusion("Processes", r"C:\Windows\System32\cmd.exe")),
            [Severity::High]
        );
        // A build directory, a data extension, an application: worth seeing, not alarming.
        assert_eq!(
            severities(&exclusion("Paths", r"D:\builds\app")),
            [Severity::Medium]
        );
        assert_eq!(
            severities(&exclusion("Extensions", ".iso")),
            [Severity::Medium]
        );
        assert_eq!(
            severities(&exclusion("Processes", "backup.exe")),
            [Severity::Medium]
        );
        assert_eq!(
            severities(&exclusion("IpAddresses", "10.0.0.5")),
            [Severity::Medium]
        );
    }

    #[test]
    fn the_alert_names_the_excluded_item_in_its_original_case() {
        let alerts = evaluate_defender_event(&exclusion("Paths", r"C:\Users\Public\SynLab"));
        assert!(
            alerts[0]
                .message
                .contains(r"exclusion added (Paths): C:\Users\Public\SynLab"),
            "{}",
            alerts[0].message
        );
    }

    #[test]
    fn an_exclusion_removed_is_quiet() {
        let removed = change(
            r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\Public",
            Some("0x0"),
            None,
        );
        assert!(evaluate_defender_event(&removed).is_empty());
    }

    #[test]
    fn a_protection_switch_turned_on_is_high_and_turned_back_is_quiet() {
        let name = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring";
        assert_eq!(
            severities(&change(name, Some("0x0"), Some("0x1"))),
            [Severity::High]
        );
        assert_eq!(severities(&change(name, None, Some("1"))), [Severity::High]);
        assert!(
            severities(&change(name, Some("0x1"), Some("0x0"))).is_empty(),
            "protection restored"
        );
        assert!(
            severities(&change(name, Some("0x1"), Some("0x1"))).is_empty(),
            "no change"
        );
        let spyware = r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware";
        assert_eq!(
            severities(&change(spyware, None, Some("0x1"))),
            [Severity::High]
        );
    }

    #[test]
    fn tamper_protection_alerts_only_when_it_leaves_on() {
        let name = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection";
        assert_eq!(
            severities(&change(name, Some("0x5"), Some("0x4"))),
            [Severity::High]
        );
        assert!(severities(&change(name, Some("0x4"), Some("0x5"))).is_empty());
        assert!(severities(&change(name, Some("0x5"), Some("0x5"))).is_empty());
    }

    #[test]
    fn verdicts_and_other_settings_raise_nothing() {
        for kind in [DefenderEventKind::Detection, DefenderEventKind::Remediation] {
            let event = DefenderEvent {
                kind,
                threat_name: Some("HackTool:Win32/Lab".into()),
                ..fixtures::defender()
            };
            assert!(evaluate_defender_event(&event).is_empty());
        }
        let other = change(
            r"HKLM\SOFTWARE\Microsoft\Windows Defender\Scan\CheckForSignaturesBeforeRunningScan",
            None,
            Some("0x1"),
        );
        assert!(evaluate_defender_event(&other).is_empty());
        assert!(evaluate_defender_event(&change("", None, None)).is_empty());
    }
}
