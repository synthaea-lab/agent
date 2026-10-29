//! OSASCRIPT-PASSWORD-PROMPT (T1056.002 / T1059.002, #1032). Events are fabricated: the macOS
//! VM was not run.

use schema::{ExecEvent, detection::Severity};

use super::exec_event;
use crate::{Alert, evaluate_exec};

const PHISH: &str = "osascript -e 'display dialog \"macOS needs your password to apply an \
    update\" default answer \"\" with hidden answer with icon caution'";
const PHISH_THEN_SUDO: &str = "osascript -e 'set p to text returned of (display dialog \"Password\" \
    default answer \"\" with hidden answer)' -e 'do shell script \"id\" password p with \
    administrator privileges'";
const ADMIN_ONLY: &str = "osascript -e 'do shell script \"launchctl load /x.plist\" with \
    administrator privileges'";

fn osascript(cmdline: &str, parent: &str) -> ExecEvent {
    let mut event = exec_event(cmdline);
    event.image_path = "/usr/bin/osascript".into();
    event.meta.comm = "osascript".into();
    event.parent_comm = Some(parent.into());
    event
}

fn prompt_alerts(event: &ExecEvent) -> Vec<Alert> {
    evaluate_exec(event)
        .into_iter()
        .filter(|a| a.technique.contains("T1056.002") || a.technique == "T1059.002")
        .collect()
}

#[test]
fn a_hidden_answer_dialog_from_a_shell_alerts_as_input_capture() {
    let alerts = prompt_alerts(&osascript(PHISH, "zsh"));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1056.002/T1059.002");
    assert_eq!(alerts[0].severity, Severity::Medium);
    assert!(alerts[0].message.contains("hidden answer"));
}

#[test]
fn the_dialog_feeding_an_administrator_shell_command_is_high() {
    let alerts = prompt_alerts(&osascript(PHISH_THEN_SUDO, "Terminal"));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1056.002/T1059.002");
    assert_eq!(alerts[0].severity, Severity::High);
}

#[test]
fn the_administrator_shell_command_alone_is_a_low_t1059_002() {
    let alerts = prompt_alerts(&osascript(ADMIN_ONLY, "zsh"));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1059.002");
    assert_eq!(alerts[0].severity, Severity::Low);
}

/// How a benign installer is told apart: the parent process. A package's postinstall that asks
/// for a password runs `osascript` under the installer's processes; the dialog text cannot
/// separate it from a fake one. The hidden-answer case stays visible at Low, since a malicious
/// package has the same shape; the administrator-only case is silent.
#[test]
fn an_installer_script_is_told_apart_by_its_parent_process() {
    let dialog = prompt_alerts(&osascript(PHISH, "package_script_service"));
    assert_eq!(dialog.len(), 1);
    assert_eq!(dialog[0].severity, Severity::Low);
    assert!(prompt_alerts(&osascript(ADMIN_ONLY, "installd")).is_empty());
    assert!(prompt_alerts(&osascript(ADMIN_ONLY, "Installer")).is_empty());
}

#[test]
fn a_visible_dialog_or_plain_automation_stays_silent() {
    for cmdline in [
        "osascript -e 'display dialog \"Done\" buttons {\"OK\"}'",
        "osascript -e 'display dialog \"Name?\" default answer \"\"'",
        "osascript -e 'tell application \"Finder\" to activate'",
        "osascript -e 'do shell script \"ls\"'",
        "osascript /tmp/script.scpt",
        "osascript -e 'display alert \"hidden answer\" message \"x\"'",
    ] {
        assert!(
            prompt_alerts(&osascript(cmdline, "zsh")).is_empty(),
            "{cmdline}"
        );
    }
}

#[test]
fn only_the_osascript_binary_is_read() {
    let mut event = osascript(PHISH, "zsh");
    event.image_path = "/usr/bin/echo".into();
    event.meta.comm = "echo".into();
    assert!(prompt_alerts(&event).is_empty());
    event.image_path = "/tmp/not-osascript".into();
    assert!(prompt_alerts(&event).is_empty());
}

#[test]
fn matching_is_case_insensitive_on_the_script_text() {
    let event = osascript(
        "osascript -e 'Display Dialog \"x\" Default Answer \"\" With Hidden Answer'",
        "zsh",
    );
    assert_eq!(prompt_alerts(&event).len(), 1);
}
