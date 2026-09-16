//! The Windows persistence rules that flow through `FileOpenEvent` with a
//! high-bit `flags` marker rather than a dedicated `Event::Persistence`
//! variant (see ADR-0004): `check_scheduled_task_persistence` (T1053.005,
//! event 4698). A `check_service_install_persistence` (T1543.003, event 7045)
//! belongs in this module too once its rule lands.

use super::*;

#[test]
fn scheduled_task_flag_matches() {
    // Canonical shape: the sensor sets `flags = FLAG_PERSISTENCE_TASK_ARTIFACT`
    // on a 4698, `path` is the task's action path, `comm` is the leaf name.
    let event =
        file_open_event_scheduled_task("SynthaeaDemoTask", "C:\\Windows\\System32\\notepad.exe");
    let alert = check_scheduled_task_persistence(&event).expect("must alert on flagged event");
    assert_eq!(alert.technique, "T1053.005");
}

#[test]
fn scheduled_task_alert_carries_action_path_and_task_name() {
    // Alert message must contain both signals an analyst needs to jump to
    // triage (`schtasks /Delete /TN <name> /F` needs the leaf name; the action
    // path is what the persistence actually executes).
    let event = file_open_event_scheduled_task("MalwareDropper", "C:\\Users\\Public\\malware.exe");
    let alert = check_scheduled_task_persistence(&event).expect("must alert on flagged event");
    assert!(
        alert.message.contains("MalwareDropper"),
        "alert missing task name: {}",
        alert.message
    );
    assert!(
        alert.message.contains("C:\\Users\\Public\\malware.exe"),
        "alert missing action path: {}",
        alert.message
    );
}

#[test]
fn file_open_without_persistence_flag_does_not_alert() {
    // Ordinary `FileOpenEvent` without the high-bit persistence marker — must
    // not fire T1053.005 even if `path` looks scheduled-task-shaped (the flag
    // *is* the signal, not the path).
    let event = file_open_event("C:\\Windows\\System32\\notepad.exe", O_CREAT | O_WRONLY);
    assert!(check_scheduled_task_persistence(&event).is_none());
}

#[test]
fn file_open_with_only_service_install_flag_does_not_alert_as_scheduled_task() {
    // FLAG_PERSISTENCE_ARTIFACT (event 7045, T1543.003 service install) is a
    // distinct bit from FLAG_PERSISTENCE_TASK_ARTIFACT (event 4698,
    // T1053.005). The two techniques must not both fire off a single event —
    // T1053.005 must stay silent on a service-install-only flag.
    let event = file_open_event(
        "C:\\Windows\\System32\\evil.exe",
        schema::FLAG_PERSISTENCE_ARTIFACT,
    );
    assert!(check_scheduled_task_persistence(&event).is_none());
}

#[test]
fn file_open_with_both_persistence_flags_still_alerts_as_scheduled_task() {
    // Contrived defensive case: if a future sensor path ever sets both bits on
    // the same event (currently doesn't happen — the two events come from
    // different `sensor-windows-eventlog` polling threads), T1053.005 must
    // still fire on its own bit rather than silently defer to the other.
    let flags = schema::FLAG_PERSISTENCE_TASK_ARTIFACT | schema::FLAG_PERSISTENCE_ARTIFACT;
    let mut event = file_open_event("C:\\Windows\\System32\\whatever.exe", flags);
    event.meta.comm = "AmbiguousArtifact".to_string();
    let alert = check_scheduled_task_persistence(&event).expect("must alert on the task bit");
    assert_eq!(alert.technique, "T1053.005");
}
