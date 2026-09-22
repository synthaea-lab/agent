//! The persistence rules that flow through `FileOpenEvent` with a high-bit
//! `flags` marker rather than a dedicated `Event::Persistence` variant (see
//! ADR-0004): the Windows trio `check_scheduled_task_persistence` (T1053.005,
//! event 4698), `check_service_install_persistence` (T1543.003, event 7045),
//! `check_account_creation_persistence` (T1136.001, event 4720) — plus the
//! Linux sibling `check_systemd_service_persistence` (T1543.002, issue #93).

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

#[test]
fn service_install_flag_matches() {
    // Canonical shape: the sensor sets `flags = FLAG_PERSISTENCE_ARTIFACT` on
    // a 7045, `path` is the service's image path, `comm` is the service name.
    let event =
        file_open_event_service_install("SynthaeaDemoSvc", "C:\\Windows\\System32\\notepad.exe");
    let alert = check_service_install_persistence(&event).expect("must alert on flagged event");
    assert_eq!(alert.technique, "T1543.003");
}

#[test]
fn service_install_alert_carries_image_path_and_service_name() {
    // Alert message must contain both signals an analyst needs to jump to
    // triage (`sc.exe delete <name>` needs the service name; the image path
    // is what the persistence actually executes at each service start).
    let event =
        file_open_event_service_install("MalwareSvc", "C:\\Users\\Public\\malware-service.exe");
    let alert = check_service_install_persistence(&event).expect("must alert on flagged event");
    assert!(
        alert.message.contains("MalwareSvc"),
        "alert missing service name: {}",
        alert.message
    );
    assert!(
        alert
            .message
            .contains("C:\\Users\\Public\\malware-service.exe"),
        "alert missing image path: {}",
        alert.message
    );
}

#[test]
fn file_open_without_service_install_flag_does_not_alert() {
    // Ordinary `FileOpenEvent` without the high-bit persistence marker — must
    // not fire T1543.003 even if `path` looks service-install-shaped (the flag
    // *is* the signal, not the path).
    let event = file_open_event("C:\\Windows\\System32\\svchost.exe", O_CREAT | O_WRONLY);
    assert!(check_service_install_persistence(&event).is_none());
}

#[test]
fn file_open_with_only_scheduled_task_flag_does_not_alert_as_service_install() {
    // Mirror of the scheduled-task guard: the two bits are distinct, so the
    // scheduled-task bit alone must not cross-fire the service-install rule.
    let event = file_open_event(
        "C:\\Windows\\System32\\evil.exe",
        schema::FLAG_PERSISTENCE_TASK_ARTIFACT,
    );
    assert!(check_service_install_persistence(&event).is_none());
}

#[test]
fn file_open_with_both_persistence_flags_still_alerts_as_service_install() {
    // Symmetric to the scheduled-task variant: if a future sensor path ever
    // sets both bits on the same event (currently doesn't happen — different
    // `sensor-windows-eventlog` polling threads), T1543.003 must still fire on
    // its own bit rather than silently defer to the other. Both rules alerting
    // on the same event is the intended behaviour, not a bug.
    let flags = schema::FLAG_PERSISTENCE_TASK_ARTIFACT | schema::FLAG_PERSISTENCE_ARTIFACT;
    let mut event = file_open_event("C:\\Windows\\System32\\whatever.exe", flags);
    event.meta.comm = "AmbiguousArtifact".to_string();
    let alert = check_service_install_persistence(&event).expect("must alert on the service bit");
    assert_eq!(alert.technique, "T1543.003");
}

// ── T1136.001 — Local account creation (event 4720) ─────────────────────────

#[test]
fn account_creation_flag_matches() {
    // Canonical shape: the sensor sets `flags = FLAG_PERSISTENCE_ACCOUNT_ARTIFACT`
    // on a 4720, `path` is the new account's SID, `comm` is the SAM name.
    let event = file_open_event_account_created(
        "attacker",
        "S-1-5-21-1004336348-1177238915-682003330-1005",
    );
    let alert = check_account_creation_persistence(&event).expect("must alert on flagged event");
    assert_eq!(alert.technique, "T1136.001");
}

#[test]
fn account_creation_alert_carries_sid_and_account_name() {
    // Alert message must contain both signals an analyst needs to jump to
    // triage (`net user <name> /delete` needs the SAM name; the SID identifies
    // the account uniquely and survives a rename).
    let event = file_open_event_account_created(
        "MalwareAdmin",
        "S-1-5-21-1004336348-1177238915-682003330-1006",
    );
    let alert = check_account_creation_persistence(&event).expect("must alert on flagged event");
    assert!(
        alert.message.contains("MalwareAdmin"),
        "alert missing account name: {}",
        alert.message
    );
    assert!(
        alert
            .message
            .contains("S-1-5-21-1004336348-1177238915-682003330-1006"),
        "alert missing SID: {}",
        alert.message
    );
}

#[test]
fn file_open_without_account_creation_flag_does_not_alert() {
    // Ordinary `FileOpenEvent` without the high-bit persistence marker — must
    // not fire T1136.001 even if `path` looks SID-shaped (the flag *is* the
    // signal, not the path).
    let event = file_open_event(
        "S-1-5-21-1004336348-1177238915-682003330-1007",
        O_CREAT | O_WRONLY,
    );
    assert!(check_account_creation_persistence(&event).is_none());
}

#[test]
fn file_open_with_only_task_or_service_flag_does_not_alert_as_account_creation() {
    // The three high-bit persistence flags are all distinct — a task or
    // service bit alone must not cross-fire the account-creation rule.
    let task_only = file_open_event(
        "C:\\Windows\\System32\\evil.exe",
        schema::FLAG_PERSISTENCE_TASK_ARTIFACT,
    );
    assert!(check_account_creation_persistence(&task_only).is_none());
    let service_only = file_open_event(
        "C:\\Windows\\System32\\evil.exe",
        schema::FLAG_PERSISTENCE_ARTIFACT,
    );
    assert!(check_account_creation_persistence(&service_only).is_none());
}

#[test]
fn file_open_with_all_three_persistence_flags_still_alerts_as_account_creation() {
    // Symmetric to the guards on the other two rules: if a future sensor path
    // ever sets multiple bits on the same event (currently doesn't happen —
    // each comes from its own `sensor-windows-eventlog` polling thread),
    // T1136.001 must still fire on its own bit. All three rules alerting on
    // the same event is the intended behaviour, not a bug.
    let flags = schema::FLAG_PERSISTENCE_TASK_ARTIFACT
        | schema::FLAG_PERSISTENCE_ARTIFACT
        | schema::FLAG_PERSISTENCE_ACCOUNT_ARTIFACT;
    let mut event = file_open_event("S-1-5-21-0-0-0-9999", flags);
    event.meta.comm = "AmbiguousArtifact".to_string();
    let alert = check_account_creation_persistence(&event).expect("must alert on the account bit");
    assert_eq!(alert.technique, "T1136.001");
}

// ── T1543.002 — Linux systemd unit first-start (issue #93) ──────────────────

#[test]
fn systemd_unit_flag_matches() {
    // Canonical shape: the sensor sets `flags = FLAG_PERSISTENCE_SYSTEMD_ARTIFACT`
    // on a unit's first observed start; `path` and `comm` are both the unit name.
    let event = file_open_event_systemd_unit("cryptominer.service");
    let alert = check_systemd_service_persistence(&event).expect("must alert on flagged event");
    assert_eq!(alert.technique, "T1543.002");
}

#[test]
fn systemd_unit_alert_carries_unit_name() {
    let event = file_open_event_systemd_unit("backdoor.service");
    let alert = check_systemd_service_persistence(&event).expect("must alert on flagged event");
    assert!(
        alert.message.contains("backdoor.service"),
        "alert missing unit name: {}",
        alert.message
    );
}

#[test]
fn file_open_without_systemd_flag_does_not_alert() {
    // Ordinary `FileOpenEvent` without the high-bit persistence marker — must
    // not fire T1543.002 even if `path` looks unit-shaped (the flag *is* the
    // signal, not the path).
    let event = file_open_event("sshd.service", O_CREAT | O_WRONLY);
    assert!(check_systemd_service_persistence(&event).is_none());
}

#[test]
fn file_open_with_only_windows_flags_does_not_alert_as_systemd() {
    // The Windows persistence bits are all distinct from the Linux one — none
    // of them alone should cross-fire T1543.002.
    let flags = schema::FLAG_PERSISTENCE_TASK_ARTIFACT
        | schema::FLAG_PERSISTENCE_ARTIFACT
        | schema::FLAG_PERSISTENCE_ACCOUNT_ARTIFACT;
    let event = file_open_event("whatever", flags);
    assert!(check_systemd_service_persistence(&event).is_none());
}

#[test]
fn file_open_with_systemd_and_a_windows_flag_still_alerts_as_systemd() {
    // Contrived defensive case (the two sensors never share a process, so this
    // never happens in practice): if a future event ever carried both bits,
    // T1543.002 must still fire on its own bit rather than silently defer.
    let flags = schema::FLAG_PERSISTENCE_SYSTEMD_ARTIFACT | schema::FLAG_PERSISTENCE_ARTIFACT;
    let mut event = file_open_event("ambiguous.service", flags);
    event.meta.comm = "ambiguous.service".to_string();
    let alert = check_systemd_service_persistence(&event).expect("must alert on the systemd bit");
    assert_eq!(alert.technique, "T1543.002");
}
