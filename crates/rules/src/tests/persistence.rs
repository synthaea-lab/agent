//! The persistence rules that flow through `FileOpenEvent` with a high-bit
//! `flags` marker rather than a dedicated `Event::Persistence` variant (see
//! ADR-0004): the Windows trio `check_scheduled_task_persistence` (T1053.005,
//! event 4698), `check_service_install_persistence` (T1543.003, event 7045),
//! `check_account_creation_persistence` (T1136.001, event 4720) — plus the
//! Linux sibling `check_systemd_service_persistence` (T1543.002, issue #93)
//! and the macOS sibling `check_btm_launch_item_persistence`
//! (T1543.001/T1547.015, issue #32), and the 4702 task-hijack sub-case
//! `check_scheduled_task_update_persistence` (T1053.005).

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

#[test]
fn btm_launch_item_flag_matches() {
    // Canonical shape (issue #32): `sensor-macos` sets
    // `flags = FLAG_PERSISTENCE_BTM_ARTIFACT` on a BTM_LAUNCH_ITEM_ADD,
    // `path` is the persistence payload, `comm` the instigating process.
    let mut event = file_open_event(
        "/Users/mal/.hidden/payload",
        schema::FLAG_PERSISTENCE_BTM_ARTIFACT,
    );
    event.meta.comm = "sfltool".to_string();
    let alert = check_btm_launch_item_persistence(&event).expect("must alert on flagged event");
    assert_eq!(alert.technique, "T1543.001/T1547.015");
    assert!(
        alert.message.contains("/Users/mal/.hidden/payload"),
        "alert missing payload path: {}",
        alert.message
    );
}

#[test]
fn file_open_without_btm_flag_does_not_alert() {
    // Ordinary write into a launchd directory must not fire the BTM rule —
    // that path-shaped signal belongs to `check_persistence_write` (the flag
    // *is* the BTM signal, not the path).
    let event = file_open_event(
        "/Users/mal/Library/LaunchAgents/com.evil.plist",
        O_CREAT | O_WRONLY,
    );
    assert!(check_btm_launch_item_persistence(&event).is_none());
}

#[test]
fn file_open_with_other_persistence_flags_does_not_alert_as_btm() {
    // Every other platform's persistence bit is distinct from the BTM one —
    // none of them may cross-fire T1543.001/T1547.015.
    let flags = schema::FLAG_PERSISTENCE_TASK_ARTIFACT
        | schema::FLAG_PERSISTENCE_ARTIFACT
        | schema::FLAG_PERSISTENCE_ACCOUNT_ARTIFACT
        | schema::FLAG_PERSISTENCE_SYSTEMD_ARTIFACT;
    let event = file_open_event("whatever", flags);
    assert!(check_btm_launch_item_persistence(&event).is_none());
}

#[test]
fn launchd_directory_write_alerts_via_persistence_path_patterns() {
    // The complementary signal: a plist dropped into a launchd directory is an
    // ordinary write-intent `FileOpenEvent` from the ES file stream and must
    // fire `check_persistence_write` without any flag bit.
    let event = file_open_event(
        "/Users/mal/Library/LaunchAgents/com.evil.plist",
        O_CREAT | O_WRONLY,
    );
    let alert = check_persistence_write(&event).expect("launchd plist write must alert");
    assert_eq!(alert.technique, "T1037.004/T1053.003");
}

#[test]
fn scheduled_task_with_unknown_action_still_alerts() {
    // The sensor never drops a 4698: when no action is readable it sets
    // FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN on top of the task bit (#422).
    let mut event = file_open_event_scheduled_task("HiddenTask", "<action unknown>");
    event.flags |= schema::FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN;
    let alert = check_scheduled_task_persistence(&event).expect("must still alert");
    assert_eq!(alert.technique, "T1053.005");
    assert!(alert.message.contains("<action unknown>"));
}

// ── One registration on two channels: 4698 + 106 (#422) ──

const SECOND_NS: u64 = 1_000_000_000;

/// A task registration as either channel reports it, at `seconds` into the run.
/// `None` actions = the sensor could not read them (placeholder + unknown bit).
fn task_registration(task: &str, actions: Option<&str>, seconds: u64) -> FileOpenEvent {
    let mut event = file_open_event_scheduled_task(task, actions.unwrap_or("<action unknown>"));
    if actions.is_none() {
        event.flags |= schema::FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN;
    }
    event.meta.timestamp_ns = 1_000 * SECOND_NS + seconds * SECOND_NS;
    event
}

#[test]
fn task_registration_seen_on_both_channels_alerts_once() {
    // Regression (#422): one `schtasks /Create` raised two T1053.005 alerts.
    let mut state = RuleState::new();
    let notepad = Some(r"C:\Windows\System32\notepad.exe");
    assert_eq!(
        state
            .on_file_open(&task_registration("Demo", notepad, 0))
            .len(),
        1
    );
    assert!(
        state
            .on_file_open(&task_registration("Demo", notepad, 3))
            .is_empty()
    );
}

#[test]
fn task_registration_dedup_holds_whichever_channel_arrives_first() {
    // The two poll threads race: the 106 can be normalized before the 4698.
    let mut state = RuleState::new();
    let notepad = Some(r"C:\Windows\System32\notepad.exe");
    assert_eq!(
        state
            .on_file_open(&task_registration("Demo", notepad, 5))
            .len(),
        1
    );
    assert!(
        state
            .on_file_open(&task_registration("Demo", notepad, 2))
            .is_empty()
    );
}

#[test]
fn unknown_action_registration_after_a_known_one_is_suppressed() {
    let mut state = RuleState::new();
    let notepad = Some(r"C:\Windows\System32\notepad.exe");
    assert_eq!(
        state
            .on_file_open(&task_registration("Demo", notepad, 0))
            .len(),
        1
    );
    assert!(
        state
            .on_file_open(&task_registration("Demo", None, 2))
            .is_empty()
    );
}

#[test]
fn known_actions_after_an_unknown_action_report_still_alert() {
    // A 106 whose task file was unreadable must not hide the 4698's actions.
    let mut state = RuleState::new();
    assert_eq!(
        state
            .on_file_open(&task_registration("Demo", None, 0))
            .len(),
        1
    );
    let alerts = state.on_file_open(&task_registration("Demo", Some(r"C:\evil.exe"), 2));
    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].message.contains(r"C:\evil.exe"));
}

#[test]
fn re_registration_with_a_different_action_alerts() {
    let mut state = RuleState::new();
    assert_eq!(
        state
            .on_file_open(&task_registration("Demo", Some("a.exe"), 0))
            .len(),
        1
    );
    assert_eq!(
        state
            .on_file_open(&task_registration("Demo", Some("b.exe"), 5))
            .len(),
        1
    );
}

#[test]
fn same_registration_outside_the_window_alerts_again() {
    let mut state = RuleState::new();
    let window_s = crate::exclusions::TASK_REGISTRATION_DEDUP_WINDOW_NS / SECOND_NS;
    assert_eq!(
        state
            .on_file_open(&task_registration("Demo", Some("a.exe"), 0))
            .len(),
        1
    );
    let later = task_registration("Demo", Some("a.exe"), window_s + 1);
    assert_eq!(state.on_file_open(&later).len(), 1);
}

#[test]
fn registrations_of_different_tasks_are_not_deduplicated() {
    let mut state = RuleState::new();
    assert_eq!(
        state
            .on_file_open(&task_registration("A", Some("x.exe"), 0))
            .len(),
        1
    );
    assert_eq!(
        state
            .on_file_open(&task_registration("B", Some("x.exe"), 1))
            .len(),
        1
    );
}

// ── Scheduled task update (T1053.005 task-hijack, event 4702) ──

#[test]
fn task_update_repointed_into_appdata_alerts() {
    let event = file_open_event_scheduled_task_update(
        "GoogleUpdateTaskMachineUA",
        r"C:\Users\victim\AppData\Roaming\payload.exe",
    );
    let alert = check_scheduled_task_update_persistence(&event).expect("hijack must alert");
    assert_eq!(alert.technique, "T1053.005");
    assert!(alert.message.contains("GoogleUpdateTaskMachineUA"));
    assert!(alert.message.contains(r"AppData\Roaming\payload.exe"));
}

#[test]
fn task_update_repointed_at_a_script_host_alerts() {
    // The lab capture's shape (`schtasks /change /TR "cmd.exe /c ..."`).
    let event = file_open_event_scheduled_task_update("ClaudeTest", "cmd.exe /c echo hi");
    assert!(check_scheduled_task_update_persistence(&event).is_some());
}

#[test]
fn task_update_pattern_match_is_case_insensitive() {
    let event = file_open_event_scheduled_task_update("Updater", r"C:\USERS\PUBLIC\Payload.EXE");
    assert!(check_scheduled_task_update_persistence(&event).is_some());
}

#[test]
fn task_update_repointed_through_an_unexpanded_env_var_alerts() {
    // Task actions keep `%VAR%` as written: `%localappdata%\…` contains none of
    // the backslash directory patterns (#399 review).
    for action in [
        r"%LOCALAPPDATA%\Microsoft\updater.exe",
        r"%TEMP%\x.exe",
        r"%Public%\svc.exe",
    ] {
        let event = file_open_event_scheduled_task_update("Updater", action);
        assert!(
            check_scheduled_task_update_persistence(&event).is_some(),
            "{action} must alert"
        );
    }
}

#[test]
fn task_update_with_forward_slashes_alerts() {
    let event = file_open_event_scheduled_task_update("Updater", "C:/Users/Public/x.exe");
    assert!(check_scheduled_task_update_persistence(&event).is_some());
}

#[test]
fn routine_task_update_under_program_files_stays_silent() {
    // Windows and vendors rewrite their own tasks constantly — a 4702 whose new
    // action is a normal installed binary is churn, not a hijack.
    let event = file_open_event_scheduled_task_update(
        "MicrosoftEdgeUpdateTaskMachineCore",
        r"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe /c",
    );
    assert!(check_scheduled_task_update_persistence(&event).is_none());
}

#[test]
fn file_open_without_task_update_flag_does_not_alert_as_task_update() {
    let event = file_open_event(
        r"C:\Users\victim\AppData\Local\cache.dat",
        O_CREAT | O_WRONLY,
    );
    assert!(check_scheduled_task_update_persistence(&event).is_none());
}

#[test]
fn task_update_artifact_fires_only_the_task_update_rule() {
    // Distinct bit: a 4702 must not cross-fire the 4698/7045/4720/systemd/BTM
    // rules — exactly one alert through the dispatcher.
    let event = file_open_event_scheduled_task_update(
        "LegitTask",
        r"C:\Users\victim\AppData\Roaming\payload.exe",
    );
    assert!(check_scheduled_task_persistence(&event).is_none());
    assert!(check_service_install_persistence(&event).is_none());
    assert!(check_account_creation_persistence(&event).is_none());
    assert!(check_systemd_service_persistence(&event).is_none());
    assert!(check_btm_launch_item_persistence(&event).is_none());
    let alerts = all_file_open_alerts(&event);
    assert_eq!(alerts.len(), 1, "unexpected alerts: {alerts:?}");
    assert_eq!(alerts[0].technique, "T1053.005");
}

#[test]
fn task_creation_with_unknown_action_does_not_fire_the_task_update_rule() {
    // Regression (#399 review): the update flag first shared its bit with
    // FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN, so an unreadable 4698 read as a 4702.
    // Bit disjointness itself is now a compile-time check in `schema`.
    let mut event = file_open_event_scheduled_task("HiddenTask", "<action unknown>");
    event.flags |= schema::FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN;
    assert!(check_scheduled_task_update_persistence(&event).is_none());
    let alerts = all_file_open_alerts(&event);
    assert_eq!(alerts.len(), 1, "unexpected alerts: {alerts:?}");
    assert!(alerts[0].message.contains("persistence created"));
}

#[test]
fn task_update_with_unknown_action_alerts_without_the_pattern_gate() {
    // The placeholder matches no hijack pattern; an unreadable new action must
    // not slip through the gate because of it.
    let mut event = file_open_event_scheduled_task_update("GoogleUpdateTask", "<action unknown>");
    event.flags |= schema::FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN;
    let alert = check_scheduled_task_update_persistence(&event).expect("must alert");
    assert_eq!(alert.technique, "T1053.005");
    assert!(alert.message.contains("action unreadable"));
    assert!(check_scheduled_task_persistence(&event).is_none());
}

#[test]
fn task_update_hijacking_the_second_action_alerts() {
    // The sensor joins every action (#443); a benign first action must not hide
    // a repointed second one.
    let event = file_open_event_scheduled_task_update(
        "BackupTask",
        r"C:\Program Files\Backup\backup.exe | C:\Users\Public\evil.exe -q",
    );
    let alert = check_scheduled_task_update_persistence(&event).expect("hijack must alert");
    assert!(alert.message.contains(r"\users\public\"));
}
