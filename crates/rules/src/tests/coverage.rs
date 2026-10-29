//! Coverage-pack wave 1 (issues #377/#379/#381): masquerading, recovery
//! inhibit, log clearing (exec + file halves), and the auth-failure burst.

use schema::{
    AuthEvent, AuthKind, AuthOutcome, FileDeleteEvent, LogClearedEvent, detection::Severity,
};

use super::*;
use crate::{
    check_event_logging_disable_exec, check_log_clear_exec, check_log_file_delete,
    check_masquerading, check_recovery_inhibit, evaluate_exec, evaluate_file_delete,
    evaluate_log_cleared,
};

fn exec_with_path(image_path: &str, comm: &str) -> ExecEvent {
    let mut event = exec_event("irrelevant");
    event.image_path = image_path.to_string();
    event.meta.comm = comm.to_string();
    event
}

// --- T1036.005 masquerading -------------------------------------------------

#[test]
fn system_binary_name_outside_its_home_alerts() {
    let event = exec_with_path("/tmp/.hidden/bash", "bash");
    let alert = check_masquerading(&event).expect("bash in /tmp must alert");
    assert_eq!(alert.technique, "T1036.005");
    assert!(alert.message.contains("/tmp/.hidden/bash"));
}

#[test]
fn system_binary_in_its_legitimate_home_stays_silent() {
    assert!(check_masquerading(&exec_with_path("/bin/bash", "bash")).is_none());
    assert!(check_masquerading(&exec_with_path("/usr/sbin/sshd", "sshd")).is_none());
}

#[test]
fn windows_masquerade_is_case_insensitive() {
    let event = exec_with_path("C:\\Users\\Public\\SvcHost.exe", "SvcHost.exe");
    let alert = check_masquerading(&event).expect("svchost outside System32 must alert");
    assert_eq!(alert.technique, "T1036.005");
    assert!(
        check_masquerading(&exec_with_path(
            "C:\\Windows\\System32\\svchost.exe",
            "svchost.exe"
        ))
        .is_none(),
        "the real svchost must stay silent"
    );
}

#[test]
fn relative_or_truncated_paths_are_skipped_not_guessed() {
    // The Linux dfd limitation: a relative path can't prove location either way.
    assert!(check_masquerading(&exec_with_path("bash", "bash")).is_none());
    assert!(check_masquerading(&exec_with_path("subdir\\svchost.exe", "svchost.exe")).is_none());
}

#[test]
fn unlisted_names_never_alert_wherever_they_run() {
    assert!(check_masquerading(&exec_with_path("/tmp/build-helper", "build-helper")).is_none());
}

// --- T1490 recovery inhibit -------------------------------------------------

#[test]
fn shadow_copy_deletion_alerts() {
    let event = exec_event("vssadmin.exe Delete Shadows /All /Quiet");
    let alert = check_recovery_inhibit(&event).expect("must alert");
    assert_eq!(alert.technique, "T1490");
    assert_eq!(alert.severity, schema::detection::Severity::High);
}

/// #615: severity is per rule, not per technique string: the same ATT&CK id can be a
/// routine-looking finding from one rule and a serious one from another.
#[test]
fn severity_is_assigned_per_rule_not_flat() {
    use schema::detection::Severity;
    let base64 = crate::evaluate_exec(&exec_event("bash -c echo cGF5bG9hZAo= | base64 -d | sh"));
    assert!(
        base64
            .iter()
            .any(|a| a.technique == "T1059.004" && a.severity == Severity::Medium)
    );
    let shadow = check_recovery_inhibit(&exec_event("vssadmin.exe Delete Shadows /All /Quiet"));
    assert_eq!(shadow.unwrap().severity, Severity::High);
}

#[test]
fn shadow_copy_listing_stays_silent() {
    // Every token must match — admins list shadows constantly.
    assert!(check_recovery_inhibit(&exec_event("vssadmin list shadows")).is_none());
}

#[test]
fn time_machine_snapshot_destruction_alerts() {
    let event = exec_event("tmutil deletelocalsnapshots /");
    assert_eq!(
        check_recovery_inhibit(&event)
            .expect("must alert")
            .technique,
        "T1490"
    );
}

// --- T1070.001/.002 log clearing (exec half) -------------------------------

#[test]
fn windows_event_log_clearing_is_tagged_t1070_001() {
    // Regression (#424): Windows event-log clearing was tagged T1070.002 (Clear
    // Linux or Mac System Logs).
    for cmdline in [
        "wevtutil cl Security",
        "wevtutil.exe clear-log System",
        "powershell -c Clear-EventLog -LogName Application",
    ] {
        let alert = check_log_clear_exec(&exec_event(cmdline)).expect("must alert");
        assert_eq!(alert.technique, "T1070.001", "{cmdline}");
    }
}

#[test]
fn macos_unified_log_erase_is_tagged_t1070_002() {
    let alert = check_log_clear_exec(&exec_event("/usr/bin/log erase --all")).expect("alert");
    assert_eq!(alert.technique, "T1070.002");
}

#[test]
fn journald_vacuum_alerts_but_status_queries_do_not() {
    let alert = check_log_clear_exec(&exec_event("journalctl --vacuum-time=1s")).expect("alert");
    assert_eq!(alert.technique, "T1070.002");
    assert!(check_log_clear_exec(&exec_event("journalctl -u sshd -f")).is_none());
}

// --- T1562.002 disable Windows event logging (exec) ------------------------

/// A Windows exec event: the rule is gated on `User::Windows`.
fn win_exec(cmdline: &str) -> ExecEvent {
    exec_event_win(1, 0, "cmd.exe", cmdline, 0)
}

fn t1562_002(event: &ExecEvent) -> bool {
    evaluate_exec(event)
        .iter()
        .any(|a| a.technique == "T1562.002")
}

#[test]
fn disabling_windows_event_logging_is_tagged_t1562_002() {
    for cmdline in [
        r#"wevtutil sl "Microsoft-Windows-PowerShell/Operational" /e:false"#,
        "wevtutil.exe set-log Microsoft-Windows-Sysmon/Operational /enabled:false",
        "wevtutil.exe\tsl Security /e:\"false\"",
        r#""C:\Windows\System32\wevtutil.exe" sl Security /e:False"#,
        "auditpol /clear /y",
        "auditpol.exe /remove /allusers",
        r#"auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable"#,
        r"C:\Windows\system32\sc.exe config eventlog start= disabled",
        r#"sc config "eventlog" start= disabled"#,
        "sc config eventlog start=disabled",
        r"sc \\lab-host stop eventlog",
        "net stop eventlog /y",
        "net1 stop EventLog",
        r#"net stop "Windows Event Log" /y"#,
        "sc stop eventlog",
        r#"sc stop "eventlog""#,
        "powershell -c Stop-Service -Name EventLog -Force",
        r#"powershell -Command "Stop-Service -Name 'EventLog' -Force""#,
        "powershell -c Set-Service EventLog -StartupType Disabled",
        r#"pwsh -c "Set-Service -Name EventLog -StartupType Disabled""#,
        r"reg add HKLM\SYSTEM\CurrentControlSet\Services\EventLog /v Start /t REG_DWORD /d 4 /f",
        r#"reg add "HKLM\SYSTEM\CurrentControlSet\Services\EventLog" /v Start /t REG_DWORD /d 4 /f"#,
    ] {
        let alert = check_event_logging_disable_exec(&win_exec(cmdline))
            .unwrap_or_else(|| panic!("must alert: {cmdline}"));
        assert_eq!(alert.technique, "T1562.002", "{cmdline}");
        assert_eq!(
            alert.severity,
            schema::detection::Severity::High,
            "{cmdline}"
        );
    }
}

#[test]
fn the_agents_own_audit_and_query_commands_do_not_alert() {
    // sensor-windows-eventlog runs these itself at start-up and on every poll.
    for cmdline in [
        "auditpol /set /subcategory:{0CCE9227-69AE-11D9-BED3-505054503030}          /success:enable /failure:enable",
        r#"wevtutil qe Security /c:1 /rd:true /f:xml "/q:*[System[(EventID=4698)]]""#,
        "wevtutil gl Microsoft-Windows-TaskScheduler/Operational",
        "wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true",
        "auditpol /get /category:*",
    ] {
        assert!(!t1562_002(&win_exec(cmdline)), "{cmdline}");
    }
}

#[test]
fn reading_or_querying_the_eventlog_service_does_not_alert() {
    for cmdline in [
        "sc query eventlog",
        "sc qc eventlog",
        r"reg query HKLM\SYSTEM\CurrentControlSet\Services\EventLog /v Start",
        "powershell -c Get-EventLog -LogName System -Newest 5",
        "powershell -c Get-Service EventLog",
        "net start eventlog",
    ] {
        assert!(
            check_event_logging_disable_exec(&win_exec(cmdline)).is_none(),
            "{cmdline}"
        );
    }
}

#[test]
fn lookalike_command_lines_do_not_alert() {
    for cmdline in [
        // A substring of the program or of the service name is not the command.
        "dotnet MyApp.dll stop eventlog-forwarder",
        r"C:\tools\descr.exe stop eventlog",
        "net stop eventlog-forwarder",
        // Another service, or EventLog named in another statement.
        "sc stop spooler",
        "net stop spooler",
        r#"powershell -c "Stop-Service -Name Spooler; Get-WinEvent -LogName EventLog""#,
        r#"powershell -c "Set-Service Spooler -StartupType Disabled; Get-EventLog System""#,
        // The same service set to start automatically, or a channel's own configuration.
        "sc config eventlog start= auto",
        r"reg add HKLM\SYSTEM\CurrentControlSet\Services\EventLog /v Start /t REG_DWORD /d 2 /f",
        r"reg add HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security /v File /t REG_SZ /d 4 /f",
    ] {
        assert!(!t1562_002(&win_exec(cmdline)), "{cmdline}");
    }
}

#[test]
fn a_cmd_wrapper_is_caught_on_the_child_it_starts() {
    // `cmd /c net stop eventlog` is not matched on its own line; the `net.exe` it starts
    // has its own exec, with the command line cmd passes on, and that one alerts.
    assert!(!t1562_002(&win_exec("cmd /c net stop eventlog")));
    let child = exec_event_win(2, 1, "net.exe", "net  stop eventlog", 0);
    assert!(t1562_002(&child));
}

#[test]
fn a_non_windows_exec_never_raises_the_windows_event_logging_rule() {
    // The same text on a Unix agent (a script path, `ssh host net stop eventlog`) is not a
    // Windows command.
    for cmdline in [
        "net stop eventlog /y",
        "ssh winhost net stop eventlog",
        "wevtutil sl Security /e:false",
    ] {
        assert!(!t1562_002(&exec_event(cmdline)), "{cmdline}");
    }
}

// --- T1070.001 log clearing (OS-record half, #799) -------------------------

#[test]
fn a_cleared_security_log_is_one_high_t1070_001_alert_naming_who() {
    let event = LogClearedEvent {
        meta: EventMeta {
            user: User::Windows {
                sid: "S-1-5-21-1-2-3-1001".into(),
                integrity_level: None,
            },
            ..schema::fixtures::meta()
        },
        channel: "Security".into(),
        subject_user: r"LAB\analyst".into(),
        subject_logon_id: Some("0x4d2c1".into()),
        ..schema::fixtures::log_cleared()
    };
    let alerts = evaluate_log_cleared(&event);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1070.001");
    assert_eq!(alerts[0].severity, Severity::High);
    assert_eq!(
        alerts[0].message,
        r"event log cleared: channel=Security by=LAB\analyst (sid=S-1-5-21-1-2-3-1001 logon=0x4d2c1)"
    );
}

#[test]
fn a_cleared_log_still_alerts_high_when_it_was_backed_up_first() {
    let event = LogClearedEvent {
        channel: "Microsoft-Windows-PowerShell/Operational".into(),
        backup_path: Some(r"C:\Users\Public\ps.evtx".into()),
        ..schema::fixtures::log_cleared()
    };
    let alerts = evaluate_log_cleared(&event);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].severity, Severity::High);
    assert!(
        alerts[0]
            .message
            .ends_with(r"by=- (sid=-), backed up to C:\Users\Public\ps.evtx"),
        "{}",
        alerts[0].message
    );
}

// --- T1070.001/.002 log clearing (file-deletion half) ----------------------

fn file_delete(path: &str) -> FileDeleteEvent {
    FileDeleteEvent {
        meta: meta(),
        path: path.to_string(),
    }
}

#[test]
fn deleting_a_log_file_alerts() {
    let alert = check_log_file_delete(&file_delete("/var/log/auth.log")).expect("must alert");
    assert_eq!(alert.technique, "T1070.002");
    // The dispatcher carries it too.
    assert_eq!(
        evaluate_file_delete(&file_delete("/var/log/auth.log")).len(),
        1
    );
}

#[test]
fn journal_and_evtx_paths_alert_under_their_platform_technique() {
    let journal = check_log_file_delete(&file_delete("/var/log/journal/abc/system.journal"))
        .expect("must alert");
    assert_eq!(journal.technique, "T1070.002");
    // #424: an event log file is Windows event-log clearing, T1070.001.
    let evtx = check_log_file_delete(&file_delete(
        "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
    ))
    .expect("must alert");
    assert_eq!(evtx.technique, "T1070.001");
}

#[test]
fn unblocking_a_downloaded_evtx_is_not_a_log_deletion() {
    // `Unblock-File` deletes the `Zone.Identifier` stream, not the log.
    for path in [
        r"C:\Users\u\Downloads\Security.evtx:Zone.Identifier",
        r"C:\Users\u\Downloads\Security.evtx:Zone.Identifier:$DATA",
    ] {
        assert!(
            check_log_file_delete(&file_delete(path)).is_none(),
            "{path}"
        );
    }
    let upper = check_log_file_delete(&file_delete(
        r"C:\Windows\System32\winevt\Logs\SECURITY.EVTX",
    ))
    .expect("an event log in any case is still one");
    assert_eq!(upper.technique, "T1070.001");
}

#[test]
fn ordinary_deletions_stay_silent() {
    assert!(check_log_file_delete(&file_delete("/tmp/build.o")).is_none());
    assert!(evaluate_file_delete(&file_delete("/home/u/notes.txt")).is_empty());
}

// --- T1110 auth-failure burst -----------------------------------------------

fn auth_failure(target: &str, source: Option<&str>, ts: u64) -> AuthEvent {
    AuthEvent {
        meta: EventMeta {
            timestamp_ns: ts,
            ..meta()
        },
        outcome: AuthOutcome::Failure,
        kind: AuthKind::LogonFailure,
        target_user: target.to_string(),
        target_user_sid: None,
        source_address: source.map(|s| s.parse().unwrap()),
        status_code: None,
    }
}

#[test]
fn failure_burst_alerts_once_per_window() {
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..AUTH_FAILURE_THRESHOLD as u64 + 2 {
        alerts.extend(state.on_auth(&auth_failure("root", Some("10.0.0.5"), i * 1_000_000_000)));
    }
    assert_eq!(alerts.len(), 1, "one alert per window, not one per failure");
    assert_eq!(alerts[0].technique, "T1110");
    assert!(alerts[0].message.contains("root"));
    assert!(alerts[0].message.contains("10.0.0.5"));
}

#[test]
fn below_threshold_stays_silent() {
    let mut state = RuleState::new();
    for i in 0..u64::from(AUTH_FAILURE_THRESHOLD - 1) {
        assert!(
            state
                .on_auth(&auth_failure("root", Some("10.0.0.5"), i * 1_000_000_000))
                .is_empty()
        );
    }
}

#[test]
fn distinct_sources_do_not_pool_into_one_burst() {
    // 3 failures each from two sources must not sum past the threshold —
    // the key is (target, source), or every busy VPN gateway would alert.
    let mut state = RuleState::new();
    for i in 0..3u64 {
        assert!(
            state
                .on_auth(&auth_failure("root", Some("10.0.0.5"), i * 1_000_000_000))
                .is_empty()
        );
        assert!(
            state
                .on_auth(&auth_failure("root", Some("10.0.0.6"), i * 1_000_000_000))
                .is_empty()
        );
    }
}

#[test]
fn successes_never_count_toward_the_burst() {
    let mut state = RuleState::new();
    for i in 0..20u64 {
        let mut event = auth_failure("root", Some("10.0.0.5"), i * 1_000_000_000);
        event.outcome = AuthOutcome::Success;
        event.kind = AuthKind::Logon;
        assert!(state.on_auth(&event).is_empty());
    }
}

#[test]
fn sourceless_local_failures_burst_under_their_own_key() {
    // Console logons carry no source address (honest, per the schema doc) —
    // they count under a distinct "local" key, never a fabricated loopback.
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..u64::from(AUTH_FAILURE_THRESHOLD) {
        alerts.extend(state.on_auth(&auth_failure("admin", None, i * 1_000_000_000)));
    }
    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].message.contains("local"));
}
