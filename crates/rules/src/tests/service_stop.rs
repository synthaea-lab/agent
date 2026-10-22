//! SERVICE-STOP-BURST (T1489, #381): five distinct services stopped from one lineage in a
//! minute, the services a ransomware run stops first.

use super::*;
use crate::{Alert, Severity};

const SEC: u64 = 1_000_000_000;
const SHELL: u32 = 600;

/// The T1489 alerts of running `commands` (one per `step` seconds) under `SHELL`.
fn run(commands: &[&str], step: u64) -> Vec<Alert> {
    let mut state = RuleState::new();
    commands
        .iter()
        .enumerate()
        .flat_map(|(i, c)| {
            let comm = c.split_whitespace().next().unwrap();
            state.on_exec(&exec_event_full(
                2000 + i as u32,
                SHELL,
                comm,
                c,
                i as u64 * step * SEC,
            ))
        })
        .filter(|a| a.technique == "T1489")
        .collect()
}

const FIVE_UNITS: [&str; 5] = [
    "systemctl stop mysqld",
    "systemctl stop postgresql",
    "systemctl stop veeam",
    "systemctl stop postfix",
    "systemctl stop falcon-sensor",
];

#[test]
fn five_distinct_services_stopped_in_a_minute_alert_once_and_name_them() {
    let alerts = run(&FIVE_UNITS, 1);
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(alerts[0].severity, Severity::Medium);
    for name in ["mysqld", "postgresql", "veeam", "postfix", "falcon-sensor"] {
        assert!(alerts[0].message.contains(name), "{}", alerts[0].message);
    }
}

#[test]
fn a_continued_burst_does_not_alert_again_inside_the_window() {
    let more: Vec<&str> = FIVE_UNITS
        .iter()
        .copied()
        .chain(["systemctl stop cron", "systemctl stop rsyslog"])
        .collect();
    assert_eq!(run(&more, 1).len(), 1);
}

#[test]
fn one_exec_that_names_several_services_counts_each() {
    let alerts = run(&["systemctl stop mysqld postgresql veeam postfix nginx"], 1);
    assert_eq!(alerts.len(), 1, "{alerts:?}");
}

#[test]
fn four_services_are_a_maintenance_window_not_a_burst() {
    assert!(run(&FIVE_UNITS[..4], 1).is_empty());
    assert!(run(&["systemctl stop nginx php-fpm"], 1).is_empty());
}

#[test]
fn stopping_the_same_service_over_and_over_is_one_service() {
    let same = ["systemctl stop nginx"; 12];
    assert!(run(&same, 1).is_empty());
    // The `.service` suffix is the same unit.
    assert!(run(&["systemctl stop nginx", "systemctl stop nginx.service"], 1).is_empty());
}

#[test]
fn a_slow_sequence_never_has_five_inside_the_window() {
    // One every 20 s: at most four are ever inside a 60 s window.
    assert!(run(&FIVE_UNITS, 20).is_empty());
    let seven: Vec<&str> = FIVE_UNITS
        .iter()
        .copied()
        .chain(["systemctl stop cron", "systemctl stop rsyslog"])
        .collect();
    assert!(run(&seven, 20).is_empty());
}

#[test]
fn only_stops_count_not_starts_restarts_or_status() {
    for verb in [
        "start",
        "restart",
        "reload",
        "status",
        "enable",
        "is-active",
        "disable",
    ] {
        let commands: Vec<String> = ["a", "b", "c", "d", "e", "f"]
            .iter()
            .map(|s| format!("systemctl {verb} {s}"))
            .collect();
        let commands: Vec<&str> = commands.iter().map(String::as_str).collect();
        assert!(run(&commands, 1).is_empty(), "{verb}");
    }
}

#[test]
fn disable_or_mask_with_now_stops_the_unit() {
    for verb in ["disable --now", "mask --now"] {
        let commands: Vec<String> = ["a", "b", "c", "d", "e"]
            .iter()
            .map(|s| format!("systemctl {verb} {s}"))
            .collect();
        let commands: Vec<&str> = commands.iter().map(String::as_str).collect();
        assert_eq!(run(&commands, 1).len(), 1, "{verb}");
    }
}

#[test]
fn the_sysv_forms_count() {
    let alerts = run(
        &[
            "service mysql stop",
            "service postgresql stop",
            "service apache2 stop",
            "service postfix stop",
            "service cron stop",
        ],
        1,
    );
    assert_eq!(alerts.len(), 1, "{alerts:?}");

    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for (i, name) in ["mysql", "postgresql", "apache2", "postfix", "cron"]
        .iter()
        .enumerate()
    {
        let mut event = exec_event_full(
            2100 + i as u32,
            SHELL,
            name,
            &format!("/etc/init.d/{name} stop"),
            i as u64 * SEC,
        );
        event.image_path = format!("/etc/init.d/{name}");
        alerts.extend(state.on_exec(&event));
    }
    let alerts: Vec<_> = alerts
        .into_iter()
        .filter(|a| a.technique == "T1489")
        .collect();
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    // A start script is not a stop.
    assert!(run(&["service mysql start"; 8], 1).is_empty());
}

#[test]
fn the_windows_forms_count() {
    let net = run(
        &[
            "net stop MSSQLSERVER",
            "net stop \"SQL Server Agent (MSSQLSERVER)\" /y",
            "net1 stop vss",
            "net stop wuauserv",
            "net stop Veeam",
        ],
        1,
    );
    assert_eq!(net.len(), 1, "{net:?}");
    assert!(
        net[0].message.contains("sql server agent (mssqlserver)"),
        "a display name with spaces is one service: {}",
        net[0].message
    );

    let sc = run(
        &[
            "sc.exe stop MSSQLSERVER",
            "sc stop vss",
            "sc \\\\fileserver stop Veeam",
            "sc stop wuauserv",
            "sc stop WinDefend",
        ],
        1,
    );
    assert_eq!(sc.len(), 1, "{sc:?}");

    let ps = run(
        &["powershell -Command Stop-Service MSSQLSERVER,vss,Veeam,wuauserv,WinDefend -Force"],
        1,
    );
    assert_eq!(ps.len(), 1, "{ps:?}");
    let named = run(
        &["pwsh -c Stop-Service -Name MSSQLSERVER,vss,Veeam,wuauserv,WinDefend"],
        1,
    );
    assert_eq!(named.len(), 1, "{named:?}");
}

#[test]
fn windows_commands_that_do_not_stop_a_service_do_not_count() {
    for verb in ["start", "query", "config", "qc", "queryex"] {
        let commands: Vec<String> = ["a", "b", "c", "d", "e", "f"]
            .iter()
            .map(|s| format!("sc {verb} {s}"))
            .collect();
        let commands: Vec<&str> = commands.iter().map(String::as_str).collect();
        assert!(run(&commands, 1).is_empty(), "sc {verb}");
    }
    assert!(
        run(
            &[
                "net start a",
                "net start b",
                "net user",
                "net view",
                "net share",
                "net use"
            ],
            1
        )
        .is_empty()
    );
    assert!(
        run(&["powershell -Command Get-Service a,b,c,d,e,f"], 1).is_empty(),
        "listing services is not stopping them"
    );
}

#[test]
fn a_piped_stop_service_names_no_service_and_counts_as_one() {
    // `Get-Service *sql* | Stop-Service -Force` stops an unknown number: one label, no alert
    // on its own, but it does not vanish from a burst either.
    assert!(
        run(
            &["powershell -Command Get-Service *sql* | Stop-Service -Force"],
            1
        )
        .is_empty()
    );
    let alerts = run(
        &[
            "powershell -Command Get-Service *sql* | Stop-Service -Force",
            "net stop vss",
            "net stop wuauserv",
            "net stop Veeam",
            "sc stop WinDefend",
        ],
        1,
    );
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert!(
        alerts[0].message.contains("Stop-Service (piped)"),
        "{}",
        alerts[0].message
    );
}

#[test]
fn the_macos_forms_count() {
    let alerts = run(
        &[
            "launchctl bootout system/com.vendor.backup",
            "launchctl unload -w /Library/LaunchDaemons/com.vendor.db.plist",
            "launchctl remove com.vendor.mail",
            "launchctl stop com.vendor.av",
            "launchctl bootout system/com.vendor.sync",
        ],
        1,
    );
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert!(
        alerts[0].message.contains("com.vendor.db"),
        "{}",
        alerts[0].message
    );
    // A load or a listing is not a stop.
    assert!(
        run(
            &[
                "launchctl load a.plist",
                "launchctl list",
                "launchctl bootstrap system b.plist",
                "launchctl print system/c",
                "launchctl kickstart system/d",
                "launchctl enable system/e",
            ],
            1,
        )
        .is_empty()
    );
}

#[test]
fn two_lineages_are_not_added_together() {
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for (i, c) in FIVE_UNITS.iter().enumerate() {
        // Alternate between two parents: three and two stops each.
        let parent = if i % 2 == 0 { SHELL } else { SHELL + 1 };
        alerts.extend(state.on_exec(&exec_event_full(
            2200 + i as u32,
            parent,
            "systemctl",
            c,
            i as u64 * SEC,
        )));
    }
    assert!(alerts.iter().all(|a| a.technique != "T1489"), "{alerts:?}");
}

#[test]
fn a_shell_started_per_command_is_one_lineage() {
    // `sh -c "systemctl stop x"` per service: every command has its own parent shell, and the
    // shells share one parent.
    let web = 80;
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for (i, c) in FIVE_UNITS.iter().enumerate() {
        let sh = 4000 + 2 * i as u32;
        state.on_exec(&exec_event_full(
            sh,
            web,
            "sh",
            &format!("sh -c {c}"),
            i as u64 * SEC,
        ));
        alerts.extend(state.on_exec(&exec_event_full(sh + 1, sh, "systemctl", c, i as u64 * SEC)));
    }
    assert!(alerts.iter().any(|a| a.technique == "T1489"), "{alerts:?}");
}

#[test]
fn a_second_burst_after_the_window_alerts_again() {
    let mut state = RuleState::new();
    let mut total = 0;
    for round in 0..2u64 {
        for (i, c) in FIVE_UNITS.iter().enumerate() {
            total += state
                .on_exec(&exec_event_full(
                    5000 + (round * 10) as u32 + i as u32,
                    SHELL,
                    "systemctl",
                    c,
                    (round * 300 + i as u64) * SEC,
                ))
                .iter()
                .filter(|a| a.technique == "T1489")
                .count();
        }
    }
    assert_eq!(total, 2);
}

#[test]
fn a_command_line_naming_thousands_of_services_is_bounded() {
    let line = format!(
        "systemctl stop {}",
        (0..5000)
            .map(|i| format!("svc{i}"))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let alerts = run(&[&line], 1);
    assert_eq!(alerts.len(), 1);
    assert!(
        alerts[0].message.contains("..."),
        "the list is cut: {}",
        alerts[0].message
    );
}

#[test]
fn state_stays_bounded_under_many_lineages() {
    let mut state = RuleState::new();
    for i in 0..(COUNTER_CAP as u32 + 500) {
        state.on_exec(&exec_event_full(
            100_000 + i,
            10_000 + i,
            "systemctl",
            "systemctl stop nginx",
            u64::from(i) * SEC,
        ));
    }
    // Still alerting for a fresh burst afterwards.
    let alerts: Vec<_> = FIVE_UNITS
        .iter()
        .enumerate()
        .flat_map(|(i, c)| {
            state.on_exec(&exec_event_full(
                900_000 + i as u32,
                SHELL,
                "systemctl",
                c,
                (1_000_000 + i as u64) * SEC,
            ))
        })
        .filter(|a| a.technique == "T1489")
        .collect();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn the_alert_is_not_a_ransomware_alert() {
    // The reflex and the damage manifest of #82 consume T1486 only; this one must not look
    // like it.
    let alerts = run(&FIVE_UNITS, 1);
    assert_eq!(alerts[0].technique, "T1489");
    assert_ne!(alerts[0].technique, "T1486");
}

#[test]
fn a_unit_with_and_without_the_service_suffix_is_one_service() {
    // Four units, one of them named twice: four distinct, so quiet. Counted by spelling it
    // would be five.
    assert!(
        run(
            &[
                "systemctl stop a",
                "systemctl stop a.service",
                "systemctl stop b",
                "systemctl stop c",
                "systemctl stop d",
            ],
            1,
        )
        .is_empty()
    );
}

#[test]
fn one_exec_contributes_at_most_the_cap_of_names() {
    let line = format!(
        "systemctl stop {}",
        (0..500)
            .map(|i| format!("svc{i}"))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let event = exec_event_full(2300, SHELL, "systemctl", &line, 0);
    assert_eq!(crate::servicestop::services_stopped(&event).len(), 32);
}

#[test]
fn an_sc_command_aimed_at_another_host_still_names_the_service() {
    let event = exec_event_full(2301, SHELL, "sc", "sc \\\\fileserver stop Veeam", 0);
    assert_eq!(crate::servicestop::services_stopped(&event), ["veeam"]);
}
