//! RECON-BURST (T1057/T1082/T1016/T1087, #378): distinct discovery commands from one
//! lineage inside a window. The cases that matter are the ones that must stay quiet: an
//! administrator at a shell, a monitoring loop, commands spread over minutes.

use super::*;
use crate::{Alert, Severity};

const SEC: u64 = 1_000_000_000;
/// The parent every test command is a child of.
const SHELL: u32 = 500;

/// One discovery command run by `ppid` at second `at`, in its own process.
fn run(pid: u32, ppid: u32, command: &str, at: u64) -> ExecEvent {
    let comm = command.split_whitespace().next().unwrap();
    exec_event_full(pid, ppid, comm, command, at * SEC)
}

/// The alerts of feeding `commands` (one per second) from `SHELL` through a fresh state.
fn feed(commands: &[&str]) -> Vec<Alert> {
    let mut state = RuleState::new();
    commands
        .iter()
        .enumerate()
        .flat_map(|(i, c)| state.on_exec(&run(1000 + i as u32, SHELL, c, i as u64)))
        .filter(|a| a.technique == "T1057/T1082/T1016/T1087")
        .collect()
}

#[test]
fn six_distinct_commands_across_the_categories_alert_once_and_name_them() {
    let alerts = feed(&[
        "whoami",
        "id",
        "uname -a",
        "ip addr",
        "ps aux",
        "hostname",
        "netstat -an",
    ]);
    assert_eq!(alerts.len(), 1, "one alert per window: {alerts:?}");
    let alert = &alerts[0];
    assert_eq!(alert.severity, Severity::Low);
    for name in ["whoami", "id", "uname", "ip", "ps", "hostname"] {
        assert!(alert.message.contains(name), "{}", alert.message);
    }
    assert!(alert.message.contains("4 categories"), "{}", alert.message);
}

#[test]
fn an_administrator_running_five_commands_does_not_alert() {
    // The case to tune: a human at a shell asks a handful of questions.
    assert!(feed(&["ps aux", "whoami", "ip addr", "uptime", "hostname"]).is_empty());
}

#[test]
fn a_loop_over_one_command_is_one_command() {
    let commands = vec!["ps aux"; 60];
    assert!(feed(&commands).is_empty());
}

#[test]
fn many_commands_of_one_or_two_categories_do_not_alert() {
    // Six distinct commands, but processes and accounts only: two categories.
    assert!(feed(&["ps", "pgrep java", "pstree", "tasklist", "whoami", "id"]).is_empty());
}

#[test]
fn commands_spread_over_minutes_do_not_alert() {
    let mut state = RuleState::new();
    let commands = [
        "whoami",
        "id",
        "uname -a",
        "ip addr",
        "ps aux",
        "hostname",
        "netstat -an",
    ];
    for (i, c) in commands.iter().enumerate() {
        let alerts = state.on_exec(&run(2000 + i as u32, SHELL, c, i as u64 * 20));
        assert!(
            alerts
                .iter()
                .all(|a| a.technique != "T1057/T1082/T1016/T1087"),
            "{c}: {alerts:?}"
        );
    }
}

#[test]
fn commands_of_different_parents_are_not_added_together() {
    let mut state = RuleState::new();
    let commands = [
        "whoami",
        "id",
        "uname -a",
        "ip addr",
        "ps aux",
        "hostname",
        "netstat -an",
    ];
    for (i, c) in commands.iter().enumerate() {
        // Each command has its own parent.
        let alerts = state.on_exec(&run(3000 + i as u32, 600 + i as u32, c, i as u64));
        assert!(alerts.is_empty(), "{c}: {alerts:?}");
    }
}

#[test]
fn only_the_questions_a_multi_purpose_tool_can_ask_count() {
    // `ip link set`, `net use`, `dscl . create`, `getent hosts` and `cat` of an ordinary
    // file are not discovery.
    assert!(
        feed(&[
            "ip netns list",
            "net use Z: \\\\fs\\share",
            "dscl . create /Users/x",
            "getent hosts example.org",
            "cat /etc/hostname",
            "wmic service list",
            "whoami",
            "ps",
        ])
        .is_empty()
    );
    // The same tools with the arguments that ask do count.
    assert_eq!(
        feed(&[
            "net user",
            "net group",
            "net localgroup",
            "net view",
            "dscl . list /Users",
            "wmic os get caption",
        ])
        .len(),
        1
    );
}

#[test]
fn a_web_shell_that_starts_a_new_shell_per_command_is_one_lineage() {
    // `system("whoami")`, `system("id")`, ... : each runs `sh -c <cmd>`, so every command
    // has its own parent shell, and the shells share the web server as their parent.
    let web = 80;
    let commands = ["whoami", "id", "uname -a", "ip addr", "ps aux", "hostname"];
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for (i, c) in commands.iter().enumerate() {
        let sh = 4000 + 2 * i as u32;
        state.on_exec(&run(sh, web, &format!("sh -c {c}"), i as u64));
        alerts.extend(state.on_exec(&run(sh + 1, sh, c, i as u64)));
    }
    assert!(
        alerts
            .iter()
            .any(|a| a.technique == "T1057/T1082/T1016/T1087"),
        "{alerts:?}"
    );
}

#[test]
fn a_pid_reused_by_another_process_does_not_inherit_a_wrapper_lineage() {
    // pid 7000 was a `sh -c` wrapper under the web server (pid 80, generation 1); the pid is
    // reused by an unrelated process (generation 2) that runs three discovery commands.
    // The web server itself ran three others. Added together they would be a burst; they
    // are two lineages of three commands each, and quiet.
    let mut state = RuleState::new();
    let mut wrapper = run(7000, 80, "sh -c true", 0);
    wrapper.meta.process_generation = Some(1);
    state.on_exec(&wrapper);
    let mut alerts = Vec::new();
    for (i, c) in ["whoami", "uname -a", "ps aux"].iter().enumerate() {
        alerts.extend(state.on_exec(&run(7100 + i as u32, 80, c, 1 + i as u64)));
    }
    for (i, c) in ["id", "ip addr", "hostname"].iter().enumerate() {
        let mut event = run(7200 + i as u32, 7000, c, 5 + i as u64);
        event.meta.parent_process_generation = Some(2);
        alerts.extend(state.on_exec(&event));
    }
    assert!(alerts.is_empty(), "{alerts:?}");

    // The same three, from the wrapper's own incarnation, do join the web server's lineage.
    let mut state = RuleState::new();
    state.on_exec(&wrapper);
    let mut alerts = Vec::new();
    for (i, c) in ["whoami", "uname -a", "ps aux"].iter().enumerate() {
        alerts.extend(state.on_exec(&run(7100 + i as u32, 80, c, 1 + i as u64)));
    }
    for (i, c) in ["id", "ip addr", "hostname"].iter().enumerate() {
        let mut event = run(7200 + i as u32, 7000, c, 5 + i as u64);
        event.meta.parent_process_generation = Some(1);
        alerts.extend(state.on_exec(&event));
    }
    assert_eq!(alerts.len(), 1, "{alerts:?}");
}

#[test]
fn a_second_burst_after_the_window_alerts_again() {
    let mut state = RuleState::new();
    let commands = ["whoami", "id", "uname -a", "ip addr", "ps aux", "hostname"];
    let mut total = 0;
    for round in 0..2u64 {
        for (i, c) in commands.iter().enumerate() {
            let at = round * 120 + i as u64;
            total += state
                .on_exec(&run(5000 + (round * 10) as u32 + i as u32, SHELL, c, at))
                .iter()
                .filter(|a| a.technique == "T1057/T1082/T1016/T1087")
                .count();
        }
    }
    assert_eq!(total, 2);
}

#[test]
fn the_windows_forms_count_too() {
    let alerts = feed(&[
        "whoami /all",
        "net user",
        "net localgroup administrators",
        "systeminfo",
        "ipconfig /all",
        "tasklist /v",
    ]);
    assert_eq!(alerts.len(), 1, "{alerts:?}");
}

#[test]
fn the_state_stays_bounded_under_many_lineages() {
    // One discovery command from each of far more parents than the map holds: memory is
    // capped, and nothing alerts.
    let mut state = RuleState::new();
    for i in 0..(crate::state::COUNTER_CAP as u32 + 1_000) {
        let alerts = state.on_exec(&run(10_000 + i, 100_000 + i, "whoami", u64::from(i % 5)));
        assert!(alerts.is_empty());
    }
}
