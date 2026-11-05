//! SECURITY-TOOL-STOP (T1562.001, #379): a command that stops a named security tool.

use super::*;
use crate::Severity;

/// The T1562.001 alerts one command raises through the stateless dispatcher.
fn stops(command: &str) -> Vec<crate::Alert> {
    let comm = command.split_whitespace().next().unwrap();
    crate::evaluate_exec(&exec_event_full(2000, 600, comm, command, 0))
        .into_iter()
        .filter(|a| a.technique == "T1562.001")
        .collect()
}

#[test]
fn stopping_a_listed_security_tool_alerts_once_and_names_it() {
    for (command, tool) in [
        ("systemctl stop falco", "falco"),
        ("systemctl stop auditd", "auditd"),
        ("systemctl stop falcon-sensor.service", "falcon-sensor"),
        ("systemctl disable --now osqueryd", "osqueryd"),
        ("systemctl mask --now wazuh-agent", "wazuh-agent"),
        ("service clamav-daemon stop", "clamav-daemon"),
        ("sc stop Sysmon64", "sysmon64"),
        ("sc stop WinDefend", "windefend"),
        ("net stop sense", "sense"),
        (
            "powershell Stop-Service -Name CSFalconService -Force",
            "csfalconservice",
        ),
        (
            "launchctl bootout system/com.crowdstrike.falcond",
            "com.crowdstrike.falcond",
        ),
        (
            "launchctl unload -w /Library/LaunchDaemons/com.microsoft.wdav.plist",
            "com.microsoft.wdav",
        ),
    ] {
        let alerts = stops(command);
        assert_eq!(alerts.len(), 1, "{command}: {alerts:?}");
        assert_eq!(alerts[0].severity, Severity::Medium, "{command}");
        assert!(
            alerts[0].message.contains(tool),
            "{command}: {}",
            alerts[0].message
        );
    }
}

#[test]
fn stopping_other_services_does_not_alert() {
    for command in [
        "systemctl stop nginx",
        "systemctl stop postgresql",
        "service apache2 stop",
        "sc stop Spooler",
        "net stop wuauserv",
        "launchctl bootout system/com.apple.dock",
        "systemctl stop auditd-helper",
    ] {
        assert!(stops(command).is_empty(), "{command}");
    }
}

#[test]
fn a_command_that_does_not_stop_anything_does_not_alert() {
    for command in [
        "systemctl status falco",
        "systemctl start auditd",
        "systemctl restart falco",
        "systemctl enable --now osqueryd",
        "systemctl disable falco",
        "sc query WinDefend",
        "sc start Sysmon64",
        "launchctl list com.crowdstrike.falcond",
        "service auditd status",
    ] {
        assert!(stops(command).is_empty(), "{command}");
    }
}

#[test]
fn a_command_stopping_several_security_tools_is_one_alert() {
    let alerts = stops("systemctl stop falco osqueryd auditd");
    assert_eq!(alerts.len(), 1, "{alerts:?}");
}

#[test]
fn a_security_tool_among_other_services_is_still_found() {
    let alerts = stops("systemctl stop nginx falco postfix");
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert!(alerts[0].message.contains("falco"), "{}", alerts[0].message);
}

#[test]
fn the_names_are_compared_without_regard_to_case() {
    assert_eq!(stops("sc stop SYSMON64").len(), 1);
    assert_eq!(stops("net stop WinDefend").len(), 1);
}

#[test]
fn the_event_log_service_is_left_to_its_own_rule() {
    // T1562.002 (#800) owns the EventLog service; this rule must not double it.
    assert!(stops("sc stop eventlog").is_empty());
    assert!(stops("net stop eventlog").is_empty());
}

#[test]
fn the_agents_own_service_is_not_a_security_tool_here() {
    assert!(stops("systemctl stop synthaea-agent").is_empty());
    assert!(stops("launchctl bootout system/dev.synthaea.agent").is_empty());
}

#[test]
fn the_burst_rule_and_this_one_are_independent() {
    // Five services, one of them a security tool: the burst alert (T1489) and this one both
    // fire, on different exec events' worth of state, without one hiding the other.
    let mut state = RuleState::new();
    let mut techniques = Vec::new();
    for (i, unit) in ["mysqld", "postgresql", "veeam", "postfix", "falco"]
        .iter()
        .enumerate()
    {
        let command = format!("systemctl stop {unit}");
        let event = exec_event_full(
            3000 + i as u32,
            600,
            "systemctl",
            &command,
            i as u64 * 1_000_000_000,
        );
        techniques.extend(crate::evaluate_exec(&event).iter().map(|a| a.technique));
        techniques.extend(state.on_exec(&event).iter().map(|a| a.technique));
    }
    assert!(techniques.contains(&"T1562.001"), "{techniques:?}");
    assert!(techniques.contains(&"T1489"), "{techniques:?}");
}

#[test]
fn an_open_carrying_the_old_unit_stopped_bit_raises_no_unit_stop_finding() {
    // #1085: the unit stop used to travel as `FLAG_UNIT_STOPPED` (0x8000_0000) on a
    // `FileOpenEvent`. A raw `openat` flag can carry any bit, so an unprivileged open could set
    // it. The stop is now `Event::UnitStop`, and no open raises a T1562.001 finding, with the
    // bit alone or on top of real `O_*` flags (`O_RDWR | O_CREAT | O_TMPFILE`).
    const OLD_UNIT_STOPPED: u32 = 0x8000_0000;
    const O_RDWR: u32 = 0x2;
    const O_CREAT: u32 = 0x40;
    const O_TMPFILE: u32 = 0x0041_0000;
    let mut state = crate::RuleState::new();
    for flags in [
        OLD_UNIT_STOPPED,
        OLD_UNIT_STOPPED | O_RDWR | O_CREAT | O_TMPFILE,
    ] {
        for path in ["auditd.service", "/tmp", "falco"] {
            let event = file_open_event_full(4242, path, path, flags, 1_000);
            let stateless = crate::evaluate_file_open(&event);
            let stateful = state.on_file_open(&event);
            assert!(
                stateless
                    .iter()
                    .chain(stateful.iter())
                    .all(|a| a.technique != "T1562.001"),
                "open {path} flags {flags:#x} raised a T1562.001 finding",
            );
        }
    }
}
