//! SECURITY-TOOL-STOP (T1562.001, #379): a command that stops, or stops and disables, a named
//! security tool.
//!
//! The parser is [`crate::servicestop::services_stopped`] (SERVICE-STOP-BURST, T1489): what an
//! exec stops, from `systemctl`, `service`, `net`, `sc`, `launchctl` and `Stop-Service`. The
//! burst rule counts how many services; this one asks **which**: a single `systemctl stop
//! falco` is what an intruder does to blind the host before acting, and it is below the
//! burst's threshold by design.

use schema::{ExecEvent, detection::Severity};

use crate::{Alert, servicestop::services_stopped};

/// Services of security tooling, lowercase, compared without a `.service` suffix. Product
/// names are as the vendors' documentation gives them and were **not checked on a host**: a
/// name that is wrong costs a missed stop, never a false alert. `auditd` is here although
/// two Sigma rules name two forms of its stop: those match `mask --now` and `auditctl -e 0`,
/// this matches the rest, and `mask --now auditd` raises both.
///
/// Left out on purpose: the Windows `EventLog` service (T1562.002, #800), the firewall
/// services (T1562.004) and this agent's own service (stopped by its own package scripts on
/// every upgrade, and unable to alert on its own stop).
const SECURITY_SERVICES: &[&str] = &[
    // Linux
    "auditd",
    "apparmor",
    "falco",
    "falco-bpf",
    "falco-modern-bpf",
    "osqueryd",
    "wazuh-agent",
    "ossec",
    "clamav-daemon",
    "clamd",
    "suricata",
    "snort",
    "sysmon",
    "mdatp",
    "falcon-sensor",
    "sentinelone",
    // Windows
    "windefend",
    "wdnissvc",
    "sense",
    "sysmon64",
    "securityhealthservice",
    "csfalconservice",
    "sentinelagent",
    "cbdefense",
];

/// launchd label prefixes of macOS security tooling: a vendor's namespace, so any daemon
/// stopped under it is that vendor's tool. Same caveat on the names as above.
const SECURITY_LABEL_PREFIXES: &[&str] = &[
    "com.crowdstrike.",
    "com.sentinelone.",
    "com.microsoft.wdav",
    "com.carbonblack.",
    "com.apple.xprotect",
];

/// Whether `service` (lowercase, as [`services_stopped`] gives it) names security tooling.
fn is_security_tool(service: &str) -> bool {
    let name = service.strip_suffix(".service").unwrap_or(service);
    SECURITY_SERVICES.contains(&name)
        || SECURITY_LABEL_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

/// T1562.001 — Impair Defenses: Disable or Modify Tools. An exec that stops (or
/// `disable --now` / `mask --now`) a service of [`SECURITY_SERVICES`] or a launchd label
/// under [`SECURITY_LABEL_PREFIXES`]. One alert per exec, naming the first such service; a
/// command that stops several security tools is one finding, and the burst rule counts them.
///
/// Medium: an administrator stopping `auditd` or `clamav-daemon` to debug or upgrade, a
/// package script, and configuration management look the same. It reads the **command**: a
/// stop that is refused (a Defender service cannot be stopped from `sc` on a current
/// Windows), a tool killed with `kill`, `pkill` or `taskkill`, or stopped over D-Bus or an
/// API, is not seen here, and the stop's success is not observed. A `SIGKILL` of the agent
/// itself is `check_security_process_signal`'s.
#[must_use]
pub(crate) fn check_security_tool_stop(event: &ExecEvent) -> Option<Alert> {
    let tool = services_stopped(event)
        .into_iter()
        .find(|service| is_security_tool(service))?;
    Some(Alert {
        technique: "T1562.001",
        severity: Severity::Medium,
        message: format!(
            "pid={} comm={}: stopped the security tool {tool} ({})",
            event.meta.pid,
            event.meta.comm,
            crate::recon::program(event),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::is_security_tool;

    #[test]
    fn a_listed_service_matches_with_or_without_the_unit_suffix() {
        assert!(is_security_tool("auditd"));
        assert!(is_security_tool("falco.service"));
        assert!(is_security_tool("windefend"));
    }

    #[test]
    fn launchd_labels_match_by_vendor_prefix() {
        assert!(is_security_tool("com.crowdstrike.falcond"));
        assert!(is_security_tool("com.microsoft.wdav.daemon"));
        assert!(is_security_tool("com.apple.xprotect.daemon.scan"));
    }

    #[test]
    fn near_misses_and_ordinary_services_do_not_match() {
        for name in [
            "nginx",
            "auditd-helper",
            "myfalco",
            "sensex",
            "com.crowdstrike",
            "com.example.crowdstrike.x",
            "org.com.crowdstrike.falcond",
            "com.apple.dock",
            "eventlog",
            "",
        ] {
            assert!(!is_security_tool(name), "{name}");
        }
    }
}
