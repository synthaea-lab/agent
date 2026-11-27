//! Names the sensors and the rules must agree on to protect the agent and its neighbours.

/// The bpffs directory holding the Linux agent's pinned maps (#362): the sensor pins
/// `SIGNAL_TAMPER_LAST` there so a `SIGKILL` stays attributable across the restart, and the
/// rules treat removing anything in it as tampering (AGENT-PIN-REMOVED, #356). One constant
/// for both, so the rule cannot drift from where the sensor pins.
pub const AGENT_BPF_PIN_DIR: &str = "/sys/fs/bpf/synthaea";

/// The name of the agent's `SIGNAL_TAMPER_LAST` pin in [`AGENT_BPF_PIN_DIR`], before its wire
/// version. The rule reads a relative removal (`cd /sys/fs/bpf/synthaea && rm signal_tamper_*`)
/// by this name, since such an event carries no directory.
pub const AGENT_TAMPER_PIN_NAME_PREFIX: &str = "signal_tamper_last_v";

/// Services of security tooling, lowercase, compared without a `.service` suffix. Product
/// names are as the vendors' documentation gives them and were **not checked on a host**: a
/// name that is wrong costs a missed stop, never a false alert. `auditd` is here although
/// two Sigma rules name two forms of its stop: those match `mask --now` and `auditctl -e 0`,
/// this matches the rest, and `mask --now auditd` raises both.
///
/// Left out on purpose: the Windows `EventLog` service (T1562.002, #800), the firewall
/// services (T1562.004) and this agent's own service (stopped by its own package scripts on
/// every upgrade, and unable to alert on its own stop).
pub const SECURITY_SERVICES: &[&str] = &[
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
