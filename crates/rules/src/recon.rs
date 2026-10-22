//! RECON-BURST (T1057/T1082/T1016/T1087, #378): the discovery commands an intruder runs
//! first, seen as a burst.
//!
//! One `ps` or one `whoami` is what every administrator, monitoring check and installer
//! runs. What separates hands-on-keyboard reconnaissance (or a script that does the same
//! job, `linpeas`-style) is the *set*: processes, system, network and accounts asked
//! about, one after the other, from one place, in a few seconds. So the rule counts
//! **distinct commands** (a loop that runs `ps` fifty times is one) and **distinct
//! categories** of discovery, from one *lineage*, inside a sliding window.
//!
//! A lineage is the parent process (pid plus its generation stamp where the sensor has
//! one). Commands run through a one-shot shell wrapper (`sh -c`, `cmd /c`,
//! `powershell -Command`) are attributed to the wrapper's own parent instead: a web shell
//! that runs `system("whoami")` then `system("id")` starts a new `sh -c` each time, and
//! would otherwise look like as many lineages as commands.
//!
//! **False positives, and the calibration** (no fleet data yet, so it is a choice, not a
//! measurement): an administrator typing five commands is below the threshold of six, and
//! three categories exclude a loop over one kind of query. What still fires is
//! configuration management and inventory collectors that gather facts the same way
//! (`ansible` `setup`, `sosreport`, `inxi`, some installers). That is the accepted cost,
//! and why the alert is Low: it names the burst, and the verdict decides what it adds to.
//! No process is excluded by name: a name is what an attacker changes first.

use schema::ExecEvent;

use crate::sliding::SlidingDistinct;

/// The techniques a discovery burst covers: process (T1057), system information
/// (T1082), network configuration (T1016) and account (T1087) discovery.
pub(crate) const RECON_BURST_TECHNIQUE: &str = "T1057/T1082/T1016/T1087";
/// Sliding window of the burst.
pub(crate) const RECON_BURST_WINDOW_NS: u64 = 30_000_000_000; // 30s
/// Distinct discovery commands, from one lineage, that make a burst.
pub(crate) const RECON_BURST_MIN_COMMANDS: u32 = 6;
/// Distinct categories those commands must span.
pub(crate) const RECON_BURST_MIN_CATEGORIES: u32 = 3;

/// What a discovery command asks about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Category {
    Process,
    System,
    Network,
    Account,
}

/// The process whose children are counted together: its pid and generation stamp.
pub(crate) type Lineage = (u32, Option<u64>);

/// The lineage of a process, as recorded when it was exec'd, with the generation stamp of
/// that incarnation of the pid.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ExecLineage {
    pub(crate) generation: Option<u64>,
    pub(crate) lineage: Lineage,
}

impl ExecLineage {
    /// The lineage recorded for the process `pid` of generation `generation`, unless the pid
    /// was recorded for another incarnation.
    pub(crate) fn current(recorded: Option<&Self>, generation: Option<u64>) -> Option<Lineage> {
        let recorded = recorded?;
        match (recorded.generation, generation) {
            (Some(was), Some(is)) if was != is => None,
            _ => Some(recorded.lineage),
        }
    }
}

/// A one-shot shell wrapper seen running, and the lineage its children belong to.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Wrapper {
    pub(crate) generation: Option<u64>,
    pub(crate) lineage: Lineage,
}

impl Wrapper {
    /// The lineage a child of `ppid` belongs to, when `ppid` is a recorded wrapper of the
    /// incarnation the child was forked from. A pid reused by something else carries
    /// another generation, and its children are not attributed to the old wrapper.
    pub(crate) fn lineage_for(
        wrapper: Option<&Self>,
        parent_generation: Option<u64>,
    ) -> Option<Lineage> {
        let wrapper = wrapper?;
        match (wrapper.generation, parent_generation) {
            (Some(recorded), Some(wanted)) if recorded != wanted => None,
            _ => Some(wrapper.lineage),
        }
    }
}

/// The discovery commands one lineage has run inside the window.
#[derive(Default)]
pub(crate) struct ReconWindow {
    commands: SlidingDistinct<&'static str>,
    categories: SlidingDistinct<Category>,
}

/// A burst that crossed the thresholds.
pub(crate) struct Burst {
    pub(crate) commands: Vec<&'static str>,
    pub(crate) categories: u32,
}

impl ReconWindow {
    /// Records one discovery command at `ts`. Returns the burst once the thresholds are
    /// crossed, at most once per window.
    pub(crate) fn record(
        &mut self,
        command: &'static str,
        category: Category,
        ts: u64,
    ) -> Option<Burst> {
        let commands = self.commands.record(command, ts, RECON_BURST_WINDOW_NS);
        let categories = self.categories.record(category, ts, RECON_BURST_WINDOW_NS);
        if commands >= RECON_BURST_MIN_COMMANDS
            && categories >= RECON_BURST_MIN_CATEGORIES
            && self.commands.try_alert(ts, RECON_BURST_WINDOW_NS)
        {
            return Some(Burst {
                commands: self.commands.values().copied().collect(),
                categories,
            });
        }
        None
    }
}

/// The program's lowercase basename without `.exe`: `C:\Windows\System32\NET.exe` → `net`.
/// Falls back to `comm` when the sensor reports no image path.
fn program(event: &ExecEvent) -> String {
    let path = if event.image_path.is_empty() {
        event.meta.comm.as_str()
    } else {
        event.image_path.as_str()
    };
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let lower = base.to_ascii_lowercase();
    lower
        .strip_suffix(".exe")
        .map_or(lower.clone(), str::to_owned)
}

/// The arguments after the program, lowercase: `argv[1..]` where the platform gives one,
/// the whitespace-split command line otherwise (Windows). Quotes are dropped.
fn args(event: &ExecEvent) -> Vec<String> {
    let lower = |s: &str| s.trim_matches('"').to_ascii_lowercase();
    if event.argv.is_empty() {
        event
            .cmdline
            .split_whitespace()
            .skip(1)
            .map(lower)
            .collect()
    } else {
        event.argv.iter().skip(1).map(|a| lower(a)).collect()
    }
}

/// Whether the program was started to run one command line and exit: `sh -c`, `cmd /c`,
/// `powershell -Command`.
pub(crate) fn is_one_shot_wrapper(event: &ExecEvent) -> bool {
    let args = args(event);
    match program(event).as_str() {
        "sh" | "bash" | "dash" | "zsh" | "ash" | "ksh" => args
            .iter()
            .any(|a| a.starts_with('-') && !a.starts_with("--") && a[1..].contains('c')),
        "cmd" => args.iter().any(|a| a == "/c" || a == "/k"),
        "powershell" | "pwsh" => args.iter().any(|a| a == "-c" || a == "-command"),
        _ => false,
    }
}

/// The discovery command this exec is, with its category; `None` for anything else.
/// Commands that also do other things (`ip`, `net`, `dscl`, `wmic`, `getent`, `cat`) count
/// only with the arguments that ask a question.
pub(crate) fn discovery(event: &ExecEvent) -> Option<(&'static str, Category)> {
    let program = program(event);
    let args = args(event);
    let first = args.first().map(String::as_str);
    let found = match program.as_str() {
        "ps" => ("ps", Category::Process),
        "pgrep" => ("pgrep", Category::Process),
        "pstree" => ("pstree", Category::Process),
        "tasklist" => ("tasklist", Category::Process),
        "whoami" => ("whoami", Category::Account),
        "id" => ("id", Category::Account),
        "who" => ("who", Category::Account),
        "w" => ("w", Category::Account),
        "last" => ("last", Category::Account),
        "lastlog" => ("lastlog", Category::Account),
        "quser" => ("quser", Category::Account),
        "qwinsta" => ("qwinsta", Category::Account),
        "uname" => ("uname", Category::System),
        "hostname" => ("hostname", Category::System),
        "hostnamectl" => ("hostnamectl", Category::System),
        "systeminfo" => ("systeminfo", Category::System),
        "uptime" => ("uptime", Category::System),
        "lscpu" => ("lscpu", Category::System),
        "lsb_release" => ("lsb_release", Category::System),
        "sw_vers" => ("sw_vers", Category::System),
        "system_profiler" => ("system_profiler", Category::System),
        "ifconfig" => ("ifconfig", Category::Network),
        "ipconfig" => ("ipconfig", Category::Network),
        "netstat" => ("netstat", Category::Network),
        "ss" => ("ss", Category::Network),
        "arp" => ("arp", Category::Network),
        "nbtstat" => ("nbtstat", Category::Network),
        "route" => ("route", Category::Network),
        "ip" => match first? {
            "a" | "addr" | "address" | "r" | "route" | "l" | "link" | "n" | "neigh"
            | "neighbour" => ("ip", Category::Network),
            _ => return None,
        },
        "net" | "net1" => match first? {
            "user" | "users" => ("net user", Category::Account),
            "group" => ("net group", Category::Account),
            "localgroup" => ("net localgroup", Category::Account),
            "accounts" => ("net accounts", Category::Account),
            "view" => ("net view", Category::Network),
            "share" => ("net share", Category::Network),
            "session" => ("net session", Category::Network),
            "config" => ("net config", Category::System),
            _ => return None,
        },
        "dscl" => {
            let asks = args
                .iter()
                .any(|a| matches!(a.as_str(), "-list" | "list" | "-read" | "read"));
            let about_accounts = args.iter().any(|a| {
                matches!(a.as_str(), "/users" | "/groups" | "users" | "groups")
                    || a.starts_with("/users/")
                    || a.starts_with("/groups/")
            });
            if asks && about_accounts {
                ("dscl", Category::Account)
            } else {
                return None;
            }
        }
        "getent" => match first? {
            "passwd" | "group" => ("getent", Category::Account),
            _ => return None,
        },
        "wmic" => match first? {
            "useraccount" | "group" => ("wmic accounts", Category::Account),
            "os" | "cpu" | "computersystem" | "bios" => ("wmic system", Category::System),
            "process" => ("wmic process", Category::Process),
            "nic" | "nicconfig" => ("wmic network", Category::Network),
            _ => return None,
        },
        "nltest" => {
            if args
                .iter()
                .any(|a| a.starts_with("/dclist") || a.starts_with("/domain_trusts"))
            {
                ("nltest", Category::Account)
            } else {
                return None;
            }
        }
        "cat" | "less" | "more" | "head" | "tail" => {
            if args.iter().any(|a| a == "/etc/passwd" || a == "/etc/group") {
                ("read /etc/passwd", Category::Account)
            } else {
                return None;
            }
        }
        _ => return None,
    };
    Some(found)
}

/// T1021.004 (#378): outbound SSH connections to this many distinct hosts from one lineage
/// inside [`SSH_FANOUT_WINDOW_NS`].
pub(crate) const SSH_FANOUT_THRESHOLD: u32 = 8;
/// Sliding window of [`SSH_FANOUT_THRESHOLD`].
pub(crate) const SSH_FANOUT_WINDOW_NS: u64 = 60_000_000_000; // 60s
/// The SSH port.
pub(crate) const SSH_PORT: u16 = 22;

/// T1518.001 (#378): distinct security-software discovery commands from one lineage inside
/// [`SECURITY_DISCOVERY_WINDOW_NS`].
pub(crate) const SECURITY_DISCOVERY_THRESHOLD: u32 = 3;
/// Sliding window of [`SECURITY_DISCOVERY_THRESHOLD`].
pub(crate) const SECURITY_DISCOVERY_WINDOW_NS: u64 = 60_000_000_000; // 60s

/// Programs that look a product up by name: process lists, service managers, package
/// queries, file search, the registry.
const LOOKUP_PROGRAMS: &[&str] = &[
    "ps",
    "pgrep",
    "tasklist",
    "grep",
    "egrep",
    "fgrep",
    "findstr",
    "systemctl",
    "service",
    "launchctl",
    "ls",
    "find",
    "where",
    "which",
    "rpm",
    "dpkg",
    "pkgutil",
    "reg",
    "sc",
    "wmic",
    "get-process",
    "get-service",
];

/// Names that identify a security product in a process, service, package or path, each
/// with the label the alert shows. Lowercase substrings.
const SECURITY_PRODUCTS: &[(&str, &str)] = &[
    ("falcon-sensor", "lookup: crowdstrike"),
    ("falcond", "lookup: crowdstrike"),
    ("crowdstrike", "lookup: crowdstrike"),
    ("csagent", "lookup: crowdstrike"),
    ("sentinelone", "lookup: sentinelone"),
    ("sentinelagent", "lookup: sentinelone"),
    ("sentinelctl", "lookup: sentinelone"),
    ("carbonblack", "lookup: carbon black"),
    ("cbagentd", "lookup: carbon black"),
    ("cbdefense", "lookup: carbon black"),
    ("cylance", "lookup: cylance"),
    ("sophos", "lookup: sophos"),
    ("symantec", "lookup: symantec"),
    ("sepagent", "lookup: symantec"),
    ("mcafee", "lookup: mcafee/trellix"),
    ("trellix", "lookup: mcafee/trellix"),
    ("mfetp", "lookup: mcafee/trellix"),
    ("windefend", "lookup: defender"),
    ("wdnissvc", "lookup: defender"),
    ("mssense", "lookup: defender"),
    ("mdatp", "lookup: defender"),
    ("ossec", "lookup: wazuh/ossec"),
    ("wazuh", "lookup: wazuh/ossec"),
    ("clamd", "lookup: clamav"),
    ("clamav", "lookup: clamav"),
    ("freshclam", "lookup: clamav"),
    ("osqueryd", "lookup: osquery"),
    ("auditd", "lookup: auditd"),
    ("elastic-agent", "lookup: elastic"),
    ("elastic-endpoint", "lookup: elastic"),
    ("synthaea", "lookup: synthaea"),
];

/// The security-software discovery command this exec is, as the label that counts toward
/// the set; `None` for anything else. Two kinds: commands that ask about the host's
/// security posture (`SELinux`, `AppArmor`, audit rules, SIP, Defender, the firewall, loaded
/// filter drivers), and a lookup of a named security product through a program that looks
/// things up (`ps | grep falcon`, `systemctl status sentinelone`, `sc query windefend`).
/// One lookup per product: two commands about the same product are one label.
pub(crate) fn security_discovery(event: &ExecEvent) -> Option<&'static str> {
    let program = program(event);
    let args = args(event);
    let joined = args.join(" ");
    let first = args.first().map(String::as_str);
    let has = |flag: &str| args.iter().any(|a| a == flag);
    let posture = match program.as_str() {
        "getenforce" => Some("getenforce"),
        "sestatus" => Some("sestatus"),
        "aa-status" | "apparmor_status" => Some("aa-status"),
        "auditctl" if has("-l") || has("-s") => Some("auditctl"),
        "csrutil" if first == Some("status") => Some("csrutil"),
        "spctl" if has("--status") => Some("spctl"),
        "systemextensionsctl" if first == Some("list") => Some("systemextensionsctl"),
        "mdatp" if first == Some("health") => Some("mdatp health"),
        "fltmc" => Some("fltmc"),
        "driverquery" => Some("driverquery"),
        "netsh" if joined.contains("advfirewall show") || joined.contains("firewall show") => {
            Some("netsh firewall")
        }
        "wmic" if joined.contains("securitycenter2") => Some("wmic SecurityCenter2"),
        "powershell" | "pwsh" => {
            let line = event.cmdline.to_ascii_lowercase();
            if line.contains("get-mpcomputerstatus")
                || line.contains("get-mppreference")
                || line.contains("get-mpthreat")
            {
                Some("Get-Mp*")
            } else if line.contains("securitycenter2") {
                Some("SecurityCenter2 query")
            } else {
                None
            }
        }
        _ => None,
    };
    if posture.is_some() {
        return posture;
    }
    if !LOOKUP_PROGRAMS.contains(&program.as_str()) {
        return None;
    }
    let line = joined;
    SECURITY_PRODUCTS
        .iter()
        .find(|(name, _)| line.contains(name))
        .map(|(_, label)| *label)
}
