//! SECURITY-TOOL-STOP (T1562.001, #379): a command that stops, or stops and disables, a named
//! security tool.
//!
//! The parser is [`crate::servicestop::services_stopped`] (SERVICE-STOP-BURST, T1489): what an
//! exec stops, from `systemctl` (`stop`, `disable --now`, `mask --now` and `kill` with a signal
//! that ends the unit), `service`, `net`, `sc`, `launchctl` and `Stop-Service`. The
//! burst rule counts how many services; this one asks **which**: a single `systemctl stop
//! falco` is what an intruder does to blind the host before acting, and it is below the
//! burst's threshold by design.
//!
//! What no command line shows is [`crate::unitstop`]'s (#1085): a stop over D-Bus or an API, or a
//! service that was killed, reaches the journal as a unit stop, and that rule alerts on the ones
//! no exec, restart or host shutdown explains. A stop this rule alerted on is among the ones it
//! treats as explained, so one `systemctl stop falco` is one finding.

use schema::{ExecEvent, FileOpenEvent, SECURITY_SERVICES, detection::Severity, has_write_intent};

use crate::{
    Alert,
    recon::{args, args_cased, program},
    servicestop::services_stopped,
};

/// launchd label prefixes of macOS security tooling: a vendor's namespace, so any daemon
/// stopped under it is that vendor's tool. Same caveat on the names as [`SECURITY_SERVICES`]
/// (in `schema`, so the journal sensor filters on the same list).
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
/// Windows), a tool killed with `kill`, `pkill` or `taskkill` (`systemctl kill` is read, since the
/// manager's signal from pid 1 is only Low in `check_security_process_signal`), or stopped over
/// D-Bus or an API, is not seen here, and the stop's success is not observed. A Linux unit
/// stopped over D-Bus or an API is not seen here either, but [`crate::unitstop`] sees it in the
/// journal, which names no actor. A signal to a tool, the agent's or (Linux, #1103) a listed
/// tool's, is `check_security_process_signal`'s.
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

/// `systemctl set-property` keys that make the kernel end or starve a unit's cgroup: the
/// memcg OOM kill (`MemoryMax`), reclaim pressure (`MemoryHigh`) and a fork limit (`TasksMax`).
/// Lowercase, as [`args`] gives them. `CPUQuota` is judged on its value, by [`cpu_quota_starves`].
const LIMIT_PROPERTIES: &[&str] = &["memorymax", "memoryhigh", "tasksmax"];

/// A `CPUQuota=` below this many percent of one CPU starves a daemon (a 1% quota leaves an
/// `osqueryd` or `auditd` no time to run) rather than tuning it. An administrator who caps a
/// tool sets 20% to 50% or more; the threshold is a judgement, not a measured one (agent#49),
/// and a quota just above it starves the tool as well.
const CPU_QUOTA_STARVE_BELOW_PERCENT: f64 = 10.0;

/// Whether the value of `CPUQuota=` is below [`CPU_QUOTA_STARVE_BELOW_PERCENT`] percent of one
/// CPU. systemd reads the value as a per-myriad number, so `%`, `‰` (per mille, a tenth of a
/// percent) and `‱` (per ten thousand, a hundredth) all set the same quota: `5%`, `50‰` and
/// `500‱` are one 5% quota. An empty value lifts the quota, and a value with none of these
/// suffixes is not one systemd accepts: neither alerts. `0%` is read by systemd as an invalid
/// quota too, but a zero is still a starving one.
fn cpu_quota_starves(value: &str) -> bool {
    let (number, divisor) = if let Some(number) = value.strip_suffix('%') {
        (number, 1.0)
    } else if let Some(number) = value.strip_suffix('\u{2030}') {
        (number, 10.0)
    } else if let Some(number) = value.strip_suffix('\u{2031}') {
        (number, 100.0)
    } else {
        return false;
    };
    number
        .parse::<f64>()
        .ok()
        .is_some_and(|quota| quota / divisor < CPU_QUOTA_STARVE_BELOW_PERCENT)
}

/// What a `systemctl` exec does to the cgroups of units besides stopping them, and the units:
/// `freeze` (the cgroup freezer, the effect of a `SIGSTOP` without the signal; it takes several
/// units, `systemctl freeze nginx auditd`, so every positional one is returned) or
/// `set-property` of one of [`LIMIT_PROPERTIES`] (not `infinity` or empty, which lifts a limit)
/// or a `CPUQuota` that [`cpu_quota_starves`].
/// Lowercase unit names, without `.service`.
///
/// `args` keep their case, because systemctl's short options do (see [`positional_arguments`]);
/// the verb, the units and the properties are lowercased here. A command that names another
/// machine (`-M`, `-H`) is read like a local one, not skipped: `-M .host` and `-H localhost`
/// reach this host, so a command line that names a target cannot be told from a local one, and
/// an alert on a remote host's tool is the safer error (#246).
fn cgroup_squeeze(args: &[String]) -> Option<(&'static str, Vec<String>)> {
    let positional: Vec<String> = positional_arguments(args)
        .into_iter()
        .map(|arg| arg.to_ascii_lowercase())
        .collect();
    let mut positional = positional.into_iter();
    let verb = positional.next()?;
    match verb.as_str() {
        "freeze" => Some((
            "freeze",
            positional.flat_map(|unit| freeze_targets(&unit)).collect(),
        )),
        "set-property" => {
            let rest: Vec<String> = positional.collect();
            let limits = rest.iter().any(|a| {
                a.split_once('=').is_some_and(|(key, value)| {
                    LIMIT_PROPERTIES.contains(&key) && !value.is_empty() && value != "infinity"
                        || key == "cpuquota" && cpu_quota_starves(value)
                })
            });
            let unit = rest.iter().find(|a| !a.contains('='))?;
            limits.then(|| ("set-property limit", vec![unit_base(unit)]))
        }
        _ => None,
    }
}

/// `systemctl`'s short options that take a value, case-sensitive (`-T`, `--show-transaction`,
/// takes none; `-h` is `--help`, `-H` takes a host).
const SYSTEMCTL_SHORT_WITH_VALUE: &str = "CHMPnopst";

/// Every long option of `systemctl` (systemd 258, `systemctl --help` and the manual, plus the
/// legacy and hidden ones its `getopt_long` table still accepts) and whether it takes a value.
/// All take it as `--name=value` or as the next argument; the next-argument form is the one
/// that hides the verb. The whole table is needed, not the value-taking part: a prefix is
/// resolved against every name, as `getopt_long` does.
const SYSTEMCTL_LONG_OPTIONS: &[(&str, bool)] = &[
    ("after", false),
    ("all", false),
    ("boot-loader-entry", true),
    ("boot-loader-menu", true),
    ("before", false),
    ("capsule", true),
    ("check-inhibitors", true),
    ("drop-in", true),
    ("dry-run", false),
    ("fail", false),
    ("failed", false),
    ("firmware-setup", false),
    ("force", false),
    ("full", false),
    ("global", false),
    ("help", false),
    ("host", true),
    ("ignore-dependencies", false),
    ("ignore-inhibitors", false),
    ("image", true),
    ("image-policy", true),
    ("irreversible", false),
    ("job-mode", true),
    ("kill-subgroup", true),
    ("kill-value", true),
    ("kill-who", true),
    ("kill-whom", true),
    ("legend", true),
    ("lines", true),
    ("machine", true),
    ("marked", false),
    ("message", true),
    ("mkdir", false),
    ("no-ask-password", false),
    ("no-block", false),
    ("no-legend", false),
    ("no-pager", false),
    ("no-reload", false),
    ("no-wall", false),
    ("no-warn", false),
    ("now", false),
    ("output", true),
    ("plain", false),
    ("preset-mode", true),
    ("property", true),
    ("quiet", false),
    ("read-only", false),
    ("reboot-argument", true),
    ("recursive", false),
    ("reverse", false),
    ("root", true),
    ("runtime", false),
    ("show-transaction", false),
    ("show-types", false),
    ("signal", true),
    ("state", true),
    ("stdin", false),
    ("system", false),
    ("timestamp", true),
    ("type", true),
    ("user", false),
    ("value", false),
    ("verbose", false),
    ("version", false),
    ("wait", false),
    ("what", true),
    ("when", true),
    ("with-dependencies", false),
];

/// Whether the long option `name` (after `--`, before any `=`) takes a value, read as
/// `getopt_long` does: an exact name, else the one option it is a prefix of. A prefix that
/// fits several options with different needs (`--ma`: machine and marked; `--h`: help and
/// host) is rejected by `systemctl`, so it is read as taking none: the command never ran, and
/// the next argument stays the verb.
fn systemctl_long_takes_value(name: &str) -> bool {
    if let Some(&(_, takes)) = SYSTEMCTL_LONG_OPTIONS
        .iter()
        .find(|(long, _)| *long == name)
    {
        return takes;
    }
    let mut fits = SYSTEMCTL_LONG_OPTIONS
        .iter()
        .filter(|(long, _)| !name.is_empty() && long.starts_with(name))
        .map(|&(_, takes)| takes);
    match fits.next() {
        Some(first) => fits.all(|takes| takes == first) && first,
        None => false,
    }
}

/// Whether the next argument is the value of `arg`, a `systemctl` option: a long option that takes
/// one and has no `=`, or a short cluster whose **last** letter takes one and that has no
/// attached value. In `-qM host` the `q` is a flag and the next argument is `M`'s value; in
/// `-Mhost` the value is attached, and in `-qMhost` too (`getopt` stops reading letters at the
/// first one that takes a value).
fn takes_separate_value(arg: &str) -> bool {
    if let Some(name) = arg.strip_prefix("--") {
        return !name.contains('=') && systemctl_long_takes_value(name);
    }
    let Some(letters) = arg.strip_prefix('-') else {
        return false;
    };
    for (at, letter) in letters.char_indices() {
        if SYSTEMCTL_SHORT_WITH_VALUE.contains(letter) {
            return at + letter.len_utf8() == letters.len();
        }
    }
    false
}

/// The arguments of a `systemctl` exec that are not options, in order, with their case. An
/// option's value, given as the next argument (`systemctl -M host set-property ...`, `-t service`,
/// `--job-mode fail`), is not the verb; see [`takes_separate_value`].
fn positional_arguments(args: &[String]) -> Vec<&String> {
    let mut out = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if !arg.starts_with('-') {
            out.push(arg);
        } else if takes_separate_value(arg) {
            iter.next();
        }
    }
    out
}

fn unit_base(unit: &str) -> String {
    unit.strip_suffix(".service").unwrap_or(unit).to_owned()
}

/// The units one `systemctl freeze` argument names. `freeze` takes `PATTERN...`: systemd matches
/// a glob against the full names of the loaded units (`fnmatch(3)`, no `.service` appended), so
/// `audit*` freezes `auditd.service`. A glob is resolved to every listed service whose unit
/// name it matches (whether that unit is loaded on the host is not known here); a plain name is
/// returned as is.
fn freeze_targets(unit: &str) -> Vec<String> {
    if !unit.contains(['*', '?', '[']) {
        return vec![unit_base(unit)];
    }
    SECURITY_SERVICES
        .iter()
        .filter(|service| unit_pattern_matches(unit, &format!("{service}.service")))
        .map(ToString::to_string)
        .collect()
}

/// Whether `name` matches the unit pattern `pattern` as systemd's `fnmatch(3)` call reads it
/// (`FNM_NOESCAPE`): `*`, `?` and a bracket class (`[a-z]`, `[!d]`, `[^d]`); an unterminated
/// `[` is a literal. Iterative, with backtracking to the last `*` only, which is exact for
/// these three operators.
fn unit_pattern_matches(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    let (mut p, mut n) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while let Some(&c) = name.get(n) {
        let next = match pattern.get(p) {
            Some('*') => {
                star = Some((p + 1, n));
                p += 1;
                continue;
            }
            Some('?') => Some(p + 1),
            Some('[') => match bracket_class(&pattern, p, c) {
                Some((true, past)) => Some(past),
                Some((false, _)) => None,
                None => (c == '[').then_some(p + 1),
            },
            Some(&literal) => (literal == c).then_some(p + 1),
            None => None,
        };
        if let Some(past) = next {
            p = past;
            n += 1;
        } else if let Some((resume, from)) = star {
            p = resume;
            n = from + 1;
            star = Some((resume, from + 1));
        } else {
            return false;
        }
    }
    pattern
        .get(p..)
        .is_some_and(|rest| rest.iter().all(|&c| c == '*'))
}

/// The bracket class opening at `pattern[open]`: whether `c` is in it, and the index past its
/// closing `]`. `None` when the class is never closed. A `]` right after the `[` (or `[!`) is a
/// member, as in `fnmatch(3)`.
fn bracket_class(pattern: &[char], open: usize, c: char) -> Option<(bool, usize)> {
    let mut i = open + 1;
    let negated = matches!(pattern.get(i), Some('!' | '^'));
    if negated {
        i += 1;
    }
    let first = i;
    let mut member = false;
    loop {
        let &low = pattern.get(i)?;
        if low == ']' && i > first {
            return Some((member != negated, i + 1));
        }
        match (pattern.get(i + 1), pattern.get(i + 2)) {
            (Some('-'), Some(&high)) if high != ']' => {
                member |= (low..=high).contains(&c);
                i += 3;
            }
            _ => {
                member |= low == c;
                i += 1;
            }
        }
    }
}

/// T1562.001 — a command that makes the kernel stop or freeze a listed security tool without a
/// signal the probe can attribute (<https://github.com/synthaea-lab/agent/issues/49>): `systemctl freeze <tool>` (the cgroup freezer) and
/// `systemctl set-property <tool> MemoryMax=...|MemoryHigh=...|TasksMax=...` (a limit the memcg
/// OOM killer then enforces with a `SEND_SIG_PRIV` `SIGKILL`, which the `signal_generate` probe
/// drops). Every unit of a `freeze` is checked, not the first only, and a unit pattern
/// (`systemctl freeze 'audit*'`) is matched against the listed units' names. Medium, like the stop
/// verbs, and for the same reasons: it reads the command, an administrator can do the same,
/// and an empty `argv` (<https://github.com/synthaea-lab/agent/issues/48>) blinds it.
///
/// Not covered, by choice (ADR-0046): the **ancestor slice** (`systemctl freeze system.slice`,
/// `set-property system.slice MemoryMax=...`, a write to `system.slice/cgroup.freeze`), which
/// acts on every service of the host and is ordinary administration far more often than an
/// attack on a tool; and moving the tool's pid into a cgroup the attacker froze or limited
/// (`cgroup.procs`). `CPUQuota` is read on its value (below
/// [`CPU_QUOTA_STARVE_BELOW_PERCENT`] percent), since the quota a tool is capped at is the
/// only thing that tells a starved tool from a tuned one.
///
/// `prlimit --pid <pid> --cpu=...` (or `--as=...`) is the third path, read by
/// [`check_security_tool_prlimit`], which needs the pid-to-process table of `RuleState`.
#[must_use]
pub(crate) fn check_security_tool_throttle(event: &ExecEvent) -> Option<Alert> {
    match program(event).as_str() {
        "systemctl" => {
            let (how, units) = cgroup_squeeze(&args_cased(event))?;
            let tool = units.iter().find(|unit| is_security_tool(unit))?;
            Some(Alert {
                technique: "T1562.001",
                severity: Severity::Medium,
                message: format!(
                    "pid={} comm={}: the kernel is made to stop or freeze the security tool {tool} ({how})",
                    event.meta.pid, event.meta.comm,
                ),
            })
        }
        _ => None,
    }
}

/// T1562.001 — `prlimit --pid <pid> --cpu=...` (or `--as=...`): the third kernel-mediated stop
/// of agent#49. At the next CPU tick the kernel ends the tool with a `SEND_SIG_PRIV` `SIGKILL`
/// the signal probe drops, so the command is the only trace. The exec names a pid, not a tool,
/// so `resolve` gives what the rules know of that pid: its comm and image path, as
/// [`crate::RuleState`] holds them (falling back to `/proc`).
///
/// - the pid is a listed security tool: **Medium**, naming it, like `systemctl set-property`;
/// - it is not, or it cannot be resolved (the process exited, never exec'd under the agent and
///   has no `/proc` entry): **Low**, as before, with "target not resolved to a tool". A
///   `RLIMIT_CPU` set on another process is rare enough to be worth a line, not a verdict.
///
/// The target is matched by comm and by image basename (a comm is cut to 15 bytes, so
/// `falco-modern-bpf` reads `falco-modern-bp`). A tool renamed or run from a copy with another
/// name is not matched.
#[must_use]
pub(crate) fn check_security_tool_prlimit(
    event: &ExecEvent,
    resolve: impl Fn(u32) -> Vec<String>,
) -> Option<Alert> {
    if program(event) != "prlimit" {
        return None;
    }
    let args = args(event);
    if !prlimit_sets_cpu_or_as_on_a_pid(&args) {
        return None;
    }
    let tool = prlimit_target_pid(&args).and_then(|pid| {
        resolve(pid)
            .into_iter()
            .map(|name| name.to_ascii_lowercase())
            .find(|name| is_security_tool(name))
    });
    Some(match tool {
        Some(tool) => Alert {
            technique: "T1562.001",
            severity: Severity::Medium,
            message: format!(
                "pid={} comm={}: prlimit sets RLIMIT_CPU or RLIMIT_AS on the security tool {tool}",
                event.meta.pid, event.meta.comm,
            ),
        },
        None => Alert {
            technique: "T1562.001",
            severity: Severity::Low,
            message: format!(
                "pid={} comm={}: prlimit sets RLIMIT_CPU or RLIMIT_AS on another pid (target not resolved to a tool)",
                event.meta.pid, event.meta.comm,
            ),
        },
    })
}

/// Whether `name` (the part of a long option after `--` and before any `=`) is the `pid` option
/// of `prlimit`: `getopt_long` accepts any non-empty prefix of a long option that no other one
/// shares, and `pid` is the only long option of util-linux `prlimit` starting with `p`, so `--p`,
/// `--pi` and `--pid` all name it (live, on util-linux 2.38: `prlimit --pi=N --cpu=…` sets the
/// limit).
fn is_pid_long_option(name: &str) -> bool {
    !name.is_empty() && "pid".starts_with(name)
}

/// The pid `prlimit` is told to act on: `--pid N`, `--pid=N` (or any prefix of `--pid`:
/// `--p N`, `--pi=N`), `-p N`, `-pN` or `-p=N`. `None` when it is not a number (`prlimit`
/// accepts none other).
fn prlimit_target_pid(args: &[String]) -> Option<u32> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let value = if let Some(long) = arg.strip_prefix("--") {
            match long.split_once('=') {
                Some((name, value)) if is_pid_long_option(name) => Some(value),
                None if is_pid_long_option(long) => iter.next().map(String::as_str),
                _ => continue,
            }
        } else if arg == "-p" {
            iter.next().map(String::as_str)
        } else if let Some(value) = arg.strip_prefix("-p") {
            Some(value.trim_start_matches('='))
        } else {
            continue;
        };
        return value.and_then(|v| v.parse().ok());
    }
    None
}

/// `prlimit --pid N --cpu=1:1`: a pid is named and a CPU or address-space limit is **set**
/// (`--cpu` alone only prints it). Long options may be abbreviated to a unique prefix
/// (`--cp=`, `--a=`: `a` is a unique prefix of `--as` among the long options of util-linux
/// `prlimit`, from its manual page, not checked against a build), the short forms attach their
/// value (`-t1:1`). Not exhaustive: an option clustered with another short one (`-tp`) is not
/// read. That is the
/// argv-reading limit of ADR-0006.
fn prlimit_sets_cpu_or_as_on_a_pid(args: &[String]) -> bool {
    let names_pid = args.iter().any(|a| match a.strip_prefix("--") {
        Some(long) => is_pid_long_option(long.split_once('=').map_or(long, |(name, _)| name)),
        None => a.starts_with("-p"),
    });
    let sets = args.iter().any(|a| {
        if let Some(long) = a.strip_prefix("--") {
            long.split_once('=').is_some_and(|(name, value)| {
                !value.is_empty()
                    && (!name.is_empty() && "as".starts_with(name)
                        || (name.len() >= 2 && "cpu".starts_with(name)))
            })
        } else {
            ["-t", "-v"].iter().any(|short| {
                a.strip_prefix(short)
                    .is_some_and(|value| !value.trim_start_matches('=').is_empty())
            })
        }
    });
    names_pid && sets
}

/// The cgroup control files whose write ends, freezes or starves a unit: cgroup v2 and the v1
/// controllers' equivalents.
const THROTTLE_FILES: &[&str] = &[
    "memory.max",
    "memory.high",
    "cgroup.freeze",
    "pids.max",
    // The CPU quota: `echo '1000 100000' > cpu.max` leaves a tool 1% of a CPU, like
    // `systemctl set-property CPUQuota=1%`. The open does not carry the value, so any write
    // alerts, as for `memory.max` (a write that lifts the limit alerts too).
    "cpu.max",
    "memory.limit_in_bytes",
    "memory.soft_limit_in_bytes",
    "freezer.state",
];

/// The unit and the control file a cgroup path names, read the way the kernel does for the
/// forms that reach the rule: empty and `.` segments are dropped (`//sys/fs//cgroup/x/./y`) and
/// `..` pops the segment before it (`/sys/fs/../fs/cgroup/x/y`), then the path is read on its
/// last two segments, `<unit>.service/<file>`, whether it is absolute or relative (the shell did
/// a `cd` first, and `openat` with a directory fd gives a relative one too). So a cgroup2 mounted
/// elsewhere (`mount -t cgroup2 none /mnt/cg2`) is read too. A path of one segment
/// (`cgroup.freeze` after a `cd` into the unit's directory) names no unit and is not read: the
/// event carries no working directory. An `x.service/memory.max` from an unrelated directory is
/// read as the cgroup of `x` (a false positive only for a listed tool's name).
fn cgroup_unit_and_file(path: &str) -> Option<(&str, &str)> {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/').filter(|s| !s.is_empty() && *s != ".") {
        if segment == ".." {
            segments.pop();
        } else {
            segments.push(segment);
        }
    }
    let [.., unit, file] = &segments[..] else {
        return None;
    };
    Some((unit.strip_suffix(".service")?, file))
}

/// T1562.001 — a write-intent open of `memory.max`, `memory.high`, `cgroup.freeze`, `pids.max` or `cpu.max`
/// (or the cgroup v1 equivalents) in the cgroup of a listed unit: `echo 1M >
/// /sys/fs/cgroup/system.slice/auditd.service/memory.max`. The kernel then OOM-kills or freezes
/// the tool with no signal the probe reports (<https://github.com/synthaea-lab/agent/issues/49>).
///
/// The Linux open probe passes a write-intent open of such a file under `/sys/`
/// (`is_cgroup_limit_write` in `sensor-linux-wire`: a tail match with no `/sys/fs/cgroup/` prefix test,
/// a little wider than this list,
/// since the probe cannot know the listed units); the filter is unit-tested and was run on Fedora
/// 43 (kernel 7.2.9) and Rocky 9.8 (5.14). A relative path or one written `//sys/...` also reaches the rule
/// ([`cgroup_unit_and_file`]). The rule fires for any source that reports such an open. Pid 1 is skipped: the manager writes these files when
/// it starts a unit that has a configured limit, and when it carries out `systemctl
/// set-property` and `freeze`, which `check_security_tool_throttle` reads from the exec.
/// Medium.
#[must_use]
pub(crate) fn check_security_tool_cgroup_write(event: &FileOpenEvent) -> Option<Alert> {
    if !has_write_intent(event.flags) || event.meta.pid == 1 {
        return None;
    }
    let (unit, file) = cgroup_unit_and_file(&event.path)?;
    (THROTTLE_FILES.contains(&file) && SECURITY_SERVICES.contains(&unit)).then(|| Alert {
        technique: "T1562.001",
        severity: Severity::Medium,
        message: format!(
            "pid={} comm={}: write to {file} of the security tool {unit}: {}",
            event.meta.pid, event.meta.comm, event.path,
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::{is_security_tool, unit_pattern_matches};

    #[test]
    fn unit_patterns_match_as_fnmatch_does() {
        for (pattern, name) in [
            ("audit*", "auditd.service"),
            ("*", "auditd.service"),
            ("*.service", "auditd.service"),
            ("a*d*", "auditd.service"),
            ("auditd.servic?", "auditd.service"),
            ("[a]uditd.service", "auditd.service"),
            ("[!b]uditd.service", "auditd.service"),
            ("[^b]uditd.service", "auditd.service"),
            ("[a-c]uditd.service", "auditd.service"),
            ("[]a]uditd.service", "auditd.service"),
            ("[x.service", "[x.service"),
        ] {
            assert!(unit_pattern_matches(pattern, name), "{pattern} {name}");
        }
        for (pattern, name) in [
            ("audit?", "auditd.service"),
            ("auditd", "auditd.service"),
            ("*.slice", "auditd.service"),
            ("[!a]uditd.service", "auditd.service"),
            ("[b-z]uditd.service", "auditd.service"),
            ("[", "auditd.service"),
            ("[!", "auditd.service"),
            ("[]", "auditd.service"),
            ("*[", "auditd.service"),
            ("auditd.service?", "auditd.service"),
            ("", "auditd.service"),
        ] {
            assert!(!unit_pattern_matches(pattern, name), "{pattern} {name}");
        }
    }

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
