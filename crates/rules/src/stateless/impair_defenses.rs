//! Impair Defenses (T1562): event logging disabled, security processes signalled.

use schema::{ExecEvent, User, detection::Severity};

use crate::Alert;

/// T1562.002 — Impair Defenses: Disable Windows Event Logging. The exec-side
/// counterpart of [`check_log_clear_exec`](super::check_log_clear_exec): instead
/// of wiping what was logged, stop anything new from being logged.
///
/// Windows events only (`User::Windows`). The command line is read as words, the way the
/// tool reads it, and matched on the program it starts with (`wevtutil`, `auditpol`, `sc`,
/// `net`/`net1`, `reg`, `powershell`/`pwsh`, with or without a path or `.exe`): a quoted
/// `"eventlog"`, a tab, `/e:"false"` or the display name `"Windows Event Log"` are seen,
/// and `dotnet app.dll stop eventlog-forwarder` is not `net stop eventlog`.
///
/// Only the disabling forms match: the agent itself runs
/// `auditpol /set /subcategory:{guid} /success:enable /failure:enable` and
/// `wevtutil qe` (`sensor-windows-eventlog`), and neither may alert; neither may
/// read-only queries (`sc query`, `reg query`, `Get-EventLog`, `net start`).
///
/// A wrapper such as `cmd /c net stop eventlog` is not matched on its own line: `cmd.exe`
/// starts `net.exe` as a child, and that child's exec (`net stop eventlog`) is the one that
/// alerts, so the wrapper adds nothing to look for.
///
/// Known gaps: a channel disabled through the API or the registry rather than by one of
/// these command lines is not seen here, and the sensor's start-up channel check (#786) only
/// warns about a channel that is already disabled when the agent starts, so a channel
/// switched off afterwards is not caught; a pipeline such as
/// `Get-Service EventLog | Stop-Service`, an encoded command, and a renamed copy of a tool
/// are not matched either.
#[must_use]
pub(crate) fn check_event_logging_disable_exec(event: &ExecEvent) -> Option<Alert> {
    if !matches!(event.meta.user, User::Windows { .. }) {
        return None;
    }
    let words = windows_words(&event.cmdline);
    let (program, args) = words.split_first()?;
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let program = program.as_str();
    let program = program.rsplit(['/', '\\']).next().unwrap_or(program);
    let program = program.strip_suffix(".exe").unwrap_or(program);
    let what = match program {
        "wevtutil" => wevtutil_disables_a_channel(&args),
        "auditpol" => auditpol_weakens_the_policy(&args),
        "sc" => sc_stops_or_disables_eventlog(&args),
        "net" | "net1" => net_stops_eventlog(&args),
        "reg" => reg_disables_eventlog(&args),
        "powershell" | "pwsh" => powershell_stops_or_disables_eventlog(&event.cmdline),
        _ => None,
    }?;
    Some(Alert {
        technique: "T1562.002",
        severity: Severity::High,
        message: format!(
            "pid={} comm={}: {what}: {}",
            event.meta.pid, event.meta.comm, event.cmdline,
        ),
    })
}

/// The words of a Windows command line, lowercased: whitespace outside double quotes
/// separates them and the quote characters are dropped, so `/e:"false"` is `/e:false` and
/// `"Windows Event Log"` is one word.
fn windows_words(cmdline: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for c in cmdline.chars() {
        if c == '"' {
            quoted = !quoted;
        } else if c.is_whitespace() && !quoted {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
        } else {
            current.extend(c.to_lowercase());
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// A switch without its prefix: `/e:false` and `-e:false` are both `e:false`.
fn switch(word: &str) -> Option<&str> {
    word.strip_prefix(['/', '-'])
}

/// `wevtutil sl <log> /e:false` or `wevtutil set-log <log> /enabled:false`.
fn wevtutil_disables_a_channel(args: &[&str]) -> Option<&'static str> {
    let sets_the_log = args.iter().any(|a| matches!(*a, "sl" | "set-log"));
    let disables = args
        .iter()
        .filter_map(|a| switch(a))
        .any(|s| matches!(s, "e:false" | "enabled:false"));
    (sets_the_log && disables).then_some("event log channel disabled")
}

/// `auditpol /clear`, `auditpol /remove`, or `auditpol /set ... /success:disable` (or
/// `/failure:disable`).
fn auditpol_weakens_the_policy(args: &[&str]) -> Option<&'static str> {
    let has = |name: &str| args.iter().filter_map(|a| switch(a)).any(|s| s == name);
    let disables = args
        .iter()
        .filter_map(|a| switch(a))
        .any(|s| matches!(s, "success:disable" | "failure:disable"));
    if has("clear") {
        Some("audit policy cleared")
    } else if has("remove") {
        Some("audit policy removed")
    } else if has("set") && disables {
        Some("audit subcategory disabled")
    } else {
        None
    }
}

/// `sc [\\server] stop eventlog` and `sc [\\server] config eventlog start= disabled`.
fn sc_stops_or_disables_eventlog(args: &[&str]) -> Option<&'static str> {
    let mut rest = args.iter().copied().skip_while(|a| a.starts_with("\\\\"));
    let verb = rest.next()?;
    let service = rest.next()?;
    if service != "eventlog" {
        return None;
    }
    let rest: Vec<&str> = rest.collect();
    match verb {
        "stop" => Some("EventLog service stopped"),
        "config" if sc_start_is_disabled(&rest) => Some("EventLog service disabled"),
        _ => None,
    }
}

/// `start= disabled` (two words) or `start=disabled`.
fn sc_start_is_disabled(args: &[&str]) -> bool {
    args.iter().enumerate().any(|(i, a)| match *a {
        "start=" => args.get(i + 1) == Some(&"disabled"),
        "start=disabled" => true,
        _ => false,
    })
}

/// `net stop eventlog` and `net stop "Windows Event Log"`: the service name runs up to the
/// first switch (`/y`), and an unquoted display name is several words.
fn net_stops_eventlog(args: &[&str]) -> Option<&'static str> {
    let (verb, rest) = args.split_first()?;
    if *verb != "stop" {
        return None;
    }
    let service = rest
        .iter()
        .take_while(|a| !a.starts_with('/'))
        .copied()
        .collect::<Vec<_>>()
        .join(" ");
    matches!(service.as_str(), "eventlog" | "windows event log")
        .then_some("EventLog service stopped")
}

/// `reg add <...>\Services\EventLog /v Start /d 4`: only the data that disables the service
/// (`4`); `/d 2` sets it back to automatic. A subkey such as `...\EventLog\Security` is a
/// channel's configuration, not the service.
fn reg_disables_eventlog(args: &[&str]) -> Option<&'static str> {
    if args.first() != Some(&"add") {
        return None;
    }
    let key = args.get(1)?.trim_end_matches('\\');
    if !key.ends_with("\\services\\eventlog") {
        return None;
    }
    let value_of = |name: &str| {
        args.iter()
            .position(|a| switch(a) == Some(name))
            .and_then(|i| args.get(i + 1))
            .copied()
    };
    (value_of("v") == Some("start") && matches!(value_of("d"), Some("4" | "0x4")))
        .then_some("EventLog service disabled")
}

/// `Stop-Service` of `EventLog`, or `Set-Service EventLog -StartupType Disabled`, within one
/// statement of the command line: `Stop-Service -Name Spooler; Get-WinEvent -LogName
/// EventLog` names `EventLog`, but not as the service being stopped.
fn powershell_stops_or_disables_eventlog(cmdline: &str) -> Option<&'static str> {
    let lower = cmdline.to_lowercase();
    for statement in lower.split([';', '|', '&', '\n']) {
        let words: Vec<&str> = statement
            .split(|c: char| {
                c.is_whitespace() || matches!(c, '"' | '\'' | '(' | ')' | '{' | '}' | ',' | '`')
            })
            .filter(|w| !w.is_empty())
            .collect();
        let names_eventlog = words
            .iter()
            .any(|w| matches!(*w, "eventlog" | "-name:eventlog"))
            || words
                .windows(3)
                .any(|w| w[0] == "windows" && w[1] == "event" && w[2] == "log");
        if !names_eventlog {
            continue;
        }
        if words.contains(&"stop-service") {
            return Some("EventLog service stopped");
        }
        let startup_disabled = words
            .windows(2)
            .any(|w| w[0] == "-startuptype" && w[1] == "disabled")
            || words.contains(&"-startuptype:disabled");
        if words.contains(&"set-service") && startup_disabled {
            return Some("EventLog service disabled");
        }
    }
    None
}

/// `SIGKILL`: the same on Linux and macOS.
const SIGKILL: u32 = 9;

/// `SIGSTOP`'s platform-native number: the one signal of
/// [`tamper_signal_name`]'s set that differs between Linux and macOS. Signal
/// events carry the sending host's numbering, and rules run on that same host.
const SIGSTOP: u32 = if cfg!(target_os = "macos") { 17 } else { 19 };

/// Name of `signal` when it ends or freezes its target, `None` otherwise. Signal
/// `0` (an existence probe) and the user-defined or job-control signals are left
/// out: they neither stop the agent nor blind it. Every number but `SIGSTOP` is
/// the same on Linux and macOS.
fn tamper_signal_name(signal: u32) -> Option<&'static str> {
    match signal {
        1 => Some("SIGHUP"),
        2 => Some("SIGINT"),
        3 => Some("SIGQUIT"),
        6 => Some("SIGABRT"),
        9 => Some("SIGKILL"),
        15 => Some("SIGTERM"),
        s if s == SIGSTOP => Some("SIGSTOP"),
        _ => None,
    }
}

/// Linux signals that neither end nor stop a process by default (`signal(7)`): `SIGCHLD`,
/// `SIGCONT`, `SIGURG`, `SIGWINCH`. Every other number from 1 to 64 ends or stops one with no
/// handler, `SIGUSR1`, `SIGSEGV`, `SIGPIPE` and the real-time signals included.
const LINUX_BENIGN_SIGNALS: [u32; 4] = [17, 18, 23, 28];

/// The label of `signal` when it is worth an alert for `tool_event`, an event naming a listed
/// security tool (Linux, #1103): the listed signals by name, any other default-terminating one
/// as `signal` with its number in parentheses. A tool dies of any of them unless it handles it, and which ones each tool
/// handles is not known here.
fn signal_label(signal: u32, tool_event: bool) -> Option<std::borrow::Cow<'static, str>> {
    if let Some(name) = tamper_signal_name(signal) {
        return Some(name.into());
    }
    (cfg!(target_os = "linux")
        && tool_event
        && (1..=64).contains(&signal)
        && !LINUX_BENIGN_SIGNALS.contains(&signal))
    .then(|| "signal".into())
}

/// The process id of the service manager: `systemd` on Linux, `launchd` on macOS. The Linux probe
/// reports the sender's thread-group id from the **initial** pid namespace, so a container's own
/// init is not 1 here, and only the host's manager is.
const INIT_PID: u32 = 1;

/// T1562.001 — Impair Defenses: Disable or Modify Tools, the process-termination
/// half (issue #362). Every [`schema::SignalEvent`] already targets a protected
/// security process: the sensors filter at the source (Linux: the eBPF
/// `SIGNAL_WATCH_PID` gate on the agent's own pid, and `SIGNAL_WATCH_TOOLS` for the processes of
/// the listed security units (#1103); macOS: the Endpoint Security client gate). This rule only keeps the signals that end or freeze the target, and
/// then looks at the **sender** (#1103), which is all the event says about the actor:
/// `meta` is the sender's pid, parent, comm, uid and container, with no cgroup or unit.
///
/// - A process signalling **itself** (`meta.pid == target_pid`: `abort()`, a fatal-error
///   `raise(SIGTERM)`) is not tampering: no alert.
/// - The service manager (**pid 1**) is **Low**, not High. It is what delivers `systemctl
///   stop` (SIGTERM, then SIGKILL once the stop times out), `restart` and a package
///   upgrade, so High on each would make every upgrade a High finding. It is not dropped:
///   `systemctl kill -s KILL` and a D-Bus stop arrive from pid 1 too, and the event cannot
///   say who asked the manager. Who did is the exec rule's (`check_security_tool_stop`,
///   which parses `systemctl stop` and `systemctl kill`) and the journal's, not this rule's.
///   A D-Bus stop has no exec: only the journal sees it.
/// - Anyone else: High, as before, **for the agent itself**. For a listed security tool (the
///   event carries `target_unit`, Linux, #1103) the signal decides:
///   - **Caught reload signals**: a daemon that catches `SIGHUP`, `SIGUSR1`, `SIGUSR2` or a
///     real-time signal takes it as "reload" or "reopen your logs" (logrotate's `postrotate`,
///     `ExecReload=`, `systemctl reload`), the commonest benign signals a tool gets. The Linux
///     sensor drops them in the kernel for such a tool (the process's `SigCgt` at scan time), so
///     one that reaches this rule was sent to a tool with **no handler** for it, which ends it:
///     Medium like the other catchable signals. The agent keeps `SIGHUP` as High, it does not
///     reload on it.
///   - `SIGKILL` and `SIGSTOP`, which cannot be handled, are **High**.
///   - The catchable ones that end a daemon (`SIGTERM`, `SIGINT`, `SIGQUIT`, `SIGABRT`, and any
///     other signal whose default action terminates: `SIGUSR1`, `SIGPIPE`, `SIGALRM`, a
///     real-time signal, reported as `signal N`) are **Medium**: an administrator's `kill <pid>`, or `service auditd stop` (whose helper sends
///     the `SIGTERM` itself, not pid 1), is indistinguishable from an attacker's, exactly as
///     `systemctl stop auditd` is Medium in `check_security_tool_stop`.
///
/// What it **cannot** tell: whether a sender other than pid 1 is the agent's own
/// supervisor (the watchdog) or another process of the same unit, since the event has
/// no sender unit or cgroup. Such a signal still alerts High. Telling them apart needs
/// the sender's unit in the event, which is a schema change and not made here.
///
/// On Linux it is the only record of a `SIGKILL`'s sender: the agent's own
/// `kill_loudness` can only attribute the catchable signals. The kernel-side
/// record of a `SIGKILL` survives the kill in a pinned map and is replayed by the
/// restarted agent, so that alert arrives one restart late.
#[must_use]
pub(crate) fn check_security_process_signal(event: &schema::SignalEvent) -> Option<Alert> {
    if event.signals_lost != 0 {
        // The sensor's loss report, not a signal: `check_signal_events_lost`.
        return None;
    }
    let tool = event.target_unit.is_some();
    let name = signal_label(event.signal, tool)?;
    if event.meta.pid == event.target_pid {
        return None;
    }
    let target = event.target_image_path.as_deref().unwrap_or("?");
    let sender_uid = match &event.meta.user {
        schema::User::Unix { uid, .. } => format!(" uid={uid}"),
        _ => String::new(),
    };
    // The unit the source resolved (Linux, #1103): which tool it was, not only which image.
    let unit = event
        .target_unit
        .as_deref()
        .map(|unit| format!(" of unit {unit}"))
        .unwrap_or_default();
    // With an unreliable sender, `meta` may be a bystander that happens to be pid 1.
    let from_manager = event.meta.pid == INIT_PID && !event.sender_unreliable;
    // `si_code` of interrupt or completion context (or forged): `meta` may be a bystander.
    let unreliable = if event.sender_unreliable {
        ": the sender is not reliable (the siginfo carries a code the kernel sets from interrupt \
         context, which a process can also forge)"
    } else {
        ""
    };
    Some(Alert {
        technique: "T1562.001",
        severity: if from_manager {
            Severity::Low
        } else if tool && event.signal != SIGKILL && event.signal != SIGSTOP {
            Severity::Medium
        } else {
            Severity::High
        },
        message: format!(
            "pid={} comm={}{sender_uid}: sent {name} ({}) to security process pid={} ({target}){unit}{}",
            event.meta.pid,
            event.meta.comm,
            event.signal,
            event.target_pid,
            if from_manager {
                ": sent by the service manager, which does not say who asked it (a stop, \
                 restart or upgrade, or `systemctl kill`)"
            } else {
                ""
            },
        ) + unreliable,
    })
}

/// T1562.001: signals to security tools were lost to a full ring buffer (Linux, #1103). A flood
/// of signals ahead of a kill is how a tool is ended unseen, so the loss is a finding by itself.
/// **High**, like the `SIGKILL` it can hide: what was lost may be the kill, and nothing after the
/// fact says which signals they were (measured: 20,000 ignored `SIGPIPE` ahead of a `kill -9`
/// left no `SIGKILL` event, only this report).
///
/// The count is `SignalEvent::signals_lost`, a field only the sensor's own report sets: not a bit
/// of `FileOpenEvent::flags`, which an unprivileged `open(2)` can set (`O_TMPFILE` did).
#[must_use]
pub(crate) fn check_signal_events_lost(event: &schema::SignalEvent) -> Option<Alert> {
    if event.signals_lost == 0 {
        return None;
    }
    Some(Alert {
        technique: "T1562.001",
        severity: Severity::High,
        message: format!(
            "{} signals to security tools lost, signal ring buffer full: a flood of signals to a \
             security tool, or one too busy to read them, can hide a kill, and the lost signals \
             may include the SIGKILL, so this is High",
            event.signals_lost
        ),
    })
}
