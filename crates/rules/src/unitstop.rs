//! UNEXPLAINED-UNIT-STOP (T1562.001, #1085): a security service stopped that nothing visible asked
//! for.
//!
//! The journal sensor reports a stop of a unit of [`SECURITY_SERVICES`] as a `FileOpenEvent`
//! carrying [`schema::FLAG_UNIT_STOPPED`], from pid 1 only (the flag is also an `openat` bit any
//! process can set, so the pid is the check). The journal names no actor, so this rule asks the
//! other question: was the stop **explained**? `check_security_tool_stop` already alerts on a
//! `systemctl stop falco`; what it cannot see is a stop over D-Bus, from a script's API call, or
//! after the service was killed, and those are what is left once the explained stops are set
//! aside. A stop is explained when, judged once [`START_WITHIN_NS`] has passed over it:
//!
//! 1. an exec stopped the same unit just before ([`EXEC_LOOKBACK_NS`]), so the exec rule has
//!    already alerted and a second alert would be the same finding twice;
//! 2. the unit was started again within [`START_WITHIN_NS`] (a restart, or a package upgrade);
//! 3. the host was told to shut down just before ([`SHUTDOWN_WINDOW_NS`]).
//!
//! Anything else is Medium: a stop whose cause the agent did not see. An administrator who stops
//! a unit from a web console or a configuration-management agent over D-Bus looks the same, which
//! is why the severity is not higher.
//!
//! **No shutdown signal exists** in the stream (the journal sensor reports unit stops of the
//! listed services only, not `shutdown.target`), and the service-stop burst counts *execs*, not
//! journal stops, so neither can stand for condition 3. It is read from the exec of `shutdown`,
//! `reboot`, `poweroff`, `halt`, `systemctl reboot|poweroff|halt|kexec` and `init 0|6`. Only an
//! **immediate** shutdown (`shutdown now`, `+0`) opens the window: `shutdown +60` or `23:00`
//! schedules one that stops nothing yet, and would otherwise cloak any stop in the next five
//! minutes (`shutdown +99`, stop the tool, `shutdown -c`). `shutdown -c`/`--cancel` (and
//! `systemctl --when=cancel`) closes a window already open. A shutdown asked another way (power button, logind from a
//! desktop session, a hypervisor ACPI request) is a stated gap: its stops alert.
//!
//! Judging at the end of a wait, not on arrival, is what makes condition 2 possible and what makes
//! the order the exec and the journal events arrive in irrelevant: the journal and the eBPF exec
//! stream are drained independently. The cost is latency, and that a stop waits for the stream
//! clock (any later exec or file-open event) to pass it, like SETUID-ROOT-REQUEST's queue.

use std::collections::VecDeque;

use schema::{ExecEvent, FileOpenEvent, SECURITY_SERVICES, detection::Severity};
use store::BoundedMap;

use crate::{
    Alert,
    recon::{args, program},
    servicestop::services_stopped,
};

/// The pid the journal sensor gives a unit stop it reports: the manager's.
const JOURNAL_STOP_PID: u32 = 1;

/// How long after a stop the unit may start again for the stop to count as a restart. A
/// `systemctl restart` is back in seconds, but a package upgrade stops the service in its
/// pre-remove script and starts it in post-install, with the unpack in between: two minutes
/// covers that for a large package without leaving a stopped security tool unreported for long.
/// A choice, not a measurement: no fleet data yet.
pub(crate) const START_WITHIN_NS: u64 = 120_000_000_000;

/// How long before the journal's stop record a stopping exec may have run. A stop is logged when
/// its job ends, up to systemd's `DefaultTimeoutStopSec` (90 s) after the exec asked for it; the
/// rest is margin.
pub(crate) const EXEC_LOOKBACK_NS: u64 = 120_000_000_000;

/// How long after a shutdown was asked for its stops are expected: the units stop in dependency
/// order, each bounded by `DefaultTimeoutStopSec` (90 s), so a shutdown's last stop can come
/// minutes later. A scheduled `shutdown +10` does not open it: its stops alert.
pub(crate) const SHUTDOWN_WINDOW_NS: u64 = 300_000_000_000;

/// Clock difference tolerated between the two sources: the journal's realtime timestamp and the
/// exec's boot-offset kernel time are not the same clock, so an exec may look a moment later than
/// the stop it caused.
pub(crate) const CLOCK_SKEW_NS: u64 = 5_000_000_000;

/// Stops waiting for their wait to end. Only the listed units are queued and a host has a handful
/// of them, so the bound is a flood guard: the oldest is judged at once, which errs towards an
/// alert.
const PENDING_CAP: usize = 64;

/// Units tracked. `SECURITY_SERVICES` has 24 names.
const UNIT_CAP: usize = 64;

/// Touches kept per unit, oldest dropped.
const TOUCHES_PER_UNIT: usize = 16;

/// What an exec did to a unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Touch {
    /// `systemctl stop`, `disable --now`, `mask --now`, `service X stop`: the exec rule's.
    Stop,
    /// `systemctl restart` / `try-restart`: a stop and a start.
    Restart,
    /// `systemctl start` / `reload-or-restart`, `enable --now`, `service X start`.
    Start,
}

/// The history and queue of UNEXPLAINED-UNIT-STOP, held by `RuleState`.
pub(crate) struct UnitStops {
    /// Unit (lowercase, no suffix) → its recent touches `(kind, exec time)`. LRU-bounded.
    touches: BoundedMap<String, Vec<(Touch, u64)>>,
    /// When the host was last told to shut down.
    shutdown_ns: Option<u64>,
    /// Stops waiting to be judged, oldest first.
    pending: VecDeque<FileOpenEvent>,
    /// Stops judged early because the queue overflowed, until the next [`Self::take_due`].
    ready: Vec<(FileOpenEvent, Alert)>,
    /// The latest timestamp of any exec or unit stop seen: the stream's clock.
    clock_ns: u64,
}

impl UnitStops {
    pub(crate) fn new() -> Self {
        Self {
            touches: BoundedMap::new(UNIT_CAP),
            shutdown_ns: None,
            pending: VecDeque::new(),
            ready: Vec::new(),
            clock_ns: 0,
        }
    }

    /// An exec: record what it does to a listed unit, or that it shuts the host down.
    pub(crate) fn on_exec(&mut self, event: &ExecEvent) {
        let ts = event.meta.timestamp_ns;
        self.clock_ns = self.clock_ns.max(ts);
        // The shutdown and start claims are name-keyed (the basename of the image), and each one
        // suppresses an alert: they count only from a system image path, or an unknown one
        // (`policy::name_exclusion_applies`), so a `/tmp/reboot` copy of `true` explains nothing.
        let trusted = policy::name_exclusion_applies(Some(&event.image_path));
        match shutdown_effect(event).filter(|_| trusted) {
            Some(Shutdown::Now) => self.shutdown_ns = Some(ts),
            Some(Shutdown::Cancel) => self.shutdown_ns = None,
            None => {}
        }
        for (touch, unit) in unit_touches(event, trusted) {
            let list = self.touches.get_or_insert_with(unit, Vec::new);
            if list.len() >= TOUCHES_PER_UNIT {
                list.remove(0);
            }
            list.push((touch, ts));
        }
    }

    /// A file-open event: a unit stop is queued, to be judged by [`Self::take_due`].
    pub(crate) fn on_file_open(&mut self, event: &FileOpenEvent) {
        self.clock_ns = self.clock_ns.max(event.meta.timestamp_ns);
        // Only the journal sensor builds a unit stop, and it does so as pid 1 (`to_unit_stop_event`).
        // The flag is also a bit of `openat`'s `flags` that any process can set on a file it
        // names, so a flagged open from any other pid is a forgery, not a stop (#1102 review).
        // Stopgap until #1127 gives the stop its own event.
        if event.meta.pid != JOURNAL_STOP_PID
            || event.flags & schema::FLAG_UNIT_STOPPED == 0
            || listed_unit(&event.path).is_none()
        {
            return;
        }
        if self.pending.len() >= PENDING_CAP
            && let Some(oldest) = self.pending.pop_front()
            && let Some(alert) = self.judge(&oldest)
        {
            self.ready.push((oldest, alert));
        }
        self.pending.push_back(event.clone());
    }

    /// The queued stops whose wait is over, judged. The sink calls this after every exec and
    /// file-open event, which are what move the clock.
    pub(crate) fn take_due(&mut self) -> Vec<(FileOpenEvent, Alert)> {
        let mut due = std::mem::take(&mut self.ready);
        while let Some(front) = self.pending.front() {
            if front.meta.timestamp_ns.saturating_add(START_WITHIN_NS) > self.clock_ns {
                break;
            }
            let Some(event) = self.pending.pop_front() else {
                break;
            };
            if let Some(alert) = self.judge(&event) {
                due.push((event, alert));
            }
        }
        due
    }

    /// `None` when the stop is explained, else the alert.
    fn judge(&self, event: &FileOpenEvent) -> Option<Alert> {
        let unit = listed_unit(&event.path)?;
        let at = event.meta.timestamp_ns;
        // The window an exec asking for the stop may sit in, either side of the record.
        let asked_from = at.saturating_sub(EXEC_LOOKBACK_NS);
        let asked_to = at.saturating_add(CLOCK_SKEW_NS);
        let touches = self.touches.peek(&unit).map_or(&[][..], Vec::as_slice);

        let stopped_by_exec = touches
            .iter()
            .any(|&(kind, ts)| kind == Touch::Stop && (asked_from..=asked_to).contains(&ts));
        let restarted = touches.iter().any(|&(kind, ts)| match kind {
            Touch::Restart => (asked_from..=asked_to).contains(&ts),
            Touch::Start => (at.saturating_sub(CLOCK_SKEW_NS)..=at.saturating_add(START_WITHIN_NS))
                .contains(&ts),
            Touch::Stop => false,
        });
        let shutting_down = self.shutdown_ns.is_some_and(|ts| {
            (at.saturating_sub(CLOCK_SKEW_NS)..=at.saturating_add(CLOCK_SKEW_NS)).contains(&ts)
                || (ts..=ts.saturating_add(SHUTDOWN_WINDOW_NS)).contains(&at)
        });
        if stopped_by_exec || restarted || shutting_down {
            return None;
        }
        Some(Alert {
            technique: "T1562.001",
            severity: Severity::Medium,
            message: format!(
                "the security service {unit} was stopped with no `systemctl stop` of it, no \
                 start of it within {}s and no host shutdown in progress: a stop over D-Bus or \
                 an API, a kill of the service, or the service exiting by itself (the journal \
                 names no actor)",
                START_WITHIN_NS / 1_000_000_000,
            ),
        })
    }
}

/// The listed unit a journal record's `path` names (lowercase, no `.service`), if it is one of
/// [`SECURITY_SERVICES`]. A launchd label or Windows service never reaches here: the journal is
/// Linux, so only the listed names count and the label prefixes are not consulted.
fn listed_unit(path: &str) -> Option<String> {
    let lower = path.to_ascii_lowercase();
    let name = lower.strip_suffix(".service").unwrap_or(&lower);
    SECURITY_SERVICES.contains(&name).then(|| name.to_owned())
}

/// What an exec does to listed units. A stop is read whatever the image (the exec rule alerts
/// on it); a start or restart is a claim that explains a stop, so it counts only when `trusted`
/// (see [`UnitStops::on_exec`]) and, for an init script, only from `/etc/init.d/`.
fn unit_touches(event: &ExecEvent, trusted: bool) -> Vec<(Touch, String)> {
    let mut touches: Vec<(Touch, String)> = services_stopped(event)
        .into_iter()
        .filter_map(|service| listed_unit(&service))
        .map(|unit| (Touch::Stop, unit))
        .collect();
    let program = program(event);
    let args = args(event);
    let image = event.image_path.to_ascii_lowercase();
    let named: Vec<(Touch, String)> = match program.as_str() {
        _ if !trusted && !image.starts_with("/etc/init.d/") => Vec::new(),
        "systemctl" if trusted => systemctl_starts(&args),
        "service" | "rc-service" | "invoke-rc.d" if trusted => init_script_starts(&args),
        "deb-systemd-invoke" if trusted => deb_systemd_invoke_starts(&args),
        _ if image.starts_with("/etc/init.d/") => args
            .first()
            .and_then(|verb| verb_touch(verb))
            .map(|touch| vec![(touch, program.clone())])
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    touches.extend(
        named
            .into_iter()
            .filter_map(|(touch, unit)| listed_unit(&unit).map(|unit| (touch, unit))),
    );
    touches
}

/// The touch a start-like verb makes; `None` for a verb that does not start anything.
fn verb_touch(verb: &str) -> Option<Touch> {
    match verb {
        "restart" | "try-restart" | "force-reload" | "condrestart" => Some(Touch::Restart),
        "start" | "reload-or-restart" | "try-reload-or-restart" => Some(Touch::Start),
        _ => None,
    }
}

/// Whether `systemctl`-style arguments act on a manager other than the host's system one:
/// `--user` (a user manager has no system unit), `--host`/`-H`, `--machine`/`-M` (another host or
/// a container). Such a call neither starts a local unit nor shuts the local host down.
fn targets_another_manager(args: &[String]) -> bool {
    args.iter().any(|a| {
        a == "--user"
            || a.starts_with("--host")
            || a.starts_with("--machine")
            // `-H`/`-M`, lowercased by `recon::args` (`-h` is `--help`, which acts on nothing).
            || a.starts_with("-h")
            || a.starts_with("-m")
    })
}

/// Whether the arguments only print or check something: `--help`, `--version`, `--dry-run`. Such
/// a call starts nothing and shuts nothing down, so it explains no stop.
fn does_nothing(args: &[String]) -> bool {
    args.iter()
        .any(|a| matches!(a.as_str(), "--help" | "--version" | "--dry-run"))
}

/// `systemctl start|restart|try-restart|reload-or-restart a b`, `systemctl enable --now a`.
fn systemctl_starts(args: &[String]) -> Vec<(Touch, String)> {
    if targets_another_manager(args) || does_nothing(args) {
        return Vec::new();
    }
    let mut positional = args.iter().filter(|a| !a.starts_with('-'));
    let Some(verb) = positional.next() else {
        return Vec::new();
    };
    let touch = if verb == "enable" && args.iter().any(|a| a == "--now") {
        Touch::Start
    } else if let Some(touch) = verb_touch(verb) {
        touch
    } else {
        return Vec::new();
    };
    positional.map(|unit| (touch, unit.clone())).collect()
}

/// `service X start|restart`, `rc-service X restart`, `invoke-rc.d X restart`.
fn init_script_starts(args: &[String]) -> Vec<(Touch, String)> {
    match args {
        [name, verb, ..] if !name.starts_with('-') => verb_touch(verb)
            .map(|touch| vec![(touch, name.clone())])
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// `deb-systemd-invoke [--user] start|restart a b` (Debian maintainer scripts).
fn deb_systemd_invoke_starts(args: &[String]) -> Vec<(Touch, String)> {
    if targets_another_manager(args) || does_nothing(args) {
        return Vec::new();
    }
    let mut positional = args.iter().filter(|a| !a.starts_with('-'));
    let Some(touch) = positional.next().and_then(|verb| verb_touch(verb)) else {
        return Vec::new();
    };
    positional.map(|unit| (touch, unit.clone())).collect()
}

/// Whether a `reboot`/`poweroff`/`halt` option still brings the host down. An allowlist: an
/// option not listed (`-w`, `--help`, `--version`, a typo) gives no window. Short options may be
/// clustered (`-fn`); long ones must be spelled out.
fn shuts_down_option(arg: &str) -> bool {
    match arg.strip_prefix("--") {
        Some(long) => matches!(
            long,
            "force" | "no-wtmp" | "no-sync" | "no-wall" | "poweroff" | "reboot" | "halt"
        ),
        None => arg
            .strip_prefix('-')
            .is_some_and(|short| !short.is_empty() && short.chars().all(|c| "fdnp".contains(c))),
    }
}

/// What an exec does to the host's shutdown state.
#[derive(Debug, PartialEq, Eq)]
enum Shutdown {
    /// The host is told to go down now: the units stop in the next minutes.
    Now,
    /// A scheduled shutdown is cancelled: the window it opened is closed.
    Cancel,
}

/// Whether this exec tells the host to shut down or reboot **now** (`Now`), or cancels one
/// (`Cancel`). `shutdown` counts only with an immediate time (`now`, `+0`): `+N` and `HH:MM`
/// schedule a shutdown that stops nothing yet, and a bare `shutdown` is `+1` for systemd. `-k`
/// only warns. `reboot`, `poweroff`, `halt` (only with argv captured and every option one that still shuts down, see [`shuts_down_option`]), `systemctl reboot|poweroff|halt|kexec` and
/// `init`/`telinit 0|6` are immediate, unless `systemctl` is given `--when=` (a schedule, or
/// `--when=cancel`).
fn shutdown_effect(event: &ExecEvent) -> Option<Shutdown> {
    let program = program(event);
    let args = args(event);
    match program.as_str() {
        "reboot" | "poweroff" | "halt" => {
            // Fail towards an alert: with no argv captured (the usual case for a short-lived
            // process, #1118) the options are unknown, so `reboot -w` or `reboot --help` cannot
            // be told from a real one. Count the command only when its options are all ones that
            // still bring the host down; anything else (`-w`, `--help`, a bad option) does not.
            if event.argv.is_empty() && event.cmdline.trim().is_empty() {
                return None;
            }
            args.iter()
                .all(|a| shuts_down_option(a))
                .then_some(Shutdown::Now)
        }
        "shutdown" => {
            if does_nothing(&args) {
                return None;
            }
            let short = |flag: char| {
                args.iter()
                    .any(|a| a.starts_with('-') && !a.starts_with("--") && a.contains(flag))
            };
            if short('c') || args.iter().any(|a| a == "--cancel") {
                return Some(Shutdown::Cancel);
            }
            if short('k') {
                return None;
            }
            // The first argument that is not an option is the time; the rest is the wall message.
            let time = args.iter().find(|a| !a.starts_with('-'))?;
            (time == "now" || time == "+0").then_some(Shutdown::Now)
        }
        "systemctl" => {
            if targets_another_manager(&args) || does_nothing(&args) {
                return None;
            }
            let verb = args.iter().find(|a| !a.starts_with('-'))?;
            if !matches!(
                verb.as_str(),
                "reboot" | "poweroff" | "halt" | "kexec" | "soft-reboot"
            ) {
                return None;
            }
            let when = args.iter().enumerate().find_map(|(i, a)| {
                a.strip_prefix("--when=")
                    .or_else(|| (a == "--when").then(|| args.get(i + 1).map_or("", String::as_str)))
            });
            match when {
                None => Some(Shutdown::Now),
                Some("cancel") => Some(Shutdown::Cancel),
                Some(_) => None,
            }
        }
        "init" | "telinit" => args
            .first()
            .is_some_and(|level| level == "0" || level == "6")
            .then_some(Shutdown::Now),
        _ => None,
    }
}
