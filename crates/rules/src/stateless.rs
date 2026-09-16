//! Stateless rules: a single event is enough to decide — no history, no state.

use schema::{ExecEvent, FileOpenEvent};

use crate::{Alert, has_write_intent};

/// T1059.004 — Command and Scripting Interpreter: Unix Shell, sub-case base64-encoded
/// command. Deliberately simple heuristic (`base64` substrings + a decode flag): no
/// entropy analysis here — that is the role of the ML model as a complement, not of
/// this deterministic rule.
#[must_use]
pub fn check_base64_decode(event: &ExecEvent) -> Option<Alert> {
    let cmdline = &event.cmdline;
    let has_base64 = cmdline.contains("base64");
    let has_decode_flag =
        cmdline.contains("-d") || cmdline.contains("-D") || cmdline.contains("--decode");
    if has_base64 && has_decode_flag {
        Some(Alert {
            technique: "T1059.004",
            message: format!(
                "pid={} comm={}: command line contains a base64 decode: {cmdline}",
                event.meta.pid, event.meta.comm,
            ),
        })
    } else {
        None
    }
}

/// T1059.001 — Command and Scripting Interpreter: `PowerShell`, sub-case
/// base64-encoded command (`-EncodedCommand` / `-enc`). Same philosophy as
/// `check_base64_decode`: deterministic substring heuristic on the cmdline, no
/// entropy analysis (that is the ML model's role as a complement, per
/// `threat-model.md`).
///
/// Matches the `PowerShell` parameter alias `-EncodedCommand` in its canonical
/// form and the short truncation `-enc` — the two shapes observed in T1059.001
/// tradecraft in the wild. Rarer intermediate truncations (`-e`, `-en`,
/// `-enco`, ...) are accepted by `PowerShell` itself but are a follow-up
/// widening once we have telemetry to guide the trade-off against false
/// positives (any shell script with a token starting with `-e` is very common
/// on Linux).
///
/// Requires the cmdline to also mention a `PowerShell` interpreter
/// (`powershell` on Windows via `powershell.exe`, `pwsh` on Linux/macOS and
/// `PowerShell` Core on Windows) to filter out unrelated
/// `-enc`/`-encodedcommand` tokens (an `openssl enc` pipeline, a fictitious
/// tool with its own `-encodedcommand` flag, ...). Both anchor strings are
/// specific enough that false positives are negligible in practice.
/// Case-insensitive on the full string — `PowerShell` parameter names and
/// image paths are.
#[must_use]
pub fn check_encoded_powershell(event: &ExecEvent) -> Option<Alert> {
    let cmdline = &event.cmdline;
    let cmdline_lower = cmdline.to_ascii_lowercase();
    let mentions_powershell =
        cmdline_lower.contains("powershell") || cmdline_lower.contains("pwsh");
    if !mentions_powershell {
        return None;
    }
    let has_encoded_flag = cmdline_lower
        .split(|c: char| c.is_whitespace() || c == '\0')
        .any(|token| token == "-encodedcommand" || token == "-enc");
    if has_encoded_flag {
        Some(Alert {
            technique: "T1059.001",
            message: format!(
                "pid={} comm={}: PowerShell EncodedCommand invocation: {cmdline}",
                event.meta.pid, event.meta.comm,
            ),
        })
    } else {
        None
    }
}

/// T1037.004 (Boot or Logon Initialization Scripts) / T1053.003 (Cron) — write to a
/// known persistence path. List deliberately restricted to the threat-model examples,
/// not exhaustive coverage of Linux persistence mechanisms. Per-platform path sets are
/// follow-up scope (Windows persistence arrives with registry telemetry, M3).
const PERSISTENCE_PATH_PATTERNS: &[&str] = &[
    ".bashrc",
    "/etc/profile.d/",
    "/etc/cron.d/",
    "/etc/systemd/system/",
];

/// A path captured by the `open` collector can be relative to an unresolved `dfd`
/// (known limitation of the eBPF collector) — the substring filter tolerates this case
/// as long as the meaningful path fragment (e.g. `.bashrc`) is present verbatim.
#[must_use]
pub fn check_persistence_write(event: &FileOpenEvent) -> Option<Alert> {
    let path = &event.path;
    let matched_pattern = PERSISTENCE_PATH_PATTERNS
        .iter()
        .find(|pattern| path.contains(*pattern))?;

    if !has_write_intent(event.flags) {
        return None;
    }

    Some(Alert {
        technique: "T1037.004/T1053.003",
        message: format!(
            "pid={} comm={}: write to a known persistence path ({matched_pattern}): {path}",
            event.meta.pid, event.meta.comm,
        ),
    })
}

/// Evaluates all stateless rules applicable to an `ExecEvent`.
#[must_use]
pub fn evaluate_exec(event: &ExecEvent) -> Vec<Alert> {
    check_base64_decode(event)
        .into_iter()
        .chain(check_encoded_powershell(event))
        .collect()
}

/// T1611 — Escape to Host: a containerized process opening `/proc/<pid>/root` reaches
/// through procfs into another process's root filesystem — normal containerized
/// workloads have no legitimate reason to do this. The textbook path is a container
/// run with a shared/host PID namespace (`--pid=host`) reaching `/proc/1/root` to
/// read/write the host's own filesystem (issue #80's suggested example). This needs
/// the container attribution #80 built, since the signal is "a containerized process
/// did X", not X alone — host-side tooling reaches into other processes'
/// `/proc/<pid>/root` constantly and legitimately (procfs walkers, `nsenter`,
/// debuggers); a bare-metal process doing this is unremarkable, a containerized one
/// almost never has a legitimate reason to.
///
/// Coverage gap, confirmed against a real Docker daemon: this needs `event.meta
/// .container` to be populated, and the sensor's attribution loses a race for a
/// process whose entire lifetime is one `open()` then exit (a bare `cat <path>`) — see
/// `read_container_id`'s doc comment in `sensor-linux`. A slower/more deliberate escape
/// (a shell that stays alive past the read) is attributed correctly and this rule fires;
/// a one-shot command is not detected. Not a bug in this rule — a sensor-side tradeoff.
#[must_use]
pub fn check_proc_root_escape(event: &FileOpenEvent) -> Option<Alert> {
    let container = event.meta.container.as_ref()?;

    let mut segments = event.path.split('/').filter(|s| !s.is_empty());
    let is_proc_pid_root = matches!(segments.next(), Some("proc"))
        && segments.next().is_some_and(|s| s.parse::<u64>().is_ok())
        && matches!(segments.next(), Some("root"));
    if !is_proc_pid_root {
        return None;
    }

    Some(Alert {
        technique: "T1611",
        message: format!(
            "pid={} comm={} container={}: opened {} — containerized process reaching \
             into another process's root filesystem via procfs, a common \
             container-escape path",
            event.meta.pid, event.meta.comm, container.id, event.path,
        ),
    })
}

/// Evaluates all stateless rules applicable to a `FileOpenEvent`.
#[must_use]
pub fn evaluate_file_open(event: &FileOpenEvent) -> Vec<Alert> {
    check_persistence_write(event)
        .into_iter()
        .chain(check_proc_root_escape(event))
        .collect()
}
