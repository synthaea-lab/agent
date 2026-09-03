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
    check_base64_decode(event).into_iter().collect()
}

/// Evaluates all stateless rules applicable to a `FileOpenEvent`.
#[must_use]
pub fn evaluate_file_open(event: &FileOpenEvent) -> Vec<Alert> {
    check_persistence_write(event).into_iter().collect()
}
