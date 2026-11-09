//! Execution (TA0002): command-line content of a single exec.

use schema::{ExecEvent, detection::Severity};

use crate::Alert;

/// T1059.004 — Command and Scripting Interpreter: Unix Shell, sub-case base64-encoded
/// command. Deliberately simple heuristic (`base64` substrings + a decode flag): no
/// entropy analysis here — that is the role of the ML model as a complement, not of
/// this deterministic rule.
#[must_use]
pub(crate) fn check_base64_decode(event: &ExecEvent) -> Option<Alert> {
    let cmdline = &event.cmdline;
    let has_base64 = cmdline.contains("base64");
    let has_decode_flag =
        cmdline.contains("-d") || cmdline.contains("-D") || cmdline.contains("--decode");
    if has_base64 && has_decode_flag {
        Some(Alert {
            technique: "T1059.004",
            severity: Severity::Medium,
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
pub(crate) fn check_encoded_powershell(event: &ExecEvent) -> Option<Alert> {
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
            severity: Severity::Medium,
            message: format!(
                "pid={} comm={}: PowerShell EncodedCommand invocation: {cmdline}",
                event.meta.pid, event.meta.comm,
            ),
        })
    } else {
        None
    }
}
