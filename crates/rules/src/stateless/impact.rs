//! Impact (TA0040): system recovery inhibited.

use schema::{ExecEvent, detection::Severity};

use crate::Alert;

/// T1490 — Inhibit System Recovery. The commands that destroy a host's
/// ability to roll back before encryption: shadow-copy deletion, backup
/// catalog wipes, recovery-boot disabling, and Time Machine local-snapshot
/// destruction. Deterministic multi-token matches on the command line — each
/// pattern requires every listed token, so `vssadmin list shadows` never
/// fires.
#[must_use]
pub(crate) fn check_recovery_inhibit(event: &ExecEvent) -> Option<Alert> {
    const PATTERNS: &[(&str, &[&str])] = &[
        ("shadow-copy deletion", &["vssadmin", "delete", "shadows"]),
        ("shadow-copy deletion", &["wmic", "shadowcopy", "delete"]),
        ("backup catalog wipe", &["wbadmin", "delete", "catalog"]),
        (
            "recovery boot disabled",
            &["bcdedit", "recoveryenabled", "no"],
        ),
        (
            "local snapshot destruction",
            &["tmutil", "deletelocalsnapshots"],
        ),
    ];
    let cmdline = event.cmdline.to_ascii_lowercase();
    let (label, _) = PATTERNS
        .iter()
        .find(|(_, tokens)| tokens.iter().all(|t| cmdline.contains(t)))?;
    Some(Alert {
        technique: "T1490",
        severity: Severity::High,
        message: format!(
            "pid={} comm={}: {label} — the pre-encryption tell: {}",
            event.meta.pid, event.meta.comm, event.cmdline,
        ),
    })
}
