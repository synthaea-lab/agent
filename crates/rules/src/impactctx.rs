//! Impact context (#973): what an Impact finding is told about the lineage that caused it.
//!
//! Two facts, both attached to a finding that already exists. Neither raises anything by
//! itself, and neither changes what any other consumer reads.
//!
//! **A service-stop burst before mass renames (corroboration).** SERVICE-STOP-BURST (T1489,
//! [`crate::servicestop`]) remembers the lineage that raised it. When a T1486 finding comes
//! from the same lineage within [`BURST_TO_RENAME_WINDOW_NS`], the T1486 message says so. The
//! finding keeps its technique and its severity (Critical already, so there is nothing to
//! raise), no threshold moves, and the damage manifest and the reflex kill read the technique
//! and the event, never the message: the boundary kept by #381 holds.
//!
//! **A shutdown or reboot after an Impact finding (T1529, case context).** A reboot is
//! ordinary: patch windows, installers, cloud agents and every admin do it. So the command is
//! never a finding alone. It is reported, Low, only when the same lineage already raised a T1486
//! or a T1490 finding within [`IMPACT_TO_SHUTDOWN_WINDOW_NS`], and then it says that (the
//! host going down after encryption or recovery destruction is the finish of the run: it
//! drops what memory holds and ends the incident response in progress). Severity is Low so a
//! verdict, which takes the maximum over an entity's findings, cannot rise because of it.
//!
//! What identifies "the same lineage" is [`crate::recon::Lineage`], the process whose children
//! are counted together. A finding arms the lineages that can plausibly own the follow-up:
//! the lineage its process was exec'd under (the shell that launched an encryptor) and the
//! process itself (an encryptor that runs `reboot` as its own child).
//!
//! **Which command counts as a shutdown** is read from the program name where that is enough
//! (`shutdown`, `reboot`, `halt`, `poweroff`), because the argv of a short-lived process can
//! be empty (ADR-0045, <https://github.com/synthaea-lab/edr-agent/issues/48>). The commands whose meaning is in the arguments (`systemctl
//! reboot`, `init 6`) count only when the arguments are there, which fails closed. A visible
//! argument that says the command does nothing (`shutdown -c`, `-k`, `--help`, `--dry-run`,
//! `reboot -w`, `shutdown /a`) is excluded. The better source for the fact itself is the
//! manager's own journal record (ADR-0006, `reboot.target`); it needs a new event and is not
//! built here.

use schema::ExecEvent;

use crate::recon::{Lineage, args, program};

/// How long after a service-stop burst a mass-rename finding is still told about it.
pub(crate) const BURST_TO_RENAME_WINDOW_NS: u64 = 900_000_000_000; // 15 min
/// How long after a T1486 or T1490 finding a shutdown from the same lineage is context for it.
pub(crate) const IMPACT_TO_SHUTDOWN_WINDOW_NS: u64 = 1_800_000_000_000; // 30 min

/// A SERVICE-STOP-BURST finding, as remembered per lineage.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BurstMark {
    pub(crate) at_ns: u64,
    pub(crate) services: u32,
}

/// A T1486 or T1490 finding, as remembered per lineage.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ImpactMark {
    pub(crate) at_ns: u64,
    pub(crate) technique: &'static str,
    /// The shutdown was already reported for this finding: one note per finding.
    pub(crate) reported: bool,
}

/// The shutdown or reboot command this exec runs, as a short label (`reboot`, `systemctl
/// poweroff`); `None` for anything else and for a command that visibly does nothing.
pub(crate) fn shutdown_command(event: &ExecEvent) -> Option<String> {
    let program = program(event);
    let args = args(event);
    let any = |flags: &[&str]| args.iter().any(|a| flags.contains(&a.as_str()));
    // Short flags may be bundled (`-ck`): a letter of `letters` in any `-xyz` group.
    let bundled = |letters: &[char]| {
        args.iter().any(|a| {
            a.starts_with('-')
                && !a.starts_with("--")
                && a.chars().skip(1).any(|c| letters.contains(&c))
        })
    };
    let inert = any(&["--help", "--version", "--dry-run", "/?"]);
    match program.as_str() {
        // Windows spells the options `/s /r /p`; it is read from the first `/` argument.
        "shutdown" if args.iter().any(|a| a.starts_with('/')) => {
            let acts = any(&["/s", "/r", "/p", "/g", "/sg"]);
            (acts && !any(&["/a"]) && !inert).then_some(program)
        }
        // `-c` cancels, `-k` only warns.
        "shutdown" => (!bundled(&['c', 'k']) && !any(&["--cancel"]) && !inert).then_some(program),
        // `-w` only writes the wtmp record.
        "reboot" | "halt" | "poweroff" => (!bundled(&['w']) && !inert).then_some(program),
        "systemctl" => {
            let verb = args.iter().find(|a| !a.starts_with('-'))?;
            matches!(
                verb.as_str(),
                "reboot" | "poweroff" | "halt" | "kexec" | "soft-reboot"
            )
            .then(|| format!("systemctl {verb}"))
            .filter(|_| !inert)
        }
        "init" | "telinit" => matches!(
            args.iter()
                .find(|a| !a.starts_with('-'))
                .map(String::as_str),
            Some("0" | "6")
        )
        .then_some(program),
        _ => None,
    }
}

/// The lineages a finding from `pid` arms: the lineage `pid` was exec'd under, when known,
/// and `pid` itself as the parent of what it starts.
pub(crate) fn armed_lineages(
    exec_lineage: Option<Lineage>,
    pid: u32,
    generation: Option<u64>,
) -> impl Iterator<Item = Lineage> {
    exec_lineage.into_iter().chain(Some((pid, generation)))
}
