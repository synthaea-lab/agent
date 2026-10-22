//! SERVICE-STOP-BURST (T1489, #381): the services an intruder stops before encrypting.
//!
//! Ransomware stops the database, backup, mail and security services first so their files
//! are not held open and nothing restores them. A hands-on or scripted run does it in one
//! go: a dozen `net stop` or one `Stop-Service a,b,c,d,e`. One `systemctl stop nginx` is
//! maintenance, so the rule counts **distinct services stopped** from one lineage (see
//! [`crate::recon`]) inside a sliding window, and an exec that names several services
//! counts each of them.
//!
//! What counts: `systemctl stop` / `disable --now` / `mask --now` and `service X stop` and
//! `/etc/init.d/X stop` (Linux); `net stop`, `sc stop` and `Stop-Service` (Windows);
//! `launchctl bootout` / `unload` / `remove` / `stop` (macOS). A `Get-Service ... |
//! Stop-Service` pipeline names no service and counts as one, labelled as such.
//!
//! **False positives, and the calibration** (no fleet data yet, so five in a minute is a
//! choice, not a measurement): a maintenance window, a shutdown script, a package upgrade
//! that stops what it replaces, and configuration management stopping a stack all stop
//! several services. That is the accepted cost and why the alert is Medium and not High:
//! it names the burst and the services, the verdict decides what it adds to. No process is
//! excluded by name.
//!
//! The alert is a plain T1489 detection. It does not feed the ransomware reflex or the
//! damage manifest of #82: both consume T1486 alerts only, and joining them is a decision
//! of its own (a service-stop burst followed by mass renames would be the corroboration).

use schema::ExecEvent;

use crate::recon::{args, program};

/// Distinct services, from one lineage, that make a burst.
pub(crate) const SERVICE_STOP_THRESHOLD: u32 = 5;
/// Sliding window of [`SERVICE_STOP_THRESHOLD`].
pub(crate) const SERVICE_STOP_WINDOW_NS: u64 = 60_000_000_000; // 60s

/// The most service names one exec contributes: a command line can name thousands, and the
/// threshold only needs to be reached.
const MAX_NAMES_PER_EXEC: usize = 32;

/// The label an unnamed pipeline stop counts as.
const PIPELINE_LABEL: &str = "Stop-Service (piped)";

/// The services this exec stops, lowercase, without a `.service` suffix; empty for anything
/// that is not a stop.
pub(crate) fn services_stopped(event: &ExecEvent) -> Vec<String> {
    let program = program(event);
    let args = args(event);
    let mut names = match program.as_str() {
        "systemctl" => systemctl(&args),
        "service" | "rc-service" => init_script(&args),
        "net" | "net1" => net_stop(&args),
        "sc" => sc_stop(&args),
        "launchctl" => launchctl(&args),
        "powershell" | "pwsh" => stop_service(&event.cmdline),
        _ if event.image_path.contains("/init.d/")
            && args.first().map(String::as_str) == Some("stop") =>
        {
            vec![program.clone()]
        }
        _ => Vec::new(),
    };
    names.truncate(MAX_NAMES_PER_EXEC);
    names
}

/// `systemctl stop a b`, `systemctl disable --now a`, `systemctl mask --now a`: the first
/// argument that is not a flag is the verb, the rest that are not flags are units.
fn systemctl(args: &[String]) -> Vec<String> {
    let mut positional = args.iter().filter(|a| !a.starts_with('-'));
    let Some(verb) = positional.next() else {
        return Vec::new();
    };
    let now = args.iter().any(|a| a == "--now");
    let stops = verb == "stop" || (now && (verb == "disable" || verb == "mask"));
    if !stops {
        return Vec::new();
    }
    positional.map(|unit| unit_name(unit)).collect()
}

/// `service X stop`, `rc-service X stop`: the unit then the action.
fn init_script(args: &[String]) -> Vec<String> {
    match args {
        [name, action, ..] if action == "stop" && !name.starts_with('-') => {
            vec![unit_name(name)]
        }
        _ => Vec::new(),
    }
}

/// `net stop <display name>`: the rest of the line is one name (it may hold spaces).
fn net_stop(args: &[String]) -> Vec<String> {
    match args.split_first() {
        Some((verb, rest)) if verb == "stop" => {
            let name: Vec<&str> = rest
                .iter()
                .filter(|a| !a.starts_with('/'))
                .map(String::as_str)
                .collect();
            if name.is_empty() {
                Vec::new()
            } else {
                vec![name.join(" ")]
            }
        }
        _ => Vec::new(),
    }
}

/// `sc stop <name>`, `sc \\host stop <name>`.
fn sc_stop(args: &[String]) -> Vec<String> {
    let rest = match args.first() {
        Some(host) if host.starts_with("\\\\") => &args[1..],
        _ => args,
    };
    match rest {
        [verb, name, ..] if verb == "stop" => vec![name.clone()],
        _ => Vec::new(),
    }
}

/// `launchctl bootout <domain>/<label>`, `unload [-w] <plist>`, `remove <label>`,
/// `stop <label>`.
fn launchctl(args: &[String]) -> Vec<String> {
    let mut positional = args.iter().filter(|a| !a.starts_with('-'));
    let Some(verb) = positional.next() else {
        return Vec::new();
    };
    if !matches!(verb.as_str(), "bootout" | "unload" | "remove" | "stop") {
        return Vec::new();
    }
    positional
        .map(|target| {
            // A label is the last path segment of `system/com.vendor.x`; a plist is its stem.
            let last = target.rsplit('/').next().unwrap_or(target);
            last.strip_suffix(".plist").unwrap_or(last).to_owned()
        })
        .collect()
}

/// `Stop-Service a,b,c` / `Stop-Service -Name a,b -Force`; a pipeline into it names nothing.
fn stop_service(cmdline: &str) -> Vec<String> {
    let line = cmdline.to_ascii_lowercase();
    let Some(at) = line.find("stop-service") else {
        return Vec::new();
    };
    let before = &line[..at];
    let after = &line[at + "stop-service".len()..];
    // `Get-Service ... | Stop-Service`: the services come from the pipeline.
    if before.trim_end().ends_with('|') {
        return vec![PIPELINE_LABEL.to_owned()];
    }
    let mut names = Vec::new();
    let mut tokens = after.split_whitespace().peekable();
    while let Some(token) = tokens.next() {
        let token = token.trim_matches(['"', '\'', ';']);
        if token == "-name" || token == "-n" {
            if let Some(list) = tokens.next() {
                names.extend(split_names(list));
            }
        } else if token.starts_with('-') || token == "|" {
            // `-Force`, `-PassThru`, ...; a later pipe ends the command.
            if token == "|" {
                break;
            }
        } else if names.is_empty() {
            names.extend(split_names(token));
        }
    }
    names
}

fn split_names(list: &str) -> impl Iterator<Item = String> + '_ {
    list.split(',')
        .map(|n| n.trim_matches(['"', '\'', ';', ' ']))
        .filter(|n| !n.is_empty())
        .map(str::to_owned)
}

fn unit_name(unit: &str) -> String {
    unit.strip_suffix(".service").unwrap_or(unit).to_owned()
}
