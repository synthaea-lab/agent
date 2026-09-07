//! Co-occurrence rules — one function per scenario, evaluated by the engine over the
//! bus's current window.

use std::collections::{HashMap, HashSet};

use schema::Event;

use crate::{bus::EventBus, event::is_file_write};

#[derive(Debug, Clone)]
pub struct CorrelationAlert {
    pub technique: &'static str,
    pub message: String,
}

/// T1059/T1071 — A recently spawned process establishes a network connection within
/// the same time window. Weak signal on its own, strong in combination (LOLBIN +
/// beacon, for example). Co-occurrence by pid, order unconstrained.
pub(crate) fn rule_spawn_connect(pid: u32, bus: &EventBus) -> Option<CorrelationAlert> {
    let events: Vec<&Event> = bus.events_for_pid(pid).collect();

    let has_exec = events.iter().any(|e| matches!(e, Event::Exec(_)));
    let has_connect = events.iter().any(|e| matches!(e, Event::Connect(_)));

    if has_exec && has_connect {
        Some(CorrelationAlert {
            technique: "T1059/T1071",
            message: format!("pid={pid}: spawn + network connection in the same time window"),
        })
    } else {
        None
    }
}

/// Returns `true` if the path looks like a downloaded payload:
/// executable/script extension or suspicious temporary location.
/// T1105 filter: avoids FPs on app caches (sentry, Chrome, Spotify…).
fn is_payload_file(path: &str) -> bool {
    let p = path.to_lowercase();
    // Extensions carrying executable code or scripts
    let suspicious_ext = p.ends_with(".exe")
        || p.ends_with(".dll")
        || p.ends_with(".bat")
        || p.ends_with(".ps1")
        || p.ends_with(".vbs")
        || p.ends_with(".hta")
        || p.ends_with(".cmd")
        || p.ends_with(".scr")
        || p.ends_with(".msi")
        || p.ends_with(".jar")
        || p.ends_with(".js")
        || p.ends_with(".jse");
    // Locations systematically used by droppers — both path grammars (review
    // finding: the shipped Linux dropper scenario writes /tmp/… with no extension,
    // and the Windows-only separators made the full-chain alert impossible).
    let suspicious_path = p.contains("\\temp\\")
        || p.contains("\\tmp\\")
        || p.contains("\\downloads\\")
        || p.contains("\\startup\\")
        || p.starts_with("/tmp/")
        || p.starts_with("/var/tmp/")
        || p.starts_with("/dev/shm/")
        || p.contains("/downloads/");
    suspicious_ext || suspicious_path
}

/// Write of a payload file: write intent AND payload path/extension.
/// The write-bit test lives in [`is_file_write`] — a single place.
fn writes_payload_file(event: &Event) -> bool {
    match event {
        Event::FileOpen(f) => is_file_write(event) && is_payload_file(&f.path),
        _ => false,
    }
}

/// T1105 — A process connects AND writes a payload file within the same window.
/// Staging signal: download to disk over a network connection.
/// Co-occurrence by pid, order unconstrained.
/// Filter: only files with an executable/script extension or in a temp directory
/// are considered — eliminates FPs on app caches (sentry, Chrome, Spotify…).
pub(crate) fn rule_connect_filewrite(pid: u32, bus: &EventBus) -> Option<CorrelationAlert> {
    let events: Vec<&Event> = bus.events_for_pid(pid).collect();

    let has_connect = events.iter().any(|e| matches!(e, Event::Connect(_)));
    let has_filewrite = events.iter().any(|e| writes_payload_file(e));

    if has_connect && has_filewrite {
        Some(CorrelationAlert {
            technique: "T1105",
            message: format!(
                "pid={pid}: network connection + file write in the same window — suspected staging"
            ),
        })
    } else {
        None
    }
}

/// T1105 (full chain) — Spawn + network connection + file write by the same pid
/// within the same window. High confidence: complete dropper (spawned, connects,
/// writes a payload to disk).
pub(crate) fn rule_spawn_connect_filewrite(pid: u32, bus: &EventBus) -> Option<CorrelationAlert> {
    let events: Vec<&Event> = bus.events_for_pid(pid).collect();

    let has_exec = events.iter().any(|e| matches!(e, Event::Exec(_)));
    let has_connect = events.iter().any(|e| matches!(e, Event::Connect(_)));
    let has_filewrite = events.iter().any(|e| writes_payload_file(e));

    if has_exec && has_connect && has_filewrite {
        Some(CorrelationAlert {
            technique: "T1105/T1059/T1071",
            message: format!(
                "pid={pid}: spawn + network connection + file write — complete dropper chain"
            ),
        })
    } else {
        None
    }
}

/// T1059/T1071 (reinforced) — A process respawns several times AND establishes
/// network connections. SELF-SPAWN + network combination: automatic respawn with
/// beaconing, persistent C2 pattern.
///
/// Correlated by (ppid, comm), not by literal pid: a real respawn (fork+exec, e.g.
/// a listener restarted after each crash/connection) gets a new pid on every
/// iteration — filtering by the `pid` of the single current event can therefore
/// never accumulate several `Exec`s for a real scenario (see
/// lab/scenarios/respawn-beacon.sh, which documented the hypothesis; confirmed by
/// rereading the original test, which artificially reused the same pid for the 3
/// execs). Same principle as SELF-SPAWN in `rules`, which already correlates on
/// (ppid, comm).
const RESPAWN_THRESHOLD: usize = 3;

pub(crate) fn rule_respawn_connect(pid: u32, bus: &EventBus) -> Option<CorrelationAlert> {
    let (ppid, comm) = bus
        .events_for_pid(pid)
        .next()
        .map(|e| (e.meta().ppid, e.meta().comm.clone()))?;
    let events: Vec<&Event> = bus.events_for_ppid_comm(ppid, &comm).collect();

    let spawn_count = events
        .iter()
        .filter(|e| matches!(e, Event::Exec(_)))
        .count();
    let has_connect = events.iter().any(|e| matches!(e, Event::Connect(_)));

    if spawn_count >= RESPAWN_THRESHOLD && has_connect {
        Some(CorrelationAlert {
            technique: "T1059/T1071",
            message: format!(
                "ppid={ppid} comm={comm}: {spawn_count} spawns + network connection — automatic respawn with suspected beaconing"
            ),
        })
    } else {
        None
    }
}

/// T1048.003 / T1071.004 — data exfiltration or C2 tunnelled over DNS. A single
/// process issues many DNS queries in the window that share one parent domain but
/// each carry a distinct leftmost label that is both long and high-entropy — the
/// shape of data chunked and base32/hex-encoded into subdomains (`iodine`, `dnscat2`,
/// `DNSExfiltrator`). Co-occurrence by pid, order unconstrained.
///
/// Only DNS telemetry feeds this today (Windows ETW DNS-Client, EID 3008); the rule
/// itself is source-agnostic and will pick up a Linux DNS sensor unchanged.
///
/// Parent-domain grouping is a plain "last two labels" split — it over-groups under
/// multi-part public suffixes (`co.uk`, `s3.amazonaws.com`), which only makes the
/// rule *less* likely to fire (queries scattered across sibling parents), never a
/// false positive. A real public-suffix list is deferred (issue tracked with the
/// rest of the DNS work).
///
/// Thresholds (Nikolas, 2026-09-07): entropy > 3.5 bits/char on the leftmost label,
/// label length > 30, N >= 10 distinct such subdomains under one parent within the
/// window. To be re-tuned against a lab capture.
const DNS_TUNNEL_MIN_QUERIES: usize = 10;
const DNS_TUNNEL_LABEL_MIN_LEN: usize = 30;
const DNS_TUNNEL_LABEL_MIN_ENTROPY: f64 = 3.5;

/// Shannon entropy of `s` in bits per character (0.0 for the empty string).
/// Encoded payload labels land around 4–5 bits/char (base32 ≈ 5 max); dictionary
/// hostnames and CDN hashes sit well below `DNS_TUNNEL_LABEL_MIN_ENTROPY`.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let len = s.chars().count() as f64;
    counts
        .values()
        .map(|&n| {
            let p = n as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// `("aGVsbG8", "example.com")` for `aGVsbG8.example.com`; `None` when the name has
/// fewer than three labels (nothing to encode data into) or is malformed.
fn split_leftmost_label(query: &str) -> Option<(&str, String)> {
    let name = query.trim_end_matches('.');
    let labels: Vec<&str> = name.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() < 3 {
        return None;
    }
    let leftmost = labels[0];
    let parent = labels[labels.len() - 2..].join(".");
    Some((leftmost, parent))
}

fn is_tunnel_like_label(label: &str) -> bool {
    label.len() > DNS_TUNNEL_LABEL_MIN_LEN
        && shannon_entropy(&label.to_ascii_lowercase()) > DNS_TUNNEL_LABEL_MIN_ENTROPY
}

pub(crate) fn rule_dns_exfil(pid: u32, bus: &EventBus) -> Option<CorrelationAlert> {
    let comm = bus
        .events_for_pid(pid)
        .next()
        .map(|e| e.meta().comm.clone())?;

    // parent domain → set of distinct tunnel-like leftmost labels seen under it.
    let mut per_parent: HashMap<String, HashSet<String>> = HashMap::new();
    for event in bus.events_for_pid(pid) {
        let Event::DnsQuery(dns) = event else {
            continue;
        };
        let Some((label, parent)) = split_leftmost_label(&dns.query) else {
            continue;
        };
        if is_tunnel_like_label(label) {
            per_parent
                .entry(parent)
                .or_default()
                .insert(label.to_ascii_lowercase());
        }
    }

    let (parent, labels) = per_parent
        .into_iter()
        .max_by_key(|(_, labels)| labels.len())?;
    let count = labels.len();
    if count >= DNS_TUNNEL_MIN_QUERIES {
        Some(CorrelationAlert {
            technique: "T1048.003/T1071.004",
            message: format!(
                "pid={pid} comm={comm}: {count} distinct high-entropy subdomains of {parent} \
                 within the window — suspected DNS tunnelling / exfiltration"
            ),
        })
    } else {
        None
    }
}
