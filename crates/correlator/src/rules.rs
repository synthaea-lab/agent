//! Co-occurrence rules — one function per scenario, evaluated by the engine over the
//! bus's current window.

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
