//! Diffed package inventory (issue #87): wires `inventory::{parse_dpkg_status,
//! diff_packages}` into the agent. Periodically re-reads `dpkg`'s status database,
//! diffs it against the snapshot persisted from the last check, and turns every
//! change into a real [`schema::Event::PackageChange`] through the normal sink
//! path — unlike `tamper`'s `sink.emit` (a local-only alert line), going through
//! [`EventSink::on_event`] reaches `rules::evaluate_package_change`, becomes a
//! real `Detection`, and is uploaded and case-attachable, which "server side
//! feeds graph/prevalence" (#87) needs.
//!
//! Linux only: `dpkg` is Debian/Ubuntu-specific. An rpm-based host's package
//! inventory, and every inventory category besides packages, stay tracked by #87.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use inventory::{PackageChangeKind, PackageSnapshot};
use schema::{
    Event, EventMeta, PackageChangeEvent, PackageChangeKind as SchemaChangeKind, User,
    sensor::EventSink,
};

use crate::sink::DetectionSink;

/// How often the snapshot is re-read and re-diffed after the first, immediate
/// check (see [`spawn_monitor`]'s doc for why the first one does not wait).
/// Packages change far less often than the files `integrity` re-verifies, but
/// not so rarely that a slower interval would cost nothing: an incident
/// investigated an hour after a dropper's `apt install` benefits from the
/// record existing promptly, so this matches `integrity::CHECK_INTERVAL`
/// rather than going slower.
pub(crate) const CHECK_INTERVAL: Duration = Duration::from_secs(300);

/// Where `dpkg` keeps its status database on every Debian/Ubuntu host.
const DPKG_STATUS_PATH: &str = "/var/lib/dpkg/status";

/// Name of the persisted snapshot file, under `<state_dir>/inventory/`.
const SNAPSHOT_FILE: &str = "packages.json";

/// Spawns the thread that checks the package inventory for the life of the
/// process. The **first** check runs immediately, not after [`CHECK_INTERVAL`]
/// — unlike `integrity`'s periodic re-verification (where a few extra minutes
/// before the first pass costs nothing), this check establishes the baseline
/// every later diff is computed against, so delaying it only delays the point
/// where the feature starts working, for no benefit.
pub(crate) fn spawn_monitor(state_dir: PathBuf, sink: Arc<DetectionSink>) {
    std::thread::Builder::new()
        .name("inventory".into())
        .spawn(move || {
            let snapshot_path = snapshot_path_for(&state_dir);
            loop {
                check_once(Path::new(DPKG_STATUS_PATH), &snapshot_path, &sink);
                std::thread::sleep(CHECK_INTERVAL);
            }
        })
        .expect("spawning the inventory monitor thread");
}

fn snapshot_path_for(state_dir: &Path) -> PathBuf {
    state_dir.join("inventory").join(SNAPSHOT_FILE)
}

/// One check: read the real `dpkg` status at `dpkg_status_path`, diff it against
/// whatever is persisted at `snapshot_path`, emit a [`PackageChangeEvent`] per
/// change into `sink`, then persist the new snapshot. Best-effort at every I/O
/// step — a host with no `dpkg` (`rpm`-based, or the status file briefly locked
/// mid-transaction by a real `dpkg` run) just skips this pass rather than
/// panicking the thread; the next interval tries again.
///
/// No previous snapshot (first run, or the file was removed) is day zero: the
/// current state becomes the baseline with **no** change events — every
/// installed package looks "Added" to [`inventory::diff_packages`], and
/// reporting a fresh host's entire package list as a flood of findings on its
/// first check would be exactly the "re-uploads itself on a timer" noise this
/// feature exists to avoid (see `crates/inventory`'s doc).
fn check_once(dpkg_status_path: &Path, snapshot_path: &Path, sink: &DetectionSink) {
    let Ok(text) = std::fs::read_to_string(dpkg_status_path) else {
        return;
    };
    let current = inventory::parse_dpkg_status(&text);
    let previous = load_snapshot(snapshot_path);
    if let Some(previous) = previous {
        for change in inventory::diff_packages(&previous, &current) {
            sink.on_event(to_event(&change));
        }
    }
    save_snapshot(snapshot_path, &current);
}

/// `None` when the file does not exist yet (day zero) or fails to parse — a
/// corrupt snapshot is treated the same as none, re-baselining rather than
/// propagating a parse error into the monitor thread.
fn load_snapshot(path: &Path) -> Option<PackageSnapshot> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn save_snapshot(path: &Path, snapshot: &PackageSnapshot) {
    let Some(parent) = path.parent() else { return };
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    if let Ok(json) = serde_json::to_string(snapshot) {
        // Same temp-file-then-rename shape as `heartbeat::write_once`: a reader
        // (there is none today, but the next `check_once` is one) never sees a
        // torn write.
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, json).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }
}

/// `meta.pid`/`ppid` are 0 and `meta.comm` is `"dpkg"` — a diffed snapshot carries
/// no process, same convention as `schema::HttpRequestEvent` (see
/// [`PackageChangeEvent`]'s own doc).
fn to_event(change: &inventory::PackageChange) -> Event {
    Event::PackageChange(PackageChangeEvent {
        meta: EventMeta {
            pid: 0,
            ppid: 0,
            user: User::Unknown,
            timestamp_ns: schema::time::now_ns(),
            comm: "dpkg".into(),
            container: None,
            process_generation: None,
            parent_process_generation: None,
        },
        package: change.package.clone(),
        change: match change.kind {
            PackageChangeKind::Added => SchemaChangeKind::Added,
            PackageChangeKind::Removed => SchemaChangeKind::Removed,
            PackageChangeKind::Upgraded => SchemaChangeKind::Upgraded,
        },
        previous_version: change.previous_version.clone(),
        version: change.version.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("inventory-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sink_in(dir: &Path) -> DetectionSink {
        DetectionSink::new(
            rules::RuleState::new(),
            &dir.join("alerts.ndjson"),
            None,
            None,
            None,
            &dir.join("content"),
            &dir.join("ml-registry"),
        )
        .unwrap()
    }

    fn alerts_of(dir: &Path) -> String {
        std::fs::read_to_string(dir.join("alerts.ndjson")).unwrap_or_default()
    }

    fn write_dpkg_status(dir: &Path, packages: &[(&str, &str)]) -> PathBuf {
        let path = dir.join("status");
        let text = packages
            .iter()
            .map(|(name, version)| {
                format!("Package: {name}\nStatus: install ok installed\nVersion: {version}\n")
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn day_zero_saves_the_baseline_and_emits_nothing() {
        let dir = tmp("day-zero");
        let dpkg = write_dpkg_status(&dir, &[("curl", "8.5.0")]);
        let snapshot_path = snapshot_path_for(&dir);
        let sink = sink_in(&dir);

        check_once(&dpkg, &snapshot_path, &sink);

        assert_eq!(
            alerts_of(&dir),
            "",
            "day zero must not flood the whole fleet's package list"
        );
        assert!(
            snapshot_path.exists(),
            "the baseline must still be persisted"
        );
    }

    #[test]
    fn a_real_change_between_two_checks_fires_an_inventory_detection() {
        let dir = tmp("change");
        let snapshot_path = snapshot_path_for(&dir);
        let sink = sink_in(&dir);

        let dpkg = write_dpkg_status(&dir, &[("curl", "8.5.0")]);
        check_once(&dpkg, &snapshot_path, &sink); // day zero: baseline only

        let dpkg = write_dpkg_status(&dir, &[("curl", "8.5.0"), ("jq", "1.7")]);
        check_once(&dpkg, &snapshot_path, &sink); // jq appeared

        let alerts = alerts_of(&dir);
        assert!(alerts.contains("INVENTORY-PACKAGE"), "alerts: {alerts}");
        assert!(alerts.contains("jq"), "alerts: {alerts}");
        assert!(alerts.contains("installed"), "alerts: {alerts}");
    }

    #[test]
    fn an_upgrade_is_reported_as_one_change_not_two() {
        let dir = tmp("upgrade");
        let snapshot_path = snapshot_path_for(&dir);
        let sink = sink_in(&dir);

        check_once(
            &write_dpkg_status(&dir, &[("openssl", "3.0.13")]),
            &snapshot_path,
            &sink,
        );
        check_once(
            &write_dpkg_status(&dir, &[("openssl", "3.0.15")]),
            &snapshot_path,
            &sink,
        );

        let alerts = alerts_of(&dir);
        assert_eq!(alerts.lines().count(), 1, "alerts: {alerts}");
        assert!(alerts.contains("3.0.13"));
        assert!(alerts.contains("3.0.15"));
    }

    #[test]
    fn no_change_between_checks_emits_nothing() {
        let dir = tmp("no-change");
        let snapshot_path = snapshot_path_for(&dir);
        let sink = sink_in(&dir);

        let dpkg = write_dpkg_status(&dir, &[("curl", "8.5.0")]);
        check_once(&dpkg, &snapshot_path, &sink);
        check_once(&dpkg, &snapshot_path, &sink);

        assert_eq!(alerts_of(&dir), "");
    }

    #[test]
    fn a_missing_dpkg_status_is_a_quiet_skip_not_a_panic() {
        let dir = tmp("no-dpkg");
        let snapshot_path = snapshot_path_for(&dir);
        let sink = sink_in(&dir);
        check_once(&dir.join("does-not-exist"), &snapshot_path, &sink);
        assert!(
            !snapshot_path.exists(),
            "nothing to baseline when dpkg itself is unreadable"
        );
    }

    #[test]
    fn a_corrupt_persisted_snapshot_re_baselines_instead_of_propagating_an_error() {
        let dir = tmp("corrupt");
        let snapshot_path = snapshot_path_for(&dir);
        std::fs::create_dir_all(snapshot_path.parent().unwrap()).unwrap();
        std::fs::write(&snapshot_path, "not json").unwrap();
        let sink = sink_in(&dir);

        check_once(
            &write_dpkg_status(&dir, &[("curl", "8.5.0")]),
            &snapshot_path,
            &sink,
        );

        assert_eq!(
            alerts_of(&dir),
            "",
            "a corrupt snapshot must re-baseline quietly, not alert"
        );
        let saved = load_snapshot(&snapshot_path).unwrap();
        assert_eq!(saved.get("curl"), Some(&"8.5.0".to_string()));
    }
}
