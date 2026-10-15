//! # inventory
//!
//! Periodic, diffed asset inventory per host — the substrate several features
//! quietly assume: installed packages (dpkg/rpm on Linux, MSI/Store on Windows,
//! pkg receipts + apps on macOS), enabled services/daemons, autoruns/persistence
//! points, listening ports, local users/groups.
//!
//! Principles: snapshots are DIFFED on-device and only changes ship (an inventory
//! that re-uploads itself hourly is telemetry spam); every record is timestamped
//! and case-attachable ("what changed on this host in the incident window" is the
//! DFIR question); server side lands in the entity graph and prevalence ("how many
//! hosts run this package/service"), and gives cases vulnerability CONTEXT via
//! version facts — without becoming vulnerability management (a recorded non-goal).
//!
//! ## Implemented so far (issue #87)
//!
//! Packages only, as the walking-skeleton slice: [`PackageSnapshot`] holds a
//! point-in-time package→version map, [`parse_dpkg_status`] builds one from
//! `dpkg`'s own status database (pure text parsing — no platform code, no I/O:
//! the agent binary reads the actual file and hands this the bytes), and
//! [`diff_packages`] is the pure comparison between two snapshots. Turning a
//! [`PackageChange`] into a real `schema::Event`/alert, persisting the snapshot
//! between runs, and the periodic timer are the agent binary's job
//! (`agent/src/inventory.rs`) — this crate is a LEAF (`tools/check-deps.py`) and
//! stays free of `schema`'s event/detection types, same posture as `tamper`.
//!
//! Services, autoruns, listening ports and users are not built yet; tracked by #87.

use std::collections::BTreeMap;

/// A point-in-time package inventory: package name → installed version. A
/// `BTreeMap` rather than a `HashMap` so two snapshots of the same real state
/// compare and iterate in the same order, which keeps [`diff_packages`]'s output
/// order deterministic without a separate sort step.
pub type PackageSnapshot = BTreeMap<String, String>;

/// What happened to one package between two snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageChangeKind {
    Added,
    Removed,
    Upgraded,
}

/// One package's change between two snapshots, enough to build the
/// `schema::PackageChangeEvent` the agent emits for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageChange {
    pub package: String,
    pub kind: PackageChangeKind,
    pub previous_version: Option<String>,
    pub version: Option<String>,
}

/// Parses `dpkg`'s status database (`/var/lib/dpkg/status` verbatim, or the
/// concatenated output of `dpkg-query -W -f '...'` the caller composed the same
/// way — this function only cares about the stanza shape) into a
/// [`PackageSnapshot`]. Stanzas are separated by a blank line; a continuation
/// line (a multi-line field like `Description`) starts with whitespace and is
/// skipped, since none of the three fields this reads ever spans multiple lines
/// in practice.
///
/// Only a package whose `Status` field is exactly `install ok installed` —
/// dpkg's own "actually present" status — counts; `deinstall ok config-files`
/// (removed, config kept), `half-installed`, and friends do not, or a purge
/// would show up as neither Added nor Removed. A stanza missing `Package` or
/// `Version` is skipped rather than failing the whole parse — this runs over a
/// real system file, and one malformed or `dpkg`-version-specific stanza must
/// not blind the rest of the snapshot.
#[must_use]
pub fn parse_dpkg_status(text: &str) -> PackageSnapshot {
    let mut snapshot = PackageSnapshot::new();
    for stanza in text.split("\n\n") {
        let mut package = None;
        let mut version = None;
        let mut installed = false;
        for line in stanza.lines() {
            if line.starts_with(|c: char| c.is_whitespace()) {
                continue;
            }
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            match key {
                "Package" => package = Some(value.trim().to_string()),
                "Version" => version = Some(value.trim().to_string()),
                "Status" => installed = value.trim() == "install ok installed",
                _ => {}
            }
        }
        if let (true, Some(package), Some(version)) = (installed, package, version) {
            snapshot.insert(package, version);
        }
    }
    snapshot
}

/// Compares two package snapshots and returns every package that was added,
/// removed, or changed version — a package whose version is unchanged produces
/// nothing, which is the whole point of diffing rather than re-shipping every
/// snapshot whole (an inventory that re-uploads itself hourly is telemetry spam,
/// per this crate's own doc).
///
/// Pure and total: any two snapshots, including two empty ones, produce a result
/// with no panic — the only case this never produces a change for is `previous ==
/// current`. Ordered by package name ([`PackageSnapshot`]'s `BTreeMap` iteration),
/// so the same two snapshots diffed twice agree on the order, not just the set.
#[must_use]
pub fn diff_packages(previous: &PackageSnapshot, current: &PackageSnapshot) -> Vec<PackageChange> {
    let mut changes = Vec::new();
    for (package, version) in current {
        match previous.get(package) {
            None => changes.push(PackageChange {
                package: package.clone(),
                kind: PackageChangeKind::Added,
                previous_version: None,
                version: Some(version.clone()),
            }),
            Some(old) if old != version => changes.push(PackageChange {
                package: package.clone(),
                kind: PackageChangeKind::Upgraded,
                previous_version: Some(old.clone()),
                version: Some(version.clone()),
            }),
            Some(_) => {}
        }
    }
    for (package, old_version) in previous {
        if !current.contains_key(package) {
            changes.push(PackageChange {
                package: package.clone(),
                kind: PackageChangeKind::Removed,
                previous_version: Some(old_version.clone()),
                version: None,
            });
        }
    }
    changes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(entries: &[(&str, &str)]) -> PackageSnapshot {
        entries
            .iter()
            .map(|(name, version)| (name.to_string(), version.to_string()))
            .collect()
    }

    #[test]
    fn two_empty_snapshots_diff_to_nothing() {
        assert_eq!(
            diff_packages(&PackageSnapshot::new(), &PackageSnapshot::new()),
            vec![]
        );
    }

    #[test]
    fn identical_snapshots_diff_to_nothing() {
        let s = snapshot(&[("curl", "8.5.0"), ("openssl", "3.0.13")]);
        assert_eq!(diff_packages(&s, &s), vec![]);
    }

    #[test]
    fn a_new_package_is_added() {
        let previous = snapshot(&[("curl", "8.5.0")]);
        let current = snapshot(&[("curl", "8.5.0"), ("jq", "1.7")]);
        assert_eq!(
            diff_packages(&previous, &current),
            vec![PackageChange {
                package: "jq".into(),
                kind: PackageChangeKind::Added,
                previous_version: None,
                version: Some("1.7".into()),
            }]
        );
    }

    #[test]
    fn a_removed_package_is_removed() {
        let previous = snapshot(&[("curl", "8.5.0"), ("jq", "1.7")]);
        let current = snapshot(&[("curl", "8.5.0")]);
        assert_eq!(
            diff_packages(&previous, &current),
            vec![PackageChange {
                package: "jq".into(),
                kind: PackageChangeKind::Removed,
                previous_version: Some("1.7".into()),
                version: None,
            }]
        );
    }

    #[test]
    fn a_version_change_is_upgraded_not_removed_then_added() {
        // The whole point of diffing by key rather than by (name, version) pair:
        // a version bump is one Upgraded record, not a Removed-then-Added pair
        // that would make the same package look like two different ones.
        let previous = snapshot(&[("openssl", "3.0.13")]);
        let current = snapshot(&[("openssl", "3.0.15")]);
        assert_eq!(
            diff_packages(&previous, &current),
            vec![PackageChange {
                package: "openssl".into(),
                kind: PackageChangeKind::Upgraded,
                previous_version: Some("3.0.13".into()),
                version: Some("3.0.15".into()),
            }]
        );
    }

    #[test]
    fn a_downgrade_is_still_upgraded_kind_a_version_change() {
        // "Upgraded" names the common case; the diff has no opinion on version
        // ordering (parsing/comparing distro version schemes is its own
        // problem this crate does not take on) — any change in the version
        // string is this one kind, previous/current carry the actual values.
        let previous = snapshot(&[("openssl", "3.0.15")]);
        let current = snapshot(&[("openssl", "3.0.13")]);
        assert_eq!(
            diff_packages(&previous, &current),
            vec![PackageChange {
                package: "openssl".into(),
                kind: PackageChangeKind::Upgraded,
                previous_version: Some("3.0.15".into()),
                version: Some("3.0.13".into()),
            }]
        );
    }

    #[test]
    fn everything_in_one_pass_and_in_name_order() {
        let previous = snapshot(&[
            ("a-removed", "1"),
            ("b-upgraded", "1"),
            ("d-unchanged", "1"),
        ]);
        let current = snapshot(&[("b-upgraded", "2"), ("c-added", "1"), ("d-unchanged", "1")]);
        let changes = diff_packages(&previous, &current);
        let names: Vec<&str> = changes.iter().map(|c| c.package.as_str()).collect();
        // Added/Upgraded come from iterating `current` (name order), Removed from
        // iterating `previous` afterwards — asserting the exact interleaving
        // documents the order rather than leaving it to iteration-order luck.
        assert_eq!(names, vec!["b-upgraded", "c-added", "a-removed"]);
    }

    #[test]
    fn dpkg_status_parses_installed_packages() {
        let text = "\
Package: coreutils
Status: install ok installed
Priority: required
Version: 9.4-2
Description: GNU core utilities
 This package also includes...

Package: libfoo
Status: install ok installed
Version: 1:2.3-4ubuntu1
";
        let snapshot = parse_dpkg_status(text);
        assert_eq!(snapshot.get("coreutils"), Some(&"9.4-2".to_string()));
        assert_eq!(snapshot.get("libfoo"), Some(&"1:2.3-4ubuntu1".to_string()));
        assert_eq!(snapshot.len(), 2);
    }

    #[test]
    fn dpkg_status_skips_non_installed_statuses() {
        // "deinstall ok config-files": removed, config kept — not installed.
        let text = "\
Package: oldpkg
Status: deinstall ok config-files
Version: 1.0

Package: halfdone
Status: half-installed
Version: 2.0
";
        assert_eq!(parse_dpkg_status(text), PackageSnapshot::new());
    }

    #[test]
    fn dpkg_status_skips_a_stanza_missing_a_field_rather_than_failing() {
        let text = "\
Package: nopkgversion
Status: install ok installed

Status: install ok installed
Version: 1.0

Package: good
Status: install ok installed
Version: 1.0
";
        let snapshot = parse_dpkg_status(text);
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot.get("good"), Some(&"1.0".to_string()));
    }

    #[test]
    fn dpkg_status_never_panics_on_garbage() {
        for text in [
            "",
            "\n\n\n",
            "not a status file at all",
            ":::::",
            "Package\nVersion\n",
        ] {
            let _ = parse_dpkg_status(text);
        }
    }

    #[test]
    fn first_ever_snapshot_is_all_additions_not_noise() {
        // Day zero (no previous snapshot exists yet): every installed package
        // is "added", not a flood the agent should suppress — the caller (the
        // agent) decides whether to ship day-zero's full list or just persist
        // it as the baseline; this crate makes no judgment either way.
        let current = snapshot(&[("curl", "8.5.0"), ("jq", "1.7")]);
        let changes = diff_packages(&PackageSnapshot::new(), &current);
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().all(|c| c.kind == PackageChangeKind::Added));
    }
}
