//! Periodic self-integrity verification (issue #71/#30) — wires `tamper::integrity`
//! into the agent, using the signed release manifest `updater` persists at promote
//! time (`updater::layout::Layout::persist_manifest`) as the root of trust: does
//! every file the active release's manifest lists still hash to what was promoted?
//!
//! Complements `silence` rather than duplicating it: silence proves a sensor
//! stopped *producing*, which is exactly as true for a swapped binary that still
//! runs as for one that was killed — it cannot tell the two apart. This module is
//! the check that actually looks at the bytes on disk, against a signature-verified
//! baseline an attacker cannot forge without the updater's private key.

use std::{path::PathBuf, sync::Arc, time::Duration};

use crate::sink::DetectionSink;

/// How often the active release is re-verified. Deliberately much coarser than
/// `silence::POLL_INTERVAL` (10s) — this hashes every protected file (real I/O),
/// and a same-privilege on-disk swap is not a race that needs sub-minute detection
/// to still be useful, unlike a sensor going silent mid-attack.
pub(crate) const CHECK_INTERVAL: Duration = Duration::from_secs(300);

/// ATT&CK technique tag for every alert this module emits — "Modify System Image"
/// (T1601), the closest existing tag to "the installed binary/config no longer
/// matches what was shipped". Reuses the same "T-code + message via `sink.emit`"
/// shape `silence`/`kill_loudness` already established for the other tamper
/// detections, rather than a new `schema::detection::DetectionSource` variant —
/// `tamper` is a LEAF crate and stays free of sink/schema types by design
/// (`IntegrityViolation::message`'s own doc), so composing its output into an
/// alert line is this module's job, same as `silence::spawn_monitor` already does
/// for `SilenceVerdict`.
const TAMPER_TECHNIQUE: &str = "T1601";

/// Spawns the thread that re-verifies the active release's signed manifest against
/// the binaries on disk every [`CHECK_INTERVAL`], for the life of the process.
/// `state_dir` is `updater`'s base directory (`AgentConfig::storage.state_dir` —
/// `/var/lib/synthaea` in production), the same root `updater::layout::Layout`
/// itself is built from — the updater and this check must agree on it, or the
/// manifest this reads back is never the one a real update actually staged.
pub(crate) fn spawn_monitor(state_dir: PathBuf, sink: Arc<DetectionSink>) {
    std::thread::Builder::new()
        .name("self-integrity".into())
        .spawn(move || {
            let layout = updater::layout::Layout::new(&state_dir);
            loop {
                std::thread::sleep(CHECK_INTERVAL);
                check_once(&layout, &sink);
            }
        })
        .expect("spawning the self-integrity monitor thread");
}

/// One verification pass. `None` from [`updater::layout::Layout::current_release_version`]
/// (bootstrap / day 0, ADR-0015 Decision 7 — nothing has ever been promoted) is the
/// honest no-op case: the package-installed bootstrap binaries carry no
/// updater-signed manifest by design, so there is nothing to check yet.
fn check_once(layout: &updater::layout::Layout, sink: &DetectionSink) {
    let Some(release_version) = layout.current_release_version() else {
        return;
    };
    let manifest = match layout.read_manifest(release_version) {
        Ok(manifest) => manifest,
        Err(e) => {
            tracing::warn!(
                error = %e,
                release_version,
                "self-integrity: failed to read the persisted release manifest"
            );
            return;
        }
    };
    // The manifest file being readable is not the same as it being trustworthy —
    // re-verify the signature every pass rather than once at load time, so a
    // manifest swapped on disk *after* a clean earlier check still gets caught on
    // the next one.
    if let Err(e) = manifest.verify_signature() {
        tracing::warn!(
            error = %e,
            release_version,
            "self-integrity: persisted manifest failed signature verification"
        );
        sink.emit(
            TAMPER_TECHNIQUE,
            &format!(
                "release {release_version}'s persisted manifest failed signature \
                 verification — the manifest file itself may have been tampered with"
            ),
        );
        return;
    }

    let active_dir = layout.resolve_active_dir();
    let integrity_manifest = tamper::integrity::Manifest::from_entries(
        manifest
            .entries
            .into_iter()
            .map(|(rel_path, hash)| (active_dir.join(rel_path), hash)),
    );
    for violation in integrity_manifest.verify() {
        sink.emit(TAMPER_TECHNIQUE, &violation.message());
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::PathBuf};

    use updater::{ReleaseManifest, key::test_key_pair, layout::Layout};

    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("integrity-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sink_in(dir: &std::path::Path) -> DetectionSink {
        DetectionSink::new(
            rules::RuleState::new(),
            &dir.join("alerts.ndjson"),
            &dir.join("events.jsonl"),
            None,
        )
        .unwrap()
    }

    fn alerts_of(dir: &std::path::Path) -> String {
        std::fs::read_to_string(dir.join("alerts.ndjson")).unwrap_or_default()
    }

    /// Stages release 1 under `layout`, with one file (`agent`) whose real bytes
    /// match `contents`, persists a signed manifest recording `contents`'s hash,
    /// and promotes it — the state `check_once` expects to find already in place.
    fn promote_signed_release(layout: &Layout, contents: &[u8]) {
        let dir = layout.version_dir(1);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("agent"), contents).unwrap();
        let hash = updater::hash::hash_file(&dir.join("agent")).unwrap();
        let mut entries = BTreeMap::new();
        entries.insert(PathBuf::from("agent"), hash);
        let mut manifest = ReleaseManifest::new(1, entries);
        manifest.sign(&test_key_pair());
        layout.verify_staged(&manifest).unwrap();
        layout.persist_manifest(&manifest).unwrap();
        layout.promote(1).unwrap();
    }

    #[test]
    fn day_zero_with_no_promoted_release_checks_clean() {
        let dir = tmp("day-zero");
        let layout = Layout::new(&dir);
        std::fs::create_dir_all(layout.bootstrap_dir()).unwrap();
        std::fs::create_dir_all(layout.versions_dir()).unwrap();
        std::os::unix::fs::symlink(layout.bootstrap_dir(), layout.current_link()).unwrap();

        let sink = sink_in(&dir);
        check_once(&layout, &sink);

        assert_eq!(
            alerts_of(&dir),
            "",
            "no manifest exists yet — nothing to check"
        );
    }

    #[test]
    fn an_unmodified_release_produces_no_alert() {
        let dir = tmp("clean");
        let layout = Layout::new(&dir);
        std::fs::create_dir_all(layout.bootstrap_dir()).unwrap();
        std::fs::create_dir_all(layout.versions_dir()).unwrap();
        std::os::unix::fs::symlink(layout.bootstrap_dir(), layout.current_link()).unwrap();
        promote_signed_release(&layout, b"the real agent binary");

        let sink = sink_in(&dir);
        check_once(&layout, &sink);

        assert_eq!(alerts_of(&dir), "");
    }

    #[test]
    fn a_binary_swapped_after_promotion_is_caught() {
        let dir = tmp("swapped");
        let layout = Layout::new(&dir);
        std::fs::create_dir_all(layout.bootstrap_dir()).unwrap();
        std::fs::create_dir_all(layout.versions_dir()).unwrap();
        std::os::unix::fs::symlink(layout.bootstrap_dir(), layout.current_link()).unwrap();
        promote_signed_release(&layout, b"the real agent binary");

        // The exact scenario #71 exists to catch: the file at the promoted path
        // now has different bytes, the manifest is untouched.
        std::fs::write(layout.version_dir(1).join("agent"), b"a neutered build").unwrap();

        let sink = sink_in(&dir);
        check_once(&layout, &sink);

        let alerts = alerts_of(&dir);
        assert!(alerts.contains("T1601"), "alerts: {alerts}");
        assert!(
            alerts.contains("neutered-build swap"),
            "expected the integrity violation's own message, got: {alerts}"
        );
    }

    #[test]
    fn a_manifest_file_tampered_with_on_disk_fails_signature_verification() {
        let dir = tmp("manifest-tampered");
        let layout = Layout::new(&dir);
        std::fs::create_dir_all(layout.bootstrap_dir()).unwrap();
        std::fs::create_dir_all(layout.versions_dir()).unwrap();
        std::os::unix::fs::symlink(layout.bootstrap_dir(), layout.current_link()).unwrap();
        promote_signed_release(&layout, b"the real agent binary");

        // Rewrite the persisted manifest with a hash matching the swapped binary —
        // the file-level check alone would pass; only the signature check catches
        // this, since the attacker does not have the updater's private key.
        let dir_v1 = layout.version_dir(1);
        std::fs::write(dir_v1.join("agent"), b"a neutered build").unwrap();
        let forged_hash = updater::hash::hash_file(&dir_v1.join("agent")).unwrap();
        let mut entries = BTreeMap::new();
        entries.insert(PathBuf::from("agent"), forged_hash);
        let forged = ReleaseManifest::new(1, entries); // unsigned — no private key available
        layout.persist_manifest(&forged).unwrap();

        let sink = sink_in(&dir);
        check_once(&layout, &sink);

        let alerts = alerts_of(&dir);
        assert!(alerts.contains("T1601"), "alerts: {alerts}");
        assert!(
            alerts.contains("signature verification"),
            "expected the signature-failure message, got: {alerts}"
        );
    }
}
