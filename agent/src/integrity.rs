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

/// Whether a failed manifest verification says anything about the file: a build with no
/// release key (ADR-0027, `crates/updater/keys` unprovisioned) cannot verify any manifest, so
/// reporting that as "the manifest may have been tampered with" would be a false detection on
/// every pass. Everything else (a bad signature, an unsupported schema) is about the file.
fn signature_failure_is_tamper(error: &updater::UpdaterError) -> bool {
    !matches!(error, updater::UpdaterError::SigningKeyUnprovisioned)
}

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

/// The layout's base directory: where the record of key rotations lives.
fn state_dir(layout: &updater::layout::Layout) -> std::path::PathBuf {
    layout
        .versions_dir()
        .parent()
        .map_or_else(std::path::PathBuf::new, std::path::Path::to_path_buf)
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
    // The manifest was verified under the `release` key in force when it was promoted, which a
    // rotation since then may have replaced: accept any key this install has trusted. That is a
    // re-check of a manifest already on disk, never an approval of anything new.
    let keys = match crate::trust::load(&state_dir(layout)) {
        Ok(keys) => keys,
        Err(e) => {
            tracing::warn!(error = %e, "self-integrity: the record of key rotations is not trustworthy");
            sink.emit_tamper(
                TAMPER_TECHNIQUE,
                &format!(
                    "the record of applied key rotations is not trustworthy ({e}); releases \
                     and content are not verified until it is repaired"
                ),
            );
            return;
        }
    };
    let verified = if keys.release_lineage.is_empty() {
        manifest.verify_signature_with(None)
    } else {
        let mut outcome = Err(updater::UpdaterError::SignatureInvalid);
        for key in &keys.release_lineage {
            outcome = manifest.verify_signature_with(Some(key));
            if outcome.is_ok() {
                break;
            }
        }
        outcome
    };
    if let Err(e) = verified {
        if !signature_failure_is_tamper(&e) {
            tracing::warn!(
                release_version,
                "self-integrity: this build embeds no release key, so the persisted manifest \
                 cannot be verified; the check is skipped"
            );
            return;
        }
        tracing::warn!(
            error = %e,
            release_version,
            "self-integrity: persisted manifest failed signature verification"
        );
        sink.emit_tamper(
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
        sink.emit_tamper(TAMPER_TECHNIQUE, &violation.message());
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::PathBuf};

    use updater::{ReleaseManifest, key::test_key_pair, layout::Layout};

    use super::*;

    #[test]
    fn a_build_with_no_release_key_does_not_report_tamper() {
        assert!(!signature_failure_is_tamper(
            &updater::UpdaterError::SigningKeyUnprovisioned
        ));
        assert!(signature_failure_is_tamper(
            &updater::UpdaterError::SignatureInvalid
        ));
    }

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
            Some(&dir.join("events.jsonl")),
            None,
            None,
            &dir.join("content"),
            &dir.join("ml-registry"),
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
        assert_eq!(
            sink.tamper_events(),
            0,
            "a clean check is not a tamper event"
        );
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
        assert_eq!(sink.tamper_events(), 1, "one violation, one tamper event");
    }

    /// A rotation of `release` away from the embedded test key, signed by the test recovery key
    /// and recorded under `dir` the way `apply-key-rotation` does.
    fn record_release_rotation(dir: &std::path::Path) {
        let embedded = updater::key::RELEASE_PUBLIC_KEY.unwrap();
        let mut rotation = updater::KeyRotationManifest {
            expires_at: 2_000_000_000,
            issued_at: 1_999_990_000,
            new_content_key: None,
            new_release_key: Some(updater::hash::hex_encode(&[0x61; 32])),
            reason: "test".into(),
            release_version: 9,
            retired_content_key: None,
            retired_release_key: Some(updater::hash::hex_encode(&embedded)),
            schema_version: updater::rotation::ROTATION_SCHEMA_VERSION,
            signature: String::new(),
        };
        rotation.sign(&updater::key::test_recovery_key_pair());
        crate::rotation::apply(&rotation, dir, None, 1_999_990_100).unwrap();
    }

    #[test]
    fn a_release_promoted_before_a_key_rotation_still_checks_clean_after_it() {
        let dir = tmp("rotated-after-promotion");
        let layout = Layout::new(&dir);
        std::fs::create_dir_all(layout.bootstrap_dir()).unwrap();
        std::fs::create_dir_all(layout.versions_dir()).unwrap();
        std::os::unix::fs::symlink(layout.bootstrap_dir(), layout.current_link()).unwrap();
        promote_signed_release(&layout, b"the real agent binary");
        record_release_rotation(&dir);

        let sink = sink_in(&dir);
        check_once(&layout, &sink);

        assert_eq!(alerts_of(&dir), "", "signed by a key this install trusted");
        assert_eq!(sink.tamper_events(), 0);
    }

    #[test]
    fn a_manifest_signed_by_a_key_this_install_never_trusted_is_still_tamper_after_a_rotation() {
        let dir = tmp("rotated-forged");
        let layout = Layout::new(&dir);
        std::fs::create_dir_all(layout.bootstrap_dir()).unwrap();
        std::fs::create_dir_all(layout.versions_dir()).unwrap();
        std::os::unix::fs::symlink(layout.bootstrap_dir(), layout.current_link()).unwrap();
        promote_signed_release(&layout, b"the real agent binary");
        record_release_rotation(&dir);
        let mut forged = layout.read_manifest(1).unwrap();
        forged.sign(&updater::key::test_recovery_key_pair());
        layout.persist_manifest(&forged).unwrap();

        let sink = sink_in(&dir);
        check_once(&layout, &sink);

        assert!(alerts_of(&dir).contains("T1601"));
        assert_eq!(sink.tamper_events(), 1);
    }

    #[test]
    fn a_corrupt_record_of_key_rotations_is_a_tamper_event() {
        let dir = tmp("record-corrupt");
        let layout = Layout::new(&dir);
        std::fs::create_dir_all(layout.bootstrap_dir()).unwrap();
        std::fs::create_dir_all(layout.versions_dir()).unwrap();
        std::os::unix::fs::symlink(layout.bootstrap_dir(), layout.current_link()).unwrap();
        promote_signed_release(&layout, b"the real agent binary");
        std::fs::write(crate::trust::record_path(&dir), b"{ truncated").unwrap();

        let sink = sink_in(&dir);
        check_once(&layout, &sink);

        assert!(alerts_of(&dir).contains("key rotations is not trustworthy"));
        assert_eq!(sink.tamper_events(), 1);
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
        assert_eq!(
            sink.tamper_events(),
            1,
            "one failed signature, one tamper event"
        );
    }
}
