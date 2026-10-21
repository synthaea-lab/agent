//! Keeps the fleet common-set snapshot fresh (ADR-0033 decision 4, issue #76 box 2): a loop
//! inside `agent run` that polls the control plane for the signed snapshot manifest at a
//! jittered interval, downloads the artifact only when `built_at` moved, verifies it, writes
//! `snapshots/common-set.bin` atomically and asks the sink to reload just that file.
//!
//! **Off unless a `snapshot` key is embedded** (`updater::key::SNAPSHOT_PUBLIC_KEY`): a build
//! without the `test-key` feature has none until the custody decision of #753 provisions one, so
//! the loop never starts there and nothing is fetched. A test-key build runs it in the lab.
//!
//! Failure posture, the rule directories': a manifest with a bad signature, a stale or
//! future `built_at`, an artifact whose size or hash differs from what was signed, or one that
//! does not parse as a snapshot leaves the snapshot in force untouched and is logged with its
//! reason. The snapshot in force ages out on its own (`updater::snapshot::DEFAULT_MAX_AGE_SECS`,
//! checked where the evidence is judged), so a server that stops publishing cannot keep a stale
//! set alive.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context as _;
use transport::{TransportClient, TransportError};
use updater::{
    SnapshotManifest, UpdaterError,
    snapshot::{DEFAULT_MAX_AGE_SECS, is_expired},
};

use crate::sink::{DetectionSink, MAX_COMMON_SET_BYTES};

/// How often the manifest is polled. A starting point for a daily snapshot (ADR-0033), calibrated
/// in slice 6. `SYNTHAEA_SNAPSHOT_POLL_SECS` overrides it for a lab run; it is not a security
/// setting (the signature, freshness and size checks do not depend on it).
const POLL_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
/// The override is clamped to at least this, so a typo cannot turn the loop into a flood.
const MIN_POLL_SECS: u64 = 5;
const POLL_ENV: &str = "SYNTHAEA_SNAPSHOT_POLL_SECS";

/// Where the snapshot lives under the content root: the file the loader reads (slice 3).
fn snapshot_path(content_root: &Path) -> PathBuf {
    content_root.join("snapshots").join("common-set.bin")
}

/// What one poll found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The control plane has published nothing for this tenant yet.
    NothingPublished,
    /// The offer is the snapshot already in force.
    UpToDate,
    /// The offer is older than the snapshot in force: ignored, never applied.
    OlderOffer { offered: u64, current: u64 },
    /// The offer is past the maximum age: it would be withheld at once, so it is not applied.
    Expired { built_at: u64 },
    /// A new snapshot was verified and written; the sink must reload it.
    Applied {
        built_at: u64,
        entries: u64,
        hosts_covered: u64,
    },
}

/// Where a manifest and its artifact come from: the control plane, or a fake in tests.
pub(crate) trait SnapshotSource {
    /// The signed manifest, `None` when nothing is published (HTTP 404).
    fn manifest(&self) -> anyhow::Result<Option<SnapshotManifest>>;
    /// The artifact bytes the manifest names, at most `max_bytes`.
    fn artifact(&self, manifest: &SnapshotManifest, max_bytes: u64) -> anyhow::Result<Vec<u8>>;
}

impl SnapshotSource for TransportClient {
    fn manifest(&self) -> anyhow::Result<Option<SnapshotManifest>> {
        match self.get_json(&self.config().snapshot_manifest_url()) {
            Ok(manifest) => Ok(Some(manifest)),
            Err(TransportError::ServerError { status: 404, .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn artifact(&self, manifest: &SnapshotManifest, max_bytes: u64) -> anyhow::Result<Vec<u8>> {
        Ok(self.get_bytes(
            &self.config().snapshot_artifact_url(),
            &[("sha256", manifest.sha256.as_str())],
            max_bytes,
        )?)
    }
}

/// The `built_at` of the snapshot on disk, or `None` when there is none or it is not readable as
/// one. The artifact's header carries it, and the manifest signs the artifact's hash, so a
/// snapshot this loop wrote has a header the signature covers.
fn built_at_in_force(content_root: &Path) -> Option<u64> {
    let bytes = std::fs::read(snapshot_path(content_root)).ok()?;
    ml::features::common_set::CommonSetSnapshot::parse(&bytes)
        .ok()
        .map(|s| s.header().built_at)
}

/// One poll: fetch, verify, and write when there is something newer. Pure over the source, the
/// directory and `now`, so every refusal is tested without a server or a clock.
///
/// # Errors
///
/// Anything that makes the offer unusable: the source failing, a signature, kind or schema
/// version that does not verify, a `built_at` from the future, a declared size over `max_bytes`,
/// an artifact that is not the one signed or that disagrees with its manifest, or a failed write.
/// In every case the snapshot in force is untouched.
pub(crate) fn poll_once(
    source: &dyn SnapshotSource,
    content_root: &Path,
    now_secs: u64,
    max_bytes: u64,
) -> anyhow::Result<Outcome> {
    let Some(manifest) = source
        .manifest()
        .context("fetching the snapshot manifest")?
    else {
        return Ok(Outcome::NothingPublished);
    };
    manifest
        .verify_signature()
        .context("the snapshot manifest does not verify")?;

    match manifest.check_freshness(built_at_in_force(content_root), now_secs) {
        Ok(()) => {}
        Err(UpdaterError::SnapshotNotNewer { offered, current }) if offered == current => {
            return Ok(Outcome::UpToDate);
        }
        Err(UpdaterError::SnapshotNotNewer { offered, current }) => {
            return Ok(Outcome::OlderOffer { offered, current });
        }
        Err(e) => return Err(e.into()),
    }
    if is_expired(manifest.built_at, now_secs, DEFAULT_MAX_AGE_SECS) {
        return Ok(Outcome::Expired {
            built_at: manifest.built_at,
        });
    }
    if manifest.size > max_bytes {
        anyhow::bail!(
            "the snapshot declares {} bytes, over the {max_bytes}-byte cap",
            manifest.size
        );
    }

    let bytes = source
        .artifact(&manifest, max_bytes)
        .context("downloading the snapshot artifact")?;
    manifest.verify_artifact(&bytes)?;
    // Parsed before anything is written: a signed but unreadable artifact must not replace a
    // file the loader can read. The header must say what the manifest signed.
    let parsed = ml::features::common_set::CommonSetSnapshot::parse(&bytes).map_err(|e| {
        UpdaterError::SnapshotArtifactMismatch(format!("not a usable snapshot: {e}"))
    })?;
    let header = parsed.header();
    let agrees = header.built_at == manifest.built_at
        && u64::from(header.hosts_covered) == manifest.hosts_covered
        && u64::from(header.min_hosts) == manifest.min_hosts
        && u64::from(header.entry_count) == manifest.entry_count;
    if !agrees {
        return Err(UpdaterError::SnapshotArtifactMismatch(
            "the artifact's header disagrees with its signed manifest".into(),
        )
        .into());
    }

    let dest = snapshot_path(content_root);
    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    updater::fsutil::write_atomically(content_root, &dest, &bytes)
        .with_context(|| format!("writing {}", dest.display()))?;
    Ok(Outcome::Applied {
        built_at: manifest.built_at,
        entries: manifest.entry_count,
        hosts_covered: manifest.hosts_covered,
    })
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The poll interval: the default, or the lab override, clamped.
fn poll_interval(override_secs: Option<&str>) -> Duration {
    match override_secs.and_then(|v| v.trim().parse::<u64>().ok()) {
        Some(secs) => Duration::from_secs(secs.max(MIN_POLL_SECS)),
        None => POLL_INTERVAL,
    }
}

/// `interval` spread by up to ±10% so a fleet does not poll in step.
fn jittered(interval: Duration) -> Duration {
    let mut bytes = [0u8; 4];
    if getrandom::fill(&mut bytes).is_err() {
        return interval;
    }
    let fraction = f64::from(u32::from_le_bytes(bytes)) / f64::from(u32::MAX); // 0..=1
    interval.mul_f64(0.9 + 0.2 * fraction)
}

/// Starts the loop when this build embeds a `snapshot` key and there is a control plane to ask.
/// Detached like the other monitors: it dies with the process. Never panics the agent: a failed
/// poll is logged and retried at the next interval.
pub(crate) fn spawn_if_enabled(
    client: Arc<TransportClient>,
    content_root: PathBuf,
    sink: Arc<DetectionSink>,
) {
    if updater::key::SNAPSHOT_PUBLIC_KEY.is_none() {
        tracing::info!(
            "snapshot fetch: off, this build embeds no snapshot key (ADR-0033, custody is #753)"
        );
        return;
    }
    let interval = poll_interval(std::env::var(POLL_ENV).ok().as_deref());
    let spawned = std::thread::Builder::new()
        .name("snapshot-fetch".into())
        .spawn(move || {
            // The first poll comes soon, not after a whole interval: a fresh agent has no
            // snapshot until it asks. A short, jittered delay lets the upload start first.
            std::thread::sleep(jittered(Duration::from_secs(10).min(interval)));
            loop {
                match poll_once(&*client, &content_root, unix_now_secs(), MAX_COMMON_SET_BYTES) {
                    Ok(Outcome::Applied {
                        built_at,
                        entries,
                        hosts_covered,
                    }) => {
                        tracing::info!(built_at, entries, hosts_covered, "snapshot fetch: new snapshot written");
                        sink.reload_common_set();
                    }
                    Ok(Outcome::NothingPublished) => tracing::debug!("snapshot fetch: nothing published yet"),
                    Ok(Outcome::UpToDate) => tracing::debug!("snapshot fetch: up to date"),
                    Ok(Outcome::OlderOffer { offered, current }) => tracing::warn!(
                        offered,
                        current,
                        "snapshot fetch: the server offers an older snapshot than the one in force, ignored"
                    ),
                    Ok(Outcome::Expired { built_at }) => tracing::warn!(
                        built_at,
                        "snapshot fetch: the server's snapshot is past the maximum age, not applied"
                    ),
                    Err(e) => tracing::warn!(
                        error = %format!("{e:#}"),
                        "snapshot fetch: the snapshot in force is kept"
                    ),
                }
                std::thread::sleep(jittered(interval));
            }
        });
    if let Err(e) = spawned {
        tracing::warn!(error = %e, "snapshot fetch: could not start the thread");
    }
}

#[cfg(all(test, feature = "test-key"))]
mod tests {
    use std::cell::{Cell, RefCell};

    use updater::snapshot::{KIND_COMMON_SET, SNAPSHOT_MANIFEST_SCHEMA_VERSION};

    use super::*;

    const NOW: u64 = 1_790_000_000;
    const CAP: u64 = 1 << 20;

    /// A minimal valid version-1 snapshot: a 64-bit filter, header fields as given.
    fn artifact(built_at: u64, hosts: u32, min_hosts: u32, entries: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"SYCS");
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&min_hosts.to_le_bytes());
        out.extend_from_slice(&hosts.to_le_bytes());
        out.extend_from_slice(&entries.to_le_bytes());
        out.extend_from_slice(&64u32.to_le_bytes());
        out.extend_from_slice(&built_at.to_le_bytes());
        out.extend_from_slice(&[0u8; 8]);
        out
    }

    fn signed(bytes: &[u8], built_at: u64) -> SnapshotManifest {
        let mut m = SnapshotManifest {
            built_at,
            entry_count: 3,
            hosts_covered: 12,
            kind: KIND_COMMON_SET.into(),
            min_hosts: 2,
            schema_version: SNAPSHOT_MANIFEST_SCHEMA_VERSION,
            sha256: updater::hash::hash_bytes(bytes),
            signature: String::new(),
            size: bytes.len() as u64,
        };
        m.sign(&updater::key::test_snapshot_key_pair());
        m
    }

    struct Fake {
        manifest: RefCell<Option<anyhow::Result<Option<SnapshotManifest>>>>,
        bytes: Vec<u8>,
        downloads: Cell<u32>,
    }

    impl Fake {
        fn offering(manifest: SnapshotManifest, bytes: Vec<u8>) -> Self {
            Self {
                manifest: RefCell::new(Some(Ok(Some(manifest)))),
                bytes,
                downloads: Cell::new(0),
            }
        }
    }

    impl SnapshotSource for Fake {
        fn manifest(&self) -> anyhow::Result<Option<SnapshotManifest>> {
            self.manifest
                .borrow_mut()
                .take()
                .expect("one manifest fetch")
        }
        fn artifact(&self, _: &SnapshotManifest, _: u64) -> anyhow::Result<Vec<u8>> {
            self.downloads.set(self.downloads.get() + 1);
            Ok(self.bytes.clone())
        }
    }

    fn good(built_at: u64) -> Fake {
        let bytes = artifact(built_at, 12, 2, 3);
        Fake::offering(signed(&bytes, built_at), bytes)
    }

    fn on_disk(root: &Path) -> Option<Vec<u8>> {
        std::fs::read(snapshot_path(root)).ok()
    }

    fn put(root: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(snapshot_path(root).parent().unwrap()).unwrap();
        std::fs::write(snapshot_path(root), bytes).unwrap();
    }

    #[test]
    fn a_new_snapshot_is_verified_written_and_reported() {
        let dir = tempfile::tempdir().unwrap();
        let source = good(NOW - 60);
        let outcome = poll_once(&source, dir.path(), NOW, CAP).unwrap();
        assert_eq!(
            outcome,
            Outcome::Applied {
                built_at: NOW - 60,
                entries: 3,
                hosts_covered: 12
            }
        );
        assert_eq!(on_disk(dir.path()).unwrap(), artifact(NOW - 60, 12, 2, 3));
        assert_eq!(built_at_in_force(dir.path()), Some(NOW - 60));
    }

    #[test]
    fn no_manifest_published_is_not_an_error_and_downloads_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let source = Fake {
            manifest: RefCell::new(Some(Ok(None))),
            bytes: vec![],
            downloads: Cell::new(0),
        };
        assert_eq!(
            poll_once(&source, dir.path(), NOW, CAP).unwrap(),
            Outcome::NothingPublished
        );
        assert_eq!(source.downloads.get(), 0);
    }

    #[test]
    fn the_snapshot_already_in_force_is_not_downloaded_again() {
        let dir = tempfile::tempdir().unwrap();
        put(dir.path(), &artifact(NOW - 60, 12, 2, 3));
        let source = good(NOW - 60);
        assert_eq!(
            poll_once(&source, dir.path(), NOW, CAP).unwrap(),
            Outcome::UpToDate
        );
        assert_eq!(source.downloads.get(), 0);
    }

    #[test]
    fn an_older_offer_never_replaces_the_snapshot_in_force() {
        let dir = tempfile::tempdir().unwrap();
        let in_force = artifact(NOW - 60, 12, 2, 3);
        put(dir.path(), &in_force);
        let source = good(NOW - 3600);
        assert_eq!(
            poll_once(&source, dir.path(), NOW, CAP).unwrap(),
            Outcome::OlderOffer {
                offered: NOW - 3600,
                current: NOW - 60
            }
        );
        assert_eq!(source.downloads.get(), 0);
        assert_eq!(on_disk(dir.path()).unwrap(), in_force);
    }

    #[test]
    fn a_newer_snapshot_replaces_the_one_in_force() {
        let dir = tempfile::tempdir().unwrap();
        put(dir.path(), &artifact(NOW - 7200, 12, 2, 3));
        let outcome = poll_once(&good(NOW - 60), dir.path(), NOW, CAP).unwrap();
        assert!(matches!(outcome, Outcome::Applied { built_at, .. } if built_at == NOW - 60));
        assert_eq!(built_at_in_force(dir.path()), Some(NOW - 60));
    }

    #[test]
    fn an_offer_past_the_maximum_age_is_not_applied() {
        let dir = tempfile::tempdir().unwrap();
        let old = NOW - DEFAULT_MAX_AGE_SECS - 1;
        let source = good(old);
        assert_eq!(
            poll_once(&source, dir.path(), NOW, CAP).unwrap(),
            Outcome::Expired { built_at: old }
        );
        assert_eq!(source.downloads.get(), 0);
        assert!(on_disk(dir.path()).is_none());
    }

    #[test]
    fn a_bad_signature_is_refused_and_the_file_in_force_is_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let in_force = artifact(NOW - 7200, 12, 2, 3);
        put(dir.path(), &in_force);
        let bytes = artifact(NOW - 60, 12, 2, 3);
        let mut manifest = signed(&bytes, NOW - 60);
        manifest.signature = "00".repeat(64);
        let source = Fake::offering(manifest, bytes);
        assert!(poll_once(&source, dir.path(), NOW, CAP).is_err());
        assert_eq!(
            source.downloads.get(),
            0,
            "nothing is downloaded for a manifest that does not verify"
        );
        assert_eq!(on_disk(dir.path()).unwrap(), in_force);
    }

    #[test]
    fn a_manifest_signed_by_the_content_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = artifact(NOW - 60, 12, 2, 3);
        let mut manifest = signed(&bytes, NOW - 60);
        manifest.sign(&updater::key::test_key_pair());
        let source = Fake::offering(manifest, bytes);
        assert!(poll_once(&source, dir.path(), NOW, CAP).is_err());
        assert!(on_disk(dir.path()).is_none());
    }

    #[test]
    fn a_manifest_from_the_future_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let err = poll_once(&good(NOW + 3600), dir.path(), NOW, CAP).unwrap_err();
        assert!(format!("{err:#}").contains("beyond now"), "{err:#}");
        assert!(on_disk(dir.path()).is_none());
    }

    #[test]
    fn an_artifact_that_is_not_the_signed_one_is_refused_and_nothing_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let in_force = artifact(NOW - 7200, 12, 2, 3);
        put(dir.path(), &in_force);
        let signed_bytes = artifact(NOW - 60, 12, 2, 3);
        let manifest = signed(&signed_bytes, NOW - 60);
        let mut tampered = signed_bytes.clone();
        tampered[39] ^= 1; // same size, one bit of the filter flipped
        let source = Fake::offering(manifest, tampered);
        let err = poll_once(&source, dir.path(), NOW, CAP).unwrap_err();
        assert!(format!("{err:#}").contains("sha256"), "{err:#}");
        assert_eq!(on_disk(dir.path()).unwrap(), in_force);
    }

    #[test]
    fn a_declared_size_over_the_cap_is_refused_before_any_download() {
        let dir = tempfile::tempdir().unwrap();
        let source = good(NOW - 60);
        let err = poll_once(&source, dir.path(), NOW, 8).unwrap_err();
        assert!(format!("{err:#}").contains("cap"), "{err:#}");
        assert_eq!(source.downloads.get(), 0);
    }

    #[test]
    fn a_signed_artifact_that_is_not_a_snapshot_is_refused_and_not_written() {
        let dir = tempfile::tempdir().unwrap();
        let junk = b"not a snapshot at all, but signed".to_vec();
        let source = Fake::offering(signed(&junk, NOW - 60), junk);
        let err = poll_once(&source, dir.path(), NOW, CAP).unwrap_err();
        assert!(
            format!("{err:#}").contains("not a usable snapshot"),
            "{err:#}"
        );
        assert!(on_disk(dir.path()).is_none());
    }

    #[test]
    fn an_artifact_whose_header_disagrees_with_its_manifest_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        // Signed and hashed correctly, but the header says another host count than the manifest.
        let bytes = artifact(NOW - 60, 99, 2, 3);
        let source = Fake::offering(signed(&bytes, NOW - 60), bytes);
        let err = poll_once(&source, dir.path(), NOW, CAP).unwrap_err();
        assert!(format!("{err:#}").contains("header disagrees"), "{err:#}");
        assert!(on_disk(dir.path()).is_none());
    }

    #[test]
    fn a_failing_source_is_an_error_and_leaves_the_snapshot_in_force() {
        let dir = tempfile::tempdir().unwrap();
        let in_force = artifact(NOW - 60, 12, 2, 3);
        put(dir.path(), &in_force);
        let source = Fake {
            manifest: RefCell::new(Some(Err(anyhow::anyhow!("connection refused")))),
            bytes: vec![],
            downloads: Cell::new(0),
        };
        assert!(poll_once(&source, dir.path(), NOW, CAP).is_err());
        assert_eq!(on_disk(dir.path()).unwrap(), in_force);
    }

    #[test]
    fn the_poll_interval_is_six_hours_unless_a_lab_overrides_it_and_never_below_the_floor() {
        assert_eq!(poll_interval(None), POLL_INTERVAL);
        assert_eq!(poll_interval(Some("not a number")), POLL_INTERVAL);
        assert_eq!(poll_interval(Some("30")), Duration::from_secs(30));
        assert_eq!(poll_interval(Some("0")), Duration::from_secs(MIN_POLL_SECS));
    }

    #[test]
    fn the_jitter_stays_within_ten_percent() {
        for _ in 0..200 {
            let j = jittered(Duration::from_secs(1000));
            assert!(
                j >= Duration::from_secs(900) && j <= Duration::from_secs(1100),
                "{j:?}"
            );
        }
    }
}
