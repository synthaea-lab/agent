//! Fleet rarity (ADR-0020, #76): whether an executed image is in the fleet's common set, fed to
//! the correlator as capped evidence, and the counts of those judgements for the health beacon.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

use crate::sync::LockExt as _;

/// How many hosts a snapshot must cover before "not in the common set" counts as evidence
/// (ADR-0020): on a fleet that has just enrolled the snapshot is empty or thin, and every
/// binary would look rare. **Provisional**: ADR-0020 leaves it to calibration on lab data
/// (slice 6 of `docs/detection/fleet-prevalence-snapshot-plan.md`).
const RARITY_MIN_HOSTS_COVERED: u64 = 10;

/// How old a snapshot may be before it is treated as absent. **Provisional**, see
/// [`updater::snapshot::DEFAULT_MAX_AGE_SECS`].
pub(super) const MAX_SNAPSHOT_AGE_SECS: u64 = updater::snapshot::DEFAULT_MAX_AGE_SECS;

pub(super) fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// What became of the rarity judgements since start, for the health beacon (ADR-0020, #76).
/// Plain atomics: bumped on the enrichment worker, read by the beacon thread.
#[derive(Default)]
pub(crate) struct RarityStats {
    applied: AtomicU64,
    withheld: AtomicU64,
    unapplied: AtomicU64,
}

impl crate::health::RarityStatsSource for RarityStats {
    fn rarity_counts(&self) -> crate::health::RarityCounts {
        crate::health::RarityCounts {
            applied: self.applied.load(Ordering::Relaxed),
            withheld: self.withheld.load(Ordering::Relaxed),
            unapplied: self.unapplied.load(Ordering::Relaxed),
        }
    }
}

/// What the fleet's common set says about one executed image.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Rarity {
    /// The snapshot covers enough hosts and does not contain the image's hash.
    NotInCommonSet,
    /// The snapshot covers enough hosts and contains the hash.
    InCommonSet,
    /// No basis to say: no snapshot, too few hosts covered, or no usable hash. Never read as
    /// "rare" (the `rarity_known` of the ML feature, `ml::features::rarity`).
    Withheld,
}

/// The rarity of an image given the snapshot in force, the exec's hash and the minimum
/// coverage. A pure function over the same inputs as the ML rarity feature, so the two
/// cannot disagree about what is known.
pub(super) fn rarity_evidence(
    sha256: Option<&str>,
    snapshot: Option<&ml::features::common_set::CommonSetSnapshot>,
    min_hosts: u64,
) -> Rarity {
    use ml::features::rarity::{CommonSet, extract_features};

    let [known, in_common_set] =
        extract_features(sha256, snapshot.map(|s| s as &dyn CommonSet), min_hosts);
    if known < 0.5 {
        Rarity::Withheld
    } else if in_common_set > 0.5 {
        Rarity::InCommonSet
    } else {
        Rarity::NotInCommonSet
    }
}

/// Feeds "this exec's image is not in the fleet's common set" to the correlator, when that is
/// what the snapshot in force says. Runs on the enrichment worker, off the capture path,
/// because only the worker knows the hash, and after the capture thread already correlated the
/// exec (so the process has a belief to add to). The snapshot lock is released before the
/// correlator lock is taken: no nested locking.
pub(super) fn note_image_rarity(
    correlator: &Mutex<correlator::CorrelationEngine>,
    common_set: &Mutex<Option<Arc<ml::features::common_set::CommonSetSnapshot>>>,
    stats: &RarityStats,
    exec: &schema::ExecEvent,
    now_secs: u64,
) {
    // A snapshot past its maximum age counts as absent: the evidence is withheld, so a server
    // that stopped publishing cannot keep a stale set in force (ADR-0033 decision 3).
    let snapshot = common_set.lock_recovering().clone().filter(|s| {
        !updater::snapshot::is_expired(s.header().built_at, now_secs, MAX_SNAPSHOT_AGE_SECS)
    });
    match rarity_evidence(
        exec.sha256.as_deref(),
        snapshot.as_deref(),
        RARITY_MIN_HOSTS_COVERED,
    ) {
        Rarity::InCommonSet => {}
        Rarity::Withheld => {
            stats.withheld.fetch_add(1, Ordering::Relaxed);
        }
        Rarity::NotInCommonSet => {
            let applied = correlator
                .lock_recovering()
                .apply_rarity_evidence(exec.meta.pid, exec.meta.process_generation);
            let counter = if applied {
                &stats.applied
            } else {
                &stats.unapplied
            };
            counter.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                pid = exec.meta.pid,
                applied,
                "rarity: image not in the common set"
            );
        }
    }
}
