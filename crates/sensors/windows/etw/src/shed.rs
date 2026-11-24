//! What the sensor's bounded caches and queues shed, readable by the agent's health beacon.
//!
//! Each cache already counted its own losses and logged them; nothing read the count, so an
//! operator saw a warning in a log and the control plane saw nothing (#178). The caches now
//! count through a [`ShedCounter`], a shared atomic, and [`EtwShedding`] hands the ones that
//! lose information to the agent before the sensor runs (like `WindowsSensor::stop_handle`).

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

/// A cumulative count that a cache increments and another thread reads. Clones share the count.
#[derive(Debug, Clone, Default)]
pub(crate) struct ShedCounter(Arc<AtomicU64>);

impl ShedCounter {
    /// Counts one more shed item and returns the new total.
    pub(crate) fn add(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(crate) fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Cumulative totals since the sensor was built, one per place where the sensor sheds
/// information. A counter that shows no loss is not here: the long-path cache refills itself.
#[derive(Debug, Clone, Default)]
pub struct EtwShedding {
    pub(crate) pid_cache_evicted: ShedCounter,
    pub(crate) silo_evicted: ShedCounter,
    pub(crate) marks_dropped: ShedCounter,
    pub(crate) quarantine_unremembered: ShedCounter,
    pub(crate) registry_keys: RegistryKeyShedding,
}

/// What the registry key table loses: each count is a value write reported with less of its
/// key's name than the process used.
#[derive(Debug, Clone, Default)]
pub(crate) struct RegistryKeyShedding {
    pub(crate) unresolved_writes: ShedCounter,
    pub(crate) evicted: ShedCounter,
    pub(crate) names_truncated: ShedCounter,
}

impl EtwShedding {
    /// Pid-cache entries the cap dropped: a later event of such a process misses its image path.
    #[must_use]
    pub fn pid_cache_evicted(&self) -> u64 {
        self.pid_cache_evicted.get()
    }

    /// Silo-directory entries the cap dropped: a container event is named again by a lookup.
    #[must_use]
    pub fn silo_evicted(&self) -> u64 {
        self.silo_evicted.get()
    }

    /// `Zone.Identifier` marks the read-back queue dropped: a lost `FileQuarantine`.
    #[must_use]
    pub fn marks_dropped(&self) -> u64 {
        self.marks_dropped.get()
    }

    /// New quarantine paths reported without dedup because the dedup map was full.
    #[must_use]
    pub fn quarantine_unremembered(&self) -> u64 {
        self.quarantine_unremembered.get()
    }

    /// Registry value writes reported with their key unresolved: the key was opened relative
    /// to one the sensor never saw opened (before its session, or evicted).
    #[must_use]
    pub fn registry_unresolved_writes(&self) -> u64 {
        self.registry_keys.unresolved_writes.get()
    }

    /// Registry key objects the key table dropped at its cap or at a process's share of it:
    /// a later write through one is reported unresolved.
    #[must_use]
    pub fn registry_keys_evicted(&self) -> u64 {
        self.registry_keys.evicted.get()
    }

    /// Registry key names the key table cut to its length bound.
    #[must_use]
    pub fn registry_names_truncated(&self) -> u64 {
        self.registry_keys.names_truncated.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_one_count() {
        let counter = ShedCounter::default();
        let other = counter.clone();
        assert_eq!(counter.add(), 1);
        assert_eq!(other.add(), 2);
        assert_eq!(counter.get(), 2);
    }

    #[test]
    fn a_fresh_shedding_reads_zero_everywhere() {
        let shedding = EtwShedding::default();
        assert_eq!(
            [
                shedding.pid_cache_evicted(),
                shedding.silo_evicted(),
                shedding.marks_dropped(),
                shedding.quarantine_unremembered(),
                shedding.registry_unresolved_writes(),
                shedding.registry_keys_evicted(),
                shedding.registry_names_truncated(),
            ],
            [0; 7]
        );
    }
}
