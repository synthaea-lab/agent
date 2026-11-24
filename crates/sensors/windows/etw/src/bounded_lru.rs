//! The LRU-bounded map behind the sensor's handle and pid tables: a local copy of the
//! `store::BoundedMap` shape (sensor crates may depend only on `schema`,
//! `tools/check-deps.py`). Past its cap it evicts the least recently used eighth in one
//! batch, counted and logged, so the loss is observable rather than silent.

use std::{collections::HashMap, hash::Hash};

/// A map that never holds more than `cap` entries. Reads through [`Self::get`] refresh
/// recency; [`Self::peek`] does not.
pub(crate) struct BoundedLru<K, V> {
    /// Names the table in the eviction log line.
    name: &'static str,
    entries: HashMap<K, (V, u64)>,
    cap: usize,
    tick: u64,
    evicted: u64,
}

impl<K: Eq + Hash + Copy, V> BoundedLru<K, V> {
    /// # Panics
    ///
    /// Panics when `cap` is 0 — a configuration bug, not a runtime condition.
    pub(crate) fn new(name: &'static str, cap: usize) -> Self {
        assert!(cap >= 1, "{name} cap must be >= 1");
        Self {
            name,
            entries: HashMap::new(),
            cap,
            tick: 0,
            evicted: 0,
        }
    }

    fn next_tick(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    pub(crate) fn insert(&mut self, key: K, value: V) {
        let tick = self.next_tick();
        self.entries.insert(key, (value, tick));
        if self.entries.len() > self.cap {
            self.evict_batch();
        }
    }

    /// A use, not an inspection: refreshes recency.
    pub(crate) fn get(&mut self, key: &K) -> Option<&V> {
        let tick = self.next_tick();
        let entry = self.entries.get_mut(key)?;
        entry.1 = tick;
        Some(&entry.0)
    }

    /// An inspection: leaves recency as it is.
    pub(crate) fn peek(&self, key: &K) -> Option<&V> {
        self.entries.get(key).map(|(value, _)| value)
    }

    /// Deliberate retirement: not counted as an eviction, since no information is lost.
    pub(crate) fn remove(&mut self, key: &K) -> Option<V> {
        self.entries.remove(key).map(|(value, _)| value)
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Entries dropped by the cap since creation.
    #[cfg_attr(not(test), allow(dead_code))] // read by a future health surface
    pub(crate) fn evicted(&self) -> u64 {
        self.evicted
    }

    fn evict_batch(&mut self) {
        let batch = (self.cap / 8).max(1);
        let mut by_age: Vec<(u64, K)> = self
            .entries
            .iter()
            .map(|(key, (_, last_used))| (*last_used, *key))
            .collect();
        by_age.sort_unstable_by_key(|(last_used, _)| *last_used);
        for (_, key) in by_age.into_iter().take(batch) {
            self.entries.remove(&key);
            self.evicted += 1;
        }
        tracing::warn!(
            table = self.name,
            size = self.entries.len(),
            evicted_total = self.evicted,
            "bounded table hit its cap; least recently used entries evicted"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_never_grows_past_its_cap_and_counts_what_it_evicts() {
        let mut table = BoundedLru::new("test", 64);
        for key in 0..10_000u32 {
            table.insert(key, key);
        }
        assert!(table.len() <= 64);
        assert!(table.evicted() >= 10_000 - 64);
    }

    #[test]
    fn a_used_entry_outlives_unused_ones() {
        let mut table = BoundedLru::new("test", 8);
        table.insert(1u32, "kept");
        for key in 100..107 {
            table.insert(key, "filler");
            assert!(table.get(&1).is_some());
        }
        table.insert(200, "overflow");
        assert_eq!(table.peek(&1), Some(&"kept"));
        assert_eq!(table.evicted(), 1);
    }

    #[test]
    fn peeking_does_not_refresh_recency() {
        let mut table = BoundedLru::new("test", 8);
        table.insert(1u32, ());
        for key in 2..=8 {
            table.insert(key, ());
        }
        assert!(table.peek(&1).is_some());
        table.insert(9, ());
        assert!(table.peek(&1).is_none(), "still the oldest: evicted first");
    }

    #[test]
    fn removing_an_entry_is_not_an_eviction() {
        let mut table = BoundedLru::new("test", 8);
        table.insert(42u32, "value");
        assert_eq!(table.remove(&42), Some("value"));
        assert!(table.peek(&42).is_none());
        assert_eq!(table.evicted(), 0);
    }
}
