//! The LRU-bounded map behind the sensor's handle and pid tables: a local copy of the
//! `store::BoundedMap` shape (sensor crates may depend only on `schema`,
//! `tools/check-deps.py`). Past its cap it evicts the least recently used eighth in one
//! batch, counted and logged, so the loss is observable rather than silent.

use std::{collections::HashMap, hash::Hash};

use crate::shed::ShedCounter;

/// A map that never holds more than `cap` entries. Reads through [`Self::get`] refresh
/// recency; [`Self::peek`] does not.
pub(crate) struct BoundedLru<K, V> {
    /// Names the table in the eviction log line.
    name: &'static str,
    entries: HashMap<K, (V, u64)>,
    cap: usize,
    tick: u64,
    evicted: ShedCounter,
}

impl<K: Eq + Hash + Copy, V> BoundedLru<K, V> {
    /// # Panics
    ///
    /// Panics when `cap` is 0 — a configuration bug, not a runtime condition.
    #[cfg(test)]
    pub(crate) fn new(name: &'static str, cap: usize) -> Self {
        Self::counting(name, cap, ShedCounter::default())
    }

    /// A table whose evictions are counted into `evicted`, which the health beacon reads.
    ///
    /// # Panics
    ///
    /// Panics when `cap` is 0.
    pub(crate) fn counting(name: &'static str, cap: usize, evicted: ShedCounter) -> Self {
        assert!(cap >= 1, "{name} cap must be >= 1");
        Self {
            name,
            entries: HashMap::new(),
            cap,
            tick: 0,
            evicted,
        }
    }

    fn next_tick(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    /// Inserts `value` under `key` and returns the values the cap evicted to make room, if
    /// it was reached.
    pub(crate) fn insert(&mut self, key: K, value: V) -> Vec<V> {
        let tick = self.next_tick();
        self.entries.insert(key, (value, tick));
        if self.entries.len() <= self.cap {
            return Vec::new();
        }
        let evicted = self.evict_least_recent((self.cap / 8).max(1), |_| true);
        tracing::warn!(
            table = self.name,
            size = self.entries.len(),
            evicted_total = self.evicted.get(),
            "bounded table hit its cap; least recently used entries evicted"
        );
        evicted
    }

    /// Evicts up to `count` of the least recently used entries `selected` picks, counted like
    /// the cap's evictions, and returns them.
    pub(crate) fn evict_least_recent(
        &mut self,
        count: usize,
        selected: impl Fn(&V) -> bool,
    ) -> Vec<V> {
        let mut by_age: Vec<(u64, K)> = self
            .entries
            .iter()
            .filter(|(_, (value, _))| selected(value))
            .map(|(key, (_, last_used))| (*last_used, *key))
            .collect();
        by_age.sort_unstable_by_key(|(last_used, _)| *last_used);
        let evicted: Vec<V> = by_age
            .into_iter()
            .take(count)
            .filter_map(|(_, key)| self.entries.remove(&key))
            .map(|(value, _)| value)
            .collect();
        for _ in &evicted {
            self.evicted.add();
        }
        evicted
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
    #[cfg(test)]
    pub(crate) fn evicted(&self) -> u64 {
        self.evicted.get()
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
    fn the_cap_returns_what_it_evicted() {
        let mut table = BoundedLru::new("test", 8);
        for key in 0..8u32 {
            assert!(table.insert(key, key).is_empty());
        }
        assert_eq!(table.insert(8, 8), vec![0]);
    }

    #[test]
    fn a_selective_eviction_takes_the_oldest_selected_entries_only() {
        let mut table = BoundedLru::new("test", 8);
        for key in 0..6u32 {
            table.insert(key, key);
        }

        let mut evicted = table.evict_least_recent(2, |value| value % 2 == 1);
        evicted.sort_unstable();

        assert_eq!(evicted, vec![1, 3]);
        assert_eq!(table.evicted(), 2);
        assert!(table.peek(&0).is_some() && table.peek(&5).is_some());
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
