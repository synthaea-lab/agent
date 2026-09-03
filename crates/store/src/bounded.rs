//! LRU-bounded map. Deliberately dependency-free: a `HashMap` plus a monotonic use
//! counter, evicting the least-recently-used entries in an amortized batch (1/8 of
//! the cap) when the cap is exceeded — O(n) per eviction pass, amortized O(1)-ish
//! per insert at the sizes detection state uses (tens of thousands of entries).

use std::{collections::HashMap, hash::Hash};

/// A map that never grows past `cap` entries; inserting past the cap evicts the
/// least-recently-used entries. Reads refresh recency.
pub struct BoundedMap<K, V> {
    entries: HashMap<K, (V, u64)>,
    cap: usize,
    tick: u64,
    evicted: u64,
}

impl<K: Eq + Hash + Clone, V> BoundedMap<K, V> {
    /// `cap` must be at least 1.
    pub fn new(cap: usize) -> Self {
        assert!(cap >= 1, "BoundedMap cap must be >= 1");
        Self {
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

    pub fn insert(&mut self, key: K, value: V) {
        let tick = self.next_tick();
        self.entries.insert(key, (value, tick));
        if self.entries.len() > self.cap {
            self.evict_batch();
        }
    }

    /// Refreshes recency (this is a use, not an inspection).
    pub fn get(&mut self, key: &K) -> Option<&V> {
        let tick = self.next_tick();
        let entry = self.entries.get_mut(key)?;
        entry.1 = tick;
        Some(&entry.0)
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let tick = self.next_tick();
        let entry = self.entries.get_mut(key)?;
        entry.1 = tick;
        Some(&mut entry.0)
    }

    /// Non-refreshing read, for inspection paths that must not perturb recency.
    pub fn peek(&self, key: &K) -> Option<&V> {
        self.entries.get(key).map(|(v, _)| v)
    }

    pub fn get_or_insert_with(&mut self, key: K, default: impl FnOnce() -> V) -> &mut V {
        let tick = self.next_tick();
        if !self.entries.contains_key(&key) {
            self.entries.insert(key.clone(), (default(), tick));
            if self.entries.len() > self.cap {
                self.evict_batch();
            }
        }
        let entry = self
            .entries
            .get_mut(&key)
            .expect("inserted or present above; eviction spares the freshest entry");
        entry.1 = tick;
        &mut entry.0
    }

    pub fn extend(&mut self, iter: impl IntoIterator<Item = (K, V)>) {
        for (k, v) in iter {
            self.insert(k, v);
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Non-refreshing iteration over all entries, for scan-style lookups whose
    /// match key is not the map key (e.g. path matched by basename).
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries.iter().map(|(k, (v, _))| (k, v))
    }

    /// Entries evicted over the map's lifetime — bounded state loses information by
    /// design; the count keeps the loss observable.
    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    /// Evicts the ~cap/8 least-recently-used entries (at least one), so eviction
    /// cost amortizes instead of running on every insert at the boundary.
    fn evict_batch(&mut self) {
        let excess = self.entries.len().saturating_sub(self.cap);
        let batch = excess + (self.cap / 8).max(1) - 1;
        let mut order: Vec<(u64, K)> = self
            .entries
            .iter()
            .map(|(k, (_, tick))| (*tick, k.clone()))
            .collect();
        order.sort_unstable_by_key(|(tick, _)| *tick);
        for (_, key) in order.into_iter().take(batch.max(1)) {
            self.entries.remove(&key);
            self.evicted += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_exceeds_cap_under_load() {
        let cap = 1000;
        let mut map = BoundedMap::new(cap);
        for i in 0..100_000u32 {
            map.insert(i, i);
            assert!(map.len() <= cap, "len {} exceeded cap at i={i}", map.len());
        }
        assert!(map.evicted() >= 99_000);
    }

    #[test]
    fn evicts_least_recently_used_first() {
        let mut map = BoundedMap::new(8);
        for i in 0..8u32 {
            map.insert(i, i);
        }
        // Touch 0..4 so 4..8 become the LRU half.
        for i in 0..4u32 {
            map.get(&i);
        }
        for i in 8..10u32 {
            map.insert(i, i);
        }
        for i in 0..4u32 {
            assert!(map.peek(&i).is_some(), "recently used {i} must survive");
        }
    }

    #[test]
    fn get_or_insert_with_counts_as_use() {
        let mut map = BoundedMap::new(4);
        *map.get_or_insert_with("a", || 0) += 1;
        *map.get_or_insert_with("a", || 0) += 1;
        assert_eq!(map.peek(&"a"), Some(&2));
    }
}
