//! The bounded pid → image-path cache behind `SharedState::pids`.
//!
//! A local type rather than `store::BoundedMap`: sensor crates may depend only on
//! `schema` (`tools/check-deps.py`). Same shape as `BoundedMap` — a `HashMap` plus
//! a monotonic use counter, least-recently-used entries evicted in a batch of 1/8
//! of the cap — plus the explicit `remove` a pid cache needs for PID recycling.

use std::collections::HashMap;

/// pid → full image path, never larger than its cap. Explicit [`Self::remove`] on
/// `ProcessEnd` is the correctness path (PID recycling); LRU eviction is only the
/// backstop for when that removal never arrives, and is counted so the loss is
/// observable rather than silent.
pub(crate) struct PidCache {
    entries: HashMap<u32, (String, u64)>,
    cap: usize,
    tick: u64,
    evicted: u64,
}

impl PidCache {
    /// # Panics
    ///
    /// Panics when `cap` is 0 — a configuration bug, not a runtime condition.
    pub(crate) fn new(cap: usize) -> Self {
        assert!(cap >= 1, "PidCache cap must be >= 1");
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

    pub(crate) fn insert(&mut self, pid: u32, image_path: String) {
        let tick = self.next_tick();
        self.entries.insert(pid, (image_path, tick));
        if self.entries.len() > self.cap {
            self.evict_batch();
        }
    }

    /// Refreshes recency: a pid still producing events is still alive.
    pub(crate) fn get(&mut self, pid: u32) -> Option<&str> {
        let tick = self.next_tick();
        let entry = self.entries.get_mut(&pid)?;
        entry.1 = tick;
        Some(entry.0.as_str())
    }

    /// Deliberate retirement (`ProcessEnd`) — not counted as an eviction, since
    /// no information is lost.
    pub(crate) fn remove(&mut self, pid: u32) {
        self.entries.remove(&pid);
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Entries dropped by the cap since creation — non-zero means `ProcessEnd`
    /// events were lost (or the cap is too small for this host).
    #[cfg_attr(not(test), allow(dead_code))] // read by a future health surface
    pub(crate) fn evicted(&self) -> u64 {
        self.evicted
    }

    fn evict_batch(&mut self) {
        let batch = (self.cap / 8).max(1);
        let mut by_age: Vec<(u64, u32)> = self
            .entries
            .iter()
            .map(|(pid, (_, tick))| (*tick, *pid))
            .collect();
        by_age.sort_unstable();
        for (_, pid) in by_age.into_iter().take(batch) {
            self.entries.remove(&pid);
            self.evicted += 1;
        }
        tracing::warn!(
            size = self.entries.len(),
            evicted_total = self.evicted,
            "pid cache hit its cap — ProcessEnd events were likely lost"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_cache_never_grows_past_its_cap() {
        let mut cache = PidCache::new(64);
        for pid in 0..10_000 {
            cache.insert(pid, format!(r"C:\bin\p{pid}.exe"));
        }
        assert!(cache.len() <= 64);
        assert!(cache.evicted() > 0);
    }

    #[test]
    fn process_end_removal_is_not_counted_as_eviction() {
        let mut cache = PidCache::new(8);
        cache.insert(42, r"C:\Windows\notepad.exe".to_string());
        cache.remove(42);
        assert!(cache.get(42).is_none());
        assert_eq!(cache.evicted(), 0);
    }

    #[test]
    fn recycled_pid_resolves_to_the_new_image() {
        let mut cache = PidCache::new(8);
        cache.insert(42, r"C:\Windows\notepad.exe".to_string());
        cache.remove(42);
        cache.insert(42, r"C:\Users\Public\evil.exe".to_string());
        assert_eq!(cache.get(42), Some(r"C:\Users\Public\evil.exe"));
    }

    #[test]
    fn recently_used_pids_survive_eviction() {
        let mut cache = PidCache::new(8);
        cache.insert(1, r"C:\Windows\explorer.exe".to_string());
        for pid in 100..107 {
            cache.insert(pid, format!(r"C:\bin\p{pid}.exe"));
            // explorer keeps producing events — it stays the freshest entry.
            assert!(cache.get(1).is_some());
        }
        cache.insert(200, r"C:\bin\overflow.exe".to_string());
        assert_eq!(cache.get(1), Some(r"C:\Windows\explorer.exe"));
        assert_eq!(cache.evicted(), 1);
    }
}
