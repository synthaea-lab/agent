//! The bounded pid -> (image path, incarnation, server silo) cache behind
//! `SharedState::pids`, with the explicit `remove` a pid cache needs for PID recycling.

use crate::{bounded_lru::BoundedLru, shed::ShedCounter};

/// pid → full image path, process sequence number and server silo, never
/// larger than its cap. Explicit [`Self::remove`] on
/// `ProcessEnd` is the correctness path (PID recycling); LRU eviction is only the
/// backstop for when that removal never arrives (`ProcessEnd` records lost, or a cap
/// too small for this host), and is counted so the loss is observable rather than silent.
pub(crate) struct PidCache {
    entries: BoundedLru<u32, Entry>,
}

struct Entry {
    /// `None` for a process whose image could not be resolved: its silo and
    /// stamp are still worth keeping, but [`PidCache::get`] misses so callers
    /// keep trying a live lookup.
    image_path: Option<String>,
    /// The kernel's process sequence number: unique per process for the boot,
    /// so it tells a recycled pid from the process cached under it. `None` when
    /// it could not be read.
    generation: Option<u64>,
    /// The server silo: 0 the host, `None` when it could not be read.
    silo: Option<u32>,
}

impl PidCache {
    /// # Panics
    ///
    /// Panics when `cap` is 0 — a configuration bug, not a runtime condition.
    #[cfg(test)]
    pub(crate) fn new(cap: usize) -> Self {
        Self::counting(cap, ShedCounter::default())
    }

    /// A cache whose evictions are counted into `evicted`, which the health beacon reads.
    ///
    /// # Panics
    ///
    /// Panics when `cap` is 0.
    pub(crate) fn counting(cap: usize, evicted: ShedCounter) -> Self {
        Self {
            entries: BoundedLru::counting("pid cache", cap, evicted),
        }
    }

    pub(crate) fn insert(
        &mut self,
        pid: u32,
        image_path: String,
        generation: Option<u64>,
        silo: Option<u32>,
    ) {
        self.put(pid, Some(image_path), generation, silo);
    }

    /// A process whose image could not be resolved: its incarnation and silo
    /// are recorded, so its events keep their container (#709 review), while
    /// [`Self::get`] still misses for it.
    pub(crate) fn insert_without_image(
        &mut self,
        pid: u32,
        generation: Option<u64>,
        silo: Option<u32>,
    ) {
        self.put(pid, None, generation, silo);
    }

    fn put(
        &mut self,
        pid: u32,
        image_path: Option<String>,
        generation: Option<u64>,
        silo: Option<u32>,
    ) {
        self.entries.insert(
            pid,
            Entry {
                image_path,
                generation,
                silo,
            },
        );
    }

    /// Refreshes recency: a pid still producing events is still alive.
    pub(crate) fn get(&mut self, pid: u32) -> Option<&str> {
        self.entries.get(&pid)?.image_path.as_deref()
    }

    /// Whether `pid` is cached, without refreshing recency.
    pub(crate) fn contains(&self, pid: u32) -> bool {
        self.entries.peek(&pid).is_some()
    }

    /// The process sequence number cached for `pid`, without refreshing recency.
    pub(crate) fn generation(&self, pid: u32) -> Option<u64> {
        self.entries.peek(&pid)?.generation
    }

    /// The pid's server silo, when it was read (0 = the host). Refreshes
    /// recency like [`Self::get`].
    pub(crate) fn silo(&mut self, pid: u32) -> Option<u32> {
        self.entries.get(&pid)?.silo
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
    #[cfg(test)]
    pub(crate) fn evicted(&self) -> u64 {
        self.entries.evicted()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_cache_never_grows_past_its_cap() {
        let mut cache = PidCache::new(64);
        for pid in 0..10_000 {
            cache.insert(pid, format!(r"C:\bin\p{pid}.exe"), None, None);
        }
        assert!(cache.len() <= 64);
        assert!(cache.evicted() > 0);
    }

    #[test]
    fn contains_does_not_refresh_recency() {
        let mut cache = PidCache::new(8);
        cache.insert(1, r"C:\a.exe".to_string(), None, None);
        for pid in 2..=8 {
            cache.insert(pid, format!(r"C:\p{pid}.exe"), None, None);
        }
        assert!(cache.contains(1));
        cache.insert(9, r"C:\overflow.exe".to_string(), None, None);
        assert!(!cache.contains(1), "still the oldest: evicted first");
        assert!(!cache.contains(42));
    }

    #[test]
    fn process_end_removal_is_not_counted_as_eviction() {
        let mut cache = PidCache::new(8);
        cache.insert(42, r"C:\Windows\notepad.exe".to_string(), None, None);
        cache.remove(42);
        assert!(cache.get(42).is_none());
        assert_eq!(cache.evicted(), 0);
    }

    #[test]
    fn recycled_pid_resolves_to_the_new_image() {
        let mut cache = PidCache::new(8);
        cache.insert(42, r"C:\Windows\notepad.exe".to_string(), None, None);
        cache.remove(42);
        cache.insert(
            42,
            r"C:\Users\Public\evil.exe".to_string(),
            Some(9),
            Some(7),
        );
        assert_eq!(cache.get(42), Some(r"C:\Users\Public\evil.exe"));
        assert_eq!(cache.generation(42), Some(9));
        assert_eq!(cache.silo(42), Some(7));
    }

    #[test]
    fn a_process_without_a_known_image_keeps_its_silo_but_misses_on_get() {
        let mut cache = PidCache::new(8);
        cache.insert_without_image(42, Some(9), Some(7));
        assert_eq!(cache.silo(42), Some(7));
        assert_eq!(cache.generation(42), Some(9));
        assert!(cache.get(42).is_none());
    }

    #[test]
    fn evictions_are_counted_into_the_counter_a_reader_holds() {
        let beacon_side = ShedCounter::default();
        let mut cache = PidCache::counting(8, beacon_side.clone());
        for pid in 0..9 {
            cache.insert(pid, format!(r"C:\img\{pid}.exe"), None, None);
        }
        // Cap 8 evicts one entry (`cap / 8`) when the 9th arrives.
        assert_eq!(beacon_side.get(), 1);
        assert_eq!(cache.evicted(), 1);
    }

    #[test]
    fn recently_used_pids_survive_eviction() {
        let mut cache = PidCache::new(8);
        cache.insert(1, r"C:\Windows\explorer.exe".to_string(), None, Some(0));
        for pid in 100..107 {
            cache.insert(pid, format!(r"C:\bin\p{pid}.exe"), None, None);
            // explorer keeps producing events — it stays the freshest entry.
            assert!(cache.get(1).is_some());
        }
        cache.insert(200, r"C:\bin\overflow.exe".to_string(), None, None);
        assert_eq!(cache.get(1), Some(r"C:\Windows\explorer.exe"));
        assert_eq!(cache.evicted(), 1);
    }
}
