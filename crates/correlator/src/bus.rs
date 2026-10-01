//! Sliding queue of recent events — the correlator's short-term memory.
//!
//! Deliberately unbounded beyond time-based eviction for now; the bounded entity
//! store (`crates/store`, issue #15) takes over long-lived state.

use std::{collections::VecDeque, time::Duration};

use schema::Event;

/// An unstamped event cannot disprove identity. This preserves the existing
/// Windows/macOS behavior and Linux fallback when a stamp could not be read.
pub(crate) fn same_generation(recorded: Option<u64>, wanted: Option<u64>) -> bool {
    !matches!((recorded, wanted), (Some(a), Some(b)) if a != b)
}

/// Sliding queue of recent events. Events older than `window` are
/// evicted automatically on every insertion.
pub struct EventBus {
    events: VecDeque<Event>,
    window: Duration,
    /// Greatest timestamp ever seen — eviction cuts against this, not the last
    /// insertion (review finding: the sensor drains three ring buffers
    /// independently, so a delayed older event after a newer one must not move
    /// the cutoff backwards and resurrect stale history).
    max_seen_ns: u64,
}

impl EventBus {
    #[must_use]
    pub fn new(window: Duration) -> Self {
        Self {
            events: VecDeque::new(),
            window,
            max_seen_ns: 0,
        }
    }

    /// Inserts an event and evicts entries that are too old.
    pub fn push(&mut self, event: Event) {
        self.events.push_back(event);
        self.evict();
    }

    /// Filters events by pid and process incarnation. Missing stamps preserve the
    /// previous pid-only behavior; two known, different stamps never mix.
    pub fn events_for_pid(
        &self,
        pid: u32,
        generation: Option<u64>,
    ) -> impl Iterator<Item = &Event> {
        self.events.iter().filter(move |e| {
            e.meta().pid == pid && same_generation(e.meta().process_generation, generation)
        })
    }

    /// Filters events by (ppid, comm) — the logical identity of a respawned process
    /// (repeated fork+exec by the same parent), whose pid changes on every iteration.
    pub(crate) fn events_for_ppid_comm<'a>(
        &'a self,
        ppid: u32,
        parent_generation: Option<u64>,
        comm: &'a str,
    ) -> impl Iterator<Item = &'a Event> {
        self.events.iter().filter(move |e| {
            e.meta().ppid == ppid
                && e.meta().comm == comm
                && same_generation(e.meta().parent_process_generation, parent_generation)
        })
    }

    fn evict(&mut self) {
        if let Some(latest) = self.events.back() {
            self.max_seen_ns = self.max_seen_ns.max(latest.meta().timestamp_ns);
        }
        let window_ns = self.window.as_nanos() as u64;
        let cutoff = self.max_seen_ns.saturating_sub(window_ns);
        self.events.retain(|e| e.meta().timestamp_ns >= cutoff);
    }
}
