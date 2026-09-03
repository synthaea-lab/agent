//! Sliding queue of recent events — the correlator's short-term memory.
//!
//! Deliberately unbounded beyond time-based eviction for now; the bounded entity
//! store (`crates/store`, issue #15) takes over long-lived state.

use std::{collections::VecDeque, time::Duration};

use schema::Event;

/// Sliding queue of recent events. Events older than `window` are
/// evicted automatically on every insertion.
pub struct EventBus {
    events: VecDeque<Event>,
    window: Duration,
}

impl EventBus {
    pub fn new(window: Duration) -> Self {
        Self {
            events: VecDeque::new(),
            window,
        }
    }

    /// Inserts an event and evicts entries that are too old.
    pub fn push(&mut self, event: Event) {
        self.events.push_back(event);
        self.evict();
    }

    /// Returns all events currently in the window.
    pub fn window_events(&self) -> &VecDeque<Event> {
        &self.events
    }

    /// Filters events by pid.
    pub fn events_for_pid(&self, pid: u32) -> impl Iterator<Item = &Event> {
        self.events.iter().filter(move |e| e.meta().pid == pid)
    }

    /// Filters events by (ppid, comm) — the logical identity of a respawned process
    /// (repeated fork+exec by the same parent), whose pid changes on every iteration.
    pub fn events_for_ppid_comm<'a>(
        &'a self,
        ppid: u32,
        comm: &'a str,
    ) -> impl Iterator<Item = &'a Event> {
        self.events
            .iter()
            .filter(move |e| e.meta().ppid == ppid && e.meta().comm == comm)
    }

    fn evict(&mut self) {
        // Use the timestamp of the last inserted event as the reference.
        let Some(latest) = self.events.back() else {
            return;
        };
        let latest_ns = latest.meta().timestamp_ns;
        let window_ns = self.window.as_nanos() as u64;
        let cutoff = latest_ns.saturating_sub(window_ns);
        self.events.retain(|e| e.meta().timestamp_ns >= cutoff);
    }
}
