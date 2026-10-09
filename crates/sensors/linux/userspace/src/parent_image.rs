//! The parent's image path for `ExecEvent::parent_image_path` (#768).
//!
//! The probe knows the parent's `comm` (the fork-lineage map) but not its path, and
//! `comm` is whatever the process named itself (`prctl(PR_SET_NAME)`): lineage features
//! and rules that need "what binary is the parent" had nothing to read on Linux. The
//! kernel does hand us every process's image, at its own `sched_process_exec`, so this
//! remembers `pid -> image` from those events and answers a child's exec with what its
//! parent was running when the child started.
//!
//! The key is `(pid, process_generation)`: a pid is reused, a generation is not (#519).
//! A parent whose stamp is unknown on either side, or differs from the one recorded,
//! resolves to `None`: unknown rather than a reused pid's path. A process that forked
//! and has not exec'd (a subshell) was never recorded, so its children get `None` too.
//!
//! Bounded like the other per-pid state: least-recently-used entries go first, in
//! batches, and the loss is counted and logged, never silent. There is no exit event
//! on this path, so stale entries are only ever replaced (by the pid's next exec) or
//! evicted; the generation check is what keeps a stale one from being read.

use std::collections::HashMap;

use schema::ExecEvent;

/// Processes remembered at once. A busy host has some thousands of live processes; the
/// cap bounds the cache when exits are never seen, not the normal case.
pub(crate) const IMAGE_CACHE_CAP: usize = 32_768;

struct Entry {
    generation: u64,
    image: String,
    last_used: u64,
}

pub(crate) struct ParentImages {
    entries: HashMap<u32, Entry>,
    cap: usize,
    tick: u64,
    evicted: u64,
}

impl ParentImages {
    /// # Panics
    ///
    /// Panics when `cap` is 0: a configuration bug, not a runtime condition.
    pub(crate) fn new(cap: usize) -> Self {
        assert!(cap >= 1, "ParentImages cap must be >= 1");
        Self {
            entries: HashMap::new(),
            cap,
            tick: 0,
            evicted: 0,
        }
    }

    /// Fills `exec.parent_image_path` from what the parent last exec'd, then records
    /// this process's own image for its children.
    pub(crate) fn annotate(&mut self, exec: &mut ExecEvent) {
        exec.parent_image_path = self.parent_of(exec);
        if let Some(generation) = exec.meta.process_generation {
            self.record(exec.meta.pid, generation, exec.image_path.clone());
        }
    }

    /// Remembers a process that was already running when the agent started, with the
    /// stamp `prime_proc_lineage` gave it, so its children resolve from the first exec.
    pub(crate) fn prime(&mut self, pid: u32, generation: u64, image: String) {
        if generation != 0 && self.entries.len() < self.cap {
            self.record(pid, generation, image);
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Entries dropped by the cap since creation (also in the warning each batch logs).
    /// Non-zero means exits are not retiring entries fast enough for this host, or the
    /// cap is too small.
    #[cfg(test)]
    pub(crate) fn evicted(&self) -> u64 {
        self.evicted
    }

    fn parent_of(&mut self, exec: &ExecEvent) -> Option<String> {
        let wanted = exec.meta.parent_process_generation?;
        self.tick += 1;
        let entry = self.entries.get_mut(&exec.meta.ppid)?;
        if entry.generation != wanted {
            return None;
        }
        entry.last_used = self.tick;
        Some(entry.image.clone())
    }

    fn record(&mut self, pid: u32, generation: u64, image: String) {
        if image.is_empty() {
            return;
        }
        self.tick += 1;
        self.entries.insert(
            pid,
            Entry {
                generation,
                image,
                last_used: self.tick,
            },
        );
        if self.entries.len() > self.cap {
            self.evict_batch();
        }
    }

    fn evict_batch(&mut self) {
        let batch = (self.cap / 8).max(1);
        let mut by_age: Vec<(u64, u32)> = self
            .entries
            .iter()
            .map(|(pid, entry)| (entry.last_used, *pid))
            .collect();
        by_age.sort_unstable();
        for (_, pid) in by_age.into_iter().take(batch) {
            self.entries.remove(&pid);
            self.evicted += 1;
        }
        tracing::warn!(
            size = self.entries.len(),
            evicted_total = self.evicted,
            "parent image cache hit its cap: some exec events will carry no parent_image_path"
        );
    }
}

#[cfg(test)]
mod tests {
    use schema::{EventMeta, fixtures};

    use super::*;

    fn exec(
        pid: u32,
        generation: u64,
        ppid: u32,
        parent_generation: u64,
        image: &str,
    ) -> ExecEvent {
        ExecEvent {
            meta: EventMeta {
                pid,
                ppid,
                process_generation: Some(generation),
                parent_process_generation: Some(parent_generation),
                ..fixtures::meta()
            },
            image_path: image.to_string(),
            ..fixtures::exec()
        }
    }

    #[test]
    fn a_child_exec_carries_the_path_its_parent_last_exec_ed() {
        let mut cache = ParentImages::new(8);
        let mut shell = exec(100, 7, 1, 1, "/usr/bin/bash");
        cache.annotate(&mut shell);
        let mut child = exec(200, 9, 100, 7, "/usr/bin/curl");
        cache.annotate(&mut child);
        assert_eq!(child.parent_image_path.as_deref(), Some("/usr/bin/bash"));
    }

    #[test]
    fn a_parent_that_exec_ed_again_resolves_to_its_current_image() {
        let mut cache = ParentImages::new(8);
        cache.annotate(&mut exec(100, 7, 1, 1, "/usr/bin/bash"));
        cache.annotate(&mut exec(100, 7, 1, 1, "/usr/bin/python3"));
        let mut child = exec(200, 9, 100, 7, "/usr/bin/id");
        cache.annotate(&mut child);
        assert_eq!(child.parent_image_path.as_deref(), Some("/usr/bin/python3"));
    }

    #[test]
    fn a_reused_pid_does_not_lend_its_old_path_to_a_new_process() {
        let mut cache = ParentImages::new(8);
        cache.annotate(&mut exec(100, 7, 1, 1, "/usr/bin/nginx"));
        // pid 100 died and was reused by a process that never exec'd (a fork of
        // something else, generation 8): its child must not read nginx's path.
        let mut child = exec(200, 9, 100, 8, "/usr/bin/id");
        cache.annotate(&mut child);
        assert_eq!(child.parent_image_path, None);
    }

    #[test]
    fn an_unknown_generation_on_either_side_resolves_to_nothing() {
        let mut cache = ParentImages::new(8);
        cache.annotate(&mut exec(100, 7, 1, 1, "/usr/bin/bash"));
        let mut no_parent_stamp = exec(200, 9, 100, 7, "/usr/bin/id");
        no_parent_stamp.meta.parent_process_generation = None;
        cache.annotate(&mut no_parent_stamp);
        assert_eq!(no_parent_stamp.parent_image_path, None);

        let mut unstamped = exec(300, 0, 1, 1, "/usr/bin/sh");
        unstamped.meta.process_generation = None;
        cache.annotate(&mut unstamped);
        let mut grandchild = exec(400, 11, 300, 0, "/usr/bin/id");
        cache.annotate(&mut grandchild);
        assert_eq!(
            grandchild.parent_image_path, None,
            "a process with no stamp is never recorded, so it cannot be anyone's parent"
        );
    }

    #[test]
    fn a_parent_that_never_exec_ed_is_unknown_not_guessed() {
        let mut cache = ParentImages::new(8);
        let mut child = exec(200, 9, 100, 7, "/usr/bin/id");
        cache.annotate(&mut child);
        assert_eq!(child.parent_image_path, None);
    }

    #[test]
    fn a_primed_process_resolves_its_children() {
        let mut cache = ParentImages::new(8);
        cache.prime(1, (1 << 63) | 5, "/usr/lib/systemd/systemd".to_string());
        let mut child = exec(200, 9, 1, (1 << 63) | 5, "/usr/bin/id");
        cache.annotate(&mut child);
        assert_eq!(
            child.parent_image_path.as_deref(),
            Some("/usr/lib/systemd/systemd")
        );
        cache.prime(2, 0, "/bin/unstamped".to_string());
        assert_eq!(cache.len(), 2, "an unstamped process is not primed");
    }

    #[test]
    fn the_cache_never_grows_past_its_cap_and_counts_what_it_drops() {
        let mut cache = ParentImages::new(64);
        for pid in 0..10_000u32 {
            cache.annotate(&mut exec(pid + 10, 1, 1, 1, "/bin/x"));
        }
        assert!(cache.len() <= 64);
        assert!(cache.evicted() > 0);
    }

    #[test]
    fn a_parent_that_keeps_spawning_survives_eviction() {
        let mut cache = ParentImages::new(8);
        cache.annotate(&mut exec(100, 7, 1, 1, "/usr/sbin/sshd"));
        for pid in 200..207u32 {
            cache.annotate(&mut exec(pid, 1, 1, 1, "/bin/x"));
            let mut child = exec(pid + 1000, 2, 100, 7, "/bin/y");
            cache.annotate(&mut child);
            assert!(child.parent_image_path.is_some());
        }
        cache.annotate(&mut exec(900, 1, 1, 1, "/bin/overflow"));
        let mut child = exec(901, 2, 100, 7, "/bin/y");
        cache.annotate(&mut child);
        assert_eq!(child.parent_image_path.as_deref(), Some("/usr/sbin/sshd"));
    }
}
