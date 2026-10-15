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
//! resolves to `None`: unknown rather than a reused pid's path.
//!
//! A process that forked and has not exec'd (a subshell: `$(...)`, a pipeline stage) was
//! never recorded, but it runs the image of the process that forked it, so its children
//! inherit that image (#784): the probe hands over the parent's own parent and its stamp,
//! and whether the parent has exec'd, and the image recorded for the forker answers if, and
//! only if, the parent never exec'd (a parent that did has an image of its own, unknown when
//! the cache lost it, and is not given its forker's) and that image was already in place
//! when the subshell forked. A forker that exec'd again after the fork has a different
//! image now than its subshell still runs, and that answers `None`: the fork time is the
//! subshell's own generation (`bpf_ktime_get_ns()` at the fork, the clock the exec events
//! carry), the exec time is stored with each image. One thing this cannot see: a subshell
//! that did exec, if that event was lost, would be given its forker's image.
//!
//! Bounded like the other per-pid state, in batches, and the loss is counted and logged, never
//! silent. The count is split in two: an entry whose process had exited costs nothing (it can
//! never be a parent again) and is a debug line; one whose process was still alive is the loss,
//! and is the one that is warned about, at most once a minute (#783).
//!
//! There is no exit event on this path, so stale entries are only ever replaced (by the pid's
//! next exec) or evicted, and the generation check is what keeps a stale one from being read.
//! Eviction prefers the entries of processes that no longer exist (asked of `/proc`)
//! before the least recently used live ones, so an idle long-lived parent is not pushed out by
//! the short-lived processes that came after it (#783).

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use schema::ExecEvent;

/// Processes remembered at once. A busy host has some thousands of live processes; the
/// cap bounds the cache when exits are never seen, not the normal case.
pub(crate) const IMAGE_CACHE_CAP: usize = 32_768;

struct Entry {
    generation: u64,
    image: String,
    /// `bpf_ktime_get_ns()` of the exec that set `image`; `0` for an image read from
    /// `/proc` at startup (it was in place before anything this sensor saw forked).
    image_since_ns: u64,
    last_used: u64,
}

/// What the probe knows about an exec that the schema event does not carry: the raw clock
/// the generations are measured on, and the parent's own parent.
#[derive(Clone, Copy, Default)]
pub(crate) struct ExecStamps {
    /// `bpf_ktime_get_ns()` at this exec (`wire::EventMeta::timestamp_ns`, before the
    /// boot-to-epoch offset is added).
    pub(crate) ktime_ns: u64,
    /// The parent's parent (`wire::ExecEvent::grandparent_pid`), `0` when unknown.
    pub(crate) grandparent_pid: u32,
    /// Its stamp as the parent's fork recorded it, `0` when unknown.
    pub(crate) grandparent_generation: u64,
    /// The probe saw the parent fork and has not seen it exec since (`PROC_LINEAGE`'s
    /// `execd` flag). Only then may the parent be answered with its forker's image: a parent
    /// that exec'd has an image of its own, and when the cache lost it the answer is
    /// unknown. `false` is the default and the safe reading: no claim, no fallback.
    pub(crate) parent_never_exec_ed: bool,
}

/// What the cap dropped, by whether the process was still alive (#783).
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EvictionCounts {
    pub(crate) dead: u64,
    pub(crate) live: u64,
}

/// The live-eviction warning is logged at most this often; its fields are cumulative totals, so
/// a rate-limited line still carries the whole count.
const LIVE_EVICTION_WARN_EVERY: Duration = Duration::from_secs(60);

/// Whether `pid` is a live process (its `/proc/<pid>` exists).
fn process_exists(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

pub(crate) struct ParentImages {
    entries: HashMap<u32, Entry>,
    cap: usize,
    tick: u64,
    /// Entries dropped by the cap whose process no longer existed: nothing was lost, a child of
    /// that process cannot be exec'd any more.
    evicted_dead: u64,
    /// Entries dropped by the cap whose process was still alive (the cache had no exited ones to
    /// drop): the loss, a later child of such a process carries no `parent_image_path`.
    evicted_live: u64,
    /// When the live-eviction warning was last logged, to log it once a minute (#783).
    last_live_warn: Option<Instant>,
    /// Whether a pid is a live process now; swapped in tests.
    is_alive: fn(u32) -> bool,
}

impl ParentImages {
    /// # Panics
    ///
    /// Panics when `cap` is 0: a configuration bug, not a runtime condition.
    pub(crate) fn new(cap: usize) -> Self {
        Self::with_liveness(cap, process_exists)
    }

    /// [`Self::new`] with another liveness test, for tests that must not depend on which pids
    /// the machine running them happens to have.
    ///
    /// # Panics
    ///
    /// Panics when `cap` is 0: a configuration bug, not a runtime condition.
    pub(crate) fn with_liveness(cap: usize, is_alive: fn(u32) -> bool) -> Self {
        assert!(cap >= 1, "ParentImages cap must be >= 1");
        Self {
            entries: HashMap::new(),
            cap,
            tick: 0,
            evicted_dead: 0,
            evicted_live: 0,
            last_live_warn: None,
            is_alive,
        }
    }

    /// Fills `exec.parent_image_path` from what the parent last exec'd (or, for a parent
    /// that never exec'd, from what its forker was running), then records this process's
    /// own image for its children.
    pub(crate) fn annotate(&mut self, exec: &mut ExecEvent, stamps: ExecStamps) {
        exec.parent_image_path = self
            .parent_of(exec)
            .or_else(|| self.forkers_image(exec, stamps));
        if let Some(generation) = exec.meta.process_generation {
            self.record(
                exec.meta.pid,
                generation,
                exec.image_path.clone(),
                stamps.ktime_ns,
            );
        }
    }

    /// Remembers a process that was already running when the agent started, with the
    /// stamp `prime_proc_lineage` gave it, so its children resolve from the first exec.
    pub(crate) fn prime(&mut self, pid: u32, generation: u64, image: String) {
        if generation != 0 && self.entries.len() < self.cap {
            self.record(pid, generation, image, 0);
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(crate) fn contains(&self, pid: u32) -> bool {
        self.entries.contains_key(&pid)
    }

    /// Entries dropped by the cap since creation, split by whether the process was still alive.
    #[cfg(test)]
    pub(crate) fn eviction_counts(&self) -> EvictionCounts {
        EvictionCounts {
            dead: self.evicted_dead,
            live: self.evicted_live,
        }
    }

    /// All entries dropped by the cap since creation, dead and live.
    #[cfg(test)]
    pub(crate) fn evicted(&self) -> u64 {
        self.evicted_dead + self.evicted_live
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

    /// The image of the process that forked a parent which never exec'd (#784), when it
    /// can be said to be the parent's. `None` unless: the probe saw the parent fork and
    /// never exec, the parent's own stamp is known (its fork time), the forker is known by
    /// pid and stamp, and the forker's current image was already in place when the parent
    /// forked.
    fn forkers_image(&mut self, exec: &ExecEvent, stamps: ExecStamps) -> Option<String> {
        let fork_ns = exec.meta.parent_process_generation.filter(|g| *g != 0)?;
        if !stamps.parent_never_exec_ed
            || stamps.grandparent_pid == 0
            || stamps.grandparent_generation == 0
        {
            return None;
        }
        self.tick += 1;
        let forker = self.entries.get_mut(&stamps.grandparent_pid)?;
        if forker.generation != stamps.grandparent_generation || forker.image_since_ns > fork_ns {
            return None;
        }
        forker.last_used = self.tick;
        Some(forker.image.clone())
    }

    fn record(&mut self, pid: u32, generation: u64, image: String, image_since_ns: u64) {
        if image.is_empty() {
            // An exec we saw but could not read the image of. The generation is stamped
            // at fork and survives exec, so the previous entry would keep matching and
            // hand its children the image from before this exec: wrong, where unknown
            // is the contract. Forget it.
            self.entries.remove(&pid);
            return;
        }
        self.tick += 1;
        self.entries.insert(
            pid,
            Entry {
                generation,
                image,
                image_since_ns,
                last_used: self.tick,
            },
        );
        if self.entries.len() > self.cap {
            self.evict_batch();
        }
    }

    /// Frees a batch of the least valuable entries. Nothing tells this cache when a process
    /// exits (the probe removes its own `PROC_LINEAGE` entry but sends no event), so recency
    /// alone ranks an idle `sshd` or `nginx`, which is exactly the parent the cache is for, below
    /// every short-lived process that came after it. Among the oldest entries the ones whose
    /// process is gone (`/proc/<pid>` missing) go first, oldest first; only if there are not
    /// enough of those do the oldest live ones follow, as before. The scan asks `/proc` about at
    /// most four batches of entries, so the work per eviction is bounded.
    fn evict_batch(&mut self) {
        let batch = (self.cap / 8).max(1);
        let mut by_age: Vec<(u64, u32)> = self
            .entries
            .iter()
            .map(|(pid, entry)| (entry.last_used, *pid))
            .collect();
        by_age.sort_unstable();
        let window = by_age.len().min(batch * 4);
        let mut victims: Vec<u32> = by_age[..window]
            .iter()
            .map(|(_, pid)| *pid)
            .filter(|pid| !(self.is_alive)(*pid))
            .take(batch)
            .collect();
        let dead = victims.len();
        for (_, pid) in &by_age {
            if victims.len() >= batch {
                break;
            }
            if !victims.contains(pid) {
                victims.push(*pid);
            }
        }
        let live = victims.len() - dead;
        for pid in victims {
            self.entries.remove(&pid);
        }
        self.evicted_dead += dead as u64;
        self.evicted_live += live as u64;
        if live > 0 {
            self.warn_live_eviction();
        } else {
            tracing::debug!(
                size = self.entries.len(),
                dead,
                "parent image cache full: dropped entries of exited processes"
            );
        }
    }

    /// Says, at most once a minute, that live processes were evicted: the one case that costs a
    /// `parent_image_path`. Evicting an exited process loses nothing and is only a debug line.
    fn warn_live_eviction(&mut self) {
        if self
            .last_live_warn
            .is_some_and(|at| at.elapsed() < LIVE_EVICTION_WARN_EVERY)
        {
            return;
        }
        self.last_live_warn = Some(Instant::now());
        tracing::warn!(
            size = self.entries.len(),
            live_evicted_total = self.evicted_live,
            dead_evicted_total = self.evicted_dead,
            "parent image cache evicted live processes: a later child of one carries no parent_image_path"
        );
    }
}

#[cfg(test)]
mod tests {
    use schema::{EventMeta, fixtures};

    use super::*;

    fn note(cache: &mut ParentImages, exec: &mut ExecEvent) {
        cache.annotate(exec, ExecStamps::default());
    }

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
        note(&mut cache, &mut shell);
        let mut child = exec(200, 9, 100, 7, "/usr/bin/curl");
        note(&mut cache, &mut child);
        assert_eq!(child.parent_image_path.as_deref(), Some("/usr/bin/bash"));
    }

    #[test]
    fn a_parent_that_exec_ed_again_resolves_to_its_current_image() {
        let mut cache = ParentImages::new(8);
        note(&mut cache, &mut exec(100, 7, 1, 1, "/usr/bin/bash"));
        note(&mut cache, &mut exec(100, 7, 1, 1, "/usr/bin/python3"));
        let mut child = exec(200, 9, 100, 7, "/usr/bin/id");
        note(&mut cache, &mut child);
        assert_eq!(child.parent_image_path.as_deref(), Some("/usr/bin/python3"));
    }

    #[test]
    fn an_exec_whose_image_could_not_be_read_makes_the_parent_unknown_not_stale() {
        let mut cache = ParentImages::new(8);
        note(&mut cache, &mut exec(100, 7, 1, 1, "/usr/bin/bash"));
        // bash exec'd again, and the probe could not copy the filename: same pid, same
        // generation (exec does not change it), empty image.
        note(&mut cache, &mut exec(100, 7, 1, 1, ""));
        let mut child = exec(200, 9, 100, 7, "/usr/bin/id");
        note(&mut cache, &mut child);
        assert_eq!(
            child.parent_image_path, None,
            "the child must not be told its parent is still /usr/bin/bash"
        );
    }

    #[test]
    fn a_reused_pid_does_not_lend_its_old_path_to_a_new_process() {
        let mut cache = ParentImages::new(8);
        note(&mut cache, &mut exec(100, 7, 1, 1, "/usr/bin/nginx"));
        // pid 100 died and was reused by a process that never exec'd (a fork of
        // something else, generation 8): its child must not read nginx's path.
        let mut child = exec(200, 9, 100, 8, "/usr/bin/id");
        note(&mut cache, &mut child);
        assert_eq!(child.parent_image_path, None);
    }

    #[test]
    fn an_unknown_generation_on_either_side_resolves_to_nothing() {
        let mut cache = ParentImages::new(8);
        note(&mut cache, &mut exec(100, 7, 1, 1, "/usr/bin/bash"));
        let mut no_parent_stamp = exec(200, 9, 100, 7, "/usr/bin/id");
        no_parent_stamp.meta.parent_process_generation = None;
        note(&mut cache, &mut no_parent_stamp);
        assert_eq!(no_parent_stamp.parent_image_path, None);

        let mut unstamped = exec(300, 0, 1, 1, "/usr/bin/sh");
        unstamped.meta.process_generation = None;
        note(&mut cache, &mut unstamped);
        let mut grandchild = exec(400, 11, 300, 0, "/usr/bin/id");
        note(&mut cache, &mut grandchild);
        assert_eq!(
            grandchild.parent_image_path, None,
            "a process with no stamp is never recorded, so it cannot be anyone's parent"
        );
    }

    #[test]
    fn a_parent_that_never_exec_ed_is_unknown_not_guessed() {
        let mut cache = ParentImages::new(8);
        let mut child = exec(200, 9, 100, 7, "/usr/bin/id");
        note(&mut cache, &mut child);
        assert_eq!(child.parent_image_path, None);
    }

    #[test]
    fn a_primed_process_resolves_its_children() {
        let mut cache = ParentImages::new(8);
        cache.prime(1, (1 << 63) | 5, "/usr/lib/systemd/systemd".to_string());
        let mut child = exec(200, 9, 1, (1 << 63) | 5, "/usr/bin/id");
        note(&mut cache, &mut child);
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
            note(&mut cache, &mut exec(pid + 10, 1, 1, 1, "/bin/x"));
        }
        assert!(cache.len() <= 64);
        assert!(cache.evicted() > 0);
    }

    #[test]
    fn a_parent_that_keeps_spawning_survives_eviction() {
        let mut cache = ParentImages::new(8);
        note(&mut cache, &mut exec(100, 7, 1, 1, "/usr/sbin/sshd"));
        for pid in 200..207u32 {
            note(&mut cache, &mut exec(pid, 1, 1, 1, "/bin/x"));
            let mut child = exec(pid + 1000, 2, 100, 7, "/bin/y");
            note(&mut cache, &mut child);
            assert!(child.parent_image_path.is_some());
        }
        note(&mut cache, &mut exec(900, 1, 1, 1, "/bin/overflow"));
        let mut child = exec(901, 2, 100, 7, "/bin/y");
        note(&mut cache, &mut child);
        assert_eq!(child.parent_image_path.as_deref(), Some("/usr/sbin/sshd"));
    }

    // --- a parent that forked and never exec'd: a subshell (#784) -------------------------

    /// bash (pid 100, generation 7) exec'd at ktime 5; a subshell (pid 150, forked at ktime
    /// 20, so generation 20) never exec'd; a child of the subshell is exec'd.
    fn bash_then_a_subshells_child(bash_exec_ns: u64) -> (ParentImages, ExecEvent) {
        let mut cache = ParentImages::new(8);
        let mut bash = exec(100, 7, 1, 1, "/usr/bin/bash");
        cache.annotate(
            &mut bash,
            ExecStamps {
                ktime_ns: bash_exec_ns,
                ..ExecStamps::default()
            },
        );
        let mut child = exec(200, 30, 150, 20, "/usr/bin/id");
        cache.annotate(
            &mut child,
            ExecStamps {
                ktime_ns: 40,
                grandparent_pid: 100,
                grandparent_generation: 7,
                parent_never_exec_ed: true,
            },
        );
        (cache, child)
    }

    #[test]
    fn a_subshells_child_inherits_the_image_its_forker_was_running() {
        let (_cache, child) = bash_then_a_subshells_child(5);
        assert_eq!(child.parent_image_path.as_deref(), Some("/usr/bin/bash"));
    }

    #[test]
    fn a_forker_that_exec_ed_after_the_subshell_forked_gives_unknown_not_its_new_image() {
        // bash exec'd at ktime 30, after the subshell forked at 20: the subshell still runs
        // the image bash had at 20, which this cache no longer has.
        let (_cache, child) = bash_then_a_subshells_child(30);
        assert_eq!(child.parent_image_path, None);
    }

    #[test]
    fn a_forker_whose_pid_was_reused_is_not_asked() {
        let mut cache = ParentImages::new(8);
        let mut other = exec(100, 99, 1, 1, "/usr/sbin/nginx");
        note(&mut cache, &mut other);
        let mut child = exec(200, 30, 150, 20, "/usr/bin/id");
        cache.annotate(
            &mut child,
            ExecStamps {
                ktime_ns: 40,
                grandparent_pid: 100,
                grandparent_generation: 7, // the forker's stamp; pid 100 now holds generation 99
                parent_never_exec_ed: true,
            },
        );
        assert_eq!(child.parent_image_path, None);
    }

    #[test]
    fn nothing_is_inherited_without_a_stamp_for_the_parent_or_for_the_forker() {
        for (parent_generation, grandparent_pid, grandparent_generation) in [
            (None, 100, 7),
            (Some(0), 100, 7),
            (Some(20), 0, 7),
            (Some(20), 100, 0),
        ] {
            let mut cache = ParentImages::new(8);
            let mut bash = exec(100, 7, 1, 1, "/usr/bin/bash");
            note(&mut cache, &mut bash);
            let mut child = exec(200, 30, 150, 20, "/usr/bin/id");
            child.meta.parent_process_generation = parent_generation;
            cache.annotate(
                &mut child,
                ExecStamps {
                    ktime_ns: 40,
                    grandparent_pid,
                    grandparent_generation,
                    parent_never_exec_ed: true,
                },
            );
            assert_eq!(
                child.parent_image_path, None,
                "{parent_generation:?} {grandparent_pid} {grandparent_generation}"
            );
        }
    }

    #[test]
    fn a_parent_that_did_exec_is_answered_by_its_own_image_not_its_forkers() {
        let (mut cache, _) = bash_then_a_subshells_child(5);
        // The subshell (pid 150, generation 20) exec'd python3, then spawned a child.
        let mut python = exec(150, 20, 100, 7, "/usr/bin/python3");
        cache.annotate(
            &mut python,
            ExecStamps {
                ktime_ns: 35,
                grandparent_pid: 1,
                grandparent_generation: 1,
                parent_never_exec_ed: false,
            },
        );
        let mut grandchild = exec(300, 50, 150, 20, "/usr/bin/id");
        cache.annotate(
            &mut grandchild,
            ExecStamps {
                ktime_ns: 60,
                grandparent_pid: 100,
                grandparent_generation: 7,
                parent_never_exec_ed: false,
            },
        );
        assert_eq!(
            grandchild.parent_image_path.as_deref(),
            Some("/usr/bin/python3")
        );
    }

    #[test]
    fn a_forker_that_keeps_spawning_subshells_survives_eviction() {
        let mut cache = ParentImages::new(8);
        let mut sshd = exec(100, 7, 1, 1, "/usr/sbin/sshd");
        note(&mut cache, &mut sshd);
        for pid in 200..207u32 {
            let mut other = exec(pid, 1, 1, 1, "/bin/x");
            note(&mut cache, &mut other);
            let mut child = exec(pid + 1000, 30, 150, 20, "/bin/y");
            cache.annotate(
                &mut child,
                ExecStamps {
                    ktime_ns: 40,
                    grandparent_pid: 100,
                    grandparent_generation: 7,
                    parent_never_exec_ed: true,
                },
            );
            assert!(child.parent_image_path.is_some());
        }
        let mut overflow = exec(900, 1, 1, 1, "/bin/overflow");
        note(&mut cache, &mut overflow);
        let mut child = exec(901, 30, 150, 20, "/bin/y");
        cache.annotate(
            &mut child,
            ExecStamps {
                ktime_ns: 40,
                grandparent_pid: 100,
                grandparent_generation: 7,
                parent_never_exec_ed: true,
            },
        );
        assert_eq!(child.parent_image_path.as_deref(), Some("/usr/sbin/sshd"));
    }

    /// The stamps of a child whose parent (pid 150, generation 20) is gone from the cache and
    /// whose forker is pid 100, generation 7, with the probe's word on whether it exec'd.
    fn stamps_of_a_lost_parent(parent_never_exec_ed: bool) -> ExecStamps {
        ExecStamps {
            ktime_ns: 40,
            grandparent_pid: 100,
            grandparent_generation: 7,
            parent_never_exec_ed,
        }
    }

    #[test]
    fn a_parent_that_exec_ed_and_was_evicted_is_unknown_not_its_forkers_image() {
        // nginx (pid 100) forked a worker (pid 150) that exec'd; the cache lost the worker (LRU
        // eviction, #783). The probe says the worker exec'd, so the worker's own image is
        // unknown: answering with nginx's would report it as a child of its forker's image.
        let mut cache = ParentImages::new(8);
        note(&mut cache, &mut exec(100, 7, 1, 1, "/usr/sbin/nginx"));
        let mut child = exec(200, 30, 150, 20, "/usr/bin/id");
        cache.annotate(&mut child, stamps_of_a_lost_parent(false));
        assert_eq!(child.parent_image_path, None);
    }

    #[test]
    fn a_parent_whose_exec_image_was_unreadable_is_unknown_not_its_forkers_image() {
        // The worker exec'd and the probe could not copy its filename: `record` forgets it (#769),
        // and the fallback must not bring the forker's image back in its place.
        let mut cache = ParentImages::new(8);
        note(&mut cache, &mut exec(100, 7, 1, 1, "/usr/sbin/nginx"));
        note(&mut cache, &mut exec(150, 20, 100, 7, ""));
        let mut child = exec(200, 30, 150, 20, "/usr/bin/id");
        cache.annotate(&mut child, stamps_of_a_lost_parent(false));
        assert_eq!(child.parent_image_path, None);
    }

    #[test]
    fn a_parent_the_probe_saw_fork_and_never_exec_gets_its_forkers_image() {
        let mut cache = ParentImages::new(8);
        note(&mut cache, &mut exec(100, 7, 1, 1, "/usr/bin/bash"));
        let mut child = exec(200, 30, 150, 20, "/usr/bin/id");
        cache.annotate(&mut child, stamps_of_a_lost_parent(true));
        assert_eq!(child.parent_image_path.as_deref(), Some("/usr/bin/bash"));
    }

    // --- eviction: the processes that are gone go first (#783) -----------------------------

    fn only_pid_100_is_alive(pid: u32) -> bool {
        pid == 100
    }

    #[test]
    fn an_idle_long_lived_parent_survives_a_flood_of_short_lived_processes() {
        // sshd (pid 100) execs once and then sits idle while far more than the cap of short-lived
        // processes come and go: strictly oldest-first eviction drops it, and its next child
        // gets no parent_image_path. There is no exit event, so liveness is asked of /proc.
        let mut cache = ParentImages::with_liveness(8, only_pid_100_is_alive);
        let mut sshd = exec(100, 7, 1, 1, "/usr/sbin/sshd");
        note(&mut cache, &mut sshd);
        for pid in 1_000..1_100u32 {
            let mut short_lived = exec(pid, 1, 1, 1, "/usr/bin/true");
            note(&mut cache, &mut short_lived);
        }
        assert!(cache.evicted() > 0, "the flood must have caused eviction");
        let mut child = exec(5_000, 30, 100, 7, "/usr/bin/id");
        note(&mut cache, &mut child);
        assert_eq!(child.parent_image_path.as_deref(), Some("/usr/sbin/sshd"));
    }

    #[test]
    fn a_dead_process_goes_before_an_older_live_one() {
        let mut cache = ParentImages::with_liveness(8, only_pid_100_is_alive);
        let mut sshd = exec(100, 7, 1, 1, "/usr/sbin/sshd"); // the oldest entry, alive
        note(&mut cache, &mut sshd);
        for pid in 200..208u32 {
            let mut dead = exec(pid, 1, 1, 1, "/bin/x"); // the ninth insert triggers eviction
            note(&mut cache, &mut dead);
        }
        assert!(cache.contains(100), "the live idle parent must stay");
        assert!(!cache.contains(200), "the oldest DEAD entry goes instead");
    }

    fn every_pid_is_alive(_pid: u32) -> bool {
        true
    }

    #[test]
    fn when_every_candidate_is_alive_the_oldest_go_first_as_before() {
        let mut cache = ParentImages::with_liveness(8, every_pid_is_alive);
        for pid in 100..109u32 {
            let mut e = exec(pid, 1, 1, 1, "/bin/x");
            note(&mut cache, &mut e);
        }
        assert!(
            !cache.contains(100),
            "the oldest live entry is evicted when nothing is dead"
        );
        assert!(cache.contains(108));
        assert!(cache.evicted() >= 1);
    }

    // --- what an eviction cost: an exited process is nothing, a live one is a lost parent (#783) ---

    #[test]
    fn evicting_exited_processes_is_counted_as_dead_never_as_live() {
        let mut cache = ParentImages::with_liveness(8, only_pid_100_is_alive);
        note(&mut cache, &mut exec(100, 7, 1, 1, "/usr/sbin/sshd"));
        for pid in 1_000..1_100u32 {
            note(&mut cache, &mut exec(pid, 1, 1, 1, "/usr/bin/true"));
        }
        let counts = cache.eviction_counts();
        assert!(
            counts.dead > 0,
            "the flood must have evicted exited processes"
        );
        assert_eq!(counts.live, 0, "the idle live parent was never evicted");
        assert!(cache.contains(100));
    }

    #[test]
    fn evicting_a_live_process_is_counted_as_live() {
        let mut cache = ParentImages::with_liveness(8, every_pid_is_alive);
        for pid in 100..140u32 {
            note(&mut cache, &mut exec(pid, 1, 1, 1, "/bin/x"));
        }
        let counts = cache.eviction_counts();
        assert!(counts.live > 0, "nothing was dead, so live ones had to go");
        assert_eq!(counts.dead, 0);
    }

    fn every_pid_but_300_is_alive(pid: u32) -> bool {
        pid != 300
    }

    #[test]
    fn a_batch_that_runs_out_of_dead_processes_counts_the_rest_as_live() {
        // Cap 16 evicts 2 at a time: the oldest entry (pid 300) is dead and goes first, the second
        // victim has to be the oldest live one.
        let mut cache = ParentImages::with_liveness(16, every_pid_but_300_is_alive);
        for pid in 300..317u32 {
            note(&mut cache, &mut exec(pid, 1, 1, 1, "/bin/x"));
        }
        assert_eq!(cache.eviction_counts(), EvictionCounts { dead: 1, live: 1 });
        assert!(!cache.contains(300) && !cache.contains(301));
    }

    #[test]
    fn the_cache_still_never_grows_past_its_cap_when_every_process_is_alive() {
        let mut cache = ParentImages::with_liveness(64, every_pid_is_alive);
        for pid in 0..10_000u32 {
            let mut e = exec(pid + 10, 1, 1, 1, "/bin/x");
            note(&mut cache, &mut e);
        }
        assert!(cache.len() <= 64);
    }

    #[test]
    fn process_exists_says_yes_for_this_process_and_no_for_an_impossible_pid() {
        assert!(process_exists(std::process::id()));
        assert!(!process_exists(u32::MAX));
    }
}
