//! Coordinated shutdown of the agent's background workers (#316).
//!
//! `agent run` ends when its sensor's `run` returns (Ctrl-C). Before this
//! module every worker thread just died with the process, which is lossless by
//! construction (the spool redelivers, at-least-once) but skipped the one
//! thing worth doing on the way out: a last upload drain. [`ShutdownPlan`]
//! signals every registered worker at once, then joins each against one shared
//! deadline — a wedged worker (an upload stuck in a slow HTTP call) is logged
//! and detached instead of holding the exit hostage.

// Only wired on Linux (commands/linux.rs) — same first-platform precedent as
// `health`; the other `cmd_run`s still end with the process.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::{
    sync::atomic::{AtomicBool, Ordering},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// Total time `cmd_run` gives its workers after the sensor returns: the upload
/// loop's final drain (`DEFAULT_FINAL_DRAIN_BUDGET`, 3s) plus margin for the
/// request in flight when the stop lands.
pub const SHUTDOWN_BUDGET: Duration = Duration::from_secs(6);

/// How often [`join_bounded`] re-checks `JoinHandle::is_finished`.
const JOIN_POLL: Duration = Duration::from_millis(20);

/// Granularity of [`sleep_unless_stopped`].
const SLEEP_SLICE: Duration = Duration::from_millis(50);

/// Waits for `handle` until `deadline`. Returns `true` if the thread finished
/// (and was joined), `false` if it was still running — the handle is dropped,
/// which detaches the thread. A panicked worker counts as finished: shutdown
/// has nothing left to wait for.
pub fn join_bounded(handle: JoinHandle<()>, deadline: Instant) -> bool {
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(JOIN_POLL);
    }
    let _ = handle.join();
    true
}

/// `thread::sleep` that returns early (within [`SLEEP_SLICE`]) once `stop` is
/// set — for poll loops whose only shutdown signal is a flag.
pub fn sleep_unless_stopped(stop: &AtomicBool, total: Duration) {
    let deadline = Instant::now() + total;
    while !stop.load(Ordering::SeqCst) {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return;
        }
        thread::sleep(left.min(SLEEP_SLICE));
    }
}

struct Worker {
    name: &'static str,
    stop: Box<dyn FnOnce() + Send>,
    handle: JoinHandle<()>,
}

/// The set of workers to wind down when the sensor returns.
#[derive(Default)]
pub struct ShutdownPlan {
    workers: Vec<Worker>,
}

impl ShutdownPlan {
    /// Registers a worker: `stop` asks it to finish, `handle` is what gets
    /// joined.
    pub fn register(
        &mut self,
        name: &'static str,
        stop: impl FnOnce() + Send + 'static,
        handle: JoinHandle<()>,
    ) {
        self.workers.push(Worker {
            name,
            stop: Box::new(stop),
            handle,
        });
    }

    /// Signals every worker first (so they wind down in parallel, not one
    /// after another), then joins each within `budget` overall. Returns the
    /// names of the workers that were still running at the deadline.
    pub fn execute(self, budget: Duration) -> Vec<&'static str> {
        let deadline = Instant::now() + budget;
        let mut pending = Vec::with_capacity(self.workers.len());
        for worker in self.workers {
            (worker.stop)();
            pending.push((worker.name, worker.handle));
        }
        let mut stragglers = Vec::new();
        for (name, handle) in pending {
            if join_bounded(handle, deadline) {
                tracing::debug!(worker = name, "worker stopped");
            } else {
                tracing::warn!(
                    worker = name,
                    "worker still running at the shutdown deadline; detaching it"
                );
                stragglers.push(name);
            }
        }
        stragglers
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn flag() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    /// A worker that honours its stop flag is signalled and joined.
    #[test]
    fn stop_is_propagated_and_workers_are_joined() {
        let stop = flag();
        let seen = flag();
        let (s, o) = (Arc::clone(&stop), Arc::clone(&seen));
        let handle = thread::spawn(move || {
            sleep_unless_stopped(&s, Duration::from_secs(60));
            o.store(true, Ordering::SeqCst);
        });
        let mut plan = ShutdownPlan::default();
        let signal = Arc::clone(&stop);
        plan.register("loop", move || signal.store(true, Ordering::SeqCst), handle);

        let stragglers = plan.execute(Duration::from_secs(5));

        assert!(stragglers.is_empty());
        assert!(seen.load(Ordering::SeqCst), "worker ran to its clean exit");
    }

    /// The join is bounded: a worker that ignores the stop cannot delay exit
    /// past the budget, and is reported by name.
    #[test]
    fn a_wedged_worker_is_reported_not_waited_for() {
        let release = flag();
        let r = Arc::clone(&release);
        let handle = thread::spawn(move || {
            while !r.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(10));
            }
        });
        let mut plan = ShutdownPlan::default();
        plan.register("wedged", || {}, handle);

        let started = Instant::now();
        let stragglers = plan.execute(Duration::from_millis(200));

        assert_eq!(stragglers, vec!["wedged"]);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "join must be bounded by the budget, took {:?}",
            started.elapsed()
        );
        release.store(true, Ordering::SeqCst); // let the detached thread end
    }

    /// The budget is shared, not per worker: two wedged workers cost one
    /// budget, not two.
    #[test]
    fn the_budget_is_shared_across_workers() {
        let release = flag();
        let mut plan = ShutdownPlan::default();
        for name in ["a", "b", "c"] {
            let r = Arc::clone(&release);
            let handle = thread::spawn(move || {
                while !r.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(10));
                }
            });
            plan.register(name, || {}, handle);
        }

        let started = Instant::now();
        let stragglers = plan.execute(Duration::from_millis(300));

        assert_eq!(stragglers, vec!["a", "b", "c"]);
        assert!(started.elapsed() < Duration::from_millis(900));
        release.store(true, Ordering::SeqCst);
    }

    /// Every worker is signalled before any join starts, so slow workers wind
    /// down concurrently.
    #[test]
    fn workers_are_signalled_before_the_first_join() {
        let (first_stop, second_stop) = (flag(), flag());
        let mut plan = ShutdownPlan::default();

        // `first` only ends once `second` has been signalled: if `execute`
        // joined `first` before signalling `second`, it would hit the budget.
        let waits_on = Arc::clone(&second_stop);
        let first = thread::spawn(move || sleep_unless_stopped(&waits_on, Duration::from_secs(60)));
        let signal = Arc::clone(&first_stop);
        plan.register("first", move || signal.store(true, Ordering::SeqCst), first);

        let waits_on = Arc::clone(&first_stop);
        let second =
            thread::spawn(move || sleep_unless_stopped(&waits_on, Duration::from_secs(60)));
        let signal = Arc::clone(&second_stop);
        plan.register(
            "second",
            move || signal.store(true, Ordering::SeqCst),
            second,
        );

        assert!(plan.execute(Duration::from_secs(5)).is_empty());
    }

    #[test]
    fn sleep_unless_stopped_wakes_early() {
        let stop = flag();
        stop.store(true, Ordering::SeqCst);
        let started = Instant::now();
        sleep_unless_stopped(&stop, Duration::from_secs(60));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_panicked_worker_counts_as_finished() {
        let handle = thread::spawn(|| panic!("worker died"));
        let mut plan = ShutdownPlan::default();
        plan.register("panicky", || {}, handle);
        assert!(plan.execute(Duration::from_secs(5)).is_empty());
    }
}
