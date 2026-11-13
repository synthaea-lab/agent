//! The agent's one policy for a poisoned `Mutex`: recover, clear the poison, and say so.
//!
//! A `std::sync::Mutex` is poisoned when a thread panics while holding its guard. With
//! `lock().unwrap()` every later lock then panics too, so one panic inside a detection
//! engine (say, a rule evaluation on a malformed event) would take down every thread
//! that touches the same state afterwards, including the capture thread: the sensor
//! kills itself. An EDR must keep processing the events it can, so the agent takes the
//! guard back instead ([`PoisonError::into_inner`]). The state a panicking thread
//! left behind may be half-updated; for the agent's in-memory detection state that
//! costs at most a missed or duplicated alert, which is far cheaper than a dead
//! sensor.
//!
//! The poison is cleared on recovery, so each panic is logged once (with the call site
//! that found it) rather than on every later lock.

use std::{
    panic::Location,
    sync::{Condvar, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::Duration,
};

/// Logs a recovered poison once, with the call site that found it.
fn log_recovery(site: &Location<'_>) {
    tracing::warn!(
        file = site.file(),
        line = site.line(),
        "recovered a lock poisoned by a panicking thread; its state may be partially updated"
    );
}

/// [`Mutex::lock`] under the agent's poisoned-lock policy (see the module docs).
pub(crate) trait LockExt<T: ?Sized> {
    /// Locks the mutex, taking the guard back if a previous holder panicked.
    ///
    /// Never panics on poison: a poisoned lock is logged at `warn`, un-poisoned and
    /// returned as if it were healthy. Like [`Mutex::lock`], it still blocks (or
    /// deadlocks) if the current thread already holds the lock.
    fn lock_recovering(&self) -> MutexGuard<'_, T>;
}

impl<T: ?Sized> LockExt<T> for Mutex<T> {
    #[track_caller]
    fn lock_recovering(&self) -> MutexGuard<'_, T> {
        self.lock().unwrap_or_else(|poisoned| {
            log_recovery(Location::caller());
            self.clear_poison();
            PoisonError::into_inner(poisoned)
        })
    }
}

/// [`RwLock::read`] and [`RwLock::write`] under the same policy as [`LockExt`].
pub(crate) trait RwLockExt<T: ?Sized> {
    /// Takes a read guard, taking it back if a writer panicked.
    fn read_recovering(&self) -> RwLockReadGuard<'_, T>;
    /// Takes the write guard, taking it back if a previous holder panicked.
    fn write_recovering(&self) -> RwLockWriteGuard<'_, T>;
}

impl<T: ?Sized> RwLockExt<T> for RwLock<T> {
    #[track_caller]
    fn read_recovering(&self) -> RwLockReadGuard<'_, T> {
        self.read().unwrap_or_else(|poisoned| {
            log_recovery(Location::caller());
            self.clear_poison();
            PoisonError::into_inner(poisoned)
        })
    }

    #[track_caller]
    fn write_recovering(&self) -> RwLockWriteGuard<'_, T> {
        self.write().unwrap_or_else(|poisoned| {
            log_recovery(Location::caller());
            self.clear_poison();
            PoisonError::into_inner(poisoned)
        })
    }
}

/// [`Condvar::wait_while`] under the same policy: the guard comes back even if the
/// mutex was poisoned while the caller waited. The poison itself is left for the next
/// [`LockExt::lock_recovering`] to clear and log, since a guard cannot reach its mutex.
pub(crate) trait CondvarExt {
    /// Waits while `condition` holds, recovering a poisoned mutex instead of panicking.
    // Only the Linux uprobes supervisor (`captures`) waits on a condition.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn wait_while_recovering<'a, T>(
        &self,
        guard: MutexGuard<'a, T>,
        condition: impl FnMut(&mut T) -> bool,
    ) -> MutexGuard<'a, T>;

    /// Waits for a notification or `timeout`, recovering a poisoned mutex instead of
    /// panicking. Returns the guard only: callers re-check their own deadline.
    fn wait_timeout_recovering<'a, T>(
        &self,
        guard: MutexGuard<'a, T>,
        timeout: Duration,
    ) -> MutexGuard<'a, T>;
}

impl CondvarExt for Condvar {
    fn wait_while_recovering<'a, T>(
        &self,
        guard: MutexGuard<'a, T>,
        condition: impl FnMut(&mut T) -> bool,
    ) -> MutexGuard<'a, T> {
        self.wait_while(guard, condition)
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn wait_timeout_recovering<'a, T>(
        &self,
        guard: MutexGuard<'a, T>,
        timeout: Duration,
    ) -> MutexGuard<'a, T> {
        self.wait_timeout(guard, timeout)
            .unwrap_or_else(PoisonError::into_inner)
            .0
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Condvar, Mutex, RwLock},
        thread,
        time::Duration,
    };

    use super::{CondvarExt, LockExt, RwLockExt};

    fn poisoned(value: u32) -> Mutex<u32> {
        let lock = Mutex::new(value);
        thread::scope(|s| {
            let _ = s
                .spawn(|| {
                    let mut guard = lock.lock().unwrap();
                    *guard += 1;
                    panic!("poison the lock while holding it");
                })
                .join();
        });
        assert!(lock.is_poisoned());
        lock
    }

    #[test]
    fn a_healthy_lock_is_returned_as_is() {
        let lock = Mutex::new(7);
        *lock.lock_recovering() += 1;
        assert_eq!(*lock.lock_recovering(), 8);
        assert!(!lock.is_poisoned());
    }

    #[test]
    fn a_poisoned_lock_is_recovered_with_the_state_the_panicking_thread_left() {
        let lock = poisoned(1);
        assert_eq!(*lock.lock_recovering(), 2);
    }

    #[test]
    fn recovering_a_poisoned_lock_clears_the_poison() {
        let lock = poisoned(1);
        drop(lock.lock_recovering());
        assert!(!lock.is_poisoned());
        assert_eq!(*lock.lock().unwrap(), 2);
    }
    #[test]
    fn a_poisoned_rwlock_is_recovered_for_readers_and_writers() {
        let lock = RwLock::new(1u32);
        thread::scope(|s| {
            let _ = s
                .spawn(|| {
                    let mut guard = lock.write().unwrap();
                    *guard += 1;
                    panic!("poison the rwlock while holding it");
                })
                .join();
        });
        assert!(lock.is_poisoned());
        assert_eq!(*lock.read_recovering(), 2);
        assert!(!lock.is_poisoned());
        *lock.write_recovering() += 1;
        assert_eq!(*lock.read_recovering(), 3);
    }

    #[test]
    fn a_condvar_wait_survives_a_mutex_poisoned_while_waiting() {
        let pair = Arc::new((Mutex::new(false), Condvar::new()));
        let waiter = {
            let pair = Arc::clone(&pair);
            thread::spawn(move || {
                let (lock, cv) = &*pair;
                let guard = lock.lock_recovering();
                *cv.wait_while_recovering(guard, |ready| !*ready)
            })
        };
        // Poison the mutex while the waiter sleeps, then release it.
        let poisoner = {
            let pair = Arc::clone(&pair);
            thread::spawn(move || {
                let (lock, cv) = &*pair;
                let mut guard = lock.lock().unwrap();
                *guard = true;
                cv.notify_all();
                panic!("poison the mutex the waiter sleeps on");
            })
        };
        assert!(poisoner.join().is_err());
        assert!(waiter.join().unwrap());
    }

    #[test]
    fn a_timed_wait_on_a_poisoned_mutex_returns_the_guard() {
        let lock = Arc::new(Mutex::new(5u32));
        let cv = Condvar::new();
        let poisoner = {
            let lock = Arc::clone(&lock);
            thread::spawn(move || {
                let _guard = lock.lock().unwrap();
                panic!("poison the mutex");
            })
        };
        assert!(poisoner.join().is_err());
        let guard = lock.lock_recovering();
        let guard = cv.wait_timeout_recovering(guard, Duration::from_millis(5));
        assert_eq!(*guard, 5);
    }
}
