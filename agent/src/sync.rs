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

use std::sync::{Mutex, MutexGuard, PoisonError};

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
            let site = std::panic::Location::caller();
            tracing::warn!(
                file = site.file(),
                line = site.line(),
                "recovered a lock poisoned by a panicking thread; its state may be partially updated"
            );
            self.clear_poison();
            PoisonError::into_inner(poisoned)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Mutex, thread};

    use super::LockExt;

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
}
