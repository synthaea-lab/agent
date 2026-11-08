//! The crate's one locking policy: a poisoned mutex is recovered, never unwrapped.
//!
//! The locks here are shared between the ETW consumer callbacks and other
//! threads (the container-lookup worker, sensor start and stop). A panic on any
//! of them while holding a lock poisons it; unwrapping that lock afterwards
//! turns the one panic into a panic on every later event, and ferrisetw answers
//! a panic in a callback by exiting the process. The guarded state is a cache, a
//! gate or a table that stays structurally valid between operations, so the data
//! behind a poisoned lock is used as is.

use std::sync::{Mutex, MutexGuard, PoisonError};

pub(crate) trait LockExt<T> {
    /// The guard, whether or not a previous holder panicked.
    fn lock_or_recover(&self) -> MutexGuard<'_, T>;
}

impl<T> LockExt<T> for Mutex<T> {
    fn lock_or_recover(&self) -> MutexGuard<'_, T> {
        self.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{self, AssertUnwindSafe};

    use super::*;

    fn poisoned(value: Vec<u32>) -> Mutex<Vec<u32>> {
        let mutex = Mutex::new(value);
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            let _guard = mutex.lock().unwrap();
            panic!("a callback panicked while holding the lock");
        }));
        assert!(result.is_err());
        assert!(mutex.is_poisoned());
        mutex
    }

    #[test]
    fn a_panicked_holder_does_not_stop_later_lockers() {
        let mutex = poisoned(vec![1, 2]);
        mutex.lock_or_recover().push(3);
        assert_eq!(*mutex.lock_or_recover(), vec![1, 2, 3]);
    }

    #[test]
    fn an_unpoisoned_lock_behaves_like_lock() {
        let mutex = Mutex::new(7);
        *mutex.lock_or_recover() += 1;
        assert_eq!(*mutex.lock_or_recover(), 8);
        assert!(!mutex.is_poisoned());
    }
}
