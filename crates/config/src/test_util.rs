//! Test-only helpers shared across every module's `#[cfg(test)] mod tests`.
//!
//! `env_lock` serializes tests that mutate `std::env`. The process
//! environment is global; cargo runs tests in parallel by default, so two
//! tests both calling `set_var` on the same variable name will silently
//! observe each other's writes and produce flaky "Expected Err, got Ok"
//! failures. Every test that touches `std::env` acquires this guard first.

use std::sync::{Mutex, MutexGuard, PoisonError};

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Acquire the crate-wide test env mutex. Drop the returned guard at end
/// of test scope. Poison from a panicked test is cleared silently so one
/// panic doesn't cascade into spurious poison-error failures on every
/// subsequent env-touching test.
pub(crate) fn env_lock() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}
