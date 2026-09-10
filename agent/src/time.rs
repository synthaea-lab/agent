//! Shared time utilities.

use std::time::{SystemTime, UNIX_EPOCH};

/// Returns the current time in nanoseconds since the UNIX epoch.
#[inline]
pub fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
