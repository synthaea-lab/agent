//! The one shared clock helper. Lives in `schema` deliberately: `timestamp_ns`
//! is a schema field, and `schema` is the only crate every tier — including
//! sensors, which may depend on nothing else — is allowed to reach. Before
//! this, the same function was copied per crate and the copies had started to
//! drift. Purely additive to the semi-frozen surface: no serialization impact.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current wall-clock time in nanoseconds since the UNIX epoch, for stamping
/// [`crate::EventMeta::timestamp_ns`] at observation time. `0` if the system
/// clock reads before the epoch (the honest sentinel already used throughout —
/// never a panic on a skewed clock).
#[inline]
#[must_use]
pub fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
