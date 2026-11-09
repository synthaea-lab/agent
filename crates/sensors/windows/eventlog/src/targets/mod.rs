//! Per-domain normalization: one parsed Event Log record into a `schema::Event`. Pure code, built
//! on every platform so its tests run everywhere; the poll targets that wire each normalizer to a
//! channel stay in the Windows-only `sensor.rs`.

pub(crate) mod kerberos;
pub(crate) mod log_cleared;
pub(crate) mod session;

use schema::Event;

/// What a poll target's `parse_block` yields for one `<Event>` XML block.
/// `None`: not even parseable. `Some((record_id, None))`: parsed but skipped
/// as unusable. `Some((record_id, Some(event)))`: a normalized event.
pub(crate) type ParsedBlock = Option<(u64, Option<Event>)>;
