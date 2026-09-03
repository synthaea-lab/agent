//! Helpers over the shared [`schema::Event`] envelope — the old crate-local
//! `TimedEvent` duplicate is replaced by the canonical schema type. `Event` is
//! `#[non_exhaustive]`: variants this crate does not correlate yet fall through the
//! helpers with neutral values and are simply not pushed to the bus.

use schema::Event;

/// Write intent on a `FileOpen` (`O_WRONLY`, `O_RDWR` or `O_CREAT`) — `false` for the
/// other variants. Only place in the crate where this bit test exists (the T1105
/// rules and the behavioral vector go through here); `crates/ml`'s correlation
/// features and `ml/`'s behavior features carry its mirror.
pub(crate) fn is_file_write(event: &Event) -> bool {
    const O_WRONLY: u32 = 0o1;
    const O_RDWR: u32 = 0o2;
    const O_CREAT: u32 = 0o100;
    match event {
        Event::FileOpen(f) => f.flags & (O_WRONLY | O_RDWR | O_CREAT) != 0,
        _ => false,
    }
}

/// True for the variants this crate correlates (and therefore stores in the bus).
pub(crate) fn is_correlated(event: &Event) -> bool {
    matches!(
        event,
        Event::Exec(_) | Event::Connect(_) | Event::FileOpen(_)
    )
}
