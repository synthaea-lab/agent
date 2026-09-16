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
///
/// New event types added here must also be handled in [`BehaviorVector::from_window`]
/// (at minimum as a no-op) and covered by at least one rule or a `_ =>` arm in every
/// exhaustive match inside `rules.rs` — `NetworkFlow` is a deliberate exception, see
/// its own note below.
pub(crate) fn is_correlated(event: &Event) -> bool {
    matches!(
        event,
        Event::Exec(_)
            | Event::Connect(_)
            | Event::FileOpen(_)
            | Event::DnsQuery(_)
            | Event::AssemblyLoad(_)
            | Event::SmbConnect(_)
            | Event::UdpSend(_)
            // `NetworkFlow` (issue #92, conntrack polling) is pushed to the bus
            // without a dedicated co-occurrence rule: its beacon-detection value
            // already has a home in `crates/rules::check_beacon_flow` (the live
            // engine `agent run` actually uses, validated against
            // `lab/scenarios/beacon.sh`). Folding it into this crate's
            // `Connect`-keyed rules (`rule_spawn_connect` and friends) or
            // `BehaviorVector`'s features would either double-alert when both a
            // discrete `Connect` and a polled `NetworkFlow` observe the same real
            // connection, or shift feature values the ML side already calibrates
            // against — both cross-cutting calls left for a follow-up, not
            // decided solo here.
            | Event::NetworkFlow(_)
    )
}
