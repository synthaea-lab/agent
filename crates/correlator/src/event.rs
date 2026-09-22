//! Helpers over the shared [`schema::Event`] envelope — the old crate-local
//! `TimedEvent` duplicate is replaced by the canonical schema type. `Event` is
//! `#[non_exhaustive]`: variants this crate does not correlate yet fall through the
//! helpers with neutral values and are simply not pushed to the bus.

use schema::Event;

/// Write intent on a `FileOpen` — `false` for the other variants. The flag
/// semantics live in [`schema::has_write_intent`] (this crate used to carry a
/// drifted bitmask copy that disagreed with `rules` on invalid access modes).
pub(crate) fn is_file_write(event: &Event) -> bool {
    match event {
        Event::FileOpen(f) => schema::has_write_intent(f.flags),
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
