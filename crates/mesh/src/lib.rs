//! # mesh
//!
//! Peer-to-peer communication between agents on the same network segment — reviving
//! the old iteration's mesh design (peer attestation: "making an agent kill loud,
//! fast, and recoverable") and extending it with fleet posture. Two jobs:
//!
//! - **Peer attestation**: agents exchange signed heartbeats with their neighbors.
//!   A killed or silenced agent cannot report its own death — its peers can, and
//!   do, both to the server and locally. Combined with `tamper`'s self-detection,
//!   every kill path is loud from at least one vantage point.
//! - **Posture gossip**: adaptive posture changes (`server/fleet`) propagate
//!   peer-to-peer in addition to the server channel — faster inside a segment, and
//!   resilient when the control plane is unreachable (an offline pool can still
//!   raise its collective alertness from a local detection).
//!
//! ## Security guardrails (designed in, not bolted on)
//!
//! P2P inside an EDR is a gift to an attacker if done casually, so the protocol is
//! deliberately minimal:
//! - Peers authenticate mutually with their enrollment identities (same PKI as
//!   `transport`); unenrolled peers are noise.
//! - Messages are **signed, typed, and read-only**: attestation facts and posture
//!   hints. There is NO command channel — nothing an agent receives over the mesh
//!   makes it execute anything, and posture hints can only ever HEIGHTEN (the same
//!   never-disables rule as server posture, verified against the signed policy).
//! - A posture hint is advisory until corroborated: it carries the originating
//!   case/policy signature; unsigned or replayed hints are dropped and reported.
//! - Bounded chatter: fixed fan-out, rate limits, jittered intervals — the mesh
//!   must never become a scanning signature or a DoS amplifier.
