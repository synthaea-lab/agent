//! # conformance
//!
//! The sensor conformance suite. Runs one battery of scenario-driven checks against
//! any `Sensor` implementation (event completeness, field fidelity, ordering, delivery
//! under load) and emits the per-platform capability matrix published in the docs —
//! generated from results, never maintained by hand.
