//! # agent
//!
//! The agent binary. Responsibilities:
//!
//! - Select and start the platform sensor (Linux/Windows/macOS) behind the shared contract.
//! - Run the pipeline: sensor -> normalizer -> rules + ML -> correlator -> verdict -> response.
//! - Manage local sinks (JSONL, alerts) and the transport to the control plane.
//! - Host the CLI entry points (run, status, test-detection).
//!
//! To be migrated from `old/agent` (main, sinks, alerts, commands, jsonl).

fn main() {
    // Intentionally empty — skeleton only.
}
