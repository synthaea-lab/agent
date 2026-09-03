//! # updater
//!
//! The update client: self-update of the agent binaries (staged, verified, with
//! rollback) and download/verification of detection content and ML models via canary
//! rings. Must keep working when everything else is degraded — an agent that cannot
//! update is an agent an attacker gets to keep.
