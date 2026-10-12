//! # deception
//!
//! Deception on the endpoint: the agent plants decoys — canary files in tempting
//! locations, fake credentials (browser-store entries, dummy SSH keys, decoy cloud
//! tokens), honeypot listeners on classic ports — and treats ANY interaction with
//! them as a detection. Nothing touches a canary legitimately, so this is the
//! highest signal-to-noise layer in the stack: a near-zero-FP tripwire for the
//! post-compromise reconnaissance phase that behavioral layers can miss.
//!
//! Design intentions:
//! - **Per-host uniqueness**: decoy names/paths/contents derive from the install's
//!   seed (the per-install variation story), so decoys learned from one host don't
//!   transfer. A name's stem, template, separator, qualifier, extension and the way its
//!   32-bit token is written all come from the seed, so no single pattern matches every
//!   canary of every install. The stems come from a public vocabulary of real-looking
//!   words, so an attacker can still skip *every file with such a word in its name*; that
//!   costs them the real files they are after, and it is the limit of the claim.
//! - **Detection via the normal stream**: canary paths register as tripwire
//!   indicators; matching happens on existing file/connect events — no new hooks.
//!   Planted credentials pair with server-side alarms (use of a decoy token anywhere
//!   in the fleet = instant high-severity case with the planting host attached).
//! - **Lifecycle owned end to end**: planted decoys are inventoried, refreshed, and
//!   fully removed on uninstall (the packaging residue rule applies to decoys too).
//! - **Safety**: decoys are inert (no real entitlements), clearly machine-generated
//!   on inspection by the operator's runbook, and never placed where users work.
//!
//! ## What is built (issue #81, slice 1: canary files)
//!
//! - [`plan`] turns a [`Seed`] and the directories an operator chose ([`Placement`]) into
//!   [`Canary`] files whose names and contents differ per install.
//! - [`plant`], [`verify`] and [`remove`] are the lifecycle, with an on-disk [`Inventory`]
//!   written before a file exists, so an uninstall deletes exactly what was planted and
//!   nothing else (a file that was already there is never overwritten, a symlink put in a
//!   canary's place is never followed).
//! - [`Tripwires`] matches the existing file events (open, delete, rename) against the
//!   inventory and says which canary, how it was touched and by which pid.
//!
//! - [`refresh`] puts back a canary that was deleted, with the content it had, and nothing
//!   else.
//!
//! Not built here: honeypot listeners. The agent wiring, the decoy credentials and their
//! server-side alarm live in the agent and the control plane (ADR-0029, ADR-0030). This crate
//! does no I/O except through [`plant`], [`verify`], [`refresh`] and [`remove`], and holds no
//! platform branches.

mod lifecycle;
mod plan;
mod tripwire;

pub use lifecycle::{
    DeceptionError, Drift, DriftKind, Inventory, InventoryEntry, PlantReport, RefreshReport,
    RemoveReport, Skipped, plant, refresh, remove, sha256_hex, verify,
};
pub use plan::{
    Canary, DECOY_HEADER, DECOY_TOKEN_PREFIX, Kind, Placement, Seed, decoy_tokens, plan,
};
pub use tripwire::{Hit, Touch, Tripwires};
