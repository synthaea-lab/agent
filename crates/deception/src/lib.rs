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
//!   transfer — an attacker cannot build an avoid-list.
//! - **Detection via the normal stream**: canary paths register as tripwire
//!   indicators; matching happens on existing file/connect events — no new hooks.
//!   Planted credentials pair with server-side alarms (use of a decoy token anywhere
//!   in the fleet = instant high-severity case with the planting host attached).
//! - **Lifecycle owned end to end**: planted decoys are inventoried, refreshed, and
//!   fully removed on uninstall (the packaging residue rule applies to decoys too).
//! - **Safety**: decoys are inert (no real entitlements), clearly machine-generated
//!   on inspection by the operator's runbook, and never placed where users work.
