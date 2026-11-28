//! What the agent sends to and fetches from the control plane.
//!
//! This crate composes leaf crates that may not know each other: [`upload`] joins the
//! on-disk spool (`store`) to the uploader (`transport`), and [`content`] joins signed
//! manifests (`updater`) to the same transport, as do [`rotation`] for key rotations and
//! `release` for the binary self-update (Linux only). [`trust`] is the refusal all three
//! share: no manifest is acted on when the build can verify it only against the test key.

pub mod content;
// `apply-release` drives `updater::layout`, which exists on Linux only.
#[cfg(target_os = "linux")]
pub mod release;
pub mod rotation;
pub mod trust;
pub mod upload;
