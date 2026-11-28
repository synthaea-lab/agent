//! What the agent sends to and fetches from the control plane.
//!
//! This crate composes leaf crates that may not know each other: [`upload`] joins the
//! on-disk spool (`store`) to the uploader (`transport`), and [`content`] joins signed
//! manifests (`updater`) to the same transport.

pub mod content;
pub mod upload;
