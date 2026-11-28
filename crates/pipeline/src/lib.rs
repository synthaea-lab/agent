//! The detection pipeline: an event in, the engines' findings, a verdict and its response
//! out.
//!
//! This crate composes the detection engines with the leaf crates they may not know: the
//! [`sink`] calls every engine on each event, fuses what they find into a verdict, then
//! writes the alert, spools the detection and acts on the response policy. [`replay`] runs
//! recorded events through the same sink, and [`snapshot_fetch`] keeps its rarity snapshot
//! current.
//!
//! It holds no sensor code. What needs one is handed in by the binary (a memory source
//! for YARA, the process lookup behind the canary allow-list), and what it must know about
//! the OS it was built for is the `host` module, the only place with a platform branch.

mod enrich_queue;
pub use enrich_queue::EnrichQueue;
mod host;
mod own_traffic;
pub mod replay;
pub mod sink;
pub mod snapshot_fetch;
