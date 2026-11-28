//! The detection pipeline: an event in, the engines' findings, a verdict and its response
//! out.
//!
//! This crate composes the detection engines with the leaf crates they may not know: the
//! [`sink`] calls every engine on each event, fuses what they find into a verdict, then
//! writes the alert, spools the detection and acts on the response policy. [`replay`] runs
//! recorded events through the same sink, and [`snapshot_fetch`] keeps its rarity snapshot
//! current.
//!
//! Beside the sensors, a few sources feed the sink events of their own: the self-integrity
//! check ([`integrity`], Linux), the package inventory ([`inventory`]), the guard on the
//! agent's own files ([`protected`]) and the sensor-silence monitor ([`silence`]).
//! [`ipc_handler`] answers the local control channel from the sink's state, and
//! [`quarantine_cmd`] lists and restores what the response quarantined.
//!
//! It holds no sensor code. What needs one is handed in by the binary (a memory source
//! for YARA, the process lookup behind the canary allow-list), and what it must know about
//! the OS it was built for is the `host` module, the only place with a platform branch.

mod enrich_queue;
pub use enrich_queue::EnrichQueue;
mod host;
// The self-integrity check reads `updater::layout`, which exists on Linux only.
#[cfg(target_os = "linux")]
pub mod integrity;
pub mod inventory;
pub mod ipc_handler;
mod own_traffic;
pub mod protected;
pub mod quarantine_cmd;
pub mod replay;
pub mod silence;
pub mod sink;
pub mod snapshot_fetch;
