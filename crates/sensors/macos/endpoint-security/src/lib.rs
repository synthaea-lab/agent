//! # sensor-macos
//!
//! macOS user-mode sensor built on `EndpointSecurity` (issue #32) — the
//! platform's supported successor to kexts/kauth/openbsm (all rejected, see
//! `docs/sensors/sources.md`). Subscribes NOTIFY-only (no AUTH blocking yet —
//! inline prevention is response-milestone territory) to:
//!
//! - **exec** — argv, parent lineage, and the kernel's code-signing state
//!   (`CS_VALID`, signing/team id, platform-binary bit) at the source;
//! - **file** — open/create/rename/unlink, plus writable `MAP_SHARED` mmaps
//!   (the one mmap case that mutates a file), translated to the POSIX `O_*`
//!   values `schema::has_write_intent` expects;
//! - **persistence** — Background Task Management launch-item registration
//!   (macOS 13+, `FLAG_PERSISTENCE_BTM_ARTIFACT`), the deterministic
//!   registration-time signal; plist writes into launchd/cron directories
//!   additionally surface through the ordinary file stream and the
//!   `rules::check_persistence_write` path patterns.
//!
//! The ES event catalog beyond this core set (login/session, quarantine
//! xattrs, mount, signal, XPC) is the widening issue #96.
//!
//! ## Layout
//!
//! `es_message_t` is a version-gated union behind an Objective-C-block API —
//! hand-mirroring it in Rust would be silent ABI drift waiting to happen, so a
//! small C shim (`shim/es_shim.c`, compiled against Apple's own headers by
//! `build.rs`) flattens the subscribed messages into stable plain-C structs.
//! [`raw`] is their owned Rust form and [`normalize`] maps raw → `schema`,
//! both cross-platform and unit-tested on any host; only `ffi`/`sensor` (and
//! the shim itself) are macOS-gated. Compiles to a stub elsewhere.
//!
//! ## Running one (entitlement)
//!
//! ES clients must run as root, hold the
//! `com.apple.developer.endpoint-security.client` entitlement, and have Full
//! Disk Access. `MacosSensorError` maps each `es_new_client` refusal to the
//! operator action that fixes it; the dev-signing path (and the SIP caveat for
//! unsigned development builds) is documented in `docs/sensors/macos.md`.

pub mod normalize;
pub mod raw;

#[cfg(target_os = "macos")]
mod ffi;
#[cfg(target_os = "macos")]
mod sensor;
#[cfg(target_os = "macos")]
pub use sensor::{MacosSensor, MacosSensorError, StopHandle};
