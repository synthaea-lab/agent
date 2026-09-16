//! The sensor contract shared across platforms (`Sensor`/`EventSink`) — an eBPF
//! sensor (Linux), an ETW one (Windows), or an `EndpointSecurity` one (macOS) plug in
//! behind the same interface, without duplicating the detection logic that consumes
//! the events.
//!
//! Shape carried over from the old iteration (settled 2026-08-24): `Send`/`Sync` and
//! an owned `Box<dyn EventSink>` (not borrowed), because a sensor typically runs in
//! its own thread (ETW consumption, tokio task) and must own its sink for its entire
//! lifetime. Events are passed by value; they own their strings now, so a sink that
//! forwards across a channel just moves them.

use crate::Event;

/// Error type for [`Sensor::run`] — deliberately just a boxed error so the contract
/// crate stays dependency-light; sensors use whatever error stack they like inside.
pub type SensorError = Box<dyn core::error::Error + Send + Sync + 'static>;

/// What a given [`Sensor`] can observe on its platform. Lets consumers know a
/// category will stay silently empty rather than discovering it at runtime. Must
/// reflect what `run` actually emits — never an optimistic static value; the
/// conformance suite asserts it against observed behavior.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Capabilities {
    pub exec_events: bool,
    pub file_events: bool,
    pub connect_events: bool,
    /// True when this sensor can emit [`crate::Event::Auth`].
    pub auth_events: bool,
    /// True when emitted events carry real user attribution ([`crate::User`] not
    /// `Unknown`).
    pub user_attribution: bool,
    /// True when exec events carry parent lineage
    /// ([`crate::ExecEvent::parent_comm`] / `parent_image_path`).
    pub parent_lineage: bool,
}

/// Receives the normalized events produced by a [`Sensor`], whatever the platform.
/// One implementation (dispatch into rules + ML + correlator) serves all sensors.
///
/// A single method rather than one per event type: [`Event`] is `#[non_exhaustive]`,
/// so new telemetry categories reach existing sinks without a breaking trait change —
/// sinks match on the variants they understand and ignore the rest.
pub trait EventSink: Send + Sync {
    fn on_event(&self, event: Event);
}

/// Sensor for a given platform. `run` blocks and pushes observed events to `sink` as
/// they come, until [`Sensor::stop`] or an error.
pub trait Sensor: Send {
    /// Short name for logs/diagnostics (e.g. `"linux-ebpf"`, `"windows-etw"`).
    fn name(&self) -> &str;

    /// What this sensor can actually produce on this platform.
    fn capabilities(&self) -> Capabilities;

    /// Runs the capture loop until [`Sensor::stop`] is called.
    ///
    /// # Errors
    ///
    /// Returns [`SensorError`] when the platform capture facility cannot be
    /// started or fails irrecoverably mid-run.
    fn run(&mut self, sink: Box<dyn EventSink>) -> Result<(), SensorError>;

    /// Clean shutdown (from another thread / signal handler) — `run` must return
    /// shortly after.
    fn stop(&mut self);
}
