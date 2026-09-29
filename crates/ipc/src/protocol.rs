//! Wire protocol types the server and client agree on.
//!
//! The exchange is always one Hello handshake followed by one or more
//! Request/Response pairs. Every message is one line of JSON, terminated
//! by `\n` — see [`crate::frame`] for the framing rules and their
//! rationale.
//!
//! ## Versioning
//!
//! [`PROTOCOL_VERSION`] is the version this build implements. The client's
//! [`ClientHello::version`] and the server's [`ServerHello::version`] must
//! match; a mismatch closes the connection with
//! [`WireError::UnsupportedVersion`] (server → client) or
//! [`crate::ClientError::Refused`] (client-side view). This is a strict
//! equality check in v1 — no forward compatibility window: adding a new
//! request variant bumps the version, and the two sides negotiate their
//! shared version at handshake, not per-request.
//!
//! ## Design constraints
//!
//! - **Every enum uses `#[serde(tag = "kind", content = ...)]`** —
//!   externally tagged JSON is compact-ish, but a `kind` discriminator on
//!   the same object makes the wire trivial to grep and debug (`{"kind":
//!   "status"}` beats `{"status": null}`).
//! - **No timestamps in the protocol itself.** Timestamps belong in the
//!   response payloads that carry them (recent detections), not in the
//!   envelope.
//! - **No request/response correlation IDs.** The channel is
//!   strictly-serial in v1 (one in-flight request per connection); a
//!   correlation ID would be dead weight until multiplexing is a real
//!   need.

use serde::{Deserialize, Serialize};

/// The protocol version this build implements. Bump on any breaking
/// change to the request/response types below; additive fields on
/// existing variants stay at the same version.
pub const PROTOCOL_VERSION: u32 = 2;

// ── Handshake ────────────────────────────────────────────────────────────

/// First message the client sends after opening the connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientHello {
    /// The protocol version the client speaks. Must equal
    /// [`PROTOCOL_VERSION`] on the server side, or the server closes the
    /// connection with `WireError::UnsupportedVersion`.
    pub version: u32,
    /// A short, informational identifier the server can log — typically
    /// the client binary name (`"cli"`, `"ui"`). Not a security boundary
    /// (the client picks its own name); the actual identity check is
    /// the OS-level peer credentials read on the socket/pipe.
    pub client_name: String,
}

/// Server's reply to a valid [`ClientHello`]. Sent once, right after the
/// handshake, before any request is served.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerHello {
    /// The protocol version the server speaks — always equal to
    /// [`PROTOCOL_VERSION`] on this build.
    pub version: u32,
    /// The agent's build/version string, for the client to display and
    /// for post-mortem logs.
    pub agent_version: String,
}

// ── Request ──────────────────────────────────────────────────────────────

/// A single request the client sends over an established connection.
///
/// v1 was intentionally read-only: every variant returned a snapshot of
/// current agent state, no mutation. [`Self::ReloadContent`] (v2, issue
/// #30) is the first exception, not a reopening of that policy: it acts on
/// the agent's own already-verified local state (content
/// `agent apply-content-manifest` already fetched, signature-checked, and
/// wrote to disk over a *separately* mTLS-authenticated channel), not on
/// another process or file the way `kill`/`quarantine`/`isolate` would —
/// those still wait on the per-capability, policy-gated authorization model
/// named below, unchanged by this addition. The whole channel is already
/// gated to root-on-Unix-or-elevated-on-Windows peers (`stream::PeerCreds`),
/// the same bar those future commands will also need.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Return the agent's overall running state — variant of
    /// [`Response::Status`] answers.
    Status,
    /// Return the health of each sensor the agent has attached.
    SensorHealth,
    /// Return the N most recent detections the agent has emitted, oldest
    /// first. `limit` bounds N.
    RecentDetections {
        /// Maximum number of detections to return. Server clamps to a
        /// build-time upper bound (see [`crate::server`]).
        limit: u32,
    },
    /// Return the metadata of the currently applied policy: schema
    /// version, policy version, whether a signature was verified, and
    /// when it was issued.
    PolicyVersion,
    /// Re-read Sigma/YARA content from the agent's configured content
    /// directory and swap it into the running detection pipeline (issue
    /// #30): the way `agent apply-content-manifest` — a separate, one-shot
    /// process — tells an already-running `agent run` to pick up content it
    /// just downloaded and verified, without a restart.
    ReloadContent,
}

// ── Response ─────────────────────────────────────────────────────────────

/// The server's reply to one [`Request`], plus the error variant for
/// per-request failures. `kind` on the wire matches the request that
/// triggered the reply, so a `{"kind": "status", ...}` request pairs
/// with a `{"kind": "status", ...}` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    /// Reply to [`Request::Status`].
    Status(StatusResponse),
    /// Reply to [`Request::SensorHealth`].
    SensorHealth(SensorHealthResponse),
    /// Reply to [`Request::RecentDetections`].
    RecentDetections(RecentDetectionsResponse),
    /// Reply to [`Request::PolicyVersion`].
    PolicyVersion(PolicyVersionResponse),
    /// Reply to [`Request::ReloadContent`].
    ReloadContent(ReloadContentResponse),
    /// Any per-request failure the server chose to surface to the client
    /// without closing the connection. Fatal errors (peer-auth failure,
    /// bad framing) still close the connection — see [`WireError`].
    Error(WireError),
}

/// Payload of [`Response::Status`]. Deliberately narrow — anything more
/// detailed belongs in one of the other responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusResponse {
    /// The agent's build/version string (mirror of
    /// [`ServerHello::agent_version`] — repeated so `status` alone is
    /// a full snapshot).
    pub agent_version: String,
    /// Nanoseconds since Unix epoch when the agent process started.
    /// Same unit as `schema::EventMeta` timestamps everywhere in the
    /// workspace.
    pub started_at_ns: u64,
    /// Whether the agent's own pipeline is considered up.
    pub pipeline_healthy: bool,
}

/// Payload of [`Response::SensorHealth`]. One entry per sensor the agent
/// has attached; empty on a stripped-down build that ships no sensors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SensorHealthResponse {
    /// Per-sensor entries. Order is stable within a build (matches the
    /// agent's own sensor registration order), so a diff between two
    /// consecutive calls means an actual state change, not a re-order.
    pub sensors: Vec<SensorHealth>,
}

/// One sensor's current health as the agent sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SensorHealth {
    /// Machine-readable sensor name (`sensor-windows-eventlog`,
    /// `sensor-linux-audit`, ...).
    pub name: String,
    /// One-word state — `Up`, `Silent`, `Failed`.
    pub state: SensorState,
    /// Nanoseconds since Unix epoch of the last heartbeat the agent
    /// received from this sensor, or `None` if none has ever arrived.
    pub last_heartbeat_ns: Option<u64>,
}

/// The three states [`SensorHealth`] discretizes into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorState {
    /// Heartbeats arriving within the expected window.
    Up,
    /// Sensor attached and initialized, but heartbeats have gone silent
    /// past the silence-monitor's deadline. Not necessarily a failure —
    /// a sensor with no traffic will look Silent under some heuristics.
    Silent,
    /// The sensor's attach step failed at startup, or a fatal internal
    /// error surfaced from its worker. The agent will not retry it in
    /// this session.
    Failed,
}

/// Payload of [`Response::RecentDetections`]. Sorted oldest first; the
/// client's `limit` was the upper bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecentDetectionsResponse {
    /// Detection summaries. Empty when the agent has not emitted any yet
    /// this session.
    pub detections: Vec<DetectionSummary>,
}

/// A compact view of one detection — the fields a CLI/UI shows in a
/// list. The full detection with all matched fields lives in the alerts
/// sink, not here (this endpoint is a status snapshot, not a query).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionSummary {
    /// Nanoseconds since Unix epoch when the detection fired.
    pub emitted_at_ns: u64,
    /// Rule / correlator identifier that produced this detection (e.g.
    /// `T1543.003-service-install`, `ml-cmdline-iforest`).
    pub source: String,
    /// One-line human summary of the detection, meant for a CLI table
    /// row.
    pub summary: String,
}

/// Payload of [`Response::PolicyVersion`]. Reflects the currently-active
/// merged policy, not the on-disk baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyVersionResponse {
    /// [`crate::PROTOCOL_VERSION`]-style schema version of the active
    /// policy document. Matches `policy::SCHEMA_VERSION` when this
    /// endpoint is wired to the real `policy` crate.
    pub schema_version: u32,
    /// The monotone `policy_version` the issuer stamped. `None` when
    /// no policy has been applied yet (a fresh install pre-onboarding).
    pub policy_version: Option<u64>,
    /// `Some(true)` if the policy was signature-verified,
    /// `Some(false)` if the agent is running in "warn-only" dev mode
    /// (an explicit `SYNTHAEA_STRICT_PROVENANCE=0` or equivalent), and
    /// `None` when there is no policy applied to verify.
    pub signature_verified: Option<bool>,
    /// Nanoseconds since Unix epoch when the issuer produced the
    /// policy. `None` under the same conditions as `policy_version`.
    pub issued_at_ns: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wire-shape pin (issue #30): `ReloadContent` must round-trip through
    /// the same externally-tagged JSON every other request/response pair
    /// uses (`{"kind": "reload_content", ...}`), so a client and an older
    /// or newer server can at least recognize the shape even if
    /// `PROTOCOL_VERSION` itself gates whether they're allowed to talk.
    #[test]
    fn reload_content_request_round_trips_through_json() {
        let json = serde_json::to_string(&Request::ReloadContent).unwrap();
        assert_eq!(json, r#"{"kind":"reload_content"}"#);
        let back: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Request::ReloadContent);
    }

    #[test]
    fn reload_content_response_round_trips_through_json() {
        let response = Response::ReloadContent(ReloadContentResponse {
            sigma_rule_count: Some(12),
            yara_rule_count: None,
        });
        let json = serde_json::to_string(&response).unwrap();
        let back: Response = serde_json::from_str(&json).unwrap();
        assert_eq!(back, response);
    }
}

/// Payload of [`Response::ReloadContent`]. Reports what's loaded *after*
/// the reload, from the same content directory the agent loads at startup
/// — `None` for an engine means its content subdirectory is absent, not an
/// error (same posture the agent has always had for a missing `rules/sigma`
/// or `rules/yara`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReloadContentResponse {
    /// Sigma rules now loaded, or `None` if `rules/sigma` under the content
    /// directory does not exist.
    pub sigma_rule_count: Option<usize>,
    /// YARA rules now loaded, or `None` if `rules/yara` under the content
    /// directory does not exist.
    pub yara_rule_count: Option<usize>,
}

// ── Wire-level errors ────────────────────────────────────────────────────

/// A single, uniform error shape the server can send to the client in a
/// [`Response::Error`] frame OR (for a handshake failure) as its very
/// first reply instead of a [`ServerHello`]. The client's error handling
/// pattern-matches on this variant, not on a stringly-typed message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireError {
    /// The client's message could not be parsed as a valid request.
    /// Message carries enough context for a developer to fix the client;
    /// end users would need not to see this in normal operation.
    BadRequest {
        /// Human-readable parse-error message.
        message: String,
    },
    /// The client's peer credentials do not satisfy the server's
    /// authorization policy. In v1 this is a single-shot check
    /// (root/Administrators only) — later releases may return more
    /// context (which capability was missing).
    Unauthorized,
    /// The server does not implement the client's requested protocol
    /// version.
    UnsupportedVersion {
        /// The version the server actually implements.
        server_version: u32,
    },
    /// The server accepted the request but its internal handler failed
    /// to produce a response (e.g. a downstream crate returned an
    /// error). The message is trimmed to something safe to log.
    HandlerFailed {
        /// One-line summary of the internal failure.
        message: String,
    },
}
