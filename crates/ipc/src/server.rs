//! The agent-hosted server loop.
//!
//! `Server::run` binds the listener, accepts connections, checks peer
//! credentials, handshakes, then dispatches each request through the
//! caller-supplied [`Handler`] trait implementation. One task per
//! connected client — the client's stream is strictly serial (one
//! in-flight request), but many clients are served in parallel.
//!
//! The agent's `main` is the intended caller; it constructs one
//! `Server`, hands over its [`Handler`] impl, and spawns
//! [`Server::run`] as a top-level task.
//!
//! ## What lives here vs. in `stream`
//!
//! `stream` is purely transport: bind a listener, accept a stream, read
//! peer credentials. This module wraps a stream in the protocol: read
//! the handshake, dispatch requests, write responses. The two split
//! cleanly — a future `mock_stream` in tests could substitute for
//! [`Stream`] without touching the server logic.

use std::sync::Arc;

use tokio::io::BufReader;

use crate::{
    error::ServerError,
    frame::{FrameError, read_message, write_message},
    protocol::{
        ClientHello, PROTOCOL_VERSION, PolicyVersionResponse, RecentDetectionsResponse, Request,
        Response, SensorHealthResponse, ServerHello, StatusResponse, WireError,
    },
    stream::{Listener, Stream},
};

/// Hard upper bound on [`Request::RecentDetections::limit`] — a client
/// that requests more is served this many entries with no error, so a
/// buggy CLI can't DOS the server with a `limit: u32::MAX`. Chosen to
/// fit comfortably under the framing layer's per-message cap.
pub const RECENT_DETECTIONS_HARD_LIMIT: u32 = 256;

/// What the server calls into to build a response for each request. The
/// agent implements this on top of its own state (sensor registry,
/// alert buffer, policy holder); the crate ships one testable stub
/// implementation, [`StubHandler`], for E2E tests.
///
/// All methods are async — an implementation may need to lock, await a
/// snapshot, or query a downstream crate — but should return promptly.
/// A slow handler blocks the client's connection, not the whole server.
/// Async methods use native async-fn-in-trait (Rust 2024 edition, no
/// `async-trait` crate dependency). Every method returns a `Send`
/// future so the trait can be used across `tokio::spawn` boundaries.
pub trait Handler: Send + Sync + 'static {
    /// Answer [`Request::Status`].
    fn status(&self) -> impl std::future::Future<Output = Result<StatusResponse, String>> + Send;
    /// Answer [`Request::SensorHealth`].
    fn sensor_health(
        &self,
    ) -> impl std::future::Future<Output = Result<SensorHealthResponse, String>> + Send;
    /// Answer [`Request::RecentDetections`]. `limit` is already clamped
    /// to [`RECENT_DETECTIONS_HARD_LIMIT`] by the caller.
    fn recent_detections(
        &self,
        limit: u32,
    ) -> impl std::future::Future<Output = Result<RecentDetectionsResponse, String>> + Send;
    /// Answer [`Request::PolicyVersion`].
    fn policy_version(
        &self,
    ) -> impl std::future::Future<Output = Result<PolicyVersionResponse, String>> + Send;
}

/// A canned handler that returns fixed responses. Ships with the crate
/// so [`Server::run`] has a working target in unit and integration
/// tests without the caller having to build one — and so the whole
/// crate is compilable-and-testable in isolation, before the agent's
/// real handler exists.
pub struct StubHandler {
    /// The `agent_version` string echoed in `status` and `hello`.
    pub agent_version: String,
    /// Nanoseconds since Unix epoch of the stub's "start time".
    pub started_at_ns: u64,
}

impl Default for StubHandler {
    fn default() -> Self {
        Self {
            agent_version: format!("stub-{}", env!("CARGO_PKG_VERSION")),
            started_at_ns: 0,
        }
    }
}

impl Handler for StubHandler {
    async fn status(&self) -> Result<StatusResponse, String> {
        Ok(StatusResponse {
            agent_version: self.agent_version.clone(),
            started_at_ns: self.started_at_ns,
            pipeline_healthy: true,
        })
    }
    async fn sensor_health(&self) -> Result<SensorHealthResponse, String> {
        // No sensors from the stub — the agent wires real ones in.
        Ok(SensorHealthResponse { sensors: vec![] })
    }
    async fn recent_detections(&self, _limit: u32) -> Result<RecentDetectionsResponse, String> {
        Ok(RecentDetectionsResponse { detections: vec![] })
    }
    async fn policy_version(&self) -> Result<PolicyVersionResponse, String> {
        Ok(PolicyVersionResponse {
            schema_version: 1,
            policy_version: None,
            signature_verified: None,
            issued_at_ns: None,
        })
    }
}

/// The server's own version string, sent in the handshake reply.
/// Populated at build time from the crate's own `CARGO_PKG_VERSION`.
#[must_use]
pub fn crate_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Configure and run the IPC server.
pub struct Server<H: Handler> {
    endpoint: String,
    handler: Arc<H>,
}

impl<H: Handler> Server<H> {
    /// Build a server that will bind at `endpoint` and dispatch every
    /// request through `handler`. Does not touch the network — call
    /// [`Self::run`] to bind and start accepting.
    #[must_use]
    pub fn new(endpoint: impl Into<String>, handler: H) -> Self {
        Self {
            endpoint: endpoint.into(),
            handler: Arc::new(handler),
        }
    }

    /// Bind the listener and accept connections forever, spawning one
    /// task per connected client. Never returns under normal operation
    /// — the agent's main is meant to call this inside its own top-level
    /// task and never await its completion.
    ///
    /// # Errors
    ///
    /// [`ServerError::Bind`] if the listener cannot be created (the
    /// endpoint is taken, permission denied, or the parent directory
    /// does not exist). Runtime errors on individual connections are
    /// logged via `tracing` and do not stop the accept loop.
    pub async fn run(self) -> Result<std::convert::Infallible, ServerError> {
        let mut listener =
            Listener::bind(&self.endpoint)
                .await
                .map_err(|source| ServerError::Bind {
                    endpoint: self.endpoint.clone(),
                    source,
                })?;
        tracing::info!(endpoint = %self.endpoint, "IPC listener bound");
        loop {
            match listener.accept().await {
                Ok((stream, creds)) => {
                    let handler = self.handler.clone();
                    tokio::spawn(async move {
                        if let Err(err) = serve_one(stream, creds, handler).await {
                            tracing::warn!(?err, "IPC connection ended with an error");
                        }
                    });
                }
                Err(source) => {
                    // A single accept failure is not fatal — the OS may
                    // have run out of transient resources, or the
                    // client may have RST'd between select and accept.
                    // Log and continue.
                    tracing::warn!(?source, "IPC accept failed; continuing");
                }
            }
        }
    }
}

/// Handle one connection, end to end: handshake, then request/response
/// pairs until the client closes (clean EOF) or an error surfaces.
async fn serve_one<H: Handler>(
    stream: Stream,
    creds: crate::stream::PeerCreds,
    handler: Arc<H>,
) -> Result<(), ServerError> {
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    // Peer-auth check happens before we read a byte of the handshake.
    // A caller that fails the check gets one Unauthorized reply and
    // then EOF — no protocol negotiation.
    if let Err(reason) = creds.check_authorized() {
        tracing::info!(pid = creds.pid, reason = %reason, "IPC peer rejected");
        let _ = write_message(&mut write_half, &WireError::Unauthorized).await;
        return Err(ServerError::Unauthorized { reason });
    }
    tracing::debug!(pid = creds.pid, "IPC peer authorized");

    // Handshake: read ClientHello, respond with ServerHello (or WireError).
    let hello: Option<ClientHello> = read_message(&mut reader)
        .await
        .map_err(map_frame_err_read)?;
    let hello = match hello {
        Some(h) => h,
        None => return Ok(()), // peer closed before saying anything
    };
    if hello.version != PROTOCOL_VERSION {
        let _ = write_message(
            &mut write_half,
            &WireError::UnsupportedVersion {
                server_version: PROTOCOL_VERSION,
            },
        )
        .await;
        return Err(ServerError::UnsupportedVersion {
            client_version: hello.version,
            server_version: PROTOCOL_VERSION,
        });
    }
    write_message(
        &mut write_half,
        &ServerHello {
            version: PROTOCOL_VERSION,
            agent_version: format!("synthaea-agent-{}", crate_version()),
        },
    )
    .await
    .map_err(map_frame_err_write)?;

    // Request/response loop.
    loop {
        let req: Option<Request> = read_message(&mut reader)
            .await
            .map_err(map_frame_err_read)?;
        let Some(req) = req else {
            return Ok(()); // clean close
        };
        let response = dispatch(&*handler, req).await;
        write_message(&mut write_half, &response)
            .await
            .map_err(map_frame_err_write)?;
    }
}

/// Route one parsed request through the handler, returning the exact
/// [`Response`] variant to write back. The handler's `String` errors
/// are packaged into [`Response::Error`] with [`WireError::HandlerFailed`]
/// — the connection stays open, the client sees which request failed.
async fn dispatch<H: Handler>(handler: &H, req: Request) -> Response {
    match req {
        Request::Status => match handler.status().await {
            Ok(r) => Response::Status(r),
            Err(m) => Response::Error(WireError::HandlerFailed { message: m }),
        },
        Request::SensorHealth => match handler.sensor_health().await {
            Ok(r) => Response::SensorHealth(r),
            Err(m) => Response::Error(WireError::HandlerFailed { message: m }),
        },
        Request::RecentDetections { limit } => {
            let clamped = limit.min(RECENT_DETECTIONS_HARD_LIMIT);
            match handler.recent_detections(clamped).await {
                Ok(r) => Response::RecentDetections(r),
                Err(m) => Response::Error(WireError::HandlerFailed { message: m }),
            }
        }
        Request::PolicyVersion => match handler.policy_version().await {
            Ok(r) => Response::PolicyVersion(r),
            Err(m) => Response::Error(WireError::HandlerFailed { message: m }),
        },
    }
}

fn map_frame_err_read(err: FrameError) -> ServerError {
    match err {
        FrameError::Io { source } => ServerError::Io { source },
        other => ServerError::Protocol(other.to_string()),
    }
}

fn map_frame_err_write(err: FrameError) -> ServerError {
    match err {
        FrameError::Io { source } => ServerError::Io { source },
        other => ServerError::Protocol(other.to_string()),
    }
}
