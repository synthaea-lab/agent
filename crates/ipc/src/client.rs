//! The IPC client — the caller side of the local channel.
//!
//! One connection per client: open, handshake, then one or more
//! request/response pairs, then close. No connection pool, no auto-
//! reconnect — the intended callers (cli, ui) are short-lived processes
//! that issue one or a few commands and exit.
//!
//! The [`Client`] type wraps an already-handshook stream. The
//! [`Client::connect`] async constructor opens the transport, sends the
//! `ClientHello`, and validates the `ServerHello` — any failure at that
//! stage surfaces as [`ClientError::Refused`] or [`ClientError::Connect`]
//! so the caller can distinguish "agent unreachable" from "agent said no".

use tokio::io::BufReader;

use crate::error::ClientError;
use crate::frame::{read_message, write_message, FrameError};
use crate::protocol::{
    ClientHello, PolicyVersionResponse, RecentDetectionsResponse, Request, Response,
    SensorHealthResponse, ServerHello, StatusResponse, WireError, PROTOCOL_VERSION,
};
use crate::stream::{connect, Stream};

/// An established, handshook client connection.
pub struct Client {
    reader: BufReader<tokio::io::ReadHalf<Stream>>,
    writer: tokio::io::WriteHalf<Stream>,
    /// Kept for logs/diagnostics. Value from the server's hello.
    #[allow(dead_code)]
    agent_version: String,
}

impl Client {
    /// Connect to the agent at `endpoint` and complete the handshake.
    ///
    /// `client_name` is the informational identifier the server logs —
    /// typically the binary name (`"cli"`, `"ui"`).
    ///
    /// # Errors
    ///
    /// - [`ClientError::Connect`] if the endpoint is unreachable.
    /// - [`ClientError::Refused`] if the server rejects the handshake
    ///   (unauthorized peer, unsupported protocol version).
    /// - [`ClientError::Io`] on transport errors during handshake.
    /// - [`ClientError::Protocol`] on malformed server replies.
    pub async fn connect(endpoint: &str, client_name: &str) -> Result<Self, ClientError> {
        let stream = connect(endpoint).await.map_err(|source| ClientError::Connect {
            endpoint: endpoint.to_string(),
            source,
        })?;
        let (read_half, mut write_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);

        // Send ClientHello.
        write_message(
            &mut write_half,
            &ClientHello {
                version: PROTOCOL_VERSION,
                client_name: client_name.to_string(),
            },
        )
        .await
        .map_err(map_frame_err)?;

        // Read the first reply. Two shapes are possible: a ServerHello
        // (happy path) or a WireError (unauthorized / unsupported).
        // We deserialize into a common enum to distinguish.
        let raw: Option<HandshakeReply> = read_message(&mut reader).await.map_err(map_frame_err)?;
        let raw = raw.ok_or(ClientError::UnexpectedClose)?;
        let hello = match raw {
            HandshakeReply::Hello(h) => h,
            HandshakeReply::Error(e) => {
                return Err(ClientError::Refused(format!("{e:?}")));
            }
        };
        if hello.version != PROTOCOL_VERSION {
            return Err(ClientError::Refused(format!(
                "server implements protocol version {}, client speaks {}",
                hello.version, PROTOCOL_VERSION
            )));
        }
        Ok(Self {
            reader,
            writer: write_half,
            agent_version: hello.agent_version,
        })
    }

    /// Send one request, read one response, on the established connection.
    ///
    /// # Errors
    ///
    /// [`ClientError::Io`] on transport failure, [`ClientError::Protocol`]
    /// on malformed reply, [`ClientError::UnexpectedClose`] if the
    /// server closed mid-exchange.
    async fn call(&mut self, req: Request) -> Result<Response, ClientError> {
        write_message(&mut self.writer, &req)
            .await
            .map_err(map_frame_err)?;
        let resp: Option<Response> = read_message(&mut self.reader)
            .await
            .map_err(map_frame_err)?;
        resp.ok_or(ClientError::UnexpectedClose)
    }

    /// Ask the agent for its overall status.
    ///
    /// # Errors
    ///
    /// See [`Self::call`]. Additionally returns [`ClientError::Refused`]
    /// if the server answered with a [`WireError`] instead of the
    /// matching [`Response::Status`].
    pub async fn status(&mut self) -> Result<StatusResponse, ClientError> {
        match self.call(Request::Status).await? {
            Response::Status(s) => Ok(s),
            Response::Error(e) => Err(refused_from(e)),
            other => Err(mismatched_response(&other, "status")),
        }
    }

    /// Ask the agent for its per-sensor health snapshot.
    ///
    /// # Errors
    ///
    /// See [`Self::status`].
    pub async fn sensor_health(&mut self) -> Result<SensorHealthResponse, ClientError> {
        match self.call(Request::SensorHealth).await? {
            Response::SensorHealth(s) => Ok(s),
            Response::Error(e) => Err(refused_from(e)),
            other => Err(mismatched_response(&other, "sensor_health")),
        }
    }

    /// Ask the agent for the N most recent detections.
    ///
    /// # Errors
    ///
    /// See [`Self::status`].
    pub async fn recent_detections(
        &mut self,
        limit: u32,
    ) -> Result<RecentDetectionsResponse, ClientError> {
        match self.call(Request::RecentDetections { limit }).await? {
            Response::RecentDetections(r) => Ok(r),
            Response::Error(e) => Err(refused_from(e)),
            other => Err(mismatched_response(&other, "recent_detections")),
        }
    }

    /// Ask the agent for the currently applied policy's metadata.
    ///
    /// # Errors
    ///
    /// See [`Self::status`].
    pub async fn policy_version(&mut self) -> Result<PolicyVersionResponse, ClientError> {
        match self.call(Request::PolicyVersion).await? {
            Response::PolicyVersion(p) => Ok(p),
            Response::Error(e) => Err(refused_from(e)),
            other => Err(mismatched_response(&other, "policy_version")),
        }
    }
}

/// Union of the two shapes a handshake reply can take. Used exactly
/// once, in [`Client::connect`], to distinguish "server said hello" from
/// "server refused the handshake with a `WireError`".
#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
enum HandshakeReply {
    Hello(ServerHello),
    Error(WireError),
}

fn refused_from(err: WireError) -> ClientError {
    ClientError::Refused(format!("{err:?}"))
}

fn mismatched_response(got: &Response, expected: &str) -> ClientError {
    ClientError::Protocol(format!(
        "expected a `{expected}` response, got a different variant: {got:?}"
    ))
}

fn map_frame_err(err: FrameError) -> ClientError {
    match err {
        FrameError::Io { source } => ClientError::Io { source },
        other => ClientError::Protocol(other.to_string()),
    }
}
