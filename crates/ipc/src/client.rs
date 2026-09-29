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

use crate::{
    error::ClientError,
    frame::{FrameError, read_message, write_message},
    protocol::{
        ClientHello, PROTOCOL_VERSION, PolicyVersionResponse, RecentDetectionsResponse, Request,
        Response, SensorHealthResponse, ServerHello, StatusResponse, WireError,
    },
    stream::{Stream, connect},
};

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
    /// - [`ClientError::AccessDenied`] if the OS or the agent's peer-auth
    ///   check refuses this process.
    /// - [`ClientError::HandshakeClosed`] if the agent drops the connection
    ///   before replying (how it turns away an unauthorized peer).
    /// - [`ClientError::Refused`] if the server rejects the handshake for
    ///   another reason (unsupported protocol version).
    /// - [`ClientError::Io`] on other transport errors during handshake.
    /// - [`ClientError::Protocol`] on malformed server replies.
    pub async fn connect(endpoint: &str, client_name: &str) -> Result<Self, ClientError> {
        let stream = connect(endpoint)
            .await
            .map_err(|source| connect_error(endpoint, source))?;
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
        .map_err(|e| handshake_error(endpoint, map_frame_err(e)))?;

        // Read the first reply. Two shapes are possible: a ServerHello
        // (happy path) or a WireError (unauthorized / unsupported).
        // We deserialize into a common enum to distinguish.
        let raw: Option<HandshakeReply> = read_message(&mut reader)
            .await
            .map_err(|e| handshake_error(endpoint, map_frame_err(e)))?;
        let raw = raw.ok_or_else(|| handshake_error(endpoint, ClientError::UnexpectedClose))?;
        let hello = match raw {
            HandshakeReply::Hello(h) => h,
            HandshakeReply::Error(e) => return Err(handshake_refusal(endpoint, e)),
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

/// A failed open of the endpoint. The OS refusing it (pipe DACL, socket
/// permissions) means the agent is up but this process may not talk to
/// it, not that the agent is missing (#421).
fn connect_error(endpoint: &str, source: std::io::Error) -> ClientError {
    if source.kind() == std::io::ErrorKind::PermissionDenied {
        ClientError::AccessDenied {
            endpoint: endpoint.to_string(),
        }
    } else {
        ClientError::Connect {
            endpoint: endpoint.to_string(),
            source,
        }
    }
}

/// A transport failure during the handshake. A pipe closed under us
/// (`BrokenPipe`, which Windows' `ERROR_NO_DATA` / os error 232 maps to)
/// or an EOF before any reply is how the agent drops a peer it just told
/// `Unauthorized` (#421); anything else stays a plain transport error.
fn handshake_error(endpoint: &str, err: ClientError) -> ClientError {
    match err {
        ClientError::UnexpectedClose => ClientError::HandshakeClosed {
            endpoint: endpoint.to_string(),
        },
        ClientError::Io { source } if source.kind() == std::io::ErrorKind::BrokenPipe => {
            ClientError::HandshakeClosed {
                endpoint: endpoint.to_string(),
            }
        }
        other => other,
    }
}

/// The `WireError` a server answered the hello with.
fn handshake_refusal(endpoint: &str, err: WireError) -> ClientError {
    match err {
        WireError::Unauthorized => ClientError::AccessDenied {
            endpoint: endpoint.to_string(),
        },
        other => refused_from(other),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const EP: &str = r"\.\pipe\synthaea-test";

    #[test]
    fn permission_denied_on_open_reports_access_denied_not_a_missing_agent() {
        let err = connect_error(
            EP,
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );
        assert!(matches!(err, ClientError::AccessDenied { .. }), "{err:?}");
        let msg = err.to_string();
        assert!(
            msg.contains("permission denied") && msg.contains("Administrator"),
            "{msg}"
        );
        assert!(!msg.contains("Is the agent running"), "{msg}");
    }

    #[cfg(windows)]
    #[test]
    fn windows_access_denied_os_error_5_reports_access_denied() {
        // The exact error from #421: an elevated agent's pipe DACL refusing a
        // non-elevated cli ("Accès refusé (os error 5)").
        let err = connect_error(EP, std::io::Error::from_raw_os_error(5));
        assert!(matches!(err, ClientError::AccessDenied { .. }), "{err:?}");
    }

    #[test]
    fn a_missing_endpoint_still_asks_whether_the_agent_is_running() {
        let err = connect_error(EP, std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(matches!(err, ClientError::Connect { .. }), "{err:?}");
        assert!(err.to_string().contains("Is the agent running"));
    }

    #[test]
    fn unauthorized_handshake_reply_reports_access_denied() {
        let err = handshake_refusal(EP, WireError::Unauthorized);
        assert!(matches!(err, ClientError::AccessDenied { .. }), "{err:?}");
    }

    #[test]
    fn other_handshake_refusals_stay_refused() {
        let err = handshake_refusal(EP, WireError::UnsupportedVersion { server_version: 9 });
        assert!(matches!(err, ClientError::Refused(_)), "{err:?}");
    }

    #[test]
    fn pipe_closed_during_handshake_reports_handshake_closed() {
        let broken = ClientError::Io {
            source: std::io::Error::from(std::io::ErrorKind::BrokenPipe),
        };
        assert!(matches!(
            handshake_error(EP, broken),
            ClientError::HandshakeClosed { .. }
        ));
        assert!(matches!(
            handshake_error(EP, ClientError::UnexpectedClose),
            ClientError::HandshakeClosed { .. }
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_os_error_232_during_handshake_reports_handshake_closed() {
        // #421's third shape: the agent closed the pipe before the client
        // read its `Unauthorized` reply (ERROR_NO_DATA).
        let err = ClientError::Io {
            source: std::io::Error::from_raw_os_error(232),
        };
        assert!(matches!(
            handshake_error(EP, err),
            ClientError::HandshakeClosed { .. }
        ));
    }

    #[test]
    fn other_handshake_transport_errors_stay_io() {
        let err = ClientError::Io {
            source: std::io::Error::from(std::io::ErrorKind::TimedOut),
        };
        assert!(matches!(handshake_error(EP, err), ClientError::Io { .. }));
    }
}
