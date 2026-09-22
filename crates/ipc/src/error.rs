//! Error types for the local IPC channel.
//!
//! Errors are split by concern: [`ServerError`] for what the server-side
//! (agent-hosted listener) can fail with, [`ClientError`] for what the
//! client-side (cli, ui) can fail with. The two enums share the same
//! wire-level errors (`Protocol`, `Io`) but differ on the endpoints they
//! reach — a server can't return `ConnectionRefused`, a client can't
//! `AcceptFailed`.
//!
//! On the wire, every failure the server chooses to surface to the client
//! is packaged as a [`crate::protocol::WireError`] variant so the client
//! never gets a raw `std::io::Error` string it can't pattern-match on.

/// What can fail on the server side: the agent-hosted listener and its
/// per-connection handlers.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Failed to bind the listener at the configured endpoint (permission
    /// denied on the pipe/socket path, path already in use, parent dir
    /// missing, etc.). The endpoint is included so an operator reading
    /// the error knows which path was tried.
    #[error("failed to bind IPC listener at `{endpoint}`: {source}")]
    Bind {
        /// The endpoint the server tried to bind.
        endpoint: String,
        /// Underlying I/O failure.
        source: std::io::Error,
    },

    /// Accepting an incoming connection failed. Non-fatal for the listener
    /// (the server loop logs and continues); the variant carries enough
    /// context for the log line to be useful.
    #[error("accept failed: {source}")]
    Accept {
        /// Underlying I/O failure.
        source: std::io::Error,
    },

    /// Reading or writing on an already-accepted connection failed
    /// mid-exchange. Fatal for that one connection only; the listener
    /// continues.
    #[error("connection I/O failed: {source}")]
    Io {
        /// Underlying I/O failure.
        source: std::io::Error,
    },

    /// The client sent a message that could not be parsed as a valid
    /// framed JSON [`crate::protocol::Request`] (bad framing, invalid
    /// JSON, unknown variant, missing required field). The connection is
    /// closed after emitting a [`crate::protocol::WireError::BadRequest`]
    /// to the client.
    #[error("protocol violation: {0}")]
    Protocol(String),

    /// The client did not present credentials that pass the peer-auth
    /// check (per ADR-0010, only root/Administrators are authorized on
    /// v1). The server sends a [`crate::protocol::WireError::Unauthorized`]
    /// and closes the connection.
    #[error("peer authentication failed: {reason}")]
    Unauthorized {
        /// Human-readable reason (uid, group membership, etc.).
        reason: String,
    },

    /// The client sent a protocol version the server does not implement.
    #[error(
        "unsupported protocol version: client requested {client_version}, \
         server implements {server_version}"
    )]
    UnsupportedVersion {
        /// The version the client asked for in its hello.
        client_version: u32,
        /// The version this server implements.
        server_version: u32,
    },
}

/// What can fail on the client side: the cli/ui process connecting to a
/// running agent.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Could not connect to the agent's listener at the configured
    /// endpoint. Almost always means the agent isn't running, or is
    /// running but hasn't finished its startup yet.
    #[error(
        "cannot reach the agent at `{endpoint}`: {source}. \
         Is the agent running?"
    )]
    Connect {
        /// The endpoint the client tried to connect to.
        endpoint: String,
        /// Underlying I/O failure.
        source: std::io::Error,
    },

    /// The connection was established but the server refused the client:
    /// unauthorized peer, unsupported protocol version, or a bad-request
    /// response the client cannot recover from.
    #[error("agent refused the connection: {0}")]
    Refused(String),

    /// Reading or writing on an established connection failed.
    #[error("connection I/O failed: {source}")]
    Io {
        /// Underlying I/O failure.
        source: std::io::Error,
    },

    /// The server sent a reply the client could not parse.
    #[error("malformed response from agent: {0}")]
    Protocol(String),

    /// The server closed the connection mid-exchange, before any full
    /// response arrived. Distinguished from [`Self::Io`] so an operator
    /// sees "agent died" not "network glitch".
    #[error("connection closed by agent before a response arrived")]
    UnexpectedClose,
}
