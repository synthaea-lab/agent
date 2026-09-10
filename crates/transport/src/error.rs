//! Transport error types.

use thiserror::Error;

/// Transport operation result.
pub type Result<T> = std::result::Result<T, TransportError>;

/// Errors that can occur during transport operations.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Server returned an error status code.
    #[error("server error: {status} - {message}")]
    ServerError { status: u16, message: String },

    /// Network error (connection refused, timeout, etc.).
    #[error("network error: {0}")]
    Network(String),

    /// TLS/certificate error.
    #[error("TLS error: {0}")]
    Tls(String),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// I/O error (reading certs, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Server is unreachable (for graceful degradation).
    #[error("server unreachable")]
    Unreachable,
}

impl TransportError {
    /// Returns true if this error should trigger a retry.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            TransportError::Network(_) | TransportError::Unreachable => true,
            TransportError::ServerError { status, .. } => *status >= 500,
            _ => false,
        }
    }
}
