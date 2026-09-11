//! Transport configuration.

use std::{path::PathBuf, time::Duration};

use crate::{
    DEFAULT_BATCH_SIZE, DEFAULT_HEARTBEAT_ENDPOINT, DEFAULT_INGEST_ENDPOINT, DEFAULT_RETRY_BASE_MS,
    DEFAULT_RETRY_MAX_MS,
};

/// Configuration for the transport layer.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Base URL of the control plane (e.g., `https://api.synthaea.example.com`).
    pub server_url: String,

    /// Path to the client certificate (PEM format).
    pub client_cert_path: Option<PathBuf>,

    /// Path to the client private key (PEM format).
    pub client_key_path: Option<PathBuf>,

    /// Agent ID (assigned during enrollment).
    pub agent_id: Option<String>,

    /// Endpoint for event ingestion.
    pub ingest_endpoint: String,

    /// Endpoint for heartbeat.
    pub heartbeat_endpoint: String,

    /// Maximum events per upload request.
    pub batch_size: usize,

    /// Base retry delay (doubles on each retry).
    pub retry_base: Duration,

    /// Maximum retry delay.
    pub retry_max: Duration,

    /// Request timeout.
    pub request_timeout: Duration,

    /// Interval between heartbeats.
    pub heartbeat_interval: Duration,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            client_cert_path: None,
            client_key_path: None,
            agent_id: None,
            ingest_endpoint: DEFAULT_INGEST_ENDPOINT.to_string(),
            heartbeat_endpoint: DEFAULT_HEARTBEAT_ENDPOINT.to_string(),
            batch_size: DEFAULT_BATCH_SIZE,
            retry_base: Duration::from_millis(DEFAULT_RETRY_BASE_MS),
            retry_max: Duration::from_millis(DEFAULT_RETRY_MAX_MS),
            request_timeout: Duration::from_secs(30),
            heartbeat_interval: Duration::from_secs(30),
        }
    }
}

impl TransportConfig {
    /// Creates a new configuration with the given server URL.
    #[must_use]
    pub fn new(server_url: impl Into<String>) -> Self {
        Self {
            server_url: server_url.into(),
            ..Default::default()
        }
    }

    /// Sets the client certificate and key paths for mTLS.
    #[must_use]
    pub fn with_client_cert(mut self, cert_path: PathBuf, key_path: PathBuf) -> Self {
        self.client_cert_path = Some(cert_path);
        self.client_key_path = Some(key_path);
        self
    }

    /// Sets the agent ID.
    #[must_use]
    pub fn with_agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self
    }

    /// Returns the full URL for the ingest endpoint.
    #[must_use]
    pub fn ingest_url(&self) -> String {
        format!("{}{}", self.server_url, self.ingest_endpoint)
    }

    /// Returns the full URL for the heartbeat endpoint.
    #[must_use]
    pub fn heartbeat_url(&self) -> String {
        format!("{}{}", self.server_url, self.heartbeat_endpoint)
    }

    /// Returns true if mTLS client certificates are configured.
    #[must_use]
    pub fn has_client_cert(&self) -> bool {
        self.client_cert_path.is_some() && self.client_key_path.is_some()
    }
}
