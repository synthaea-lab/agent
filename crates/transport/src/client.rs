//! HTTP client with mTLS support.

use schema::Event;
use serde::Serialize;

use crate::config::TransportConfig;
use crate::error::{Result, TransportError};

/// HTTP client for communication with the control plane.
///
/// Supports mTLS with client certificates for agent authentication.
pub struct TransportClient {
    config: TransportConfig,
    agent: ureq::Agent,
}

impl TransportClient {
    /// Creates a new transport client with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if mTLS certificates are configured but cannot be loaded.
    pub fn new(config: TransportConfig) -> Result<Self> {
        let agent = build_agent(&config)?;
        Ok(Self { config, agent })
    }

    /// Uploads a batch of events to the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the upload fails. Retryable errors can be checked
    /// with [`TransportError::is_retryable`].
    pub fn upload_events(&self, events: &[Event]) -> Result<UploadResponse> {
        let url = self.config.ingest_url();
        let payload = UploadPayload {
            agent_id: self.config.agent_id.as_deref(),
            events,
        };

        self.post_json(&url, &payload)
    }

    /// Sends a heartbeat to the server with arbitrary payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the heartbeat fails.
    pub fn send_heartbeat<T: Serialize>(&self, beacon: &T) -> Result<()> {
        let url = self.config.heartbeat_url();
        let payload = HeartbeatPayload {
            agent_id: self.config.agent_id.as_deref(),
            beacon,
        };

        let _response: serde_json::Value = self.post_json(&url, &payload)?;
        Ok(())
    }

    /// Performs a POST request with JSON body.
    fn post_json<T: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        payload: &T,
    ) -> Result<R> {
        let body = serde_json::to_string(payload).map_err(TransportError::Serialization)?;

        let response = self
            .agent
            .post(url)
            .content_type("application/json")
            .send(&body)
            .map_err(|e| match &e {
                ureq::Error::StatusCode(status) => TransportError::ServerError {
                    status: *status,
                    message: e.to_string(),
                },
                _ => TransportError::Network(e.to_string()),
            })?;

        response
            .into_body()
            .read_json()
            .map_err(|e| TransportError::Network(e.to_string()))
    }

    /// Returns the current configuration.
    #[must_use]
    pub fn config(&self) -> &TransportConfig {
        &self.config
    }
}

/// Payload for event upload requests.
#[derive(Serialize)]
struct UploadPayload<'a> {
    agent_id: Option<&'a str>,
    events: &'a [Event],
}

/// Payload for heartbeat requests.
#[derive(Serialize)]
struct HeartbeatPayload<'a, T: Serialize> {
    agent_id: Option<&'a str>,
    beacon: &'a T,
}

/// Response from an event upload.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct UploadResponse {
    /// Number of events accepted by the server.
    pub accepted: usize,
    /// Server-assigned batch ID for tracking.
    pub batch_id: Option<String>,
}

/// Builds a ureq agent with the configured TLS settings.
fn build_agent(config: &TransportConfig) -> Result<ureq::Agent> {
    let mut agent_builder = ureq::Agent::config_builder()
        .timeout_global(Some(config.request_timeout))
        .user_agent(format!("synthaea-agent/{}", env!("CARGO_PKG_VERSION")));

    // Configure mTLS if certificates are provided
    if config.has_client_cert() {
        let tls_config = build_tls_config(config)?;
        agent_builder = agent_builder.tls_config(tls_config);
    }

    Ok(agent_builder.build().into())
}

/// Builds TLS config with client certificate authentication.
fn build_tls_config(config: &TransportConfig) -> Result<ureq::tls::TlsConfig> {
    use ureq::tls::{Certificate, ClientCert, PrivateKey, TlsConfig};

    let (Some(cert_path), Some(key_path)) = (&config.client_cert_path, &config.client_key_path)
    else {
        // No client cert configured, use default TLS
        return Ok(TlsConfig::default());
    };

    // Load certificate from PEM file
    let cert_pem = std::fs::read(cert_path)?;
    let cert = Certificate::from_pem(&cert_pem)
        .map_err(|e| TransportError::Config(format!("failed to parse cert: {e}")))?;

    // Load private key from PEM file
    let key_pem = std::fs::read(key_path)?;
    let key = PrivateKey::from_pem(&key_pem)
        .map_err(|e| TransportError::Config(format!("failed to parse key: {e}")))?;

    // Create client certificate with chain and key
    let client_cert = ClientCert::new_with_certs(&[cert], key);

    Ok(TlsConfig::builder().client_cert(Some(client_cert)).build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_builds_urls_correctly() {
        let config = TransportConfig::new("https://api.example.com");
        assert_eq!(
            config.ingest_url(),
            "https://api.example.com/api/v1/ingest/events"
        );
        assert_eq!(
            config.heartbeat_url(),
            "https://api.example.com/api/v1/ingest/heartbeat"
        );
    }

    #[test]
    fn client_builds_without_mtls() {
        let config = TransportConfig::new("https://api.example.com");
        let client = TransportClient::new(config);
        assert!(client.is_ok());
    }
}
