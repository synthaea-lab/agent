//! HTTP client with mTLS support.

use schema::{Event, detection::Detection};
use serde::Serialize;

use crate::{
    config::TransportConfig,
    error::{Result, TransportError},
};

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

    /// Uploads one structured detection to the control plane. The caller owns
    /// durable queuing and retries; this method only performs the HTTP exchange.
    ///
    /// # Errors
    ///
    /// Returns an error if the server rejects the detection or cannot be reached.
    pub fn upload_detection(&self, detection: &Detection) -> Result<()> {
        let response: DetectionUploadResponse =
            self.post_json(&self.config.detection_url(), detection)?;
        if response.status != "accepted" {
            return Err(TransportError::InvalidResponse(format!(
                "unexpected detection ingest status: {}",
                response.status
            )));
        }
        Ok(())
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

    /// Fetches an arbitrary JSON resource via GET — used for the content
    /// manifest fetch (ADR-0016, issue #30/#73). Generic over the response
    /// type rather than a concrete `updater::ContentManifest`: `transport` and
    /// `updater` are both LEAF crates and may not depend on each other
    /// (`tools/check-deps.py`), so the binary composing them supplies the
    /// concrete type at the call site.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response body is not
    /// valid JSON for `R`.
    pub fn get_json<R: serde::de::DeserializeOwned>(&self, url: &str) -> Result<R> {
        let response = self.agent.get(url).call().map_err(|e| match &e {
            ureq::Error::StatusCode(status) => TransportError::ServerError {
                status: *status,
                message: e.to_string(),
            },
            _ => TransportError::Network(e.to_string()),
        })?;

        response
            .into_body()
            .read_json()
            .map_err(|e| TransportError::InvalidResponse(e.to_string()))
    }

    /// Fetches a raw byte payload via GET — used for content artifact
    /// download (ADR-0016, issue #30/#73's download/apply slice). `query`
    /// pairs are percent-encoded by `ureq` before being appended, so a
    /// caller passes a content path's raw string, not a pre-encoded one.
    /// `max_bytes` bounds how much of the body is read *before* any hash
    /// check runs — the manifest's own declared `size` is the natural
    /// choice, so a response can't be arbitrarily larger than what was
    /// signed for. Inclusive: a body of exactly `max_bytes` is accepted.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the body exceeds `max_bytes`.
    pub fn get_bytes(&self, url: &str, query: &[(&str, &str)], max_bytes: u64) -> Result<Vec<u8>> {
        let mut req = self.agent.get(url);
        for (key, value) in query {
            req = req.query(*key, *value);
        }
        let response = req.call().map_err(|e| match &e {
            ureq::Error::StatusCode(status) => TransportError::ServerError {
                status: *status,
                message: e.to_string(),
            },
            _ => TransportError::Network(e.to_string()),
        })?;

        let mut body = response.into_body();
        body.with_config()
            // ureq's limit is exclusive in practice: its `LimitReader` treats
            // hitting exactly `limit` bytes read as "still need one more read
            // to confirm EOF", and that next read is rejected outright rather
            // than allowed to return 0. `max_bytes + 1` keeps this method's
            // own contract ("a body of exactly `max_bytes` is accepted")
            // true despite that.
            .limit(max_bytes.saturating_add(1))
            .read_to_vec()
            .map_err(|e| TransportError::InvalidResponse(e.to_string()))
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

        // The server was reached and answered (status already read successfully
        // above) — a body it can't be parsed is a server-side/deterministic
        // failure, not a connectivity blip, so it must not get the longer
        // network retry budget (issue #414 follow-up).
        response
            .into_body()
            .read_json()
            .map_err(|e| TransportError::InvalidResponse(e.to_string()))
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

#[derive(serde::Deserialize)]
struct DetectionUploadResponse {
    status: String,
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
    use crate::DEFAULT_HEARTBEAT_ENDPOINT;

    #[test]
    fn config_builds_urls_correctly() {
        let config = TransportConfig::new("https://api.example.com");
        assert_eq!(
            config.ingest_url(),
            "https://api.example.com/api/v1/ingest/events"
        );
        assert_eq!(
            config.heartbeat_url(),
            "https://api.example.com/api/ingest/heartbeat"
        );
    }

    /// Regression (#317 review): the endpoint carried a `/v1` prefix no route
    /// served, and only a mock server that accepts any path was ever tested.
    /// Next.js app router: the route for `<path>` is `server/app<path>/route.ts`.
    /// Under `/api/ingest/` is also what puts it behind nginx's mTLS location and
    /// past the middleware's login redirect.
    #[test]
    fn the_heartbeat_endpoint_is_a_real_server_route() {
        assert!(DEFAULT_HEARTBEAT_ENDPOINT.starts_with("/api/ingest/"));
        let route = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../server/app")
            .join(DEFAULT_HEARTBEAT_ENDPOINT.trim_start_matches('/'))
            .join("route.ts");
        assert!(route.is_file(), "no server route at {}", route.display());
    }

    #[test]
    fn client_builds_without_mtls() {
        let config = TransportConfig::new("https://api.example.com");
        let client = TransportClient::new(config);
        assert!(client.is_ok());
    }

    /// Pins the heartbeat request body the control plane parses — the contract
    /// in `docs/architecture/control-plane.md` (#317). A change here is a change
    /// to that contract: update the doc and the server together.
    #[test]
    fn heartbeat_body_is_the_documented_wire_shape() {
        let beacon = schema::HealthBeacon {
            timestamp_ns: 1_790_756_620_574_604_200,
            agent_version: "0.1.0".into(),
            sensors: vec![schema::SensorHealth {
                name: "windows-etw".into(),
                pulse_count: 42,
                silent: false,
            }],
            spool_bytes: 1024,
            spool_dropped: 0,
            enrich_dropped: 3,
        };
        let body = serde_json::to_value(HeartbeatPayload {
            agent_id: None,
            beacon: &beacon,
        })
        .unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "agent_id": null,
                "beacon": {
                    "timestamp_ns": 1_790_756_620_574_604_200_u64,
                    "agent_version": "0.1.0",
                    "sensors": [
                        { "name": "windows-etw", "pulse_count": 42, "silent": false }
                    ],
                    "spool_bytes": 1024,
                    "spool_dropped": 0,
                    "enrich_dropped": 3
                }
            })
        );
    }
}
