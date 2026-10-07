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
        validate_detection_response(response)
    }

    /// Uploads a detection with a stable key retained by the caller's durable
    /// spool. Reusing the key on retry lets the server acknowledge a stored
    /// detection without creating another row or counting prevalence twice.
    ///
    /// # Errors
    ///
    /// Returns an error if the server rejects the detection or cannot be reached.
    pub fn upload_detection_with_key(&self, detection: &Detection, key: &str) -> Result<()> {
        let response: DetectionUploadResponse =
            self.post_json_with_key(&self.config.detection_url(), detection, Some(key))?;
        validate_detection_response(response)
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
        let response = send_get(self.agent.get(url))?;

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
        let response = send_get(req)?;

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
        self.post_json_with_key(url, payload, None)
    }

    fn post_json_with_key<T: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        payload: &T,
        key: Option<&str>,
    ) -> Result<R> {
        let body = serde_json::to_string(payload).map_err(TransportError::Serialization)?;

        let mut request = self.agent.post(url).content_type("application/json");
        if let Some(key) = key {
            request = request.header("Idempotency-Key", key);
        }
        let response = request.send(&body).map_err(|e| match &e {
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

/// Longest server explanation kept from an error response.
const ERROR_BODY_LIMIT: u64 = 2048;

/// Sends a GET and turns a 4xx/5xx into [`TransportError::ServerError`] that
/// carries what the server said. `ureq`'s own status error discards the body, so
/// a `423 Locked` carrying "Content delivery is halted for ring `canary_0` at
/// release 3" reached the operator as `http status: 423` (#667).
fn send_get(
    request: ureq::RequestBuilder<ureq::typestate::WithoutBody>,
) -> Result<ureq::http::Response<ureq::Body>> {
    let response = request
        .config()
        .http_status_as_error(false)
        .build()
        .call()
        .map_err(|e| TransportError::Network(e.to_string()))?;
    let status = response.status().as_u16();
    if status < 400 {
        return Ok(response);
    }
    let text = response
        .into_body()
        .with_config()
        .limit(ERROR_BODY_LIMIT)
        .read_to_string()
        .unwrap_or_default();
    Err(TransportError::ServerError {
        status,
        message: error_reason(&text).unwrap_or_else(|| format!("http status: {status}")),
    })
}

/// The explanation in an error body: the `error`, `message` or `reason` string
/// of a JSON object, else the plain text. `None` when the body says nothing.
fn error_reason(body: &str) -> Option<String> {
    let body = body.trim();
    if let Ok(serde_json::Value::Object(fields)) = serde_json::from_str(body) {
        return ["error", "message", "reason"]
            .iter()
            .find_map(|key| fields.get(*key)?.as_str())
            .map(str::to_string)
            .filter(|reason| !reason.is_empty());
    }
    (!body.is_empty()).then(|| body.to_string())
}

fn validate_detection_response(response: DetectionUploadResponse) -> Result<()> {
    if response.status != "accepted" {
        return Err(TransportError::InvalidResponse(format!(
            "unexpected detection ingest status: {}",
            response.status
        )));
    }
    Ok(())
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

    // A custom TLS config is only needed for mTLS or a private CA; otherwise
    // ureq's defaults (built-in public roots) stand.
    if config.has_client_cert() || config.ca_cert_path.is_some() {
        agent_builder = agent_builder.tls_config(build_tls_config(config)?);
    }

    Ok(agent_builder.build().into())
}

/// Builds the TLS config: the client certificate for mTLS and/or the pinned CA
/// roots, whichever are configured.
fn build_tls_config(config: &TransportConfig) -> Result<ureq::tls::TlsConfig> {
    use ureq::tls::{Certificate, ClientCert, PrivateKey, TlsConfig};

    let mut builder = TlsConfig::builder();

    if let Some(ca_path) = &config.ca_cert_path {
        builder = builder.root_certs(load_ca_roots(ca_path)?);
    }

    if let (Some(cert_path), Some(key_path)) = (&config.client_cert_path, &config.client_key_path) {
        // Load certificate from PEM file
        let cert_pem = std::fs::read(cert_path).map_err(|e| {
            TransportError::Config(format!(
                "cannot read the client certificate {}: {e}",
                cert_path.display()
            ))
        })?;
        let cert = Certificate::from_pem(&cert_pem)
            .map_err(|e| TransportError::Config(format!("failed to parse cert: {e}")))?;

        // Load private key from PEM file
        let key_pem = std::fs::read(key_path).map_err(|e| {
            TransportError::Config(format!(
                "cannot read the client key {}: {e}",
                key_path.display()
            ))
        })?;
        if is_encrypted_pem(&key_pem) {
            return Err(TransportError::Config(format!(
                "the client key {} is passphrase-protected, which the transport cannot use \
                 yet (`server.mtls_passphrase` is not wired): provide an unencrypted key",
                key_path.display()
            )));
        }
        let key = PrivateKey::from_pem(&key_pem)
            .map_err(|e| TransportError::Config(format!("failed to parse key: {e}")))?;

        // Create client certificate with chain and key
        builder = builder.client_cert(Some(ClientCert::new_with_certs(&[cert], key)));
    }

    Ok(builder.build())
}

/// Whether a PEM private key is passphrase-protected (PKCS#8 `ENCRYPTED PRIVATE KEY`, or the
/// legacy `Proc-Type: 4,ENCRYPTED` header). Said plainly, because the parse error of an
/// encrypted key does not name the cause.
fn is_encrypted_pem(pem: &[u8]) -> bool {
    let text = String::from_utf8_lossy(pem);
    text.contains("BEGIN ENCRYPTED PRIVATE KEY") || text.contains("Proc-Type: 4,ENCRYPTED")
}

/// Reads every certificate of a PEM bundle as a trust root. An unreadable file or
/// a bundle with no certificate is a configuration error, not a silent fallback to
/// the public roots: the operator asked for a pinned CA.
fn load_ca_roots(path: &std::path::Path) -> Result<ureq::tls::RootCerts> {
    let pem = std::fs::read(path).map_err(|e| {
        TransportError::Config(format!("cannot read CA bundle {}: {e}", path.display()))
    })?;
    let mut roots = Vec::new();
    for item in ureq::tls::parse_pem(&pem) {
        let item = item.map_err(|e| {
            TransportError::Config(format!("invalid CA bundle {}: {e}", path.display()))
        })?;
        if let ureq::tls::PemItem::Certificate(cert) = item {
            roots.push(cert);
        }
    }
    if roots.is_empty() {
        return Err(TransportError::Config(format!(
            "CA bundle {} contains no certificate",
            path.display()
        )));
    }
    Ok(ureq::tls::RootCerts::new_with_certs(&roots))
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

    #[test]
    fn a_passphrase_protected_client_key_is_refused_with_a_clear_message() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = (dir.path().join("c.crt"), dir.path().join("c.key"));
        std::fs::write(&cert, include_str!("../tests/fixtures/ca.pem")).unwrap();
        std::fs::write(
            &key,
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n",
        )
        .unwrap();
        let config = TransportConfig::new("https://cp.example").with_client_cert(cert, key);

        let Err(err) = TransportClient::new(config) else {
            panic!("an encrypted key must be refused");
        };
        assert!(err.to_string().contains("passphrase-protected"), "{err}");

        assert!(is_encrypted_pem(
            b"Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00"
        ));
        assert!(!is_encrypted_pem(b"-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn an_unreadable_client_certificate_or_key_names_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = (dir.path().join("c.crt"), dir.path().join("c.key"));
        let missing_cert =
            TransportConfig::new("https://cp.example").with_client_cert(cert.clone(), key.clone());
        let Err(err) = TransportClient::new(missing_cert) else {
            panic!("a missing certificate must be refused");
        };
        assert!(err.to_string().contains("client certificate"), "{err}");
        assert!(err.to_string().contains("c.crt"), "{err}");

        std::fs::write(&cert, include_str!("../tests/fixtures/ca.pem")).unwrap();
        let missing_key = TransportConfig::new("https://cp.example").with_client_cert(cert, key);
        let Err(err) = TransportClient::new(missing_key) else {
            panic!("a missing key must be refused");
        };
        assert!(err.to_string().contains("client key"), "{err}");
        assert!(err.to_string().contains("c.key"), "{err}");
    }
}
