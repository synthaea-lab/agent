//! A control plane whose certificate comes from a private CA (#658): the agent
//! must trust it when told which CA to pin, and must refuse it otherwise.
//! `tests/fixtures/README.md` says where the PKI comes from.

use std::{
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use transport::{TransportClient, TransportConfig, TransportError};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Serves one TLS connection (`server.pem` for `localhost`) with `{"ok":true}`
/// and returns the base URL. A client that rejects the certificate just
/// makes the handshake fail on this side too, which the thread ignores.
fn serve_once() -> String {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(fixture("server.pem"))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_file(fixture("server.key")).unwrap();
    let tls = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    thread::spawn(move || {
        let Ok((mut tcp, _)) = listener.accept() else {
            return;
        };
        let Ok(mut conn) = rustls::ServerConnection::new(tls) else {
            return;
        };
        let mut stream = rustls::Stream::new(&mut conn, &mut tcp);
        let mut request = [0u8; 2048];
        if stream.read(&mut request).is_err() {
            return;
        }
        let body = br#"{"ok":true}"#;
        let head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(body);
        let _ = stream.flush();
    });
    url
}

fn get(config: TransportConfig, url: &str) -> Result<serde_json::Value, TransportError> {
    TransportClient::new(config)?.get_json(&format!("{url}/probe"))
}

#[test]
fn a_server_signed_by_the_configured_private_ca_is_trusted() {
    let url = serve_once();
    let config = TransportConfig::new(&url).with_ca_cert(fixture("ca.pem"));
    assert_eq!(get(config, &url).unwrap()["ok"], true);
}

#[test]
fn a_server_signed_by_a_private_ca_is_refused_without_it() {
    let url = serve_once();
    let err = get(TransportConfig::new(&url), &url).unwrap_err();
    assert!(
        err.to_string().contains("UnknownIssuer"),
        "expected an unknown-issuer failure, got: {err}"
    );
}

#[test]
fn a_server_is_refused_when_the_pinned_ca_is_a_different_one() {
    let url = serve_once();
    let config = TransportConfig::new(&url).with_ca_cert(fixture("other-ca.pem"));
    let err = get(config, &url).unwrap_err();
    assert!(
        err.to_string().contains("UnknownIssuer"),
        "expected an unknown-issuer failure, got: {err}"
    );
}

#[test]
fn an_unreadable_or_empty_ca_bundle_fails_at_construction_not_silently() {
    let missing = TransportConfig::new("https://localhost").with_ca_cert(fixture("nope.pem"));
    assert!(matches!(
        TransportClient::new(missing),
        Err(TransportError::Config(_))
    ));

    let dir = tempfile::tempdir().unwrap();
    let empty = dir.path().join("empty.pem");
    std::fs::write(&empty, "no certificate in here\n").unwrap();
    let config = TransportConfig::new("https://localhost").with_ca_cert(empty);
    assert!(matches!(
        TransportClient::new(config),
        Err(TransportError::Config(_))
    ));
}
