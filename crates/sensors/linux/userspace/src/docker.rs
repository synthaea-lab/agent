//! Minimal Docker Engine API client over the daemon's Unix socket, just enough to
//! resolve a container id to its image/name (issue #80: the "needs a cached lookup
//! against the Docker/containerd socket" half `read_container_id`'s doc comment
//! deferred). No HTTP client dependency: the request/response shape needed here
//! (one GET, one small JSON body, `Connection: close`) is simple enough that
//! hand-rolling it is less risk than a new crate for a single call site.

use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Where the Docker daemon listens by default. A containerd-only host (no Docker)
/// or a remapped socket path isn't handled specially — `lookup` returns `None`
/// either way, same as any other failure (see its doc comment).
const DOCKER_SOCKET: &str = "/var/run/docker.sock";

/// Round-trip budget: this runs on the sensor's single event-processing task
/// (spawned off it, see `sensor.rs`), so a hung/overloaded daemon must not stall
/// indefinitely. Local Unix socket to a daemon on the same host — a few hundred ms
/// is already generous.
const REQUEST_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DockerContainerInfo {
    pub(crate) image: Option<String>,
    pub(crate) name: Option<String>,
}

/// Only the two fields of `/containers/<id>/json`'s (large) response this cares
/// about. `serde` skips unknown fields by default, no `deny_unknown_fields`.
#[derive(Deserialize)]
struct InspectResponse {
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Config")]
    config: Option<InspectConfig>,
}

#[derive(Deserialize)]
struct InspectConfig {
    #[serde(rename = "Image")]
    image: Option<String>,
}

/// Resolves `container_id`'s image/name via `GET /containers/<id>/json` on the
/// Docker daemon socket. `None` on anything short of a clean 200 — no socket (no
/// Docker on this host, or it's containerd-only), permission denied, timeout,
/// container already gone, malformed response: none of these are the caller's
/// problem to handle differently, attribution is best-effort by design (the id
/// itself, from the cgroup path, already stands on its own without this).
pub(crate) async fn lookup(container_id: &str) -> Option<DockerContainerInfo> {
    match tokio::time::timeout(REQUEST_TIMEOUT, lookup_inner(container_id)).await {
        Ok(info) => info,
        Err(_) => {
            log::debug!("docker socket lookup for {container_id}: timed out");
            None
        }
    }
}

async fn lookup_inner(container_id: &str) -> Option<DockerContainerInfo> {
    let mut stream = match UnixStream::connect(DOCKER_SOCKET).await {
        Ok(s) => s,
        Err(e) => {
            log::debug!("docker socket ({DOCKER_SOCKET}) unavailable: {e}");
            return None;
        }
    };

    let request = format!(
        "GET /containers/{container_id}/json HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n"
    );
    if let Err(e) = stream.write_all(request.as_bytes()).await {
        log::debug!("docker socket write failed: {e}");
        return None;
    }

    let mut raw = Vec::new();
    if let Err(e) = stream.read_to_end(&mut raw).await {
        log::debug!("docker socket read failed: {e}");
        return None;
    }

    if !status_line_is_2xx(&raw) {
        return None;
    }

    let body = match http_response_body(&raw) {
        Some(b) => b,
        None => {
            log::debug!(
                "docker socket: malformed HTTP response ({} bytes)",
                raw.len()
            );
            return None;
        }
    };

    let parsed: InspectResponse = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            log::debug!("docker socket: response is not the expected JSON shape: {e}");
            return None;
        }
    };

    Some(DockerContainerInfo {
        image: parsed.config.and_then(|c| c.image),
        // Docker's `Name` is always `/`-prefixed (the root of its naming scheme,
        // which itself supports slashes, e.g. compose project separators); strip
        // the one leading slash rather than the whole prefix.
        name: parsed
            .name
            .map(|n| n.strip_prefix('/').unwrap_or(&n).to_string()),
    })
}

fn status_line_is_2xx(raw: &[u8]) -> bool {
    raw.split(|&b| b == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .is_some_and(|code| (200..300).contains(&code))
}

/// Splits headers from body on the first blank line and, if present, undoes
/// `Transfer-Encoding: chunked`. Docker's synchronous inspect endpoint sends
/// `Content-Length` in practice (verified against a real daemon while writing
/// this), but handling chunked defensively means a daemon version/config that
/// does differ fails to parse rather than silently corrupting every lookup.
fn http_response_body(raw: &[u8]) -> Option<Vec<u8>> {
    let sep = b"\r\n\r\n";
    let split_at = raw.windows(sep.len()).position(|w| w == sep)? + sep.len();
    let (headers, body) = (&raw[..split_at], &raw[split_at..]);
    let headers = std::str::from_utf8(headers).ok()?;
    if headers.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        dechunk(body)
    } else {
        Some(body.to_vec())
    }
}

/// Minimal chunked-transfer-encoding decoder: `<hex-size>\r\n<data>\r\n` repeated,
/// terminated by a zero-size chunk. No trailer support (Docker doesn't send any
/// here) — a malformed/unexpected shape returns `None` rather than guessing.
fn dechunk(mut body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = body.windows(2).position(|w| w == b"\r\n")?;
        let size_str = std::str::from_utf8(&body[..line_end]).ok()?;
        let size = usize::from_str_radix(size_str.trim(), 16).ok()?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Some(out);
        }
        if body.len() < size + 2 {
            return None;
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..]; // skip the chunk's trailing \r\n
    }
}

#[cfg(test)]
mod tests {
    use super::{dechunk, http_response_body, status_line_is_2xx, InspectResponse};

    #[test]
    fn status_line_2xx_accepts_200() {
        assert!(status_line_is_2xx(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
        ));
    }

    #[test]
    fn status_line_2xx_rejects_404() {
        assert!(!status_line_is_2xx(
            b"HTTP/1.1 404 Not Found\r\n\r\n{\"message\":\"No such container\"}"
        ));
    }

    #[test]
    fn http_response_body_splits_on_blank_line() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(http_response_body(raw), Some(b"{}".to_vec()));
    }

    #[test]
    fn http_response_body_dechunks() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        assert_eq!(http_response_body(raw), Some(b"{}".to_vec()));
    }

    #[test]
    fn http_response_body_none_without_blank_line() {
        assert_eq!(http_response_body(b"garbage, no header/body separator"), None);
    }

    #[test]
    fn dechunk_multiple_chunks() {
        let body = b"4\r\nabcd\r\n3\r\nefg\r\n0\r\n\r\n";
        assert_eq!(dechunk(body), Some(b"abcdefg".to_vec()));
    }

    #[test]
    fn dechunk_truncated_is_none() {
        assert_eq!(dechunk(b"4\r\nab"), None);
    }

    #[test]
    fn parses_real_inspect_shape() {
        // Trimmed from an actual `GET /containers/<id>/json` response against a
        // real Docker daemon (docker.io 29.1.3, API 1.52) while writing this.
        let json = r#"{"Id":"8a61b9f2","Name":"/probetest2","Config":{"Image":"alpine:3.20","Cmd":["sleep","60"]},"HostConfig":{"Privileged":false}}"#;
        let parsed: InspectResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.name.as_deref(), Some("/probetest2"));
        assert_eq!(parsed.config.unwrap().image.as_deref(), Some("alpine:3.20"));
    }

    #[test]
    fn parses_404_body_without_erroring() {
        // A 404 body deserializes cleanly too (every field optional) — the caller
        // must check the status line, not just whether parsing succeeded.
        let json = r#"{"message":"No such container: deadbeef"}"#;
        let parsed: InspectResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.name, None);
        assert!(parsed.config.is_none());
    }
}
