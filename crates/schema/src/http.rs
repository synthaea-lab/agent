//! What a web server's access log says about a request.

use super::*;

/// Which detection signature an [`HttpRequestEvent`] matched (ADR-0022 §3). A small
/// fixed set: the agent never emits one event per request, only for these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpSignature {
    /// `../` or its encoded forms in the path or a parameter value.
    PathTraversal,
    /// SQL injection markers in a parameter value.
    SqlInjection,
    /// A known scanner or exploitation tool named in the `User-Agent`.
    ScannerUserAgent,
    /// A request for a path or parameter typical of a dropped webshell.
    WebshellLike,
}

/// The one parameter value a signature matched on, the only value of a request that
/// leaves the host (ADR-0022 §4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpEvidence {
    /// Name of the matched query parameter.
    pub param: String,
    /// The value, cut to 128 characters by the producer. Credential redaction
    /// (ADR-0018) is not the producer's job: the agent's sink boundary applies it,
    /// so a consumer downstream of that sink sees the redacted form.
    pub value: String,
}

/// A web request that matched a detection signature, derived from an access-log line
/// by the agent (issue #478, ADR-0022). Not one event per request: a request that
/// matches nothing never becomes an event. The URL arrives reduced: the path and the
/// query parameter *names*, never the values, except [`Self::evidence`].
///
/// `meta.pid`/`ppid` are 0 and `meta.comm` names the log source: an access-log line
/// carries no process. `meta.timestamp_ns` is when the agent read the line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequestEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// The client, when the log holds an address. `None` for a resolved host name
    /// (`HostnameLookups On`), never a fabricated one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<core::net::IpAddr>,
    /// `None` when the request line was not parseable (`"-"`, or garbage).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// The request path with the query string removed.
    pub path: String,
    /// Names of the query parameters, in order, without values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub param_names: Vec<String>,
    /// HTTP response status code.
    pub status: u16,
    /// Which suspicious-request signature matched.
    pub signature: HttpSignature,
    /// Evidence for the match, when the signature carries any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<HttpEvidence>,
    /// For [`HttpSignature::ScannerUserAgent`]: the name of the matched tool
    /// (`sqlmap`, `nikto`), not the `User-Agent` string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanner: Option<String>,
    /// The log line was over the length cap and cut before it was parsed.
    #[serde(default)]
    pub truncated: bool,
}

/// One client in an [`HttpSummaryEvent`]'s ranking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpClientCount {
    /// Client IP address.
    pub client: core::net::IpAddr,
    /// Requests from this client that ended in a 4xx or 5xx status in the window.
    pub failures: u32,
}

/// The access log of one source over one window (issue #478, ADR-0022 §3): counters
/// and the clients with the most failing requests, the only thing the server sees of
/// requests that matched no signature. Emitted once per source per window that saw at
/// least one request: a quiet log is normal and an empty summary says nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpSummaryEvent {
    /// Same `pid`/`ppid` 0 convention as [`HttpRequestEvent`]; `timestamp_ns` is the
    /// end of the window.
    pub meta: EventMeta,
    /// The declared log file the counters come from.
    pub source: String,
    /// Length of the summarized window, in seconds.
    pub window_secs: u32,
    /// Total requests seen in the window.
    pub requests: u32,
    /// Requests answered with a 4xx status in the window.
    pub status_4xx: u32,
    /// Requests answered with a 5xx status in the window.
    pub status_5xx: u32,
    /// Distinct client addresses seen. A line with a host name instead of an address
    /// counts in `requests` but not here.
    pub distinct_clients: u32,
    /// Highest failure counts first, bounded by the producer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub top_clients: Vec<HttpClientCount>,
}
