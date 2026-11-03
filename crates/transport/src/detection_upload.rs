//! Store-and-forward upload of structured detections.

use std::time::Duration;

use schema::detection::Detection;
use serde::{Deserialize, Serialize};

use crate::{
    TransportClient, TransportConfig,
    error::{Result, TransportError},
    upload::UploadStep,
};

/// The largest detection body the control plane accepts: `client_max_body_size 8m` on the
/// agent ingest locations of `server/nginx.conf`. A larger body is answered `413`, which is
/// permanent, so the agent shortens a detection to fit before it sends it ([`fit_detection_to_limit`]):
/// dropping it would let a process that pads its own command line erase its detection on the
/// host it controls. A mirror of that setting, not a negotiated value: if the server limit
/// changes, change it here (a smaller server limit is still caught by the per-record `413`
/// handling below, a larger one only shortens detections more than needed).
pub const MAX_DETECTION_BODY_BYTES: usize = 8 * 1024 * 1024;

/// The `error` the detection route answers with a `400` when the payload (or the idempotency
/// key) fails validation: `server/app/api/ingest/detection/route.ts`, the `ZodError` branch.
/// Any other `400` (`Invalid certificate subject`, a proxy's HTML page for a client certificate
/// that does not verify) is about the whole agent and keeps the whole-segment rule.
const SERVER_INVALID_PAYLOAD: &str = "Invalid payload";

/// The retry identity is persisted in the same spool record as its detection.
/// Reopening an in-flight segment therefore reuses the exact same key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueuedDetection {
    pub key: String,
    pub detection: Detection,
}

/// Two-phase drain of detection records. Implementations retain a drained
/// segment until `ack` or `skip`, including across process restarts.
pub trait DetectionDrain: Send {
    /// Returns the oldest segment, or an empty vector if the spool is empty.
    ///
    /// # Errors
    /// Returns an I/O error when the segment cannot be read.
    fn drain(&mut self) -> std::io::Result<Vec<QueuedDetection>>;

    /// Removes the segment after every detection was accepted by the server.
    ///
    /// # Errors
    /// Returns an I/O error when acknowledgement cannot be persisted.
    fn ack(&mut self) -> std::io::Result<()>;

    /// Discards a permanently rejected segment and counts its lost records.
    ///
    /// # Errors
    /// Returns an I/O error when discard cannot be persisted.
    fn skip(&mut self) -> std::io::Result<()>;

    /// Removes the segment like [`ack`](Self::ack) and counts `dropped` of its records that the
    /// server refused for good (#1119): they were left out one by one, the rest was accepted.
    /// Required, with no default: a drain that forgot it would lose the count silently.
    ///
    /// # Errors
    /// Returns an I/O error when acknowledgement cannot be persisted.
    fn ack_dropping(&mut self, dropped: u64) -> std::io::Result<()>;
}

/// Whether `error` says something about this one record, not about the agent or the server:
/// `400` with the route's `Invalid payload` (it fails validation), `409` (its idempotency key
/// was already used for a different detection), `413` (it is over the body limit), `422` (it
/// cannot be processed), or a record that cannot be serialized. Retrying the record gives the
/// same answer, and the other records of its segment are not affected. Every other permanent
/// error says something that holds for the whole upload and keeps the whole-segment rule:
/// `401`, `403`, `404`, `429`, a `400` that is not `Invalid payload` (a certificate or subject
/// failure), a TLS or configuration error.
///
/// A validation `400` after a rolling upgrade (a newer agent field an older server refuses)
/// lands here too and clears when the server is upgraded: those detections are lost either way,
/// as the old whole-segment skip lost them, and each one is logged with its key.
fn refuses_this_record(error: &TransportError) -> bool {
    match error {
        TransportError::ServerError { status, message } => match status {
            400 => message == SERVER_INVALID_PAYLOAD,
            409 | 413 | 422 => true,
            _ => false,
        },
        TransportError::Serialization(_) => true,
        _ => false,
    }
}

/// Recursively cuts every string longer than `cap` bytes to `cap` (on a character boundary) and
/// marks the cut with `…`. Keys of objects are left alone.
fn truncate_strings(value: &mut serde_json::Value, cap: usize) {
    match value {
        serde_json::Value::String(text) if text.len() > cap => {
            let mut end = cap;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
            text.push('…');
        }
        serde_json::Value::Array(items) => {
            for item in items {
                truncate_strings(item, cap);
            }
        }
        serde_json::Value::Object(fields) => {
            for field in fields.values_mut() {
                truncate_strings(field, cap);
            }
        }
        _ => {}
    }
}

/// The detection serialized, shortened to [`MAX_DETECTION_BODY_BYTES`] when it is over.
///
/// A process controls fields of the events a detection carries (an argv it padded to megabytes),
/// and a field a process controls is bounded by truncation, never by rejection: the detection is
/// still sent. Only the `events` payload strings are cut (to 8 KiB, then 2 KiB, 512, 128 and 32
/// bytes, until it fits, then events are dropped from the end, the first one kept); title,
/// source, techniques, severity, score and the key are kept, and the title says the events were
/// shortened and from how many bytes. The result is a pure function of the detection, so a retry
/// of the same record sends the same bytes (the server hashes the body against the key).
///
/// # Errors
/// Returns the serialization error of the detection.
pub fn fit_detection_to_limit(
    detection: &Detection,
) -> std::result::Result<Vec<u8>, serde_json::Error> {
    let body = serde_json::to_vec(detection)?;
    if body.len() <= MAX_DETECTION_BODY_BYTES {
        return Ok(body);
    }
    let original = body.len();
    let mut value = serde_json::to_value(detection)?;
    let marker = format!(" [events shortened from {original} bytes]");
    if let Some(title) = value
        .get_mut("title")
        .and_then(|t| t.as_str())
        .map(str::to_owned)
    {
        value["title"] = serde_json::Value::String(format!("{title}{marker}"));
    }
    let mut best = body;
    for cap in [8192, 2048, 512, 128, 32] {
        if let Some(events) = value.get_mut("events") {
            truncate_strings(events, cap);
        }
        best = serde_json::to_vec(&value)?;
        if best.len() <= MAX_DETECTION_BODY_BYTES {
            return Ok(best);
        }
    }
    while best.len() > MAX_DETECTION_BODY_BYTES {
        let Some(events) = value.get_mut("events").and_then(|e| e.as_array_mut()) else {
            break;
        };
        if events.len() <= 1 {
            break;
        }
        events.pop();
        best = serde_json::to_vec(&value)?;
    }
    Ok(best)
}

/// Uploads detections one at a time, preserving each record's retry key.
pub struct DetectionUploader<D: DetectionDrain> {
    client: TransportClient,
    drain: D,
    config: TransportConfig,
    consecutive_failures: u32,
}

impl<D: DetectionDrain> DetectionUploader<D> {
    /// Creates an uploader for a durable detection drain.
    pub fn new(client: TransportClient, drain: D) -> Self {
        let config = client.config().clone();
        Self {
            client,
            drain,
            config,
            consecutive_failures: 0,
        }
    }

    /// Uploads the oldest segment. A lost response leaves it in flight; retry
    /// reuses the same keys, so the server acknowledges already-stored records.
    /// Network failures never discard a segment.
    ///
    /// A detection over the server's body limit is shortened to fit, not dropped
    /// ([`fit_detection_to_limit`]). A record the server refuses for good (see [`refuses_this_record`]) is
    /// dropped on its own, logged with its key, and the rest of the segment is uploaded: one bad
    /// record must not take with it the unrelated detections spooled in the same segment
    /// (#1119). The drops are counted once, when the segment is acknowledged, so a retry of the
    /// segment does not count them again. Any other permanent 4xx skips the whole segment to
    /// keep later detections moving; the spool counts the loss.
    ///
    /// Returns the number of records the server accepted.
    ///
    /// # Errors
    /// Returns an upload or spool error.
    pub fn upload_once(&mut self) -> Result<usize> {
        let records = self.drain.drain()?;
        if records.is_empty() {
            // A malformed segment can deserialize to zero records while still
            // becoming in-flight. `skip` is a no-op for a truly empty spool.
            self.drain.skip()?;
            return Ok(0);
        }
        let mut uploaded = 0usize;
        let mut dropped = 0u64;
        for record in &records {
            let body = match fit_detection_to_limit(&record.detection) {
                Ok(body) => {
                    if body.len() > MAX_DETECTION_BODY_BYTES {
                        tracing::warn!(
                            key = %record.key,
                            bytes = body.len(),
                            "detection still over the server body limit after shortening; sending it, the server will refuse it"
                        );
                    }
                    body
                }
                Err(error) => {
                    tracing::warn!(
                        %error,
                        key = %record.key,
                        "detection cannot be serialized; dropped, the rest of its segment goes on"
                    );
                    dropped += 1;
                    continue;
                }
            };
            match self.client.upload_detection_bytes(&body, &record.key) {
                Ok(()) => uploaded += 1,
                Err(error) if refuses_this_record(&error) => {
                    tracing::warn!(
                        error = %error,
                        key = %record.key,
                        "server refused a detection for good; dropped, the rest of its segment goes on"
                    );
                    dropped += 1;
                }
                Err(error) if !error.is_retryable() => {
                    tracing::warn!(error = %error, dropped = records.len(), "server rejected detection segment permanently");
                    self.drain.skip()?;
                    self.consecutive_failures = 0;
                    return Err(error);
                }
                Err(error) => {
                    self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                    tracing::warn!(error = %error, "detection upload failed; segment remains spooled");
                    return Err(error);
                }
            }
        }
        self.drain.ack_dropping(dropped)?;
        self.consecutive_failures = 0;
        Ok(uploaded)
    }

    /// Exponential retry delay, capped by the transport configuration.
    #[must_use]
    pub fn backoff_duration(&self) -> Duration {
        if self.consecutive_failures == 0 {
            return Duration::ZERO;
        }
        let base = self.config.retry_base.as_millis() as u64;
        let cap = self.config.retry_max.as_millis() as u64;
        Duration::from_millis(
            base.saturating_mul(1 << (self.consecutive_failures - 1).min(10))
                .min(cap),
        )
    }
}

impl<D: DetectionDrain> UploadStep for DetectionUploader<D> {
    fn upload_once(&mut self) -> Result<usize> {
        DetectionUploader::upload_once(self)
    }

    fn backoff_duration(&self) -> Duration {
        DetectionUploader::backoff_duration(self)
    }
}
