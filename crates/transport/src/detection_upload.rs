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
/// permanent, so the agent does not send it. A mirror of that setting, not a negotiated value:
/// if the server limit changes, change it here (a smaller server limit is still caught by the
/// per-record `413` handling below, a larger one only costs the detections in between).
pub const MAX_DETECTION_BODY_BYTES: usize = 8 * 1024 * 1024;

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
    /// The default keeps the old behaviour of `ack` for a drain that does not count.
    ///
    /// # Errors
    /// Returns an I/O error when acknowledgement cannot be persisted.
    fn ack_dropping(&mut self, dropped: u64) -> std::io::Result<()> {
        let _ = dropped;
        self.ack()
    }
}

/// Whether `error` says something about this one record, not about the agent or the server:
/// `400` (the payload is malformed), `413` (it is over the body limit), `422` (it cannot be
/// processed), or a record that cannot be serialized. Retrying the record gives the same
/// answer, and the other records of its segment are not affected. Every other permanent error
/// (`401`, `403`, `404`, `429`, a TLS or configuration error, ...) says something that holds
/// for the whole upload and keeps the whole-segment rule.
fn refuses_this_record(error: &TransportError) -> bool {
    match error {
        TransportError::ServerError { status, .. } => matches!(status, 400 | 413 | 422),
        TransportError::Serialization(_) => true,
        _ => false,
    }
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
    /// A record the server refuses for good (`400`, `413`, `422`, see
    /// [`refuses_this_record`]), or one the agent can tell is over the server's body limit
    /// ([`MAX_DETECTION_BODY_BYTES`]), is dropped on its own, logged with its key, and the
    /// rest of the segment is uploaded: one bad record must not take with it the unrelated
    /// detections spooled in the same segment (#1119). The drops are counted once, when the
    /// segment is acknowledged, so a retry of the segment does not count them again. Any
    /// other permanent 4xx skips the whole segment to keep later detections moving; the
    /// spool counts the loss.
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
            if let Ok(body) = serde_json::to_vec(&record.detection)
                && body.len() > MAX_DETECTION_BODY_BYTES
            {
                tracing::warn!(
                    key = %record.key,
                    bytes = body.len(),
                    limit = MAX_DETECTION_BODY_BYTES,
                    "detection over the server body limit; dropped without being sent"
                );
                dropped += 1;
                continue;
            }
            match self
                .client
                .upload_detection_with_key(&record.detection, &record.key)
            {
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
