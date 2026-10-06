//! Store-and-forward upload of structured detections.

use std::time::Duration;

use schema::detection::Detection;
use serde::{Deserialize, Serialize};

use crate::{TransportClient, TransportConfig, error::Result, upload::UploadStep};

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
    /// Network failures never discard a segment. A permanent 4xx rejection
    /// skips it to keep later detections moving; the spool counts the loss.
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
        for record in &records {
            if let Err(error) = self
                .client
                .upload_detection_with_key(&record.detection, &record.key)
            {
                if !error.is_retryable() {
                    tracing::warn!(error = %error, dropped = records.len(), "server rejected detection segment permanently");
                    self.drain.skip()?;
                    self.consecutive_failures = 0;
                } else {
                    self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                    tracing::warn!(error = %error, "detection upload failed; segment remains spooled");
                }
                return Err(error);
            }
        }
        self.drain.ack()?;
        self.consecutive_failures = 0;
        Ok(records.len())
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
