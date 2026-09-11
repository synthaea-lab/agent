//! Event upload with retry and backpressure handling.

use std::{thread, time::Duration};

use schema::Event;

use crate::{client::TransportClient, config::TransportConfig, error::Result};

/// Trait for draining events from a spool.
///
/// This abstraction allows transport to remain decoupled from the concrete
/// spool implementation. The agent binary wires up the actual `EventSpool`.
pub trait EventDrain: Send {
    /// Drains events from the oldest segment.
    ///
    /// Returns an empty vec if no events are available.
    ///
    /// # Errors
    ///
    /// Returns an error if the drain operation fails.
    fn drain(&mut self) -> std::io::Result<Vec<Event>>;
}

/// Manages event upload from a drain source to the server.
///
/// Drains events using the [`EventDrain`] trait, uploads them with retry logic,
/// and implements graceful degradation when the server is unreachable.
pub struct EventUploader<D: EventDrain> {
    client: TransportClient,
    drain: D,
    config: TransportConfig,
    consecutive_failures: u32,
}

impl<D: EventDrain> EventUploader<D> {
    /// Creates a new uploader with the given client and drain source.
    pub fn new(client: TransportClient, drain: D) -> Self {
        let config = client.config().clone();
        Self {
            client,
            drain,
            config,
            consecutive_failures: 0,
        }
    }

    /// Attempts to drain and upload events.
    ///
    /// Returns the number of events uploaded, or 0 if the drain is empty.
    /// On failure, events may be lost (depends on drain implementation).
    ///
    /// # Errors
    ///
    /// Returns an error if the upload fails. The caller should implement
    /// backoff before retrying.
    pub fn upload_once(&mut self) -> Result<usize> {
        // Drain events from the source
        let events: Vec<Event> = self.drain.drain()?;

        if events.is_empty() {
            return Ok(0);
        }

        let count = events.len();

        // Upload in batches
        for batch in events.chunks(self.config.batch_size) {
            match self.client.upload_events(batch) {
                Ok(response) => {
                    tracing::debug!(
                        accepted = response.accepted,
                        batch_id = ?response.batch_id,
                        "uploaded events"
                    );
                    self.consecutive_failures = 0;
                }
                Err(e) => {
                    self.consecutive_failures += 1;
                    tracing::warn!(
                        attempt = self.consecutive_failures,
                        error = %e,
                        "upload failed"
                    );
                    return Err(e);
                }
            }
        }

        tracing::info!(count, "uploaded events successfully");
        Ok(count)
    }

    /// Calculates the backoff duration based on consecutive failures.
    #[must_use]
    pub fn backoff_duration(&self) -> Duration {
        if self.consecutive_failures == 0 {
            return Duration::ZERO;
        }

        let base_ms = self.config.retry_base.as_millis() as u64;
        let max_ms = self.config.retry_max.as_millis() as u64;

        // Exponential backoff: base * 2^(failures-1), capped at max
        let backoff_ms = base_ms
            .saturating_mul(1 << (self.consecutive_failures - 1).min(10))
            .min(max_ms);

        Duration::from_millis(backoff_ms)
    }

    /// Returns true if the uploader is in a failed state (consecutive failures > 0).
    #[must_use]
    pub fn is_failing(&self) -> bool {
        self.consecutive_failures > 0
    }

    /// Returns the number of consecutive upload failures.
    #[must_use]
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Resets the failure counter (e.g., after a successful connection test).
    pub fn reset_failures(&mut self) {
        self.consecutive_failures = 0;
    }
}

/// Background upload loop that continuously drains events.
///
/// This is a simple blocking implementation. For production, consider
/// running this in a dedicated thread or using async.
pub struct UploadLoop<D: EventDrain> {
    uploader: EventUploader<D>,
    poll_interval: Duration,
    running: bool,
}

impl<D: EventDrain> UploadLoop<D> {
    /// Creates a new upload loop.
    #[must_use]
    pub fn new(uploader: EventUploader<D>, poll_interval: Duration) -> Self {
        Self {
            uploader,
            poll_interval,
            running: false,
        }
    }

    /// Runs the upload loop until stopped.
    ///
    /// This method blocks. Call from a dedicated thread.
    pub fn run(&mut self) {
        self.running = true;
        tracing::info!(poll_interval = ?self.poll_interval, "upload loop started");

        while self.running {
            match self.uploader.upload_once() {
                Ok(0) => {
                    // Drain empty, wait before checking again
                    thread::sleep(self.poll_interval);
                }
                Ok(n) => {
                    // Uploaded successfully, immediately try next segment
                    tracing::debug!(count = n, "uploaded events, checking for more");
                }
                Err(e) => {
                    // Upload failed, apply backoff
                    let backoff = self.uploader.backoff_duration();
                    tracing::warn!(error = %e, backoff = ?backoff, "upload failed, backing off");
                    thread::sleep(backoff);
                }
            }
        }

        tracing::info!("upload loop stopped");
    }

    /// Signals the loop to stop after the current iteration.
    pub fn stop(&mut self) {
        self.running = false;
    }

    /// Returns true if the loop is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock drain that returns predefined events.
    struct MockDrain {
        events: Vec<Event>,
        drained: bool,
    }

    impl MockDrain {
        fn empty() -> Self {
            Self {
                events: Vec::new(),
                drained: false,
            }
        }
    }

    impl EventDrain for MockDrain {
        fn drain(&mut self) -> std::io::Result<Vec<Event>> {
            if self.drained {
                return Ok(Vec::new());
            }
            self.drained = true;
            Ok(std::mem::take(&mut self.events))
        }
    }

    #[test]
    fn backoff_increases_exponentially() {
        let config = TransportConfig::new("https://example.com");
        let client = TransportClient::new(config).unwrap();
        let drain = MockDrain::empty();
        let mut uploader = EventUploader::new(client, drain);

        // No failures = no backoff
        assert_eq!(uploader.backoff_duration(), Duration::ZERO);

        // First failure = base backoff (1s)
        uploader.consecutive_failures = 1;
        assert_eq!(uploader.backoff_duration(), Duration::from_millis(1000));

        // Second failure = 2s
        uploader.consecutive_failures = 2;
        assert_eq!(uploader.backoff_duration(), Duration::from_millis(2000));

        // Third failure = 4s
        uploader.consecutive_failures = 3;
        assert_eq!(uploader.backoff_duration(), Duration::from_millis(4000));

        // Capped at max (60s)
        uploader.consecutive_failures = 20;
        assert_eq!(uploader.backoff_duration(), Duration::from_millis(60000));
    }
}
