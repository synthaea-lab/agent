//! Event upload with retry and backpressure handling.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use schema::Event;

use crate::{client::TransportClient, config::TransportConfig, error::Result};

/// Trait for draining events from a spool.
///
/// This abstraction allows transport to remain decoupled from the concrete
/// spool implementation. The agent binary wires up the actual `EventSpool`.
pub trait EventDrain: Send {
    /// Drains events from the oldest segment. A drain that was never
    /// [`EventDrain::ack`]'d re-delivers the same events on the next call —
    /// that redelivery is the at-least-once guarantee, so implementations must
    /// NOT discard on drain.
    ///
    /// Returns an empty vec if no events are available.
    ///
    /// # Errors
    ///
    /// Returns an error if the drain operation fails.
    fn drain(&mut self) -> std::io::Result<Vec<Event>>;

    /// Marks the last drained batch as durably uploaded — only now may the
    /// implementation discard it. Called by [`EventUploader::upload_once`]
    /// after every batch of the drain uploaded successfully; never called on
    /// failure, so a crash or network outage re-delivers.
    ///
    /// # Errors
    ///
    /// Returns an error if the acknowledgement cannot be persisted.
    fn ack(&mut self) -> std::io::Result<()>;

    /// Discards the last drained batch without uploading it — the poison
    /// escape hatch, called either when the server rejects the batch
    /// permanently (a non-retryable [`crate::TransportError`]) or when a
    /// retryable failure has repeated [`TransportConfig::max_drain_attempts`]
    /// times in a row on the same segment: without it one malformed or
    /// permanently-500ing segment would block all newer telemetry forever.
    ///
    /// The discard unit is everything the last `drain` returned — for the
    /// spool that is a whole segment, so valid events sharing a segment with
    /// a poison record are lost with it. Deliberate: sub-segment retry is not
    /// expressible in the spool's two-phase drain/ack protocol, and one
    /// segment (1 MiB cap, roughly one upload batch) is the accepted blast
    /// radius for the rare permanent-rejection or wedged-server path.
    ///
    /// # Errors
    ///
    /// Returns an error if the discard cannot be persisted.
    fn skip(&mut self) -> std::io::Result<()>;
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
    /// Subset of `consecutive_failures` that were server-side rejections
    /// (5xx) — gates [`TransportConfig::max_drain_attempts`] on its own,
    /// independently of any connectivity failures mixed into the same run
    /// (issue #394).
    consecutive_server_failures: u32,
    /// Subset of `consecutive_failures` that were pure connectivity failures
    /// — gates [`TransportConfig::max_network_drain_attempts`] on its own.
    consecutive_network_failures: u32,
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
            consecutive_server_failures: 0,
            consecutive_network_failures: 0,
        }
    }

    /// Attempts to drain and upload events, acknowledging the drain only after
    /// every batch uploaded — at-least-once: a retryable failure leaves the
    /// batch un-ack'd for redelivery (a partially-uploaded drain re-delivers
    /// whole, so the server may see duplicates; it never silently loses). A
    /// permanent rejection ([`crate::TransportError::is_retryable`] false) skips the
    /// poison batch instead, so one malformed segment can't block newer
    /// telemetry forever.
    ///
    /// A retryable failure (e.g. the server 500s) is NOT skipped on the first
    /// attempt — it redelivers, same as any transient outage. But because the
    /// same segment stays in-flight until ack'd or skipped, [`Self::drain`]
    /// keeps re-delivering it on every call, so the relevant counter doubles
    /// as "attempts on this segment" for as long as it keeps failing. A 5xx
    /// counts toward [`TransportConfig::max_drain_attempts`]; a pure
    /// connectivity failure (DNS, connection refused, timeout) counts toward
    /// the separate, larger [`TransportConfig::max_network_drain_attempts`]
    /// instead (issue #394) — the server rejecting a segment is stronger
    /// poison-segment evidence than never having reached the server at all,
    /// which is equally consistent with a brief blip. Either budget running
    /// out skips the segment — a permanently-broken server, or a permanently
    /// unreachable one, must not be allowed to wedge all newer telemetry
    /// forever.
    ///
    /// Returns the number of events uploaded, or 0 if the drain is empty.
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

        // Upload in batches. `consecutive_failures` is NOT reset here on a
        // per-batch success (issue #315 regression, found in PR #349 review):
        // a segment larger than `batch_size` splits into several batches per
        // call, and resetting mid-call erases the count from every PRIOR
        // failed call on this same still-unacked segment the moment any
        // later batch happens to land before the one that keeps failing —
        // `consecutive_failures` never reaches `max_drain_attempts` unless
        // the poison record happens to sit in the segment's very first
        // batch. It resets exactly once, only when the whole call succeeds
        // (see the `ack()` call below) — that is the only point at which
        // this segment's attempt history should be forgotten.
        for batch in events.chunks(self.config.batch_size) {
            match self.client.upload_events(batch) {
                Ok(response) => {
                    tracing::debug!(
                        accepted = response.accepted,
                        batch_id = ?response.batch_id,
                        "uploaded events"
                    );
                }
                Err(e) if !e.is_retryable() => {
                    tracing::warn!(
                        error = %e,
                        dropped = count,
                        "server rejected batch permanently — skipping poison segment"
                    );
                    self.drain.skip()?;
                    self.reset_failure_counters();
                    return Err(e);
                }
                Err(e) => {
                    self.consecutive_failures += 1;
                    let (attempts, max_attempts) = if e.is_network_error() {
                        self.consecutive_network_failures += 1;
                        (
                            self.consecutive_network_failures,
                            self.config.max_network_drain_attempts,
                        )
                    } else {
                        self.consecutive_server_failures += 1;
                        (
                            self.consecutive_server_failures,
                            self.config.max_drain_attempts,
                        )
                    };
                    tracing::warn!(
                        attempt = self.consecutive_failures,
                        network_attempt = self.consecutive_network_failures,
                        server_attempt = self.consecutive_server_failures,
                        error = %e,
                        "upload failed"
                    );
                    if attempts >= max_attempts {
                        tracing::warn!(
                            attempts,
                            max_attempts,
                            dropped = count,
                            network = e.is_network_error(),
                            "segment exceeded max drain attempts — skipping to restore forward progress"
                        );
                        self.drain.skip()?;
                        self.reset_failure_counters();
                    }
                    return Err(e);
                }
            }
        }

        self.drain.ack()?;
        self.reset_failure_counters();
        tracing::info!(count, "uploaded events successfully");
        Ok(count)
    }

    /// Clears every per-segment failure counter — called once the segment is
    /// no longer in flight (acked or skipped), the only point at which its
    /// attempt history should be forgotten.
    fn reset_failure_counters(&mut self) {
        self.consecutive_failures = 0;
        self.consecutive_server_failures = 0;
        self.consecutive_network_failures = 0;
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

    /// Resets the failure counters (e.g., after a successful connection test).
    pub fn reset_failures(&mut self) {
        self.reset_failure_counters();
    }
}

/// Background upload loop that continuously drains events. Blocking — run it
/// on a dedicated thread; another thread stops it through [`UploadLoop::stop_handle`]
/// (the same shared-`AtomicBool` shape the sensors use — a `&mut self` stop
/// would be uncallable while `run(&mut self)` blocks).
pub struct UploadLoop<D: EventDrain> {
    uploader: EventUploader<D>,
    poll_interval: Duration,
    stop: Arc<AtomicBool>,
}

impl<D: EventDrain> UploadLoop<D> {
    /// Creates a new upload loop.
    #[must_use]
    pub fn new(uploader: EventUploader<D>, poll_interval: Duration) -> Self {
        Self {
            uploader,
            poll_interval,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Shared stop flag: set it to `true` to end [`UploadLoop::run`] after the
    /// current iteration (including its sleep).
    #[must_use]
    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    /// Runs the upload loop until the stop flag is set.
    ///
    /// This method blocks. Call from a dedicated thread.
    pub fn run(&mut self) {
        tracing::info!(poll_interval = ?self.poll_interval, "upload loop started");

        while !self.stop.load(Ordering::SeqCst) {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock drain that returns predefined events.
    struct MockDrain {
        events: Vec<Event>,
        drained: bool,
        acked: u32,
        skipped: u32,
    }

    impl MockDrain {
        fn empty() -> Self {
            Self {
                events: Vec::new(),
                drained: false,
                acked: 0,
                skipped: 0,
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

        fn ack(&mut self) -> std::io::Result<()> {
            self.acked += 1;
            Ok(())
        }

        fn skip(&mut self) -> std::io::Result<()> {
            self.skipped += 1;
            Ok(())
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

    #[test]
    fn empty_drain_is_never_acked() {
        // ack() marks a drained batch as uploaded; an empty drain has no batch,
        // so acking it would delete whatever the NEXT drain would have returned
        // in a real spool. upload_once must return without touching the drain.
        let config = TransportConfig::new("https://example.com");
        let client = TransportClient::new(config).unwrap();
        let mut uploader = EventUploader::new(client, MockDrain::empty());
        assert_eq!(uploader.upload_once().unwrap(), 0);
        assert_eq!(uploader.drain.acked, 0);
        assert_eq!(uploader.drain.skipped, 0);
    }
}
