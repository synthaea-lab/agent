//! `AuditSensor`: `schema::sensor::Sensor` implementation.

use std::sync::Arc;
use schema::sensor::{Sensor, SensorError, Capabilities, EventSink};
use tokio::sync::Notify;
use crate::{AuditSocket, classify, normalize, parse};

pub struct AuditSensor {
    stop: Arc<Notify>,
}

impl AuditSensor {
    #[must_use]
    pub fn new() -> Self {
        Self { stop: Arc::new(Notify::new()) }
    }

    async fn run_async(&mut self, sink: Box<dyn EventSink>) -> Result<(), SensorError> {
        let socket = AuditSocket::open()
            .map_err(|e| format!("audit socket open: {e}"))?;

        let mut async_socket = tokio::io::unix::AsyncFd::with_interest(
            socket,
            tokio::io::Interest::READABLE,
        ).map_err(|e| format!("AsyncFd: {e}"))?;

        log::info!("sensor-linux-audit: listening for exec/connect");

        let ctrl_c = tokio::signal::ctrl_c();
        tokio::pin!(ctrl_c);

        let mut buf = vec![0u8; 8192];
        loop {
            tokio::select! {
                _ = &mut ctrl_c => break,
                _ = self.stop.notified() => break,
                guard = async_socket.readable_mut() => {
                    let mut guard = guard.map_err(|e| format!("poll: {e}"))?;
                    let socket = guard.get_inner_mut();

                    match socket.recv(&mut buf) {
                        Ok(n) => {
                            let record = parse::parse_audit_message(&buf[..n])
                                .map_err(|e| format!("parse: {e}"))?;

                            if let Some(event) = classify::classify(&record) {
                                let timestamp_ns = audit_ts_to_epoch_ns(
                                    record.timestamp_sec,
                                    record.timestamp_ms,
                                );

                                let schema_event = match event {
                                    crate::AuditEvent::Exec { .. } => normalize::exec_event(&event, timestamp_ns),
                                    crate::AuditEvent::Connect { .. } => normalize::connect_event(&event, timestamp_ns),
                                };

                                sink.on_event(schema_event);
                            }
                        }
                        Err(crate::AuditError::Netlink(errno))
                            if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK =>
                        {
                            // Spurious wakeup - no data available. Clear ready and continue.
                        }
                        Err(e) => {
                            return Err(format!("recv: {e}").into());
                        }
                    }

                    guard.clear_ready();
                }
            }
        }

        log::info!("sensor-linux-audit: exiting");
        Ok(())
    }
}

impl Default for AuditSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl Sensor for AuditSensor {
    fn name(&self) -> &str {
        "linux-audit"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            exec_events: true,
            file_events: false,      // Phase 2: fanotify
            connect_events: true,
            auth_events: false,      // journal sensor's domain
            user_attribution: true,
            parent_lineage: false,   // HONEST: auditd doesn't track ppid
        }
    }

    fn run(&mut self, sink: Box<dyn EventSink>) -> Result<(), SensorError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .map_err(|e| format!("tokio runtime: {e}"))?;
        rt.block_on(self.run_async(sink))
    }

    fn stop(&mut self) {
        self.stop.notify_one();
    }
}

fn audit_ts_to_epoch_ns(sec: u64, ms: u32) -> u64 {
    sec * 1_000_000_000 + (ms as u64) * 1_000_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_conversion() {
        let ns = audit_ts_to_epoch_ns(1234567890, 123);
        assert_eq!(ns, 1_234_567_890_123_000_000);
    }

    #[test]
    fn capabilities_honest_about_gaps() {
        let sensor = AuditSensor::new();
        let caps = sensor.capabilities();
        assert!(caps.exec_events);
        assert!(caps.connect_events);
        assert!(caps.user_attribution);
        assert!(!caps.parent_lineage);  // Honest: audit doesn't provide ppid
        assert!(!caps.file_events);     // Phase 2
        assert!(!caps.auth_events);     // journal owns this
    }
}
