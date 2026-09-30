//! `AuditSensor`: `schema::sensor::Sensor` implementation.

use std::sync::Arc;

use schema::sensor::{Capabilities, EventSink, Sensor, SensorError};
use tokio::sync::Notify;

use crate::{AuditSocket, classify, normalize, parse};

/// Records read per readiness wakeup before yielding back to `select!`. One
/// exec is 7 records on the lab kernel (SYSCALL, EXECVE, CWD, PATH ×2,
/// PROCTITLE, EOE), so this covers a ~36-exec burst per wakeup without letting
/// a flood starve the stop signal.
const DRAIN_BUDGET: usize = 256;

pub struct AuditSensor {
    stop: Arc<Notify>,
}

impl AuditSensor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            stop: Arc::new(Notify::new()),
        }
    }

    async fn run_async(&mut self, sink: Box<dyn EventSink>) -> Result<(), SensorError> {
        let socket = AuditSocket::open().map_err(|e| format!("audit socket open: {e}"))?;

        let mut async_socket =
            tokio::io::unix::AsyncFd::with_interest(socket, tokio::io::Interest::READABLE)
                .map_err(|e| format!("AsyncFd: {e}"))?;

        tracing::info!("sensor-linux-audit: listening for exec/connect");

        let ctrl_c = tokio::signal::ctrl_c();
        tokio::pin!(ctrl_c);

        let mut buf = vec![0u8; 8192];
        // A record this parser can't read is skipped and counted, never fatal:
        // returning the parse error here once stopped the sensor on the first
        // record it received (#504).
        let mut unparsed: u64 = 0;
        let mut overruns: u64 = 0;
        loop {
            tokio::select! {
                _ = &mut ctrl_c => break,
                _ = self.stop.notified() => break,
                guard = async_socket.readable_mut() => {
                    let mut guard = guard.map_err(|e| format!("poll: {e}"))?;
                    // Drain what is queued before re-arming: readiness is edge-
                    // triggered, and clearing it after a single recv left the rest
                    // queued until the next record arrived, so the sensor fell
                    // further behind with every burst and lost the tail on exit
                    // (#504). Bounded per wakeup so a flood can't starve `stop`;
                    // readiness stays set when the budget runs out.
                    for _ in 0..DRAIN_BUDGET {
                        match guard.get_inner_mut().recv(&mut buf) {
                            Ok(n) => match parse::parse_audit_message(&buf[..n]) {
                                Ok(record) => forward(&record, sink.as_ref()),
                                Err(e) => {
                                    unparsed += 1;
                                    // Powers of two only: a stream of bad records must not flood the log.
                                    if unparsed.is_power_of_two() {
                                        tracing::warn!(
                                            error = %e,
                                            unparsed_total = unparsed,
                                            "sensor-linux-audit: unparseable record skipped"
                                        );
                                    }
                                }
                            },
                            Err(crate::AuditError::Netlink(errno))
                                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK =>
                            {
                                guard.clear_ready();
                                break;
                            }
                            // The kernel dropped records because the socket buffer
                            // overflowed; the socket itself is still usable.
                            Err(crate::AuditError::Netlink(libc::ENOBUFS)) => {
                                overruns += 1;
                                if overruns.is_power_of_two() {
                                    tracing::warn!(
                                        overruns_total = overruns,
                                        "sensor-linux-audit: kernel dropped records (socket buffer overrun)"
                                    );
                                }
                            }
                            Err(e) => {
                                return Err(format!("recv: {e}").into());
                            }
                        }
                    }
                }
            }
        }

        tracing::info!("sensor-linux-audit: exiting");
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
            file_events: false, // Phase 2: fanotify
            connect_events: true,
            auth_events: false, // journal sensor's domain
            user_attribution: true,
            parent_lineage: false, // HONEST: auditd doesn't track ppid
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

/// Classifies one parsed record and hands the resulting event, if any, to `sink`.
fn forward(record: &parse::AuditRecord, sink: &dyn EventSink) {
    let Some(event) = classify::classify(record) else {
        return;
    };
    let timestamp_ns = audit_ts_to_epoch_ns(record.timestamp_sec, record.timestamp_ms);
    let schema_event = match &event {
        crate::AuditEvent::Exec { .. } => normalize::exec_event(&event, timestamp_ns),
        crate::AuditEvent::Connect { .. } => normalize::connect_event(&event, timestamp_ns),
        crate::AuditEvent::PolicyDenial { .. } => {
            normalize::policy_denial_event(&event, timestamp_ns)
        }
    };
    sink.on_event(schema_event);
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
        assert!(!caps.parent_lineage); // Honest: audit doesn't provide ppid
        assert!(!caps.file_events); // Phase 2
        assert!(!caps.auth_events); // journal owns this
    }
}
