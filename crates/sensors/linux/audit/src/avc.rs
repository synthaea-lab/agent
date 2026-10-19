//! AVC-only `NETLINK_AUDIT` subscription (#780): a second, independent read of the
//! same multicast stream `AuditSensor` subscribes to, filtered to `PolicyDenial`
//! events only. The agent binary's `select_sensor` picks eBPF or the audit sensor
//! for exec/connect telemetry — never both — so on a host where eBPF loads
//! (the normal case on a hardened, up-to-date `SELinux`-Enforcing box), `AuditSensor`
//! never runs and its AVC classification, the only place that produces
//! `PolicyDenial` events, goes with it. `AvcReader` exists so the caller can keep
//! that one source alive regardless of which primary sensor was chosen.
//!
//! Netlink multicast delivers one copy of each record per subscribed socket (not
//! one copy total, handed to whichever socket asks first), so a second socket here
//! does not steal records from `AuditSensor`'s own subscription. The reverse also
//! holds: running both at once (audit chosen as primary, `AvcReader` started
//! anyway) would only double up `PolicyDenial` events, not corrupt anything — the
//! caller's job to avoid by starting this reader only when the audit sensor is not
//! already running, not a safety property this type has to enforce itself.

use std::os::unix::io::{AsRawFd, RawFd};

use schema::sensor::EventSink;

use crate::{
    AuditError, AuditEvent, AuditSocket, classify, normalize, parse, sensor::audit_ts_to_epoch_ns,
};

/// Records drained per call to [`AvcReader::drain`] before returning control to
/// the caller — same budget and reasoning as `AuditSensor`'s own drain loop
/// (`sensor.rs`): bounds one call's cost so a flood can't starve the caller's own
/// stop check, which lives outside this type.
const DRAIN_BUDGET: usize = 256;

/// Reads `NETLINK_AUDIT` for `PolicyDenial` events only — see this module's doc.
pub struct AvcReader {
    socket: AuditSocket,
    /// Records this socket received but the shared parser couldn't read. Counted
    /// and logged at powers of two, same convention as `AuditSensor` (#504's
    /// lesson, #780 review): without this, a change in the AVC wire format would
    /// look exactly like "no denials happened" instead of a parser gap.
    unparsed: u64,
}

impl AvcReader {
    /// Opens a fresh, independent subscription to the audit multicast group.
    ///
    /// # Errors
    ///
    /// Returns `AuditError::Netlink` if the socket can't be opened or bound —
    /// typically a privilege error, see [`AuditSocket::open`]'s doc.
    pub fn open() -> Result<Self, AuditError> {
        Ok(Self {
            socket: AuditSocket::open()?,
            unparsed: 0,
        })
    }

    /// Test-only: wraps an already-open socket (e.g. one end of a `socketpair`)
    /// instead of opening a real `NETLINK_AUDIT` subscription (#780 review).
    #[cfg(test)]
    fn from_socket_for_test(socket: AuditSocket) -> Self {
        Self {
            socket,
            unparsed: 0,
        }
    }

    /// Waits up to `timeout_ms` for the socket to become readable, then drains
    /// what's queued (bounded by [`DRAIN_BUDGET`]), forwarding only `PolicyDenial`
    /// events to `sink`. Exec/Connect records on the same stream are classified
    /// and discarded — not this reader's job, see this module's doc. A kernel
    /// buffer overrun (`ENOBUFS`) is reported through the return value, not an
    /// error: the socket is still usable, same posture as `AuditSensor`'s own loop.
    ///
    /// Returns `(forwarded, overran)`: `forwarded` is almost always `0` — the
    /// timeout elapsing with nothing queued, or only Exec/Connect records
    /// arriving, are both normal and frequent. A call returning at all, whatever
    /// the count, is what the caller's heartbeat needs: proof the thread is not
    /// stuck, not proof of real `SELinux` traffic.
    ///
    /// # Errors
    ///
    /// Returns `AuditError::Netlink` on a `poll`/`recv` failure other than
    /// `EAGAIN`/`EWOULDBLOCK` (handled internally, see above) or `ENOBUFS`
    /// (reported via `overran`, not this).
    pub fn drain(
        &mut self,
        sink: &dyn EventSink,
        timeout_ms: i32,
    ) -> Result<(usize, bool), AuditError> {
        if !self.wait_readable(timeout_ms)? {
            return Ok((0, false));
        }

        let mut buf = [0u8; 8192];
        let mut forwarded = 0;
        let mut overran = false;
        for _ in 0..DRAIN_BUDGET {
            match self.socket.recv(&mut buf) {
                Ok(n) => match classify_raw_record(&buf[..n], sink) {
                    ForwardOutcome::Forwarded => forwarded += 1,
                    ForwardOutcome::NotPolicyDenial => {}
                    ForwardOutcome::Unparseable => {
                        self.unparsed += 1;
                        // Powers of two only: a stream of bad records must not flood the log.
                        if self.unparsed.is_power_of_two() {
                            tracing::warn!(
                                unparsed_total = self.unparsed,
                                "avc-reader: unparseable record skipped"
                            );
                        }
                    }
                },
                Err(e) => match classify_recv_error(e) {
                    RecvOutcome::WouldBlock => break,
                    RecvOutcome::Overrun => overran = true,
                    RecvOutcome::Fatal(e) => return Err(e),
                },
            }
        }
        Ok((forwarded, overran))
    }

    /// `poll(2)` on the raw fd with a timeout, so [`Self::drain`] returns control
    /// to the caller (for its own stop check and heartbeat pulse) even when the
    /// socket never has anything queued — blocking indefinitely would make a
    /// quiet host's reader thread indistinguishable from a stuck one.
    fn wait_readable(&self, timeout_ms: i32) -> Result<bool, AuditError> {
        let mut pfd = libc::pollfd {
            fd: self.socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            // SAFETY: pfd is a valid, live pointer to one initialized pollfd; nfds=1
            // matches the single-element array it points at.
            let ready = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
            // SAFETY: __errno_location returns a valid pointer to thread-local errno;
            // only meaningful when `ready < 0`, harmless to read otherwise.
            let errno = unsafe { *libc::__errno_location() };
            match classify_poll_result(ready, errno) {
                Some(result) => return result,
                // A signal interrupted the wait (e.g. the process's own Ctrl-C
                // handler elsewhere) — not a socket error, retry the wait.
                None => continue,
            }
        }
    }
}

/// What a `recv` failure on the audit socket means for [`AvcReader::drain`] — pulled
/// out as its own pure function (#780 review) so `EAGAIN`/`EWOULDBLOCK` vs `ENOBUFS`
/// vs a genuine, propagate-worthy error are each directly testable, rather than only
/// reachable through a real socket error `cargo-mutants` found nothing exercised.
enum RecvOutcome {
    /// Nothing queued right now — not an error, the caller just stops this pass.
    WouldBlock,
    /// The kernel dropped records before this socket could read them — reported
    /// through `drain`'s `overran` flag, not a hard error; the socket stays usable.
    Overrun,
    /// Anything else: a real socket problem, propagated to the caller.
    Fatal(AuditError),
}

fn classify_recv_error(error: AuditError) -> RecvOutcome {
    match error {
        AuditError::Netlink(errno) if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK => {
            RecvOutcome::WouldBlock
        }
        AuditError::Netlink(libc::ENOBUFS) => RecvOutcome::Overrun,
        other => RecvOutcome::Fatal(other),
    }
}

/// What one `poll(2)` call means for [`AvcReader::wait_readable`]'s caller — same
/// reasoning as [`classify_recv_error`]: a literal `-1`/`EINTR` return from the real
/// syscall is far harder to provoke in a test than calling this directly. `None`
/// means "retry the wait", matching `wait_readable`'s loop.
fn classify_poll_result(ready: i32, errno: i32) -> Option<Result<bool, AuditError>> {
    if ready >= 0 {
        return Some(Ok(ready > 0));
    }
    if errno == libc::EINTR {
        None
    } else {
        Some(Err(AuditError::Netlink(errno)))
    }
}

impl AsRawFd for AvcReader {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

/// Distinguishes why a raw record wasn't forwarded (#780 review) — `drain` needs
/// to count-and-log [`Unparseable`](Self::Unparseable) the way `AuditSensor` does
/// for its own stream (#504's lesson), while [`NotPolicyDenial`](Self::NotPolicyDenial)
/// (Exec/Connect, or a kind `classify` doesn't recognize) is intended, silent
/// discarding — not shedding, see this module's doc.
enum ForwardOutcome {
    Forwarded,
    NotPolicyDenial,
    Unparseable,
}

/// Parses and classifies one raw record, forwarding it to `sink` only if it is a
/// `PolicyDenial` — never fatal on a bad record, same posture as
/// `AuditSensor::forward` (#504's lesson: a parse error here must never stop the
/// reader).
fn classify_raw_record(raw: &[u8], sink: &dyn EventSink) -> ForwardOutcome {
    let Ok(record) = parse::parse_audit_message(raw) else {
        return ForwardOutcome::Unparseable;
    };
    let Some(event @ AuditEvent::PolicyDenial { .. }) = classify::classify(&record) else {
        return ForwardOutcome::NotPolicyDenial;
    };
    let timestamp_ns = audit_ts_to_epoch_ns(record.timestamp_sec, record.timestamp_ms);
    sink.on_event(normalize::policy_denial_event(&event, timestamp_ns));
    ForwardOutcome::Forwarded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::build_wire_message;

    /// `AUDIT_AVC` (see `classify.rs`) — the real kernel netlink form (no
    /// `type=`/`msg=` text prefix, see `parse::tests::parses_the_kernel_netlink_form`),
    /// exercised through the real parser rather than a hand-built `AuditRecord`, so a
    /// mismatch between this module's logic and the parser's actual output can't hide.
    fn avc_wire_message(payload: &str) -> Vec<u8> {
        build_wire_message(1400, payload)
    }

    struct RecordingSink(std::sync::Mutex<Vec<schema::Event>>);

    impl EventSink for RecordingSink {
        fn on_event(&self, event: schema::Event) {
            self.0.lock().unwrap().push(event);
        }
    }

    #[test]
    fn forwards_a_policy_denial_and_reports_its_event() {
        let bytes = avc_wire_message(
            "audit(1700000000.123:45): avc:  denied  { read } for  pid=1234 \
             comm=\"httpd\" scontext=httpd_t tcontext=shadow_t tclass=file",
        );
        let sink = RecordingSink(std::sync::Mutex::new(Vec::new()));
        assert!(matches!(
            classify_raw_record(&bytes, &sink),
            ForwardOutcome::Forwarded
        ));
        let events = sink.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        let schema::Event::PolicyDenial(denial) = &events[0] else {
            panic!("expected a PolicyDenial event, got {:?}", events[0]);
        };
        assert_eq!(denial.action.as_deref(), Some("read"));
        assert_eq!(denial.object_class.as_deref(), Some("file"));
    }

    #[test]
    fn does_not_forward_an_exec_record_on_the_same_stream() {
        let bytes = build_wire_message(
            1309, // AUDIT_EXECVE — the other record type this socket also carries
            "audit(1700000000.123:45): argc=1 a0=\"id\"",
        );
        let sink = RecordingSink(std::sync::Mutex::new(Vec::new()));
        assert!(!matches!(
            classify_raw_record(&bytes, &sink),
            ForwardOutcome::Forwarded
        ));
        assert!(
            sink.0.lock().unwrap().is_empty(),
            "an Exec record must never reach this reader's sink"
        );
    }

    #[test]
    fn an_avc_record_missing_scontext_and_tclass_is_not_forwarded() {
        // classify_avc itself drops this (see its doc) — confirms this reader
        // inherits that judgment rather than forwarding whatever classify hands back.
        let bytes = avc_wire_message("audit(1700000000.123:45): comm=\"httpd\"");
        let sink = RecordingSink(std::sync::Mutex::new(Vec::new()));
        assert!(!matches!(
            classify_raw_record(&bytes, &sink),
            ForwardOutcome::Forwarded
        ));
        assert!(sink.0.lock().unwrap().is_empty());
    }

    #[test]
    fn an_unparseable_record_is_skipped_not_fatal() {
        let sink = RecordingSink(std::sync::Mutex::new(Vec::new()));
        assert!(!matches!(
            classify_raw_record(b"\xff\xfe not an audit record", &sink),
            ForwardOutcome::Forwarded
        ));
        assert!(sink.0.lock().unwrap().is_empty());
    }

    #[test]
    fn classify_raw_record_distinguishes_unparseable_from_not_a_policy_denial() {
        // The distinction a plain forwarded/not-forwarded bool erases (#780
        // review): `drain` needs to know *why* nothing was forwarded, since only
        // one of these two should ever be counted as shedding.
        let sink = RecordingSink(std::sync::Mutex::new(Vec::new()));
        assert!(matches!(
            classify_raw_record(b"\xff\xfe not an audit record", &sink),
            ForwardOutcome::Unparseable
        ));
        let exec_bytes = build_wire_message(1309, "audit(1700000000.123:45): argc=1 a0=\"id\"");
        assert!(matches!(
            classify_raw_record(&exec_bytes, &sink),
            ForwardOutcome::NotPolicyDenial
        ));
    }

    #[test]
    fn classify_recv_error_treats_eagain_and_ewouldblock_as_would_block() {
        assert!(matches!(
            classify_recv_error(AuditError::Netlink(libc::EAGAIN)),
            RecvOutcome::WouldBlock
        ));
        assert!(matches!(
            classify_recv_error(AuditError::Netlink(libc::EWOULDBLOCK)),
            RecvOutcome::WouldBlock
        ));
    }

    #[test]
    fn classify_recv_error_treats_enobufs_as_overrun_not_fatal() {
        assert!(matches!(
            classify_recv_error(AuditError::Netlink(libc::ENOBUFS)),
            RecvOutcome::Overrun
        ));
    }

    #[test]
    fn classify_recv_error_propagates_any_other_errno() {
        assert!(matches!(
            classify_recv_error(AuditError::Netlink(libc::EBADF)),
            RecvOutcome::Fatal(_)
        ));
    }

    #[test]
    fn classify_poll_result_ready_means_readable() {
        assert!(matches!(classify_poll_result(1, 0), Some(Ok(true))));
    }

    #[test]
    fn classify_poll_result_timeout_means_not_readable() {
        assert!(matches!(classify_poll_result(0, 0), Some(Ok(false))));
    }

    #[test]
    fn classify_poll_result_eintr_means_retry() {
        assert!(classify_poll_result(-1, libc::EINTR).is_none());
    }

    #[test]
    fn classify_poll_result_other_errno_is_fatal() {
        assert!(matches!(
            classify_poll_result(-1, libc::EBADF),
            Some(Err(_))
        ));
    }

    /// One end of an `AF_UNIX`/`SOCK_DGRAM` socketpair, wrapped as an `AvcReader`
    /// (#780 review): `recv`/`poll` behave the same as on the real netlink socket
    /// for a reader that only ever calls those two syscalls, so this exercises
    /// `drain`/`wait_readable`'s actual loop without `CAP_AUDIT_READ` or root.
    fn reader_and_peer_fd() -> (AvcReader, RawFd) {
        let mut fds = [0; 2];
        // SAFETY: fds is a valid, live pointer to a 2-element array sized exactly
        // as socketpair(2) requires; return value checked below.
        let ret = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        assert_eq!(ret, 0, "socketpair() failed");
        let reader = AvcReader::from_socket_for_test(AuditSocket::from_raw_fd_for_test(fds[0]));
        (reader, fds[1])
    }

    #[test]
    fn drain_forwards_a_policy_denial_received_on_the_socket() {
        let (mut reader, peer_fd) = reader_and_peer_fd();
        let bytes = avc_wire_message(
            "audit(1700000000.123:45): avc:  denied  { read } for  pid=1234 \
             comm=\"httpd\" scontext=httpd_t tcontext=shadow_t tclass=file",
        );
        // SAFETY: peer_fd is the write end of the socketpair created above, still
        // open; bytes/len describe a valid, live slice of the correct length.
        let n = unsafe { libc::write(peer_fd, bytes.as_ptr().cast(), bytes.len()) };
        assert_eq!(n as usize, bytes.len());

        let sink = RecordingSink(std::sync::Mutex::new(Vec::new()));
        let (forwarded, overran) = reader.drain(&sink, 1000).unwrap();
        assert_eq!(forwarded, 1);
        assert!(!overran);
        assert_eq!(sink.0.lock().unwrap().len(), 1);
        // SAFETY: peer_fd is owned by this test and not used again after this.
        unsafe { libc::close(peer_fd) };
    }

    #[test]
    fn drain_times_out_promptly_when_nothing_is_queued() {
        let (mut reader, peer_fd) = reader_and_peer_fd();
        let sink = RecordingSink(std::sync::Mutex::new(Vec::new()));
        let start = std::time::Instant::now();
        let (forwarded, overran) = reader.drain(&sink, 200).unwrap();
        assert_eq!(forwarded, 0);
        assert!(!overran);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "drain must not block past its timeout when the socket is idle"
        );
        // SAFETY: peer_fd is owned by this test and not used again after this.
        unsafe { libc::close(peer_fd) };
    }

    #[test]
    fn drain_counts_an_unparseable_record_without_failing() {
        let (mut reader, peer_fd) = reader_and_peer_fd();
        let garbage = b"\xff\xfe not an audit record";
        // SAFETY: peer_fd is the write end of the socketpair created above, still
        // open; bytes/len describe a valid, live slice of the correct length.
        let n = unsafe { libc::write(peer_fd, garbage.as_ptr().cast(), garbage.len()) };
        assert_eq!(n as usize, garbage.len());

        let sink = RecordingSink(std::sync::Mutex::new(Vec::new()));
        let (forwarded, overran) = reader.drain(&sink, 1000).unwrap();
        assert_eq!(forwarded, 0);
        assert!(!overran);
        assert_eq!(reader.unparsed, 1);
        assert!(sink.0.lock().unwrap().is_empty());
        // SAFETY: peer_fd is owned by this test and not used again after this.
        unsafe { libc::close(peer_fd) };
    }
}
