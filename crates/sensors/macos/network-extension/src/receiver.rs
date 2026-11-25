//! The Unix-domain socket the Swift system extension connects to and writes
//! NDJSON [`crate::wire`] records into.
//!
//! The agent listens and the extension connects because the OS starts and
//! stops the extension on network activity, so it must be the reconnecting
//! side. [`NormalizedNeStream`] is generic over [`BufRead`] so tests feed
//! canned captures.

use std::{
    io::BufRead,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use crate::{
    NetworkExtensionError, normalize,
    wire::{NeRecord, WIRE_VERSION},
};

/// Records the receiver skipped, by cause: version skew between a deployed extension and this
/// agent, counted rather than silently dropped. Shared across connections (the extension
/// reconnects whenever the OS restarts it), so the agent hands the same handle to each
/// [`NormalizedNeStream::with_counters`] (#178).
#[derive(Debug, Default)]
pub struct SkewCounters {
    unparseable: AtomicU64,
    unknown_version: AtomicU64,
    unmapped: AtomicU64,
}

/// A reading of [`SkewCounters`] at one instant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SkewTotals {
    /// Lines that did not parse as a known record kind or field shape (a newer extension).
    pub unparseable: u64,
    /// Records of a known shape carrying a wire version this build does not speak.
    pub unknown_version: u64,
    /// Records that parsed but have no schema event (for example a remote address that is not a
    /// literal IP).
    pub unmapped: u64,
}

impl SkewTotals {
    /// True when nothing was skipped.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        *self == Self::default()
    }

    /// What was skipped since `earlier`, an older reading of the same counters.
    #[must_use]
    pub fn since(&self, earlier: &Self) -> Self {
        Self {
            unparseable: self.unparseable.saturating_sub(earlier.unparseable),
            unknown_version: self.unknown_version.saturating_sub(earlier.unknown_version),
            unmapped: self.unmapped.saturating_sub(earlier.unmapped),
        }
    }
}

impl SkewCounters {
    /// The totals now.
    #[must_use]
    pub fn totals(&self) -> SkewTotals {
        SkewTotals {
            unparseable: self.unparseable.load(Ordering::Relaxed),
            unknown_version: self.unknown_version.load(Ordering::Relaxed),
            unmapped: self.unmapped.load(Ordering::Relaxed),
        }
    }
}

/// Reads normalized schema events out of any line-oriented wire-record
/// source (one accepted extension connection).
pub struct NormalizedNeStream<R> {
    lines: std::io::Lines<R>,
    counters: Arc<SkewCounters>,
}

impl<R: BufRead> NormalizedNeStream<R> {
    /// A stream with counters of its own, for tests: a caller outside them has no way to read the
    /// counters, so it injects a handle with [`Self::with_counters`].
    #[cfg(test)]
    fn new(reader: R) -> Self {
        Self::with_counters(reader, Arc::new(SkewCounters::default()))
    }

    /// A stream that adds to `counters`, shared with the other connections.
    pub fn with_counters(reader: R, counters: Arc<SkewCounters>) -> Self {
        Self {
            lines: reader.lines(),
            counters,
        }
    }

    /// A handle on the skip counters.
    #[cfg(test)]
    #[must_use]
    pub fn counters(&self) -> Arc<SkewCounters> {
        Arc::clone(&self.counters)
    }

    /// Counts one skipped record, warning when the total for its cause reaches a power of two:
    /// one connection can last the whole run, so a version-skewed extension must show while it
    /// lives, not only when the connection ends (no health beacon on macOS yet, #34).
    fn count_skip(&self, cause: &AtomicU64, what: &'static str) {
        let total = cause.fetch_add(1, Ordering::Relaxed) + 1;
        if total.is_power_of_two() {
            tracing::warn!(
                total,
                "network-extension receiver: record skipped ({what}); extension version skew?"
            );
        }
    }
}

impl<R: BufRead> Iterator for NormalizedNeStream<R> {
    type Item = Result<schema::Event, NetworkExtensionError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let line = match self.lines.next()? {
                Ok(line) => line,
                Err(e) => return Some(Err(NetworkExtensionError::Io(e))),
            };
            if line.trim().is_empty() {
                continue;
            }
            let record: NeRecord = match serde_json::from_str(&line) {
                Ok(record) => record,
                Err(_) => {
                    // A record kind or field shape this build doesn't know —
                    // a newer extension. Skip the line, never the stream.
                    self.count_skip(&self.counters.unparseable, "unparseable");
                    continue;
                }
            };
            if record.version() != WIRE_VERSION {
                self.count_skip(&self.counters.unknown_version, "unknown wire version");
                continue;
            }
            let Some(event) = normalize(&record) else {
                self.count_skip(&self.counters.unmapped, "no schema event");
                continue;
            };
            return Some(Ok(event));
        }
    }
}

#[cfg(unix)]
pub mod socket {
    //! The real Unix-domain socket. `cfg(unix)` rather than macOS-only so the
    //! accept path is exercised by tests on any development host — macOS is
    //! where a real extension ever connects.

    use std::{
        os::unix::net::{UnixListener, UnixStream},
        path::Path,
    };

    use crate::NetworkExtensionError;

    /// Binds the listening socket, replacing a stale one from a previous
    /// agent run (the agent is the only legitimate owner of this path).
    ///
    /// # Errors
    ///
    /// [`NetworkExtensionError::Io`] when the path can't be bound (parent
    /// directory missing, permissions).
    pub fn listen(path: &Path) -> Result<UnixListener, NetworkExtensionError> {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(UnixListener::bind(path)?)
    }

    /// Accepts extension connections forever, handing each to `on_connection`
    /// (the extension reconnects when the OS restarts it, so accept must
    /// loop). Returns only on a listener-level error.
    ///
    /// # Errors
    ///
    /// [`NetworkExtensionError::Io`] when `accept` itself fails.
    pub fn accept_loop(
        listener: &UnixListener,
        mut on_connection: impl FnMut(UnixStream),
    ) -> Result<(), NetworkExtensionError> {
        loop {
            let (stream, _addr) = listener.accept()?;
            on_connection(stream);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn yields_events_and_counts_each_kind_of_skew_apart() {
        let input = [
            // A record kind from a hypothetical newer extension.
            r#"{"kind":"flow_v9_shiny","v":9}"#,
            // Known kind, future version — skipped, counted.
            r#"{"kind":"flow","v":99,"ts_ns":1,"pid":1,"direction":"outbound","remote_addr":"203.0.113.7","remote_port":443,"protocol":6}"#,
            // Good record.
            r#"{"kind":"flow","v":1,"ts_ns":1,"pid":4242,"process_path":"/usr/bin/curl","direction":"outbound","remote_addr":"203.0.113.7","remote_port":443,"local_port":52344,"protocol":6}"#,
        ]
        .join("\n");
        let mut stream = NormalizedNeStream::new(Cursor::new(input));
        let event = stream.next().unwrap().unwrap();
        assert!(matches!(event, schema::Event::Connect(_)));
        assert!(stream.next().is_none());
        assert_eq!(
            stream.counters().totals(),
            SkewTotals {
                unparseable: 1,
                unknown_version: 1,
                unmapped: 0,
            }
        );
    }

    #[test]
    fn a_record_with_no_schema_event_counts_as_unmapped() {
        // A hostname parses but maps to no event: a literal-IP remote is required.
        let mut stream = NormalizedNeStream::new(Cursor::new(UNMAPPED));
        assert!(stream.next().is_none());
        assert_eq!(
            stream.counters().totals(),
            SkewTotals {
                unparseable: 0,
                unknown_version: 0,
                unmapped: 1,
            }
        );
    }

    const UNMAPPED: &str = r#"{"kind":"flow","v":1,"ts_ns":1,"pid":4242,"direction":"outbound","remote_addr":"not-an-ip.example","remote_port":443,"protocol":6}"#;

    #[test]
    fn connections_share_one_set_of_counters() {
        let shared = Arc::new(SkewCounters::default());
        for _ in 0..2 {
            let mut stream =
                NormalizedNeStream::with_counters(Cursor::new(UNMAPPED), Arc::clone(&shared));
            assert!(stream.next().is_none());
        }
        assert_eq!(
            shared.totals().unmapped,
            2,
            "one per connection, same handle"
        );
        assert_eq!(shared.totals().unparseable, 0);
    }

    #[test]
    fn totals_since_an_earlier_reading_count_only_what_came_after() {
        let shared = Arc::new(SkewCounters::default());
        let mut first =
            NormalizedNeStream::with_counters(Cursor::new(UNMAPPED), Arc::clone(&shared));
        assert!(first.next().is_none());
        let before = shared.totals();
        let mut second =
            NormalizedNeStream::with_counters(Cursor::new(UNMAPPED), Arc::clone(&shared));
        assert!(second.next().is_none());
        assert_eq!(
            shared.totals().since(&before).unmapped,
            1,
            "only the second connection's record"
        );
    }

    #[test]
    fn since_never_underflows() {
        let later = SkewTotals {
            unmapped: 3,
            ..SkewTotals::default()
        };
        assert!(SkewTotals::default().since(&later).is_clean());
    }

    #[cfg(unix)]
    #[test]
    fn socket_round_trip_from_a_fake_extension() {
        use std::io::{BufReader, Write};

        let dir = std::env::temp_dir().join(format!("synthaea-ne-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ne.sock");

        let listener = socket::listen(&path).expect("bind");
        // Rebinding over a stale socket must work (agent restart case).
        drop(listener);
        let listener = socket::listen(&path).expect("rebind over stale socket");

        let writer_path = path.clone();
        let writer = std::thread::spawn(move || {
            let mut conn = std::os::unix::net::UnixStream::connect(&writer_path).unwrap();
            writeln!(
                conn,
                r#"{{"kind":"dns","v":1,"ts_ns":7,"pid":1,"query":"beacon.example.test","qtype":1,"result":"203.0.113.7;","rcode":0}}"#
            )
            .unwrap();
        });

        let (conn, _) = listener.accept().unwrap();
        let mut stream = NormalizedNeStream::new(BufReader::new(conn));
        let event = stream.next().unwrap().unwrap();
        assert!(
            matches!(event, schema::Event::DnsQuery(ref d) if d.query == "beacon.example.test")
        );
        writer.join().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }
}
