//! The agent side of the extension↔agent seam: a Unix-domain socket the
//! Swift system extension connects to and writes NDJSON [`crate::wire`]
//! records into.
//!
//! **Why the agent listens and the extension connects** (not the reverse):
//! the agent daemon owns its runtime directory and lifetime; the extension is
//! started/stopped by the OS on network activity and must be the reconnecting
//! side. The socket lives in the app-group container both parties share —
//! a network-extension sandbox allows connecting inside its own app group,
//! not to arbitrary filesystem paths (see `packaging/macos`).
//!
//! Same iterator shape as the crate's siblings: [`NormalizedNeStream`] is
//! generic over [`BufRead`] so tests feed canned captures, and
//! `socket::listen`/`socket::accept_loop` produce real connections on Unix
//! hosts.

use std::io::BufRead;

use crate::{
    NetworkExtensionError, normalize,
    wire::{NeRecord, WIRE_VERSION},
};

/// Reads normalized schema events out of any line-oriented wire-record
/// source (one accepted extension connection).
pub struct NormalizedNeStream<R> {
    lines: std::io::Lines<R>,
    /// Records skipped for an unknown wire version or unparseable line —
    /// version skew between a deployed extension and this agent, counted
    /// rather than silently dropped.
    pub skew_skipped: u64,
}

impl<R: BufRead> NormalizedNeStream<R> {
    pub fn new(reader: R) -> Self {
        Self {
            lines: reader.lines(),
            skew_skipped: 0,
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
                    self.skew_skipped += 1;
                    continue;
                }
            };
            if record.version() != WIRE_VERSION {
                self.skew_skipped += 1;
                continue;
            }
            let Some(event) = normalize(&record) else {
                self.skew_skipped += 1;
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
    fn yields_events_and_counts_skew() {
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
        assert_eq!(stream.skew_skipped, 2);
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
