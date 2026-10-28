//! A liveness canary for the journal tail (#71, #83).
//!
//! The tail has nothing to pulse its sensor heartbeat on when the host is idle: an
//! idle machine writes nothing for minutes, so the sensor read as silent and the
//! host as `degraded` although nothing was wrong. The agent therefore writes one
//! line of its own into journald at a fixed interval and the tail pulses on every
//! line it reads (see [`crate::ClassifiedJournal::with_line_hook`]), the canary
//! included.
//!
//! That makes the pulse an end-to-end proof, not a process check: the line has to
//! be accepted by journald, stored, and delivered back through `journalctl -f` to
//! the agent. If journald is stopped the write fails, if `journalctl` is stuck
//! nothing arrives, and in both cases the heartbeat stops and the sensor goes
//! silent at its deadline, as before.
//!
//! The line is written over journald's native datagram socket (the plain
//! `FIELD=value\n` form of the native protocol) so there is no `libsystemd`
//! dependency, the same reason `crate::tail` runs `journalctl` as a subprocess. It
//! carries its own `SYSLOG_IDENTIFIER`, which the allowlist in `crate::classify`
//! does not match: the canary is never an event, it only proves delivery.

/// `SYSLOG_IDENTIFIER` of the canary line, so an operator can find (and filter) it
/// with `journalctl -t synthaea-agent-canary`.
pub const CANARY_IDENTIFIER: &str = "synthaea-agent-canary";

/// Journald's native-protocol datagram socket.
#[cfg(target_os = "linux")]
pub const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";

/// The datagram for one canary line, in journald's native protocol: `FIELD=value`
/// lines, each ended by `\n`. Priority 7 (debug) keeps it out of anything that
/// filters on severity, and it carries no host data.
#[must_use]
pub fn canary_payload() -> Vec<u8> {
    format!("SYSLOG_IDENTIFIER={CANARY_IDENTIFIER}\nPRIORITY=7\nMESSAGE=sensor liveness canary\n")
        .into_bytes()
}

/// Writes one canary line to the journald socket at `socket`.
///
/// # Errors
///
/// Any I/O error from creating the socket or sending the datagram. A stopped
/// journald (no socket, or nobody reading it) is the case this exists to notice.
#[cfg(target_os = "linux")]
pub fn send_canary(socket: &std::path::Path) -> std::io::Result<()> {
    let sock = std::os::unix::net::UnixDatagram::unbound()?;
    sock.send_to(&canary_payload(), socket)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_payload_is_native_protocol_fields_each_ended_by_a_newline() {
        let payload = String::from_utf8(canary_payload()).expect("utf-8");
        assert!(payload.ends_with('\n'));
        assert!(
            !payload.contains("\n\n"),
            "a blank line would end the entry early"
        );
        let fields: Vec<&str> = payload.lines().collect();
        assert!(fields.contains(&"SYSLOG_IDENTIFIER=synthaea-agent-canary"));
        assert!(fields.contains(&"PRIORITY=7"));
        assert!(fields.iter().any(|f| f.starts_with("MESSAGE=")));
        for field in fields {
            assert!(
                field.split_once('=').is_some_and(|(k, _)| !k.is_empty()),
                "{field:?} is not FIELD=value"
            );
        }
    }

    #[test]
    fn the_canary_is_not_an_allowlisted_record() {
        // One line of `journalctl -o json` as the canary comes back through the tail.
        let line = format!(
            r#"{{"__CURSOR":"c","__REALTIME_TIMESTAMP":"1","SYSLOG_IDENTIFIER":"{CANARY_IDENTIFIER}","MESSAGE":"sensor liveness canary"}}"#
        );
        let record = crate::parse_record(&line).expect("parses");
        assert!(crate::classify(&record).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn send_canary_delivers_the_payload_to_the_socket() {
        use std::os::unix::net::UnixDatagram;

        let path = std::env::temp_dir().join(format!("canary-test-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let server = UnixDatagram::bind(&path).expect("bind");
        server
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("timeout");

        send_canary(&path).expect("send");

        let mut buf = [0u8; 512];
        let n = server.recv(&mut buf).expect("recv");
        assert_eq!(&buf[..n], canary_payload().as_slice());
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn send_canary_fails_when_journald_is_not_there() {
        let missing = std::env::temp_dir().join(format!("no-journald-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&missing);
        assert!(send_canary(&missing).is_err());
    }
}
