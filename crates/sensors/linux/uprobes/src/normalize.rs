//! Wire → schema normalization for uprobes events. Converts fixed-size `repr(C)`
//! wire structs from the eBPF ring buffers into the normalized `schema::Event` types.
//!
//! `boot_epoch_offset_ns` is the difference between the epoch clock and the monotonic
//! clock the probes stamp events with (`bpf_ktime_get_ns`); the sensor computes it
//! once at startup and passes it here so schema timestamps are epoch nanoseconds.
//!
//! **Security (Phase 9):** Sensitive data (passwords, tokens, credentials) is redacted
//! before event emission. See `crate::redact` for patterns and implementation.

use schema::{
    ContainerContext, Event, EventMeta, ReadlineInputEvent, ShellType, TlsCaptureEvent,
    TlsDirection, TlsLibraryType, User,
};
use sensor_linux_wire as wire;

use crate::redact;

/// Tripwire: bumping the wire ABI must come here to revisit the mappings below.
///
/// v6 (#262) added `FileWriteEvent`/`FileDeleteEvent`/`FileRenameEvent` — neither
/// imported here, and neither `TlsCaptureEvent` nor `ReadlineInputEvent` (the only
/// wire structs this module maps) changed shape, so the mappings below still hold.
///
/// v7 (#263) added `SocketBindEvent` — not imported here either, same reasoning.
const _: () = assert!(wire::WIRE_VERSION == 7);

/// Decodes a fixed comm buffer: NUL-terminated, kernel-truncated to 15 bytes — a
/// sensor property (reported by conformance), not a schema limit.
fn comm_str(comm: &[u8; wire::TASK_COMM_LEN]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

/// `container_id` is resolved by the caller from `/proc/<pid>/cgroup` at drain time
/// (issue #80) — attribution only for now, `image`/`name` await a follow-up
/// Docker/containerd socket lookup.
fn meta(
    meta: &wire::EventMeta,
    boot_epoch_offset_ns: u64,
    container_id: Option<String>,
) -> EventMeta {
    EventMeta {
        pid: meta.pid,
        ppid: meta.ppid,
        user: User::Unix {
            uid: meta.uid,
            gid: meta.gid,
        },
        timestamp_ns: meta.timestamp_ns.saturating_add(boot_epoch_offset_ns),
        comm: comm_str(&meta.comm),
        container: container_id.map(|id| ContainerContext {
            id,
            image: None,
            name: None,
        }),
    }
}

/// Normalizes a TLS capture wire event into the schema event type.
///
/// The wire format captures the first `MAX_TLS_CAPTURE` bytes of plaintext;
/// this function copies that into a Vec<u8> for the schema. Binary data is
/// preserved exactly (not treated as UTF-8).
///
/// **Security (Phase 9):** Sensitive data (Authorization headers, cookies, credentials
/// in URLs, API keys) is redacted before emission. See `crate::redact::redact_tls_data`.
#[must_use]
pub fn tls_capture(
    event: &wire::TlsCaptureEvent,
    boot_epoch_offset_ns: u64,
    container_id: Option<String>,
) -> Event {
    let direction = match event.direction {
        0 => TlsDirection::Read,
        1 => TlsDirection::Write,
        _ => TlsDirection::Read, // Defensive fallback
    };

    let lib_type = match event.lib_type {
        0 => TlsLibraryType::OpenSsl,
        1 => TlsLibraryType::BoringSsl,
        2 => TlsLibraryType::GnuTls,
        _ => TlsLibraryType::OpenSsl, // Defensive fallback
    };

    let data_len = (event.bytes_len as usize).min(wire::MAX_TLS_CAPTURE);
    let data = event.data[..data_len].to_vec();

    // Redact sensitive data (Authorization, Cookie, credentials in URLs, API keys)
    let data = redact::redact_tls_data(data);

    Event::TlsCapture(TlsCaptureEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container_id),
        direction,
        lib_type,
        data,
    })
}

/// Normalizes a readline input wire event into the schema event type.
///
/// The wire format captures up to `MAX_READLINE_INPUT` bytes of the command line;
/// this function converts it to a UTF-8 String (lossy conversion for invalid UTF-8).
///
/// **Security (Phase 9):** Sensitive data (export statements with secrets, --password
/// flags, AWS credentials, curl -u auth) is redacted before emission. See
/// `crate::redact::redact_readline_input`.
#[must_use]
pub fn readline_input(
    event: &wire::ReadlineInputEvent,
    boot_epoch_offset_ns: u64,
    container_id: Option<String>,
) -> Event {
    let shell_type = match event.shell_type {
        0 => ShellType::Bash,
        1 => ShellType::Zsh,
        _ => ShellType::Bash, // Defensive fallback
    };

    let input_len = (event.input_len as usize).min(wire::MAX_READLINE_INPUT);
    let input = String::from_utf8_lossy(&event.input[..input_len]).into_owned();

    // Redact sensitive data (passwords, export statements, AWS credentials, curl -u)
    let input = redact::redact_readline_input(input);

    Event::ReadlineInput(ReadlineInputEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container_id),
        shell_type,
        input,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire_meta(comm: &[u8]) -> wire::EventMeta {
        let mut c = [0u8; wire::TASK_COMM_LEN];
        c[..comm.len()].copy_from_slice(comm);
        wire::EventMeta {
            pid: 42,
            ppid: 7,
            uid: 1000,
            gid: 1000,
            cgroup_id: 0,
            timestamp_ns: 1_000,
            comm: c,
        }
    }

    #[test]
    fn tls_capture_normalizes_read_direction() {
        let mut event = wire::TlsCaptureEvent {
            meta: wire_meta(b"curl"),
            direction: 0,
            lib_type: 0,
            bytes_len: 16,
            data: [0; wire::MAX_TLS_CAPTURE],
        };
        event.data[..16].copy_from_slice(b"GET / HTTP/1.1\r\n");

        let Event::TlsCapture(e) = tls_capture(&event, 500, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.direction, TlsDirection::Read);
        assert_eq!(e.lib_type, TlsLibraryType::OpenSsl);
        assert_eq!(e.data, b"GET / HTTP/1.1\r\n");
        assert_eq!(e.meta.pid, 42);
        assert_eq!(e.meta.timestamp_ns, 1_500, "boot offset applied");
    }

    #[test]
    fn tls_capture_normalizes_write_direction() {
        let mut event = wire::TlsCaptureEvent {
            meta: wire_meta(b"nginx"),
            direction: 1,
            lib_type: 0,
            bytes_len: 8,
            data: [0; wire::MAX_TLS_CAPTURE],
        };
        event.data[..8].copy_from_slice(b"200 OK\r\n");

        let Event::TlsCapture(e) = tls_capture(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.direction, TlsDirection::Write);
        assert_eq!(e.data, b"200 OK\r\n");
    }

    #[test]
    fn tls_capture_handles_boringssl() {
        let event = wire::TlsCaptureEvent {
            meta: wire_meta(b"chrome"),
            direction: 0,
            lib_type: 1,
            bytes_len: 0,
            data: [0; wire::MAX_TLS_CAPTURE],
        };

        let Event::TlsCapture(e) = tls_capture(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.lib_type, TlsLibraryType::BoringSsl);
    }

    #[test]
    fn tls_capture_handles_gnutls() {
        let event = wire::TlsCaptureEvent {
            meta: wire_meta(b"gnutls-cli"),
            direction: 1,
            lib_type: 2,
            bytes_len: 0,
            data: [0; wire::MAX_TLS_CAPTURE],
        };

        let Event::TlsCapture(e) = tls_capture(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.lib_type, TlsLibraryType::GnuTls);
    }

    #[test]
    fn tls_capture_preserves_binary_data() {
        let mut event = wire::TlsCaptureEvent {
            meta: wire_meta(b"app"),
            direction: 0,
            lib_type: 0,
            bytes_len: 4,
            data: [0; wire::MAX_TLS_CAPTURE],
        };
        event.data[..4].copy_from_slice(&[0xff, 0xfe, 0xfd, 0x00]);

        let Event::TlsCapture(e) = tls_capture(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.data, &[0xff, 0xfe, 0xfd, 0x00]);
    }

    #[test]
    fn tls_capture_truncates_at_max_len() {
        let event = wire::TlsCaptureEvent {
            meta: wire_meta(b"app"),
            direction: 0,
            lib_type: 0,
            bytes_len: wire::MAX_TLS_CAPTURE as u32 + 100, // Exceeds max
            data: [0x42; wire::MAX_TLS_CAPTURE],
        };

        let Event::TlsCapture(e) = tls_capture(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.data.len(), wire::MAX_TLS_CAPTURE);
    }

    #[test]
    fn readline_normalizes_bash_input() {
        let mut event = wire::ReadlineInputEvent {
            meta: wire_meta(b"bash"),
            shell_type: 0,
            input_len: 12,
            input: [0; wire::MAX_READLINE_INPUT],
        };
        event.input[..12].copy_from_slice(b"ls -la /tmp\n");

        let Event::ReadlineInput(e) = readline_input(&event, 500, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.shell_type, ShellType::Bash);
        assert_eq!(e.input, "ls -la /tmp\n");
        assert_eq!(e.meta.pid, 42);
        assert_eq!(e.meta.timestamp_ns, 1_500, "boot offset applied");
    }

    #[test]
    fn readline_normalizes_zsh_input() {
        let mut event = wire::ReadlineInputEvent {
            meta: wire_meta(b"zsh"),
            shell_type: 1,
            input_len: 11,
            input: [0; wire::MAX_READLINE_INPUT],
        };
        event.input[..11].copy_from_slice(b"export FOO=");

        let Event::ReadlineInput(e) = readline_input(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.shell_type, ShellType::Zsh);
        assert_eq!(e.input, "export FOO=");
    }

    #[test]
    fn readline_handles_invalid_utf8_lossy() {
        let mut event = wire::ReadlineInputEvent {
            meta: wire_meta(b"bash"),
            shell_type: 0,
            input_len: 5,
            input: [0; wire::MAX_READLINE_INPUT],
        };
        event.input[..5].copy_from_slice(&[b'l', b's', 0xff, 0xfe, b'x']);

        let Event::ReadlineInput(e) = readline_input(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert!(e.input.contains('\u{fffd}'), "{:?}", e.input);
    }

    #[test]
    fn readline_truncates_at_max_len() {
        let event = wire::ReadlineInputEvent {
            meta: wire_meta(b"bash"),
            shell_type: 0,
            input_len: wire::MAX_READLINE_INPUT as u32 + 100, // Exceeds max
            input: [b'x'; wire::MAX_READLINE_INPUT],
        };

        let Event::ReadlineInput(e) = readline_input(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.input.len(), wire::MAX_READLINE_INPUT);
    }

    #[test]
    fn tls_capture_carries_container_id() {
        let event = wire::TlsCaptureEvent {
            meta: wire_meta(b"nginx"),
            direction: 0,
            lib_type: 0,
            bytes_len: 0,
            data: [0; wire::MAX_TLS_CAPTURE],
        };
        let id = "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456".to_string();

        let Event::TlsCapture(e) = tls_capture(&event, 0, Some(id.clone())) else {
            panic!("wrong variant")
        };
        let container = e.meta.container.expect("container attributed");
        assert_eq!(container.id, id);
        assert_eq!(container.image, None, "awaits the socket-lookup follow-up");
    }

    #[test]
    fn readline_carries_container_id() {
        let event = wire::ReadlineInputEvent {
            meta: wire_meta(b"bash"),
            shell_type: 0,
            input_len: 0,
            input: [0; wire::MAX_READLINE_INPUT],
        };
        let id = "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456".to_string();

        let Event::ReadlineInput(e) = readline_input(&event, 0, Some(id.clone())) else {
            panic!("wrong variant")
        };
        let container = e.meta.container.expect("container attributed");
        assert_eq!(container.id, id);
    }
}
