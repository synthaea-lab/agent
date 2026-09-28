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
    ContainerContext, DnsQueryEvent, Event, EventMeta, ReadlineInputEvent, ShellType,
    TlsCaptureEvent, TlsDirection, TlsLibraryType, User,
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
///
/// v8 (#262 Phase 2) added `FileChmodEvent`/`FileChownEvent` — not imported here
/// either, same reasoning.
///
/// v9 (#263 Phase 2) added `UdpSendEvent` — not imported here either, same reasoning.
///
/// v10 (#263 Phase 2) added `SocketListenEvent` — not imported here either, same
/// reasoning.
///
/// v11 (#263 Phase 2) added `SocketAcceptEvent` — not imported here either, same
/// reasoning.
///
/// v12 (#262 Phase 3) added `FileSetxattrEvent`/`FileRemovexattrEvent` — not
/// imported here either, same reasoning.
///
/// v13 (#362 and #264, originally claimed as v12 — see that constant's doc) added
/// `MountEvent`/`SignalEvent` and `KernelModuleEvent`/`BpfEvent` — not imported
/// here either, same reasoning.
///
/// v14 (#265, originally claimed as v12 — see that constant's doc) added
/// `PtraceEvent`/`ProcessVmReadEvent`/`ProcessVmWriteEvent`/`MemfdCreateEvent`
/// — not imported here either, same reasoning.
///
/// v15 (#266, originally claimed as v12 — see that constant's doc) added
/// `IdentityChangeEvent`/`CapSetEvent`/`NamespaceEvent` — not imported here
/// either, same reasoning.
///
/// v16 (#267 Phase 1, originally claimed as v12 — see that constant's doc)
/// added `GetAddrInfoEvent` — new `dns_query` mapping function below, reusing
/// the platform-neutral `schema::DnsQueryEvent` already shared with the
/// Windows DNS-Client ETW producer.
///
/// v17 (#457) widened `CapSetEvent`'s capability sets to `u64` — not imported
/// here, same reasoning as v15.
const _: () = assert!(wire::WIRE_VERSION == 17);

/// `container` is resolved by the caller (`crate::container::container_context`,
/// issue #312) from `EventMeta::cgroup_id` against cgroupfs, with image/name filled
/// in once the background Docker socket lookup for that container id completes —
/// same fidelity as the main sensor's events.
fn meta(
    meta: &wire::EventMeta,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> EventMeta {
    EventMeta {
        pid: meta.pid,
        ppid: meta.ppid,
        user: User::Unix {
            uid: meta.uid,
            gid: meta.gid,
        },
        timestamp_ns: meta.timestamp_ns.saturating_add(boot_epoch_offset_ns),
        comm: wire::comm_str(&meta.comm),
        container,
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
    container: Option<ContainerContext>,
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
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
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
    container: Option<ContainerContext>,
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
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        shell_type,
        input,
    })
}

/// Normalizes a `getaddrinfo(3)` wire event into the schema event type,
/// reusing `schema::DnsQueryEvent` (issue #267 Phase 1, platform-neutral,
/// already shared with the Windows DNS-Client ETW producer).
///
/// `qtype` reflects the *first resolved answer's* address family (1 = A,
/// 28 = AAAA) — `getaddrinfo` can be called with `AF_UNSPEC`, so what the
/// caller actually requested isn't visible at this probe's information
/// level; on a failed lookup (no address resolved) it defaults to `1` as a
/// neutral placeholder, not a claim about the real request. `status` is
/// `0` on success or the absolute value of the negative `EAI_*` return code
/// on failure (e.g. `EAI_NONAME` = -2 becomes `2`) — the raw two's-complement
/// bit pattern of a small negative `i32` cast straight to `u32` would be a
/// number in the billions, unreadable to a human or a detection rule.
///
/// **Security:** the query name is redacted for sensitive TLDs before
/// emission — see `crate::redact::redact_dns_query`.
#[must_use]
pub fn dns_query(
    event: &wire::GetAddrInfoEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let raw = &event.query[..(event.query_len as usize).min(wire::MAX_DNS_QUERY_LEN)];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let query = redact::redact_dns_query(String::from_utf8_lossy(&raw[..end]).into_owned());

    let (qtype, result) = if event.addr_resolved {
        let addr = if event.is_ipv6 {
            std::net::IpAddr::V6(event.addr_v6.into())
        } else {
            std::net::IpAddr::V4(event.addr_v4.into())
        };
        (if event.is_ipv6 { 28 } else { 1 }, Some(addr.to_string()))
    } else {
        (1, None)
    };

    Event::DnsQuery(DnsQueryEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        query,
        qtype,
        result,
        status: if event.status == 0 {
            0
        } else {
            event.status.unsigned_abs()
        },
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

    /// A full [`ContainerContext`] — id, image, and name — the shape
    /// `crate::container::container_context` produces once its background Docker
    /// lookup has completed (issue #312: same fidelity as the main sensor's events,
    /// not just the id).
    fn full_container_context() -> ContainerContext {
        ContainerContext {
            id: "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456".to_string(),
            image: Some("nginx:1.27".to_string()),
            name: Some("web1".to_string()),
        }
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
        let ctx = full_container_context();

        let Event::TlsCapture(e) = tls_capture(&event, 0, Some(ctx.clone())) else {
            panic!("wrong variant")
        };
        assert_eq!(e.meta.container, Some(ctx));
    }

    #[test]
    fn readline_carries_container_id() {
        let event = wire::ReadlineInputEvent {
            meta: wire_meta(b"bash"),
            shell_type: 0,
            input_len: 0,
            input: [0; wire::MAX_READLINE_INPUT],
        };
        let ctx = full_container_context();

        let Event::ReadlineInput(e) = readline_input(&event, 0, Some(ctx.clone())) else {
            panic!("wrong variant")
        };
        assert_eq!(e.meta.container, Some(ctx));
    }

    fn wire_dns(query: &[u8]) -> wire::GetAddrInfoEvent {
        let mut query_buf = [0u8; wire::MAX_DNS_QUERY_LEN];
        query_buf[..query.len()].copy_from_slice(query);
        wire::GetAddrInfoEvent {
            meta: wire_meta(b"curl"),
            query: query_buf,
            query_len: query.len() as u16,
            status: 0,
            addr_resolved: false,
            is_ipv6: false,
            addr_v4: [0; 4],
            addr_v6: [0; 16],
        }
    }

    #[test]
    fn dns_query_resolved_ipv4_carries_the_address() {
        let mut event = wire_dns(b"example.com");
        event.addr_resolved = true;
        event.addr_v4 = [93, 184, 216, 34];

        let Event::DnsQuery(e) = dns_query(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.query, "example.com");
        assert_eq!(e.qtype, 1);
        assert_eq!(e.result.as_deref(), Some("93.184.216.34"));
        assert_eq!(e.status, 0);
    }

    #[test]
    fn dns_query_resolved_ipv6_sets_qtype_aaaa() {
        let mut event = wire_dns(b"example.com");
        event.addr_resolved = true;
        event.is_ipv6 = true;
        event.addr_v6 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        let Event::DnsQuery(e) = dns_query(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.qtype, 28);
        assert_eq!(e.result.as_deref(), Some("::1"));
    }

    #[test]
    fn dns_query_failure_has_no_result_and_a_readable_status() {
        let mut event = wire_dns(b"nonexistent.invalid");
        event.status = -2; // EAI_NONAME

        let Event::DnsQuery(e) = dns_query(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.result, None);
        assert_eq!(e.status, 2, "readable, not the wrapped u32 of -2");
    }

    #[test]
    fn dns_query_redacts_internal_tlds() {
        let event = wire_dns(b"db01.internal");
        let Event::DnsQuery(e) = dns_query(&event, 0, None) else {
            panic!("wrong variant")
        };
        assert_eq!(e.query, "[REDACTED].internal");
    }
}
