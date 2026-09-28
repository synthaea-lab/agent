//! Classifies `AuditRecord` into semantic event types.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::parse::AuditRecord;

#[derive(Debug)]
pub enum AuditEvent {
    Exec {
        pid: u32,
        uid: u32,
        gid: u32,
        image_path: String,
        argv: Vec<String>,
    },
    Connect {
        pid: u32,
        uid: u32,
        gid: u32,
        remote_addr: SocketAddr,
        protocol: u8,
    },
    /// A `SELinux` AVC record (`type=AVC`) — arrives at this sensor's socket for free
    /// (it already subscribes to the whole `NETLINK_AUDIT` multicast stream, see
    /// `socket.rs`) but was previously dropped by `classify`'s `_ => None` arm.
    ///
    /// No `pid` field: the kernel's AVC message body is `avc:  denied  { read } for
    /// pid=1234 comm="httpd" ...` — text, not `key=value`, before the first real
    /// field — so the shared `parse_fields`'s byte scan (which has no concept of
    /// this preamble) folds that whole prefix into what should have been just
    /// `pid`'s key, corrupting it. Every field *after* the first one parses with a
    /// clean key (confirmed by tracing the byte scan by hand against a real AVC
    /// line), so this variant only carries what survives intact. Not worth a
    /// preamble-skipping special case in the shared parser for one record type
    /// this sensor treats as supplementary in the first place.
    ///
    /// Always a denial: `SELinux` policies that `auditallow` (log a *grant*) are rare
    /// in practice, and the "denied"/"granted" word itself lives inside the same
    /// corrupted first field as `pid` — not worth recovering for a case this
    /// unlikely. A misclassified grant-as-denial would be a very rare false
    /// positive, not a false negative.
    PolicyDenial {
        comm: Option<String>,
        scontext: Option<String>,
        tcontext: Option<String>,
        tclass: Option<String>,
        permissive: bool,
        /// The object's path, from `path=` (rare, only when the kernel
        /// resolved a full path) or `name=` (the common case — often just a
        /// filename, since this is the AVC line alone, no `type=PATH`
        /// sibling record correlation, matching the rest of this variant's
        /// "supplementary" scope, see above). `None` for non-file `tclass`
        /// denials (`process`, `capability`, `tcp_socket`, ...), which carry
        /// neither field.
        object_path: Option<String>,
    },
}

const AUDIT_EXECVE: u32 = 1309;
const AUDIT_SOCKADDR: u32 = 1306;
const AUDIT_AVC: u32 = 1400;

/// Maps `AuditRecord` to `AuditEvent`, or None if not interesting.
#[must_use]
pub fn classify(record: &AuditRecord) -> Option<AuditEvent> {
    match record.record_type {
        AUDIT_EXECVE => classify_exec(record),
        AUDIT_SOCKADDR => classify_connect(record),
        AUDIT_AVC => classify_avc(record),
        _ => None,
    }
}

fn classify_exec(record: &AuditRecord) -> Option<AuditEvent> {
    // Extract argc to know how many arguments to collect
    let argc: usize = record.fields.get("argc")?.parse().ok()?;

    // Reconstruct argv (auditd uses a0, a1, a2, ...)
    let mut argv = Vec::new();
    for i in 0..argc {
        let key = format!("a{i}");
        argv.push(decoded_field(record, &key)?);
    }

    // First argument is the image path
    let image_path = argv.first()?.clone();

    // Extract process metadata (may not always be present)
    let pid: u32 = record
        .fields
        .get("pid")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let uid: u32 = record
        .fields
        .get("uid")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let gid: u32 = record
        .fields
        .get("gid")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    Some(AuditEvent::Exec {
        pid,
        uid,
        gid,
        image_path,
        argv,
    })
}

fn classify_connect(record: &AuditRecord) -> Option<AuditEvent> {
    // Extract saddr field (sockaddr_in/in6 struct as hex)
    let saddr_hex = record.fields.get("saddr")?;

    // Parse sockaddr structure
    let remote_addr = parse_sockaddr(saddr_hex)?;

    // Extract process metadata
    let pid: u32 = record
        .fields
        .get("pid")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let uid: u32 = record
        .fields
        .get("uid")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let gid: u32 = record
        .fields
        .get("gid")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Protocol is embedded in sockaddr, default to TCP
    let protocol = 6; // IPPROTO_TCP

    Some(AuditEvent::Connect {
        pid,
        uid,
        gid,
        remote_addr,
        protocol,
    })
}

fn classify_avc(record: &AuditRecord) -> Option<AuditEvent> {
    // scontext/tclass are the two fields that actually matter for triage (who,
    // acting-as-what, tried to do what) — require at least one of them present so
    // an unrecognized/short AVC variant doesn't produce an all-`None` event.
    let scontext = record.fields.get("scontext").cloned();
    let tclass = record.fields.get("tclass").cloned();
    if scontext.is_none() && tclass.is_none() {
        return None;
    }

    Some(AuditEvent::PolicyDenial {
        comm: record.fields.get("comm").cloned(),
        scontext,
        tcontext: record.fields.get("tcontext").cloned(),
        tclass,
        permissive: record.fields.get("permissive").is_some_and(|v| v == "1"),
        // Same hex-decoding as argv (#297 review, Nikolas): the kernel hex-encodes
        // `path=`/`name=` too whenever the value contains a space or a quote (e.g.
        // `cp id_rsa "id rsa"` logs `name=696420727361`), so reading the field raw
        // would leak the encoded form straight into the alert instead of decoding
        // it — a free evasion.
        object_path: decoded_field(record, "path").or_else(|| decoded_field(record, "name")),
    })
}

/// Reads a field and decodes it only if the kernel actually emitted it
/// unquoted (issue #491). Quotedness on the wire is the kernel's own signal
/// for "safe to print as-is" vs. "hex-encoded because it contained a space
/// or a quote" — the one bit of information `decode_audit_value`'s
/// heuristic can't recover once a value has been stripped to a plain
/// `String` by `parse_fields`. Without this gate, a value that's quoted
/// *and* happens to look hex-shaped (a file genuinely named `6162`) gets
/// silently misdecoded (to `"ab"`) instead of passed through untouched.
fn decoded_field(record: &AuditRecord, key: &str) -> Option<String> {
    let value = record.fields.get(key)?;
    Some(if record.unquoted_fields.contains(key) {
        decode_audit_value(value)
    } else {
        value.clone()
    })
}

/// Decodes audit field values (handles hex-encoded strings). Only meaningful
/// on a field the kernel emitted unquoted — see `decoded_field`, its only
/// caller outside this module's own tests.
fn decode_audit_value(value: &str) -> String {
    // Callers only reach this for values the wire parser saw arrive unquoted
    // (see `decoded_field`), so an even-length, all-hex value here can only be
    // the kernel's own hex encoding of an untrusted string (it hex-encodes any
    // string containing a space, a quote, or a control character, regardless
    // of length — including a single byte, e.g. `a1=20` for a lone space).
    // There is no ambiguity left to guard against with a minimum length.
    if value.len().is_multiple_of(2)
        && value.chars().all(|c| c.is_ascii_hexdigit())
        && let Ok(bytes) = hex_decode(value)
        && let Ok(s) = String::from_utf8(bytes)
    {
        return s;
    }
    value.to_string()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }

    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

/// Parses sockaddr structure from hex string.
/// Format: family(2) + port(2) + address(4 or 16) + padding
fn parse_sockaddr(hex: &str) -> Option<SocketAddr> {
    let bytes = hex_decode(hex).ok()?;

    if bytes.len() < 4 {
        return None;
    }

    // First 2 bytes: address family (little-endian)
    let family = u16::from_le_bytes([bytes[0], bytes[1]]);

    match family {
        2 => {
            // AF_INET (IPv4)
            if bytes.len() < 8 {
                return None;
            }
            // Port is bytes 2-3 (big-endian for network order)
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            // IPv4 address is bytes 4-7
            let addr = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            Some(SocketAddr::new(IpAddr::V4(addr), port))
        }
        10 => {
            // AF_INET6 (IPv6)
            if bytes.len() < 28 {
                return None;
            }
            // Port is bytes 2-3 (big-endian)
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            // IPv6 address is bytes 8-23 (skip flow info at 4-7)
            let addr_bytes: [u8; 16] = bytes[8..24].try_into().ok()?;
            let addr = Ipv6Addr::from(addr_bytes);
            Some(SocketAddr::new(IpAddr::V6(addr), port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_exec_record() {
        let mut fields = std::collections::HashMap::new();
        fields.insert("argc".to_string(), "2".to_string());
        fields.insert("a0".to_string(), "/bin/ls".to_string());
        fields.insert("a1".to_string(), "-la".to_string());
        fields.insert("pid".to_string(), "1234".to_string());
        fields.insert("uid".to_string(), "1000".to_string());
        fields.insert("gid".to_string(), "1000".to_string());

        let record = AuditRecord {
            record_type: AUDIT_EXECVE,
            timestamp_sec: 0,
            timestamp_ms: 0,
            seq: 0,
            fields,
            unquoted_fields: std::collections::HashSet::new(),
        };

        let event = classify(&record).unwrap();
        match event {
            AuditEvent::Exec {
                pid,
                uid,
                gid,
                image_path,
                argv,
            } => {
                assert_eq!(pid, 1234);
                assert_eq!(uid, 1000);
                assert_eq!(gid, 1000);
                assert_eq!(image_path, "/bin/ls");
                assert_eq!(argv, vec!["/bin/ls", "-la"]);
            }
            _ => panic!("expected Exec event"),
        }
    }

    #[test]
    fn classify_exec_does_not_decode_a_quoted_hex_shaped_argv() {
        // Issue #491, argv side: a program invoked as `./cafe` (a real, valid
        // filename) is safe to quote as-is (`a0="./cafe"`... well, without the
        // leading path prefix here to isolate just the hex-shaped token). The
        // old heuristic decoded any even-length all-hex token regardless of
        // whether the kernel had quoted it, silently turning a literal
        // argument into decoded bytes.
        let mut fields = std::collections::HashMap::new();
        fields.insert("argc".to_string(), "1".to_string());
        fields.insert("a0".to_string(), "cafe".to_string());

        let record = AuditRecord {
            record_type: AUDIT_EXECVE,
            timestamp_sec: 0,
            timestamp_ms: 0,
            seq: 0,
            fields,
            // Not in the set: quoted on the wire, same as any ordinary argv.
            unquoted_fields: std::collections::HashSet::new(),
        };

        let AuditEvent::Exec { argv, .. } = classify(&record).unwrap() else {
            panic!("expected Exec event");
        };
        assert_eq!(argv, vec!["cafe"]);
    }

    #[test]
    fn classify_exec_decodes_a_genuinely_unquoted_hex_argv() {
        // The other half: when the kernel *did* hex-encode (argument contained
        // a space), decoding must still happen.
        let mut fields = std::collections::HashMap::new();
        fields.insert("argc".to_string(), "1".to_string());
        fields.insert("a0".to_string(), "2F62696E2F6C73".to_string()); // "/bin/ls"

        let record = AuditRecord {
            record_type: AUDIT_EXECVE,
            timestamp_sec: 0,
            timestamp_ms: 0,
            seq: 0,
            fields,
            unquoted_fields: std::collections::HashSet::from(["a0".to_string()]),
        };

        let AuditEvent::Exec { argv, .. } = classify(&record).unwrap() else {
            panic!("expected Exec event");
        };
        assert_eq!(argv, vec!["/bin/ls"]);
    }

    /// Runs a payload through the *real* parser (`crate::parse::parse_audit_message`),
    /// not a hand-built `AuditRecord` — so quotedness comes from the actual wire
    /// scan, not from what a test author assumed it would be.
    fn classify_wire(record_type: u32, fields_payload: &str) -> AuditEvent {
        let body = format!("msg=audit(1000.0:1): {fields_payload}");
        let total_len = (16 + body.len()) as u32;
        let mut raw = Vec::with_capacity(total_len as usize);
        raw.extend_from_slice(&total_len.to_ne_bytes());
        raw.extend_from_slice(&(record_type as u16).to_ne_bytes());
        raw.extend_from_slice(&[0u8; 10]); // flags + seq + pid, unused here
        raw.extend_from_slice(body.as_bytes());
        let record = crate::parse::parse_audit_message(&raw).unwrap();
        classify(&record).unwrap()
    }

    #[test]
    fn classify_wire_execve_mixes_quoted_and_hex_encoded_argv() {
        // Adapted from a real capture on a lab VM (Alpine 6.18.50, issue #504):
        // a1 is a literal hex-shaped filename (quoted), a2 is genuinely
        // hex-encoded (unquoted, because the real argument contained a space).
        // Before the fix, a1 would have been wrongly decoded to "id rsa".
        let event = classify_wire(
            AUDIT_EXECVE,
            r#"argc=3 a0="/bin/echo" a1="6162" a2=696420727361"#,
        );
        let AuditEvent::Exec { argv, .. } = event else {
            panic!("expected Exec event, got {event:?}");
        };
        assert_eq!(argv, vec!["/bin/echo", "6162", "id rsa"]);
    }

    #[test]
    fn classify_wire_decodes_a_single_hex_encoded_byte() {
        // Reported by Jihair on #505: the kernel hex-encodes any untrusted
        // string containing a space, a quote or a control character,
        // regardless of length. A lone space argument arrives as `a1=20`
        // (unquoted), and must still be decoded even though it's shorter
        // than the old `len() > 2` guard allowed.
        let event = classify_wire(AUDIT_EXECVE, r#"argc=2 a0="/bin/echo" a1=20"#);
        let AuditEvent::Exec { argv, .. } = event else {
            panic!("expected Exec event, got {event:?}");
        };
        assert_eq!(argv, vec!["/bin/echo", " "]);
    }

    #[test]
    fn parse_ipv4_sockaddr() {
        // Example: AF_INET (0x0002), port 8080 (0x1F90), IP 127.0.0.1 (0x7F000001)
        // In hex: 02 00 1F 90 7F 00 00 01 (+ padding)
        let hex = "02001F907F000001000000000000000000000000000000000000000000000000";
        let addr = parse_sockaddr(hex).unwrap();
        assert_eq!(addr.port(), 8080);
        match addr.ip() {
            IpAddr::V4(ip) => assert_eq!(ip, Ipv4Addr::new(127, 0, 0, 1)),
            _ => panic!("expected IPv4"),
        }
    }

    #[test]
    fn decode_hex_value() {
        let hex = "2F62696E2F6C73"; // "/bin/ls" in hex
        let decoded = decode_audit_value(hex);
        assert_eq!(decoded, "/bin/ls");
    }

    #[test]
    fn decode_plain_value() {
        let plain = "/bin/ls";
        let decoded = decode_audit_value(plain);
        assert_eq!(decoded, "/bin/ls");
    }

    #[test]
    fn classify_avc_record() {
        // Real kernel AVC wire shape: `pid=` is the first key=value token, so its
        // key comes out corrupted by the preceding non-key=value text (see
        // AuditEvent::PolicyDenial's doc) — everything after it parses cleanly.
        let mut fields = std::collections::HashMap::new();
        fields.insert(
            "avc:  denied  { read } for  pid".to_string(),
            "1234".to_string(),
        );
        fields.insert("comm".to_string(), "httpd".to_string());
        fields.insert(
            "scontext".to_string(),
            "system_u:system_r:httpd_t:s0".to_string(),
        );
        fields.insert(
            "tcontext".to_string(),
            "system_u:object_r:user_home_t:s0".to_string(),
        );
        fields.insert("tclass".to_string(), "file".to_string());
        fields.insert("permissive".to_string(), "0".to_string());
        fields.insert("name".to_string(), "id_rsa".to_string());

        let record = AuditRecord {
            record_type: AUDIT_AVC,
            timestamp_sec: 0,
            timestamp_ms: 0,
            seq: 0,
            fields,
            unquoted_fields: std::collections::HashSet::new(),
        };

        let event = classify(&record).unwrap();
        match event {
            AuditEvent::PolicyDenial {
                comm,
                scontext,
                tcontext,
                tclass,
                permissive,
                object_path,
            } => {
                assert_eq!(comm.as_deref(), Some("httpd"));
                assert_eq!(scontext.as_deref(), Some("system_u:system_r:httpd_t:s0"));
                assert_eq!(
                    tcontext.as_deref(),
                    Some("system_u:object_r:user_home_t:s0")
                );
                assert_eq!(tclass.as_deref(), Some("file"));
                assert!(!permissive);
                assert_eq!(object_path.as_deref(), Some("id_rsa"));
            }
            _ => panic!("expected PolicyDenial event"),
        }
    }

    #[test]
    fn classify_avc_prefers_path_over_name() {
        // `path=` (a fully resolved path) is rarer than `name=` (often a bare
        // filename) but more useful when present — issue #427.
        let mut fields = std::collections::HashMap::new();
        fields.insert("scontext".to_string(), "httpd_t".to_string());
        fields.insert("tclass".to_string(), "file".to_string());
        fields.insert("name".to_string(), "id_rsa".to_string());
        fields.insert("path".to_string(), "/home/alice/.ssh/id_rsa".to_string());

        let record = AuditRecord {
            record_type: AUDIT_AVC,
            timestamp_sec: 0,
            timestamp_ms: 0,
            seq: 0,
            fields,
            unquoted_fields: std::collections::HashSet::new(),
        };

        let AuditEvent::PolicyDenial { object_path, .. } = classify(&record).unwrap() else {
            panic!("expected PolicyDenial event");
        };
        assert_eq!(object_path.as_deref(), Some("/home/alice/.ssh/id_rsa"));
    }

    #[test]
    fn classify_avc_decodes_hex_encoded_name() {
        // The kernel hex-encodes name=/path= whenever the value contains a space
        // or a quote — same reason argv gets the same treatment. Undecoded, this
        // would leak "696420727361" (the hex form of "id rsa") straight into the
        // alert instead of the actual name (review on #490, Nikolas).
        let mut fields = std::collections::HashMap::new();
        fields.insert("scontext".to_string(), "httpd_t".to_string());
        fields.insert("tclass".to_string(), "file".to_string());
        fields.insert("name".to_string(), "696420727361".to_string());

        let record = AuditRecord {
            record_type: AUDIT_AVC,
            timestamp_sec: 0,
            timestamp_ms: 0,
            seq: 0,
            fields,
            // Realistic: this is exactly why the kernel emitted it unquoted.
            unquoted_fields: std::collections::HashSet::from(["name".to_string()]),
        };

        let AuditEvent::PolicyDenial { object_path, .. } = classify(&record).unwrap() else {
            panic!("expected PolicyDenial event");
        };
        assert_eq!(object_path.as_deref(), Some("id rsa"));
    }

    #[test]
    fn classify_avc_does_not_decode_a_quoted_hex_shaped_name() {
        // Issue #491: a file genuinely named "6162" is safe to print as-is, so
        // the kernel quotes it (`name="6162"`) instead of hex-encoding it. Once
        // `parse_fields` strips those quotes, the stored value is
        // indistinguishable from the unquoted hex form of "ab" by looking at the
        // string alone — the old heuristic (even length, all hex, len() > 2)
        // decoded it anyway, silently turning a real filename into "ab". The fix
        // is to only decode fields the parser itself marked unquoted.
        let mut fields = std::collections::HashMap::new();
        fields.insert("scontext".to_string(), "httpd_t".to_string());
        fields.insert("tclass".to_string(), "file".to_string());
        fields.insert("name".to_string(), "6162".to_string());

        let record = AuditRecord {
            record_type: AUDIT_AVC,
            timestamp_sec: 0,
            timestamp_ms: 0,
            seq: 0,
            fields,
            // Not in the set: this value arrived quoted on the wire.
            unquoted_fields: std::collections::HashSet::new(),
        };

        let AuditEvent::PolicyDenial { object_path, .. } = classify(&record).unwrap() else {
            panic!("expected PolicyDenial event");
        };
        assert_eq!(object_path.as_deref(), Some("6162"));
    }

    #[test]
    fn classify_avc_without_path_or_name_is_none() {
        // Non-file `tclass` denials (`process`, `capability`, ...) carry neither
        // field.
        let mut fields = std::collections::HashMap::new();
        fields.insert("scontext".to_string(), "unconfined_t".to_string());
        fields.insert("tclass".to_string(), "process".to_string());

        let record = AuditRecord {
            record_type: AUDIT_AVC,
            timestamp_sec: 0,
            timestamp_ms: 0,
            seq: 0,
            fields,
            unquoted_fields: std::collections::HashSet::new(),
        };

        let AuditEvent::PolicyDenial { object_path, .. } = classify(&record).unwrap() else {
            panic!("expected PolicyDenial event");
        };
        assert_eq!(object_path, None);
    }

    #[test]
    fn classify_avc_permissive_mode() {
        let mut fields = std::collections::HashMap::new();
        fields.insert(
            "scontext".to_string(),
            "unconfined_u:unconfined_r:unconfined_t:s0".to_string(),
        );
        fields.insert("tclass".to_string(), "process".to_string());
        fields.insert("permissive".to_string(), "1".to_string());

        let record = AuditRecord {
            record_type: AUDIT_AVC,
            timestamp_sec: 0,
            timestamp_ms: 0,
            seq: 0,
            fields,
            unquoted_fields: std::collections::HashSet::new(),
        };

        let AuditEvent::PolicyDenial { permissive, .. } = classify(&record).unwrap() else {
            panic!("expected PolicyDenial event");
        };
        assert!(permissive);
    }

    #[test]
    fn classify_avc_without_scontext_or_tclass_is_dropped() {
        let mut fields = std::collections::HashMap::new();
        fields.insert("comm".to_string(), "httpd".to_string());

        let record = AuditRecord {
            record_type: AUDIT_AVC,
            timestamp_sec: 0,
            timestamp_ms: 0,
            seq: 0,
            fields,
            unquoted_fields: std::collections::HashSet::new(),
        };

        assert!(classify(&record).is_none());
    }
}
