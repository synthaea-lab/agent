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
}

const AUDIT_EXECVE: u32 = 1309;
const AUDIT_SOCKADDR: u32 = 1306;

/// Maps `AuditRecord` to `AuditEvent`, or None if not interesting.
#[must_use]
pub fn classify(record: &AuditRecord) -> Option<AuditEvent> {
    match record.record_type {
        AUDIT_EXECVE => classify_exec(record),
        AUDIT_SOCKADDR => classify_connect(record),
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
        let value = record.fields.get(&key)?;
        // Auditd may hex-encode arguments - decode if needed
        let decoded = decode_audit_value(value);
        argv.push(decoded);
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

/// Decodes audit field values (handles hex-encoded strings).
fn decode_audit_value(value: &str) -> String {
    // If value looks like hex (even length, all hex chars), try to decode
    if value.len().is_multiple_of(2)
        && value.chars().all(|c| c.is_ascii_hexdigit())
        && value.len() > 2
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
}
