//! Parses raw audit netlink messages into structured records.
//!
//! Wire format: 16-byte binary nlmsghdr + text payload "msg=audit(timestamp:seq): key=value ..."
//! The record type comes from `nlmsghdr.nlmsg_type`, not from a "type=" text prefix.

use std::collections::HashMap;

/// Size of the netlink message header
const NLMSGHDR_SIZE: usize = 16;

/// Netlink message header structure (16 bytes)
#[repr(C)]
#[allow(dead_code)]
struct NlMsgHdr {
    nlmsg_len: u32,    // Length of message including header
    nlmsg_type: u16,   // Message type (AUDIT_EXECVE=1309, etc.)
    nlmsg_flags: u16,  // Additional flags
    nlmsg_seq: u32,    // Sequence number
    nlmsg_pid: u32,    // Sending process port ID
}

#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub record_type: u32,  // AUDIT_EXECVE = 1309, AUDIT_SOCKADDR = 1306
    pub timestamp_sec: u64,
    pub timestamp_ms: u32,
    pub seq: u64,
    pub fields: HashMap<String, String>,
}

/// Parses one audit message from the wire.
///
/// Wire format: 16-byte binary nlmsghdr followed by text payload.
/// The record type is extracted from `nlmsghdr.nlmsg_type` (not from a "type=" prefix).
///
/// # Errors
///
/// Returns `Err` if the message format is invalid or missing required fields.
pub fn parse_audit_message(raw: &[u8]) -> Result<AuditRecord, String> {
    // Parse the 16-byte binary netlink header
    if raw.len() < NLMSGHDR_SIZE {
        return Err(format!("message too short: {} bytes (need at least 16)", raw.len()));
    }

    // Extract record type from nlmsg_type field (u16 at offset 4, little-endian)
    let record_type = u16::from_ne_bytes([raw[4], raw[5]]) as u32;

    // The payload starts after the 16-byte header
    let payload = &raw[NLMSGHDR_SIZE..];
    let msg = String::from_utf8_lossy(payload);

    // Parse "msg=audit(1234567890.123:456):" from the text payload
    let (timestamp_sec, timestamp_ms, seq) = parse_msg_header(&msg)?;

    // Parse remaining "key=value" pairs
    let fields = parse_fields(&msg)?;

    Ok(AuditRecord {
        record_type,
        timestamp_sec,
        timestamp_ms,
        seq,
        fields,
    })
}

// Deprecated: Wire format extracts type from binary nlmsghdr, not from text.
// Kept for backward compatibility with test fixtures in auditd log format.
#[allow(dead_code)]
fn parse_type(msg: &str) -> Result<u32, String> {
    let type_prefix = "type=";
    let type_start = msg.find(type_prefix)
        .ok_or_else(|| "missing 'type=' field".to_string())?;

    let type_value_start = type_start + type_prefix.len();
    let type_end = msg[type_value_start..]
        .find(' ')
        .map(|pos| type_value_start + pos)
        .unwrap_or(msg.len());

    let type_str = &msg[type_value_start..type_end];

    // Map type names to numeric values
    match type_str {
        "EXECVE" => Ok(1309),
        "SOCKADDR" => Ok(1306),
        _ => type_str.parse().map_err(|_| format!("unknown type: {type_str}")),
    }
}

fn parse_msg_header(msg: &str) -> Result<(u64, u32, u64), String> {
    let msg_prefix = "msg=audit(";
    let msg_start = msg.find(msg_prefix)
        .ok_or_else(|| "missing 'msg=audit(' header".to_string())?;

    let timestamp_start = msg_start + msg_prefix.len();
    let timestamp_end = msg[timestamp_start..]
        .find(':')
        .map(|pos| timestamp_start + pos)
        .ok_or_else(|| "missing ':' in msg header".to_string())?;

    let timestamp_str = &msg[timestamp_start..timestamp_end];

    // Parse timestamp (format: "1234567890.123")
    let parts: Vec<&str> = timestamp_str.split('.').collect();
    if parts.len() != 2 {
        return Err(format!("invalid timestamp format: {timestamp_str}"));
    }

    let timestamp_sec: u64 = parts[0].parse()
        .map_err(|_| format!("invalid timestamp seconds: {}", parts[0]))?;
    let timestamp_ms: u32 = parts[1].parse()
        .map_err(|_| format!("invalid timestamp milliseconds: {}", parts[1]))?;

    // Parse sequence number
    let seq_start = timestamp_end + 1;
    let seq_end = msg[seq_start..]
        .find(')')
        .map(|pos| seq_start + pos)
        .ok_or_else(|| "missing ')' in msg header".to_string())?;

    let seq_str = &msg[seq_start..seq_end];
    let seq: u64 = seq_str.parse()
        .map_err(|_| format!("invalid sequence number: {seq_str}"))?;

    Ok((timestamp_sec, timestamp_ms, seq))
}

fn parse_fields(msg: &str) -> Result<HashMap<String, String>, String> {
    let mut fields = HashMap::new();

    // Find the end of the msg=audit(...): header
    let fields_start = msg.find("): ")
        .map(|pos| pos + 3)
        .unwrap_or(0);

    if fields_start == 0 || fields_start >= msg.len() {
        return Ok(fields);
    }

    let fields_str = &msg[fields_start..];
    let bytes = fields_str.as_bytes();

    // Parse key=value pairs using byte indexing (O(n) instead of O(n²))
    let mut current = 0;
    while current < bytes.len() {
        // Skip whitespace
        while current < bytes.len() && bytes[current] == b' ' {
            current += 1;
        }

        if current >= bytes.len() {
            break;
        }

        // Find '='
        let eq_pos = match bytes[current..].iter().position(|&b| b == b'=') {
            Some(pos) => current + pos,
            None => break,
        };

        let key = fields_str[current..eq_pos].to_string();
        current = eq_pos + 1;

        // Parse value (may be quoted)
        let (value, next_pos) = if current < bytes.len() && bytes[current] == b'"' {
            // Quoted value
            current += 1;
            let value_end = bytes[current..]
                .iter()
                .position(|&b| b == b'"')
                .map(|pos| current + pos)
                .unwrap_or(bytes.len());

            let value = fields_str[current..value_end].to_string();
            (value, value_end + 1)
        } else {
            // Unquoted value (until space or end)
            let value_end = bytes[current..]
                .iter()
                .position(|&b| b == b' ')
                .map(|pos| current + pos)
                .unwrap_or(bytes.len());

            let value = fields_str[current..value_end].to_string();
            (value, value_end)
        };

        fields.insert(key, value);
        current = next_pos;
    }

    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to build a wire-format message: 16-byte nlmsghdr + text payload
    fn build_wire_message(record_type: u16, payload: &str) -> Vec<u8> {
        let payload_bytes = payload.as_bytes();
        let total_len = (NLMSGHDR_SIZE + payload_bytes.len()) as u32;

        let mut buf = Vec::with_capacity(total_len as usize);

        // nlmsghdr (16 bytes, little-endian)
        buf.extend_from_slice(&total_len.to_ne_bytes());      // nlmsg_len
        buf.extend_from_slice(&record_type.to_ne_bytes());    // nlmsg_type
        buf.extend_from_slice(&0u16.to_ne_bytes());           // nlmsg_flags
        buf.extend_from_slice(&0u32.to_ne_bytes());           // nlmsg_seq
        buf.extend_from_slice(&0u32.to_ne_bytes());           // nlmsg_pid

        // Payload (text)
        buf.extend_from_slice(payload_bytes);

        buf
    }

    #[test]
    fn parse_execve_message() {
        let raw = build_wire_message(1309, "msg=audit(1234567890.123:456): argc=2 a0=\"/bin/ls\" a1=\"-la\"");
        let record = parse_audit_message(&raw).unwrap();
        assert_eq!(record.record_type, 1309);
        assert_eq!(record.timestamp_sec, 1234567890);
        assert_eq!(record.timestamp_ms, 123);
        assert_eq!(record.seq, 456);
        assert_eq!(record.fields.get("argc"), Some(&"2".to_string()));
        assert_eq!(record.fields.get("a0"), Some(&"/bin/ls".to_string()));
        assert_eq!(record.fields.get("a1"), Some(&"-la".to_string()));
    }

    #[test]
    fn parse_sockaddr_message() {
        let raw = build_wire_message(1306, "msg=audit(1234567890.500:789): saddr=02001F907F000001000000000000000000000000000000000000000000000000");
        let record = parse_audit_message(&raw).unwrap();
        assert_eq!(record.record_type, 1306);
        assert_eq!(record.timestamp_sec, 1234567890);
        assert_eq!(record.timestamp_ms, 500);
        assert_eq!(record.seq, 789);
        assert!(record.fields.contains_key("saddr"));
    }

    #[test]
    fn parse_numeric_type() {
        let raw = build_wire_message(1309, "msg=audit(1000.0:1): argc=1 a0=\"test\"");
        let record = parse_audit_message(&raw).unwrap();
        assert_eq!(record.record_type, 1309);
    }

    #[test]
    fn parse_unquoted_values() {
        let raw = build_wire_message(1309, "msg=audit(1000.0:1): pid=1234 uid=1000");
        let record = parse_audit_message(&raw).unwrap();
        assert_eq!(record.fields.get("pid"), Some(&"1234".to_string()));
        assert_eq!(record.fields.get("uid"), Some(&"1000".to_string()));
    }

    #[test]
    fn rejects_too_short_message() {
        let raw = b"short";
        let result = parse_audit_message(raw);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }
}
