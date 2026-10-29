//! The question of an outgoing DNS query, read from the datagram the UDP/53 capture sends up
//! (#458 part 3). Pure functions, platform-independent, unit-tested on every CI leg.
//!
//! The kernel side copies the first bytes of a datagram bound for port 53 without looking at
//! them (`DnsUdpQueryEvent`), so this is where it is decided whether they are a DNS query at all:
//! a descriptor number that was reused after its socket was closed, or a TCP stream to port 53,
//! produces bytes that are not one. Anything that is not a plain query with one question is
//! dropped, never guessed at.

/// Longest name a message can carry, in wire form (RFC 1035: 255 octets, labels and length bytes).
const MAX_NAME_WIRE_LEN: usize = 255;
/// Longest label (RFC 1035: 63 octets; the top two bits of a length byte mark a compression
/// pointer or an extended label, neither valid in the first question).
const MAX_LABEL_LEN: usize = 63;
/// The fixed DNS header.
const HEADER_LEN: usize = 12;

/// What a query asks: the name as written (dots between labels, no trailing dot, `"."` for the
/// root) and the record type (1 = A, 28 = AAAA, 16 = TXT, ...).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Question {
    pub(crate) name: String,
    pub(crate) qtype: u16,
}

/// The question of the query in `payload`, or `None` when `payload` is not a DNS query.
///
/// A datagram is a message from byte 0. A TCP stream to port 53 prefixes the message with its
/// length (two bytes, big endian), so that framing is tried second: a write on a socket that
/// was connected to port 53 over TCP lands here too, and its query is as good as a UDP one.
pub(crate) fn parse_query(payload: &[u8]) -> Option<Question> {
    parse_message(payload).or_else(|| {
        let (prefix, message) = payload.split_first_chunk::<2>()?;
        let length = usize::from(u16::from_be_bytes(*prefix));
        // A capture cut short by the bound is shorter than the length it announces; one that
        // is longer than the message it frames is not a framed message.
        (length >= HEADER_LEN && length >= message.len()).then_some(())?;
        parse_message(message)
    })
}

fn parse_message(message: &[u8]) -> Option<Question> {
    let header = message.get(..HEADER_LEN)?;
    let flags = u16::from_be_bytes([header[2], header[3]]);
    let question_count = u16::from_be_bytes([header[4], header[5]]);
    let answer_count = u16::from_be_bytes([header[6], header[7]]);
    let authority_count = u16::from_be_bytes([header[8], header[9]]);
    // A query (QR = 0), the standard opcode (0), one question and nothing else but the
    // additional section, where EDNS puts its OPT record.
    let is_query = flags & 0x8000 == 0;
    let is_standard = (flags >> 11) & 0xF == 0;
    if !is_query || !is_standard || question_count != 1 || answer_count != 0 || authority_count != 0
    {
        return None;
    }

    let mut at = HEADER_LEN;
    let mut name = String::new();
    let mut wire_len = 1; // the root label
    loop {
        let label_len = usize::from(*message.get(at)?);
        at += 1;
        if label_len == 0 {
            break;
        }
        if label_len > MAX_LABEL_LEN {
            return None;
        }
        wire_len += label_len + 1;
        if wire_len > MAX_NAME_WIRE_LEN {
            return None;
        }
        let label = message.get(at..at + label_len)?;
        at += label_len;
        // A hostname label is printable ASCII (internationalised names are punycode); control
        // bytes and 8-bit data mean the bytes were never a query.
        if !label.iter().all(u8::is_ascii_graphic) {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.extend(label.iter().map(|&b| char::from(b)));
    }
    let tail = message.get(at..at + 4)?; // qtype and qclass
    if name.is_empty() {
        name.push('.');
    }
    Some(Question {
        name,
        qtype: u16::from_be_bytes([tail[0], tail[1]]),
    })
}

/// Names under these private top-level domains are blanked down to the TLD: an internal host name
/// is a topology disclosure, while "queried something under `.internal`" is what DNS-tunnelling
/// detection keeps. The same rule, with the same list, as `sensor-linux-uprobes`'s
/// `redact_dns_query` (the `getaddrinfo` path, which applies it with a regex this crate does not
/// depend on): a name must come out the same whichever path saw it, so both crates test the
/// same table.
const PRIVATE_TLDS: &[&str] = &["local", "internal", "lan", "home", "corp", "intranet"];

pub(crate) fn redact_private_tld(name: String) -> String {
    let trimmed = name.strip_suffix('.').unwrap_or(&name);
    match trimmed.rsplit_once('.') {
        Some((host, tld))
            if !host.is_empty() && PRIVATE_TLDS.iter().any(|t| tld.eq_ignore_ascii_case(t)) =>
        {
            format!("[REDACTED].{tld}")
        }
        _ => name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed query message for `name` (dotted) and `qtype`, with `flags` and `arcount`.
    fn message(name: &str, qtype: u16, flags: u16, arcount: u16) -> Vec<u8> {
        let mut m = vec![0x12, 0x34];
        m.extend(flags.to_be_bytes());
        m.extend([0, 1, 0, 0, 0, 0]); // one question, no answer, no authority
        m.extend(arcount.to_be_bytes());
        for label in name.split('.').filter(|l| !l.is_empty()) {
            m.push(u8::try_from(label.len()).unwrap());
            m.extend(label.bytes());
        }
        m.push(0);
        m.extend(qtype.to_be_bytes());
        m.extend([0, 1]); // class IN
        m
    }

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        message(name, qtype, 0x0100, 0) // recursion desired, the usual
    }

    #[test]
    fn a_plain_a_query_gives_its_name_and_type() {
        assert_eq!(
            parse_query(&query("www.example.com", 1)),
            Some(Question {
                name: "www.example.com".into(),
                qtype: 1
            })
        );
    }

    #[test]
    fn the_record_type_is_the_one_asked() {
        for qtype in [1, 28, 16, 15, 255] {
            assert_eq!(
                parse_query(&query("example.org", qtype)).unwrap().qtype,
                qtype
            );
        }
    }

    #[test]
    fn the_root_is_a_dot() {
        assert_eq!(parse_query(&query("", 2)).unwrap().name, ".");
    }

    #[test]
    fn an_edns_query_with_an_additional_record_is_still_a_query() {
        assert!(parse_query(&message("example.com", 1, 0x0100, 1)).is_some());
    }

    #[test]
    fn a_tunnelling_sized_name_survives_whole() {
        // Three 63-byte labels and a short parent: 197 bytes of name, what a DNS tunnel sends.
        let label = "a1b2c3d4".repeat(8)[..63].to_string();
        let name = format!("{label}.{label}.{label}.t.example");
        let got = parse_query(&query(&name, 16)).unwrap();
        assert_eq!(got.name, name);
        assert!(
            query(&name, 16).len() <= 272,
            "it fits the kernel-side bound"
        );
    }

    #[test]
    fn the_longest_legal_name_fits_the_bound() {
        // 255 octets on the wire: 3 x (1 + 63) + 1 + 61 + 1 for the root.
        let a = "a".repeat(63);
        let b = "b".repeat(61);
        let name = format!("{a}.{a}.{a}.{b}");
        let m = query(&name, 1);
        assert_eq!(m.len(), 12 + 255 + 4);
        assert!(m.len() <= 272);
        assert_eq!(parse_query(&m).unwrap().name, name);
    }

    #[test]
    fn a_name_longer_than_the_wire_limit_is_not_a_query() {
        let a = "a".repeat(63);
        let name = format!("{a}.{a}.{a}.{a}.x");
        assert_eq!(parse_query(&query(&name, 1)), None);
    }

    #[test]
    fn a_response_is_not_a_query() {
        assert_eq!(parse_query(&message("example.com", 1, 0x8180, 0)), None);
    }

    #[test]
    fn a_non_standard_opcode_is_not_a_query() {
        // Opcode 4 (NOTIFY), QR = 0.
        assert_eq!(parse_query(&message("example.com", 1, 0x2000, 0)), None);
    }

    #[test]
    fn more_or_fewer_than_one_question_is_not_a_query() {
        for count in [0u8, 2] {
            let mut m = query("example.com", 1);
            m[5] = count;
            assert_eq!(parse_query(&m), None, "{count} questions");
        }
    }

    #[test]
    fn answers_in_a_query_are_not_a_query() {
        let mut m = query("example.com", 1);
        m[7] = 1;
        assert_eq!(parse_query(&m), None);
    }

    #[test]
    fn a_compression_pointer_in_the_question_is_not_a_query() {
        let mut m = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend([0xC0, 0x0C, 0, 1, 0, 1]);
        assert_eq!(parse_query(&m), None);
    }

    #[test]
    fn a_cut_capture_is_not_guessed_at() {
        let m = query("www.example.com", 1);
        for cut in [0, 5, 11, 12, 13, 20, m.len() - 5, m.len() - 1] {
            assert_eq!(parse_query(&m[..cut]), None, "cut at {cut}");
        }
    }

    #[test]
    fn bytes_that_are_not_text_are_not_a_name() {
        let mut m = query("www.example.com", 1);
        m[13] = 0x01; // a control byte in the first label
        assert_eq!(parse_query(&m), None);
        let mut m = query("www.example.com", 1);
        m[13] = 0xE9; // 8-bit data
        assert_eq!(parse_query(&m), None);
    }

    #[test]
    fn a_file_write_on_a_reused_descriptor_is_not_a_query() {
        for junk in [
            b"#!/bin/sh\necho hello world, this is a script\n".as_slice(),
            &[0u8; 64],
            &[0xFF; 64],
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        ] {
            assert_eq!(parse_query(junk), None);
        }
    }

    #[test]
    fn a_tcp_framed_query_is_read_past_its_length_prefix() {
        let m = query("tcp.example.com", 1);
        let mut framed = u16::try_from(m.len()).unwrap().to_be_bytes().to_vec();
        framed.extend(&m);
        assert_eq!(parse_query(&framed).unwrap().name, "tcp.example.com");
    }

    #[test]
    fn a_length_prefix_that_does_not_frame_the_message_is_refused() {
        let m = query("tcp.example.com", 1);
        let mut framed = u16::try_from(m.len() - 3).unwrap().to_be_bytes().to_vec();
        framed.extend(&m);
        assert_eq!(
            parse_query(&framed),
            None,
            "the prefix says less than follows"
        );
    }

    #[test]
    fn private_tlds_are_blanked_to_the_tld() {
        assert_eq!(
            redact_private_tld("db01.prod.internal".to_string()),
            "[REDACTED].internal"
        );
        for tld in PRIVATE_TLDS {
            assert_eq!(
                redact_private_tld(format!("host.{tld}")),
                format!("[REDACTED].{tld}"),
                "tld: {tld}"
            );
        }
    }

    /// The same table as `sensor-linux-uprobes`'s `redact` tests: the two paths must agree.
    #[test]
    fn redaction_matches_the_getaddrinfo_path() {
        assert_eq!(
            redact_private_tld("HOST.LOCAL".to_string()),
            "[REDACTED].LOCAL"
        );
        assert_eq!(redact_private_tld("example.com".to_string()), "example.com");
        // The trailing dot goes with the redaction, as the regex's `\.?$` does.
        assert_eq!(
            redact_private_tld("host.lan.".to_string()),
            "[REDACTED].lan"
        );
        // A bare TLD has no host to blank, and the regex needs `.+` before the dot.
        assert_eq!(redact_private_tld("local".to_string()), "local");
        assert_eq!(redact_private_tld(".".to_string()), ".");
        assert_eq!(redact_private_tld("x.localhost".to_string()), "x.localhost");
    }
}
