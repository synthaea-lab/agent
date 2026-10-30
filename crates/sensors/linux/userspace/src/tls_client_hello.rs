//! The SNI and the JA4 fingerprint of a TLS `ClientHello` (#86). Pure functions,
//! platform-independent, unit-tested on every CI leg.
//!
//! The kernel side (a later change) copies the first bytes a process writes on a TCP socket it
//! connected, without looking at them, so this is where it is decided whether they are a
//! `ClientHello` at all: a descriptor number reused after its socket closed, or a protocol that
//! is not TLS, produces bytes that are not one. Anything that is not a complete `ClientHello` is
//! dropped, never guessed at: a capture cut short by the byte bound has lost extensions, and a
//! fingerprint over half the extensions is a different fingerprint, not an approximation.
//!
//! JA4 is the TLS client fingerprint of `FoxIO`'s JA4+ family and the only member of it under
//! the BSD 3-Clause license (`LICENSE-JA4` upstream); the other methods (JA4S, JA4H, ...) are
//! not implemented and must not be added on this basis. It is implemented from the published
//! specification (`technical_details/JA4.md`), not from the reference code. TCP only: the
//! protocol character is always `t`; QUIC (`q`) and DTLS (`d`) are out of scope.

use std::fmt::Write as _;

use sha2::{Digest, Sha256};

/// `server_name` (RFC 6066).
const EXT_SERVER_NAME: u16 = 0x0000;
/// `application_layer_protocol_negotiation` (RFC 7301).
const EXT_ALPN: u16 = 0x0010;
/// `signature_algorithms` (RFC 8446).
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
/// `supported_versions` (RFC 8446).
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

/// The hash a JA4 section holds when there is nothing to hash.
const EMPTY_HASH: &str = "000000000000";
/// JA4 prints both counts on two digits and stops counting at 99.
const COUNT_CAP: usize = 99;

/// What a `ClientHello` says about its sender.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ClientHello {
    /// The first `host_name` of the `server_name` extension, as sent. `None` when there is no
    /// such extension, no host name in it, or a name that is not valid UTF-8; the JA4 still
    /// records that the extension existed.
    pub(crate) sni: Option<String>,
    /// The JA4 fingerprint, e.g. `t13d1516h2_8daaf6152771_e5627efa2ab1`.
    pub(crate) ja4: String,
}

/// The `ClientHello` that `payload` starts with, or `None` when `payload` is not a complete one.
///
/// `payload` is the TCP payload from its first byte: a TLS record (type 22) carrying a
/// handshake message of type 1. A hello split over several records is not reassembled and
/// yields `None`; real clients send it in one record.
pub(crate) fn parse(payload: &[u8]) -> Option<ClientHello> {
    let mut record = Reader::new(payload);
    // Content type 22 (handshake); the record version is 0x0301 or 0x0303 in practice and
    // carries no information JA4 uses, so only its presence is required.
    (record.u8()? == 22).then_some(())?;
    record.skip(2)?;
    let record_len = usize::from(record.u16()?);
    let mut handshake = Reader::new(record.take(record_len)?);

    // Handshake type 1 (client_hello), then its 24-bit length, which must fit the record.
    (handshake.u8()? == 1).then_some(())?;
    let body_len = handshake.u24()?;
    let mut body = Reader::new(handshake.take(body_len)?);

    let legacy_version = body.u16()?;
    body.skip(32)?; // random
    let session_id_len = usize::from(body.u8()?);
    body.skip(session_id_len)?;

    let cipher_bytes = usize::from(body.u16()?);
    (cipher_bytes % 2 == 0).then_some(())?;
    let mut cipher_reader = Reader::new(body.take(cipher_bytes)?);
    let mut ciphers = Vec::with_capacity(cipher_bytes / 2);
    while !cipher_reader.is_empty() {
        ciphers.push(cipher_reader.u16()?);
    }

    let compression_len = usize::from(body.u8()?);
    body.skip(compression_len)?;

    // A hello may end here: SSL 3.0 and some TLS 1.0 clients send no extensions at all.
    let mut extensions = Vec::new();
    if !body.is_empty() {
        let extensions_len = usize::from(body.u16()?);
        let mut reader = Reader::new(body.take(extensions_len)?);
        while !reader.is_empty() {
            let kind = reader.u16()?;
            let len = usize::from(reader.u16()?);
            extensions.push((kind, reader.take(len)?));
        }
    }

    Some(ClientHello {
        sni: sni(&extensions)?,
        ja4: ja4(legacy_version, &ciphers, &extensions)?,
    })
}

/// Every extension of the hello, in the order sent, with its payload.
type Extensions<'a> = [(u16, &'a [u8])];

fn find<'a>(extensions: &Extensions<'a>, kind: u16) -> Option<&'a [u8]> {
    extensions.iter().find(|(k, _)| *k == kind).map(|(_, v)| *v)
}

/// `None` when the `server_name` extension is malformed. `Some(None)` when it is absent, has no
/// host name, or its name is not UTF-8. The whole list is walked either way, so a malformed
/// entry after the host name is still caught.
fn sni(extensions: &Extensions<'_>) -> Option<Option<String>> {
    let Some(data) = find(extensions, EXT_SERVER_NAME) else {
        return Some(None);
    };
    let mut list = Reader::new(u16_vector(data)?);
    let mut host = None;
    while !list.is_empty() {
        let name_type = list.u8()?;
        let len = usize::from(list.u16()?);
        let name = list.take(len)?;
        if name_type == 0 && host.is_none() {
            host = Some(name);
        }
    }
    Some(host.and_then(|name| String::from_utf8(name.to_vec()).ok()))
}

fn ja4(legacy_version: u16, ciphers: &[u16], extensions: &Extensions<'_>) -> Option<String> {
    let ciphers: Vec<u16> = ciphers.iter().copied().filter(|c| !is_grease(*c)).collect();
    let kinds: Vec<u16> = extensions
        .iter()
        .map(|(kind, _)| *kind)
        .filter(|kind| !is_grease(*kind))
        .collect();

    let version = version(legacy_version, find(extensions, EXT_SUPPORTED_VERSIONS))?;
    let sni = if find(extensions, EXT_SERVER_NAME).is_some() {
        'd'
    } else {
        'i'
    };
    let alpn = alpn(find(extensions, EXT_ALPN))?;

    let mut sorted_ciphers = ciphers.clone();
    sorted_ciphers.sort_unstable();
    let cipher_hash = hash12(&hex_list(&sorted_ciphers));

    // SNI and ALPN count, but stay out of the hash: they say who and what, not which client.
    let mut sorted_kinds: Vec<u16> = kinds
        .iter()
        .copied()
        .filter(|k| *k != EXT_SERVER_NAME && *k != EXT_ALPN)
        .collect();
    sorted_kinds.sort_unstable();
    let extension_hash = if sorted_kinds.is_empty() {
        EMPTY_HASH.to_string()
    } else {
        let mut hashed = hex_list(&sorted_kinds);
        if let Some(data) = find(extensions, EXT_SIGNATURE_ALGORITHMS) {
            // Kept in the order sent: the order of the algorithms is part of the fingerprint.
            hashed.push('_');
            hashed.push_str(&hex_list(&signature_algorithms(data)?));
        }
        hash12(&hashed)
    };

    Some(format!(
        "t{version}{sni}{:02}{:02}{alpn}_{cipher_hash}_{extension_hash}",
        ciphers.len().min(COUNT_CAP),
        kinds.len().min(COUNT_CAP),
    ))
}

/// Two characters: the highest version the client offers in `supported_versions`, else the
/// version field of the hello. `None` when `supported_versions` is malformed.
///
/// A `supported_versions` with nothing but GREASE in it (the spec does not say) falls back to
/// the hello's own field rather than to an invented value.
fn version(legacy_version: u16, supported_versions: Option<&[u8]>) -> Option<&'static str> {
    let highest = match supported_versions {
        Some(data) => u16_values(u8_vector(data)?)?
            .into_iter()
            .filter(|v| !is_grease(*v))
            .max(),
        None => None,
    };
    Some(match highest.unwrap_or(legacy_version) {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    })
}

/// The first and last character of the first ALPN protocol, `00` when there is none. `None`
/// when the extension is malformed; the whole list is walked, not only its first entry.
fn alpn(data: Option<&[u8]>) -> Option<String> {
    let Some(data) = data else {
        return Some("00".to_string());
    };
    let mut list = Reader::new(u16_vector(data)?);
    let mut first = None;
    while !list.is_empty() {
        let len = usize::from(list.u8()?);
        let protocol = list.take(len)?;
        first.get_or_insert(protocol);
    }
    Some(match first {
        Some(protocol) if !protocol.is_empty() => alpn_chars(protocol).iter().collect(),
        _ => "00".to_string(),
    })
}

/// `protocol` is not empty. Its first and last bytes when both are ASCII letters or digits;
/// otherwise the first and last character of its lowercase hex form (`0xAB 0xCD` -> `ad`).
fn alpn_chars(protocol: &[u8]) -> [char; 2] {
    let (first, last) = (protocol[0], protocol[protocol.len() - 1]);
    if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() {
        return [char::from(first), char::from(last)];
    }
    let mut hex = String::with_capacity(protocol.len() * 2);
    for byte in protocol {
        let _ = write!(hex, "{byte:02x}");
    }
    let mut chars = hex.chars();
    let first = chars.next().unwrap_or('0');
    [first, chars.next_back().unwrap_or(first)]
}

/// The algorithms in the order sent, GREASE dropped. `None` unless the length prefix covers
/// the extension exactly and holds whole two-byte values.
fn signature_algorithms(data: &[u8]) -> Option<Vec<u16>> {
    Some(
        u16_values(u16_vector(data)?)?
            .into_iter()
            .filter(|v| !is_grease(*v))
            .collect(),
    )
}

/// The contents of a vector with a two-byte length prefix, when the prefix covers `data`
/// exactly: one that falls short leaves bytes nobody accounts for, one that overshoots lies
/// about what follows. Either way the extension is malformed, and is not read for a prefix.
fn u16_vector(data: &[u8]) -> Option<&[u8]> {
    let (len, rest) = data.split_first_chunk::<2>()?;
    (usize::from(u16::from_be_bytes(*len)) == rest.len()).then_some(rest)
}

/// [`u16_vector`] with a one-byte length prefix.
fn u8_vector(data: &[u8]) -> Option<&[u8]> {
    let (len, rest) = data.split_first()?;
    (usize::from(*len) == rest.len()).then_some(rest)
}

/// The big-endian `u16`s that fill `bytes`, or `None` when a byte is left over.
fn u16_values(bytes: &[u8]) -> Option<Vec<u16>> {
    let (values, rest) = bytes.as_chunks::<2>();
    rest.is_empty()
        .then(|| values.iter().map(|v| u16::from_be_bytes(*v)).collect())
}

/// RFC 8701 GREASE values: `0x0a0a`, `0x1a1a`, ... `0xfafa`.
fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
}

/// Four lowercase hex digits per value, comma separated.
fn hex_list(values: &[u16]) -> String {
    let mut out = String::with_capacity(values.len() * 5);
    for (i, value) in values.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "{value:04x}");
    }
    out
}

/// The first 12 hex digits of the SHA-256 of `text`, or the all-zero hash for no text.
fn hash12(text: &str) -> String {
    if text.is_empty() {
        return EMPTY_HASH.to_string();
    }
    let mut out = String::with_capacity(12);
    for byte in Sha256::digest(text.as_bytes()).into_iter().take(6) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// A cursor over a byte slice whose every read is bounds-checked: a hello cut short or lying
/// about a length ends the parse with `None`, never a panic.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, tail) = (self.rest.get(..n)?, self.rest.get(n..)?);
        self.rest = tail;
        Some(head)
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Option<usize> {
        self.take(3)
            .map(|b| (usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example of the JA4 specification: a TLS 1.3 client with 15 cipher suites and
    /// 16 extensions, offering `h2`, for `example.com`.
    const EXAMPLE_CIPHERS: [u16; 15] = [
        0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
        0x009c, 0x009d, 0x002f, 0x0035,
    ];
    const EXAMPLE_EXTENSIONS: [u16; 16] = [
        0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012,
        0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
    ];
    const EXAMPLE_SIGALGS: [u16; 8] = [
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];
    const EXAMPLE_JA4: &str = "t13d1516h2_8daaf6152771_e5627efa2ab1";

    fn u16s(values: &[u16]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_be_bytes()).collect()
    }

    /// The data of the extensions whose content matters to the fingerprint; any other
    /// extension carries a byte the parser must not look at.
    fn extension_data(kind: u16, sigalgs: &[u16], alpn: &[&[u8]]) -> Vec<u8> {
        match kind {
            EXT_SERVER_NAME => {
                let mut name = vec![0u8]; // host_name
                name.extend(11u16.to_be_bytes());
                name.extend(b"example.com");
                let mut data = (name.len() as u16).to_be_bytes().to_vec();
                data.extend(name);
                data
            }
            EXT_ALPN => {
                let mut list = Vec::new();
                for protocol in alpn {
                    list.push(protocol.len() as u8);
                    list.extend(*protocol);
                }
                let mut data = (list.len() as u16).to_be_bytes().to_vec();
                data.extend(list);
                data
            }
            EXT_SUPPORTED_VERSIONS => vec![4, 0x03, 0x04, 0x03, 0x03],
            EXT_SIGNATURE_ALGORITHMS => {
                let mut data = ((sigalgs.len() * 2) as u16).to_be_bytes().to_vec();
                data.extend(u16s(sigalgs));
                data
            }
            _ => vec![0],
        }
    }

    fn client_hello(
        version: u16,
        ciphers: &[u16],
        extensions: &[u16],
        sigalgs: &[u16],
        alpn: &[&[u8]],
    ) -> Vec<u8> {
        let extensions: Vec<(u16, Vec<u8>)> = extensions
            .iter()
            .map(|&kind| (kind, extension_data(kind, sigalgs, alpn)))
            .collect();
        client_hello_raw(version, ciphers, &extensions)
    }

    /// A hello whose extensions carry exactly the payloads given, well formed or not.
    fn client_hello_raw(version: u16, ciphers: &[u16], extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = version.to_be_bytes().to_vec();
        body.extend([0x42; 32]); // random
        body.push(32); // session id
        body.extend([0x07; 32]);
        body.extend(((ciphers.len() * 2) as u16).to_be_bytes());
        body.extend(u16s(ciphers));
        body.extend([1, 0]); // compression: null
        let mut ext = Vec::new();
        for (kind, data) in extensions {
            ext.extend(kind.to_be_bytes());
            ext.extend((data.len() as u16).to_be_bytes());
            ext.extend(data);
        }
        body.extend((ext.len() as u16).to_be_bytes());
        body.extend(ext);

        let mut handshake = vec![1];
        handshake.extend(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend(body);
        let mut record = vec![22, 0x03, 0x01];
        record.extend((handshake.len() as u16).to_be_bytes());
        record.extend(handshake);
        record
    }

    fn example() -> Vec<u8> {
        client_hello(
            0x0303,
            &EXAMPLE_CIPHERS,
            &EXAMPLE_EXTENSIONS,
            &EXAMPLE_SIGALGS,
            &[b"h2"],
        )
    }

    #[test]
    fn the_specifications_worked_example_gives_its_fingerprint() {
        let hello = parse(&example()).expect("a complete ClientHello");
        assert_eq!(hello.ja4, EXAMPLE_JA4);
        assert_eq!(hello.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn the_hashes_of_the_example_are_the_specifications() {
        // Both strings and their truncated digests are quoted in JA4.md.
        assert_eq!(
            hash12("002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"),
            "8daaf6152771"
        );
        assert_eq!(
            hash12(
                "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_\
                 0403,0804,0401,0503,0805,0501,0806,0601"
            ),
            "e5627efa2ab1"
        );
    }

    #[test]
    fn grease_is_ignored_everywhere() {
        let mut ciphers = vec![0x0a0a];
        ciphers.extend(EXAMPLE_CIPHERS);
        let mut extensions = vec![0x2a2a];
        extensions.extend(EXAMPLE_EXTENSIONS);
        extensions.push(0xfafa);
        let mut sigalgs = vec![0x1a1a];
        sigalgs.extend(EXAMPLE_SIGALGS);
        let hello = client_hello(0x0303, &ciphers, &extensions, &sigalgs, &[b"h2"]);
        assert_eq!(parse(&hello).expect("parsed").ja4, EXAMPLE_JA4);
    }

    #[test]
    fn grease_values_are_exactly_the_sixteen_of_rfc_8701() {
        let found: Vec<u16> = (0..=u16::MAX).filter(|v| is_grease(*v)).collect();
        let expected: Vec<u16> = (0..16).map(|i| ((i << 4) | 0xa) * 0x0101).collect();
        assert_eq!(found, expected);
    }

    #[test]
    fn the_extension_order_does_not_change_the_fingerprint() {
        let mut reversed = EXAMPLE_EXTENSIONS;
        reversed.reverse();
        let hello = client_hello(
            0x0303,
            &EXAMPLE_CIPHERS,
            &reversed,
            &EXAMPLE_SIGALGS,
            &[b"h2"],
        );
        assert_eq!(parse(&hello).expect("parsed").ja4, EXAMPLE_JA4);
    }

    #[test]
    fn the_signature_algorithm_order_does_change_it() {
        let mut swapped = EXAMPLE_SIGALGS;
        swapped.swap(0, 1);
        let hello = client_hello(
            0x0303,
            &EXAMPLE_CIPHERS,
            &EXAMPLE_EXTENSIONS,
            &swapped,
            &[b"h2"],
        );
        let ja4 = parse(&hello).expect("parsed").ja4;
        assert_ne!(ja4, EXAMPLE_JA4);
        // Only the extension section changes.
        assert!(ja4.starts_with("t13d1516h2_8daaf6152771_"));
    }

    #[test]
    fn no_sni_no_alpn_and_no_ciphers() {
        // One extension (0x0039), no cipher suite: the all-zero hash for the ciphers.
        let hello = client_hello(0x0303, &[], &[0x0039], &[], &[]);
        let parsed = parse(&hello).expect("parsed");
        assert_eq!(parsed.sni, None);
        assert_eq!(parsed.ja4, "t12i000100_000000000000_2cfe23c976cf");
    }

    #[test]
    fn without_extensions_the_extension_hash_is_all_zero() {
        let hello = client_hello(0x0301, &[0x002f], &[], &[], &[]);
        assert_eq!(
            parse(&hello).expect("parsed").ja4,
            format!("t10i010000_{}_000000000000", hash12("002f"))
        );
    }

    #[test]
    fn a_hello_with_no_extension_block_at_all_parses() {
        let mut hello = client_hello(0x0300, &[0x000a], &[], &[], &[]);
        // Drop the (empty) two-byte extension length, and shrink the two lengths that cover it.
        hello.truncate(hello.len() - 2);
        let handshake_len = u16::from_be_bytes([hello[3], hello[4]]) - 2;
        hello[3..5].copy_from_slice(&handshake_len.to_be_bytes());
        let body_len = u32::from_be_bytes([0, hello[6], hello[7], hello[8]]) - 2;
        hello[6..9].copy_from_slice(&body_len.to_be_bytes()[1..]);
        assert!(parse(&hello).expect("parsed").ja4.starts_with("ts3i0100"));
    }

    #[test]
    fn counts_stop_at_99() {
        let ciphers: Vec<u16> = (1..=120).collect();
        let hello = client_hello(0x0303, &ciphers, &[], &[], &[]);
        assert!(parse(&hello).expect("parsed").ja4.starts_with("t12i9900"));
    }

    #[test]
    fn the_version_is_the_highest_of_supported_versions_else_the_hello_field() {
        // TLS 1.2 in the hello field, 1.3 offered in supported_versions.
        let hello = client_hello(0x0303, &[0x002f], &[EXT_SUPPORTED_VERSIONS], &[], &[]);
        assert!(parse(&hello).expect("parsed").ja4.starts_with("t13i"));
        // Only GREASE offered: fall back to the field.
        assert_eq!(version(0x0303, Some(&[2, 0x0a, 0x0a])), Some("12"));
        assert_eq!(version(0x0301, None), Some("10"));
        assert_eq!(version(0x7a7a, None), Some("00"));
    }

    #[test]
    fn the_alpn_characters_follow_the_specification() {
        assert_eq!(alpn_chars(b"h2"), ['h', '2']);
        assert_eq!(alpn_chars(b"http/1.1"), ['h', '1']);
        assert_eq!(alpn_chars(b"x"), ['x', 'x']);
        // The specification's own examples for bytes that are not letters or digits.
        assert_eq!(alpn_chars(&[0x20]), ['2', '0']);
        assert_eq!(alpn_chars(&[0xab, 0xcd]), ['a', 'd']);
        assert_eq!(alpn_chars(&[0x20, 0x61]), ['2', '1']);
        assert_eq!(alpn_chars(&[0x61, 0x20]), ['6', '0']);
        assert_eq!(alpn_chars(&[0x30, 0xab, 0xcd, 0x31]), ['0', '1']);
    }

    #[test]
    fn an_absent_or_empty_alpn_is_00() {
        assert_eq!(alpn(None).as_deref(), Some("00"));
        assert_eq!(alpn(Some(&[0, 0])).as_deref(), Some("00")); // an empty protocol list
        assert_eq!(alpn(Some(&[0, 1, 0])).as_deref(), Some("00")); // a first protocol of length 0
    }

    #[test]
    fn only_the_first_alpn_protocol_counts() {
        let hello = client_hello(
            0x0303,
            &EXAMPLE_CIPHERS,
            &EXAMPLE_EXTENSIONS,
            &EXAMPLE_SIGALGS,
            &[b"h2", b"http/1.1"],
        );
        assert_eq!(parse(&hello).expect("parsed").ja4, EXAMPLE_JA4);
    }

    #[test]
    fn a_name_that_is_not_utf8_leaves_the_sni_empty_but_keeps_the_d() {
        let mut hello = example();
        let at = hello
            .windows(11)
            .position(|w| w == b"example.com")
            .expect("the name");
        hello[at] = 0xff;
        let parsed = parse(&hello).expect("parsed");
        assert_eq!(parsed.sni, None);
        assert_eq!(parsed.ja4, EXAMPLE_JA4);
    }

    #[test]
    fn a_capture_cut_short_is_not_a_hello() {
        let hello = example();
        for cut in [0, 1, 4, 5, 9, 43, 100, hello.len() - 1] {
            assert_eq!(parse(&hello[..cut]), None, "cut at {cut}");
        }
    }

    #[test]
    fn what_is_not_a_client_hello_is_dropped() {
        // Application data, an alert, and a server hello (handshake type 2).
        for first in [23u8, 21, 20] {
            let mut bytes = example();
            bytes[0] = first;
            assert_eq!(parse(&bytes), None);
        }
        let mut server_hello = example();
        server_hello[5] = 2;
        assert_eq!(parse(&server_hello), None);
        assert_eq!(parse(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), None);
        assert_eq!(parse(&[]), None);
    }

    #[test]
    fn lengths_that_lie_are_dropped_not_trusted() {
        // A handshake length larger than the record, an odd cipher list, a cipher list
        // longer than the hello.
        let mut bytes = example();
        bytes[6..9].copy_from_slice(&[0xff, 0xff, 0xff]);
        assert_eq!(parse(&bytes), None);

        let mut bytes = example();
        bytes[5 + 4 + 2 + 32 + 1 + 32 + 1] = 0x7f; // cipher_suites length, low byte: odd
        assert_eq!(parse(&bytes), None);

        let mut bytes = example();
        bytes[5 + 4 + 2 + 32 + 1 + 32] = 0xff; // cipher_suites length, high byte
        assert_eq!(parse(&bytes), None);
    }

    /// A hello with one extension whose payload is `data`, byte for byte.
    fn with_extension(kind: u16, data: &[u8]) -> Vec<u8> {
        client_hello_raw(0x0303, &[0x002f], &[(kind, data.to_vec())])
    }

    fn assert_rejects(kind: u16, well_formed: &[u8], malformed: &[&[u8]]) {
        assert!(
            parse(&with_extension(kind, well_formed)).is_some(),
            "the well-formed payload must parse"
        );
        for data in malformed {
            assert_eq!(
                parse(&with_extension(kind, data)),
                None,
                "{kind:#06x} payload {data:02x?}"
            );
        }
    }

    #[test]
    fn a_malformed_supported_versions_is_not_fingerprinted() {
        assert_rejects(
            EXT_SUPPORTED_VERSIONS,
            &[2, 0x03, 0x04],
            &[
                &[3, 0x03, 0x04, 0x03], // odd: the last byte would be dropped
                &[2, 0x03, 0x04, 0xff], // a byte after the declared vector
                &[4, 0x03, 0x04],       // declares more than is there
                &[0, 0x03, 0x04],       // declares less than is there
                &[],                    // no length at all
            ],
        );
    }

    #[test]
    fn a_malformed_signature_algorithms_is_not_fingerprinted() {
        assert_rejects(
            EXT_SIGNATURE_ALGORITHMS,
            &[0, 2, 0x04, 0x03],
            &[
                &[0, 8, 0x04, 0x03],       // oversized: declares more than is there
                &[0, 3, 0x04, 0x03, 0x05], // odd length
                &[0, 2, 0x04, 0x03, 0x05], // a byte after the declared vector
                &[0, 1, 0x04, 0x03],       // declares less than is there
                &[0],                      // half a length
            ],
        );
    }

    #[test]
    fn a_malformed_alpn_is_not_fingerprinted() {
        assert_rejects(
            EXT_ALPN,
            &[0, 3, 2, b'h', b'2'],
            &[
                &[0, 9, 2, b'h', b'2'],          // list longer than the extension
                &[0, 3, 2, b'h', b'2', 0xff],    // a byte after the list
                &[0, 3, 5, b'h', b'2'],          // an entry that overruns the list
                &[0, 5, 2, b'h', b'2', 3, b'x'], // a second entry that overruns
                &[0],                            // half a length
            ],
        );
    }

    #[test]
    fn a_malformed_server_name_is_not_fingerprinted() {
        let mut well_formed = vec![0, 14, 0, 0, 11];
        well_formed.extend(b"example.com");
        assert_rejects(
            EXT_SERVER_NAME,
            &well_formed,
            &[
                &[0, 99, 0, 0, 1, b'a'],      // list longer than the extension
                &[0, 4, 0, 0, 1, b'a', 0xff], // a byte after the list
                &[0, 4, 0, 0, 9, b'a'],       // a name that overruns the list
                &[0, 6, 0, 0, 1, b'a', 0, 0], // a second entry cut short
            ],
        );
    }

    #[test]
    fn trailing_bytes_after_the_record_are_ignored() {
        let mut bytes = example();
        bytes.extend(b"\x17\x03\x03\x00\x05hello");
        assert_eq!(parse(&bytes).expect("parsed").ja4, EXAMPLE_JA4);
    }
}
