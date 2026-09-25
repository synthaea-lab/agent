//! Parser robustness: `zone_identifier::parse` reads a `Zone.Identifier`
//! stream, which any process can write with any bytes — attacker-controlled
//! input consumed on the ETW callback thread, where a panic takes the whole
//! sensor down. Garbage must yield empty fields; only a panic is a bug.
//!
//! Deterministic pseudo-random bytes (seeded LCG, no dependency) rather than a
//! fuzzer, same as the Linux audit/netlink suites: reproducible in CI, and the
//! interesting failures for this format are structural (odd UTF-16 lengths,
//! lone surrogates, missing `=`/`]`, huge values), all covered explicitly.

use sensor_windows::zone_identifier::{parse, stream_host_path};

/// Minimal deterministic PRNG (Knuth LCG) — reproducible corpus, no deps.
fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

const VALID: &[u8] = b"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.test/page\r\nHostUrl=https://example.test/payload.exe\r\n";

#[test]
fn never_panics_on_arbitrary_bytes() {
    let mut state = 0x3650_2026_u64;
    for _ in 0..2_000 {
        let len = (lcg(&mut state) % 400) as usize;
        let buf: Vec<u8> = (0..len).map(|_| (lcg(&mut state) >> 33) as u8).collect();
        let _ = parse(&buf);
    }
}

#[test]
fn never_panics_on_arbitrary_bytes_behind_each_bom() {
    let mut state = 0x0BAD_F00D_u64;
    for bom in [&[0xFF_u8, 0xFE][..], &[0xEF, 0xBB, 0xBF][..]] {
        for _ in 0..1_000 {
            let len = (lcg(&mut state) % 301) as usize; // odd lengths included
            let mut buf = bom.to_vec();
            buf.extend((0..len).map(|_| (lcg(&mut state) >> 33) as u8));
            let _ = parse(&buf);
        }
    }
}

/// What a parsed URL must never carry raw: it reaches plain-text alert
/// consumers, where these forge lines or reorder text.
fn is_unsafe_in_text(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{2028}'
                | '\u{2029}'
                | '\u{061C}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
        )
}

#[test]
fn parsed_urls_never_carry_control_separator_or_bidi_chars() {
    let mut state = 0x2028_202E_u64;
    // Draw from a pool dense in the dangerous characters, so most values
    // contain several — uniform random chars would almost never hit them.
    let pool: Vec<char> =
        "\r\n\t\0\u{7}\u{1b}\u{85}\u{2028}\u{2029}\u{202E}\u{2066}\u{200F}=[]aZ:/é"
            .chars()
            .collect();
    for _ in 0..2_000 {
        let len = (lcg(&mut state) % 80) as usize;
        let noise: String = (0..len)
            .map(|_| pool[(lcg(&mut state) >> 33) as usize % pool.len()])
            .collect();
        let stream = format!("[ZoneTransfer]\nHostUrl={noise}\nReferrerUrl=h{noise}\n");
        let mut utf16 = vec![0xFF, 0xFE];
        for unit in stream.encode_utf16() {
            utf16.extend_from_slice(&unit.to_le_bytes());
        }
        for zone in [parse(stream.as_bytes()), parse(&utf16)] {
            for url in [zone.host_url, zone.referrer_url].into_iter().flatten() {
                assert!(!url.chars().any(is_unsafe_in_text), "{url:?}");
            }
        }
    }
}

#[test]
fn never_panics_on_every_truncation_of_a_valid_stream() {
    assert_eq!(parse(VALID).zone_id, Some(3), "baseline must parse");
    for cut in 0..VALID.len() {
        let _ = parse(&VALID[..cut]);
    }
    let mut utf16 = vec![0xFF, 0xFE];
    for unit in String::from_utf8_lossy(VALID).encode_utf16() {
        utf16.extend_from_slice(&unit.to_le_bytes());
    }
    for cut in 0..utf16.len() {
        let _ = parse(&utf16[..cut]);
    }
}

#[test]
fn hostile_structures_yield_fields_or_nothing_never_a_panic() {
    let payloads: &[&[u8]] = &[
        b"[",
        b"]",
        b"[]",
        b"[ZoneTransfer",
        b"=",
        b"==",
        b"ZoneId=",
        b"ZoneId=99999999999999999999",
        b"ZoneId=-1",
        b"HostUrl==https://x.test/",
        b"\xFF\xFE\x00\xD8", // lone high surrogate
        b"\xFF\xFE\x00",     // odd UTF-16 length
        b"\xEF\xBB\xBF\xFF\xFF",
        b"[ZoneTransfer]\0\0\0HostUrl=\xC3\x28",
        b"\r\r\r\n\n\n[ZoneTransfer]\r\n\r\n",
    ];
    for payload in payloads {
        let _ = parse(payload);
    }
    let huge = format!("[ZoneTransfer]\nHostUrl={}\n", "x".repeat(1 << 20));
    assert!(parse(huge.as_bytes()).host_url.is_some());
}

#[test]
fn host_path_never_panics_on_multibyte_boundaries() {
    // The suffix check slices near the end of the string: multi-byte chars
    // there must not split a char boundary.
    for path in [
        "é",
        "ééééééééééééééééé",
        "C:\\d\\a.exe:Zone.Identifieré",
        "C:\\d\\éa.exe:Zone.Identifier",
        ":$DATA",
        "日本語:Zone.Identifier:$DATA",
        "",
    ] {
        let _ = stream_host_path(path);
    }
    assert_eq!(
        stream_host_path("C:\\d\\éa.exe:Zone.Identifier"),
        Some("C:\\d\\éa.exe")
    );
}
