//! Parser robustness: `parse_audit_message` consumes bytes straight off the
//! audit netlink socket — kernel-shaped in practice, but the parser must never
//! panic on anything, because a panic on the drain path kills the sensor (the
//! one thing an EDR must not let input do). Errors are fine; panics are not.
//!
//! Deterministic pseudo-random bytes (seeded LCG, no dependency) rather than a
//! fuzzer: reproducible in CI, and the interesting failures for this format
//! are structural (truncation, missing markers, non-UTF-8), all covered
//! explicitly below.

use sensor_linux_audit::parse_audit_message;

/// Minimal deterministic PRNG (Knuth LCG) — reproducible corpus, no deps.
fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

#[test]
fn never_panics_on_arbitrary_bytes() {
    let mut state = 0x5941_7481_u64;
    for _ in 0..2_000 {
        let len = (lcg(&mut state) % 300) as usize;
        let buf: Vec<u8> = (0..len).map(|_| (lcg(&mut state) >> 33) as u8).collect();
        // Ok or Err are both acceptable — only a panic is a bug.
        let _ = parse_audit_message(&buf);
    }
}

#[test]
fn never_panics_on_every_truncation_of_a_valid_message() {
    // 16-byte nlmsghdr + a well-formed payload, then every prefix of it.
    let mut valid = Vec::new();
    valid.extend_from_slice(&64u32.to_ne_bytes()); // nlmsg_len
    valid.extend_from_slice(&1309u16.to_ne_bytes()); // nlmsg_type (EXECVE)
    valid.extend_from_slice(&0u16.to_ne_bytes());
    valid.extend_from_slice(&0u32.to_ne_bytes());
    valid.extend_from_slice(&0u32.to_ne_bytes());
    valid.extend_from_slice(b"msg=audit(1234567890.123:456): argc=2 a0=\"/bin/ls\" a1=\"-la\"");

    assert!(parse_audit_message(&valid).is_ok(), "baseline must parse");
    for cut in 0..valid.len() {
        let _ = parse_audit_message(&valid[..cut]);
    }
}

#[test]
fn never_panics_on_non_utf8_and_hostile_payloads() {
    let header = {
        let mut h = Vec::new();
        h.extend_from_slice(&64u32.to_ne_bytes());
        h.extend_from_slice(&1309u16.to_ne_bytes());
        h.extend_from_slice(&[0u8; 10]);
        h
    };
    let payloads: &[&[u8]] = &[
        b"\xFF\xFE\xFD msg=audit(1:2): a=\"\xFF\"",
        b"msg=audit(:): =",
        b"msg=audit(99999999999999999999.999:9): k=v", // over-long integer
        b"msg=audit(1.2:3): key=\"unterminated",
        b"msg=audit(1.2:3): ==== \"\"\"\" =",
        &[0u8; 200],
    ];
    for payload in payloads {
        let mut buf = header.clone();
        buf.extend_from_slice(payload);
        let _ = parse_audit_message(&buf);
    }
}
