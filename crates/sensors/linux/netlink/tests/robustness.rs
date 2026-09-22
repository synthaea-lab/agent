//! Parser robustness: these decoders consume raw netlink bytes (`sock_diag`
//! records, proc-connector broadcasts, conntrack attribute walks). The kernel
//! is the only writer in practice, but the parsers must never panic on any
//! input — a panic on the drain path kills the sensor. `None`/empty are fine;
//! panics are not. (The crate's own byte-by-byte rule — "no explicit panic
//! point to document" — is exactly what these tests pin from the outside.)

use sensor_linux_netlink::{ConntrackFlow, DiagMsg, ProcEvent};

/// Minimal deterministic PRNG (Knuth LCG) — reproducible corpus, no deps.
fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn random_corpus(seed: u64, count: usize, max_len: usize) -> Vec<Vec<u8>> {
    let mut state = seed;
    (0..count)
        .map(|_| {
            let len = (lcg(&mut state) as usize) % max_len;
            (0..len).map(|_| (lcg(&mut state) >> 33) as u8).collect()
        })
        .collect()
}

#[test]
fn diag_msg_never_panics_on_arbitrary_bytes() {
    for buf in random_corpus(0xD1A6, 2_000, 256) {
        let _ = DiagMsg::parse(&buf);
    }
    // Exact boundary probes around the fixed record size.
    for len in 0..=128 {
        let _ = DiagMsg::parse(&vec![0xFF; len]);
    }
}

#[test]
fn proc_event_never_panics_on_arbitrary_bytes() {
    for buf in random_corpus(0x920C, 2_000, 256) {
        let _ = ProcEvent::parse(&buf);
    }
    for len in 0..=96 {
        let _ = ProcEvent::parse(&vec![0x00; len]);
        let _ = ProcEvent::parse(&vec![0xFF; len]);
    }
}

#[test]
fn conntrack_flow_never_panics_on_arbitrary_bytes() {
    // The conntrack payload is a nested attribute walk — the shape most prone
    // to length-confusion bugs (attribute lengths are attacker-shaped numbers
    // as far as the parser is concerned).
    for buf in random_corpus(0xC077, 2_000, 512) {
        let _ = ConntrackFlow::parse(&buf);
    }
    // Attributes claiming lengths beyond the buffer.
    let mut lying = Vec::new();
    lying.extend_from_slice(&[0u8; 4]); // nfgenmsg
    lying.extend_from_slice(&0xFFFFu16.to_ne_bytes()); // nla_len: enormous
    lying.extend_from_slice(&1u16.to_ne_bytes()); // nla_type
    let _ = ConntrackFlow::parse(&lying);
    // Zero-length attribute: must not loop forever or panic.
    let mut zero = Vec::new();
    zero.extend_from_slice(&[0u8; 4]);
    zero.extend_from_slice(&0u16.to_ne_bytes());
    zero.extend_from_slice(&1u16.to_ne_bytes());
    let _ = ConntrackFlow::parse(&zero);
}
