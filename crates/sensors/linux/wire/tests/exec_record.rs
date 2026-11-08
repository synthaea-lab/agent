//! The variable-length exec record (<https://github.com/synthaea-lab/agent/issues/48>, ADR-0045). Its lengths describe bytes a process
//! chose, so `parse_exec_record` accepts exactly the shapes the probe writes and never reads past
//! the record: a refused record is an `Err`, never a panic (a panic on the drain path kills the
//! sensor).

use core::mem::{offset_of, size_of};

use sensor_linux_wire::{
    ARGV_HEAD_BYTES, ARGV_TAIL_BYTES, ARGV_WINDOW_BYTES, ExecEvent, ExecRecordError,
    parse_exec_record,
};

const FIXED: usize = size_of::<ExecEvent>();

/// A record whose fixed part is zero except for the three argv fields, followed by `body`.
fn record(total: u32, head: u16, tail: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; FIXED];
    let at = offset_of!(ExecEvent, argv_total);
    bytes[at..at + 4].copy_from_slice(&total.to_ne_bytes());
    let at = offset_of!(ExecEvent, argv_head_len);
    bytes[at..at + 2].copy_from_slice(&head.to_ne_bytes());
    let at = offset_of!(ExecEvent, argv_tail_len);
    bytes[at..at + 2].copy_from_slice(&tail.to_ne_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn len(n: usize) -> u16 {
    u16::try_from(n).unwrap()
}

#[test]
fn a_record_with_no_argv_is_the_proc_fallback() {
    let rec = record(0, 0, 0, b"");
    let (_, argv) = parse_exec_record(&rec).unwrap();
    assert_eq!((argv.total, argv.head, argv.tail), (0, &b""[..], &b""[..]));
    // A block the probe measured but could not read (a failed head read) is the same fallback.
    let rec = record(5000, 0, 0, b"");
    let (_, argv) = parse_exec_record(&rec).unwrap();
    assert!(argv.head.is_empty() && argv.tail.is_empty());
}

#[test]
fn a_block_that_fits_is_read_whole() {
    let body = b"ls\0-la\0";
    let rec = record(7, 7, 0, body);
    let (_, argv) = parse_exec_record(&rec).unwrap();
    assert_eq!((argv.head, argv.tail), (&body[..], &b""[..]));
}

#[test]
fn a_block_over_the_window_is_a_head_and_a_tail() {
    let body: Vec<u8> = (0..ARGV_WINDOW_BYTES).map(|i| (i % 251) as u8).collect();
    let rec = record(9000, len(ARGV_HEAD_BYTES), len(ARGV_TAIL_BYTES), &body);
    let (_, argv) = parse_exec_record(&rec).unwrap();
    assert_eq!(argv.head, &body[..ARGV_HEAD_BYTES]);
    assert_eq!(argv.tail, &body[ARGV_HEAD_BYTES..]);
    // The tail read failed: the head alone.
    let rec = record(9000, len(ARGV_HEAD_BYTES), 0, &body[..ARGV_HEAD_BYTES]);
    assert!(parse_exec_record(&rec).unwrap().1.tail.is_empty());
}

#[test]
fn bytes_after_the_announced_windows_are_ignored() {
    let rec = record(3, 3, 0, b"ab\0trailing");
    assert_eq!(parse_exec_record(&rec).unwrap().1.head, b"ab\0");
}

#[test]
fn lengths_the_probe_never_writes_are_refused() {
    let full = vec![b'x'; ARGV_WINDOW_BYTES + 64];
    for (total, head, tail) in [
        (10, 9, 0),                                        // head disagrees with a block that fits
        (10, 0, 4),                                        // a tail without a head
        (2000, 900, 0),                                    // over the window but not a head window
        (2000, len(ARGV_HEAD_BYTES), 100),                 // a tail that is not the tail window
        (900, len(ARGV_HEAD_BYTES), len(ARGV_TAIL_BYTES)), // two windows for a block that fits
        (u32::MAX, u16::MAX, u16::MAX),                    // everything at its maximum
    ] {
        assert_eq!(
            parse_exec_record(&record(total, head, tail, &full)).err(),
            Some(ExecRecordError::BadLengths),
            "total={total} head={head} tail={tail}"
        );
    }
}

#[test]
fn a_record_shorter_than_its_lengths_is_refused_not_read_past() {
    let rec = record(
        9000,
        len(ARGV_HEAD_BYTES),
        len(ARGV_TAIL_BYTES),
        &[b'x'; 100],
    );
    assert_eq!(
        parse_exec_record(&rec).err(),
        Some(ExecRecordError::Truncated)
    );
    assert_eq!(
        parse_exec_record(&rec[..FIXED - 1]).err(),
        Some(ExecRecordError::Short)
    );
    assert_eq!(parse_exec_record(&[]).err(), Some(ExecRecordError::Short));
}

/// Minimal deterministic PRNG (Knuth LCG): a reproducible corpus, no dependency.
fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

#[test]
fn arbitrary_bytes_never_panic() {
    let mut state = 0xE8EC_u64;
    for _ in 0..3_000 {
        let n = (lcg(&mut state) as usize) % (FIXED + ARGV_WINDOW_BYTES + 64);
        let buf: Vec<u8> = (0..n).map(|_| (lcg(&mut state) >> 33) as u8).collect();
        let _ = parse_exec_record(&buf);
    }
}

#[test]
fn arbitrary_lengths_over_a_valid_fixed_part_never_panic_and_stay_in_bounds() {
    let mut state = 0x1118_u64;
    for _ in 0..5_000 {
        let total = (lcg(&mut state) >> 32) as u32;
        let head = (lcg(&mut state) >> 48) as u16;
        let tail = (lcg(&mut state) >> 48) as u16;
        let body_len = (lcg(&mut state) as usize) % (ARGV_WINDOW_BYTES + 64);
        let rec = record(total, head, tail, &vec![0xA5; body_len]);
        if let Ok((_, argv)) = parse_exec_record(&rec) {
            assert!(argv.head.len() + argv.tail.len() <= ARGV_WINDOW_BYTES);
            assert!(FIXED + argv.head.len() + argv.tail.len() <= rec.len());
        }
    }
}
