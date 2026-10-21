//! Decoder for the messages `SynthaeaFilter` sends on its port (milestone 2c, #136).
//!
//! The format is the one in `docs/architecture/minifilter-event-channel.md` (protocol v3): a
//! fixed 72-byte little-endian header, then the paths in UTF-16LE, `old_path` then `new_path`, not
//! NUL-terminated. This module sees only the payload: the `FILTER_MESSAGE_HEADER` that
//! `FilterGetMessage` puts in front of it is stripped by the caller.
//!
//! ADR-0012 guardrail 7: the bytes come from the kernel, but they are still treated as hostile
//! input. Every read is bounds-checked, every length is validated against the buffer before it
//! is used, and nothing here can panic or allocate more than the message itself justifies.
//! Platform-independent on purpose, so the decoder is tested and fuzzed on every OS.

/// Bytes before the paths.
pub const HEADER_LEN: usize = 72;

/// Longest path, in UTF-16 code units, the driver puts in a record (a longer one is truncated
/// and flagged). The decoder refuses a length above it.
pub const MAX_PATH_UNITS: usize = 4_096;

/// Largest message the driver can send: the header and two maximal paths.
pub const MAX_MESSAGE_LEN: usize = HEADER_LEN + 2 * 2 * MAX_PATH_UNITS;

const KIND_HEARTBEAT: u16 = 0;
const KIND_DELETE: u16 = 1;
const KIND_RENAME: u16 = 2;

const FLAG_DELETE_ON_CLOSE: u16 = 1 << 0;
const FLAG_OLD_PATH_TRUNCATED: u16 = 1 << 1;
const FLAG_NEW_PATH_TRUNCATED: u16 = 1 << 2;
const KNOWN_FLAGS: u16 = FLAG_DELETE_ON_CLOSE | FLAG_OLD_PATH_TRUNCATED | FLAG_NEW_PATH_TRUNCATED;

/// 100 ns intervals between 1601-01-01 (the `FILETIME` epoch) and 1970-01-01.
const FILETIME_UNIX_EPOCH: i64 = 116_444_736_000_000_000;

/// Loss counters the driver keeps since it was loaded, carried in every message so the agent
/// always has the current figures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counters {
    /// Records dropped because the in-kernel queue was over its record or byte cap.
    pub dropped_queue_full: u64,
    /// Records dropped because `FltSendMessage` failed or timed out.
    pub dropped_send_failed: u64,
    /// Operations not queued because no agent was connected.
    pub not_connected: u64,
    /// Operations of a reported kind that succeeded but could not be captured (protocol v3,
    /// found by the low-resources lab run of #857): their names or their record could not be
    /// obtained, so nothing was queued. Without it, those losses were silent.
    pub dropped_capture_failed: u64,
}

/// What a message reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// The queue has been empty for a while: the driver and its sender thread are alive.
    Heartbeat,
    /// A delete was requested and accepted (disposition or delete-on-close). The file goes away
    /// at the last handle close, and another handle can still cancel it.
    Delete {
        path: String,
        /// Requested at open (`FILE_DELETE_ON_CLOSE`) rather than by a disposition.
        on_close: bool,
        truncated: bool,
    },
    /// A rename that succeeded.
    Rename {
        old_path: String,
        new_path: String,
        old_truncated: bool,
        new_truncated: bool,
    },
}

/// One decoded message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Per-connection sequence number, starting at 1: a gap means records were lost.
    pub seq: u64,
    /// When the driver saw the operation, in nanoseconds since the Unix epoch.
    pub timestamp_ns: u64,
    pub pid: u64,
    pub tid: u64,
    pub counters: Counters,
    pub body: Body,
}

/// Why a message was refused. Each one means the driver and the agent disagree on the format
/// (or the bytes are not from the driver): the caller drops the message and counts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("message of {0} bytes is shorter than the {HEADER_LEN}-byte header")]
    TooShort(usize),
    #[error("message of {0} bytes is longer than the largest the driver sends")]
    TooLong(usize),
    #[error("unknown message kind {0}")]
    UnknownKind(u16),
    #[error("unknown flag bits {0:#06x}")]
    UnknownFlags(u16),
    #[error("flags {flags:#06x} do not apply to message kind {kind}")]
    FlagsForKind { kind: u16, flags: u16 },
    #[error("path lengths {old} and {new} do not fit message kind {kind}")]
    PathLengthsForKind { kind: u16, old: u16, new: u16 },
    #[error("path of {0} UTF-16 units is longer than the driver's cap")]
    PathTooLong(u16),
    #[error("message of {actual} bytes, its header announces {expected}")]
    LengthMismatch { expected: usize, actual: usize },
    #[error("sequence number 0 (the driver starts at 1)")]
    ZeroSequence,
    #[error("timestamp {0} is before 1970")]
    TimestampBeforeEpoch(i64),
    #[error("timestamp {0} does not fit in a 64-bit nanosecond count")]
    TimestampOverflow(i64),
}

/// Decodes one message payload.
///
/// # Errors
///
/// [`WireError`] when the bytes are not a well-formed message; nothing is partially returned.
pub fn decode(bytes: &[u8]) -> Result<Message, WireError> {
    if bytes.len() < HEADER_LEN {
        return Err(WireError::TooShort(bytes.len()));
    }
    if bytes.len() > MAX_MESSAGE_LEN {
        return Err(WireError::TooLong(bytes.len()));
    }
    let mut r = Reader { bytes, at: 0 };
    let kind = r.u16();
    let flags = r.u16();
    let seq = r.u64();
    let timestamp = r.i64();
    let pid = r.u64();
    let tid = r.u64();
    let counters = Counters {
        dropped_queue_full: r.u64(),
        dropped_send_failed: r.u64(),
        not_connected: r.u64(),
        dropped_capture_failed: 0,
    };
    let old_len = r.u16();
    let new_len = r.u16();
    // v3 appends the fourth counter after the path lengths, at byte 64.
    let counters = Counters {
        dropped_capture_failed: r.u64(),
        ..counters
    };
    debug_assert_eq!(r.at, HEADER_LEN);

    if flags & !KNOWN_FLAGS != 0 {
        return Err(WireError::UnknownFlags(flags & !KNOWN_FLAGS));
    }
    let allowed_flags = match kind {
        KIND_HEARTBEAT => 0,
        KIND_DELETE => FLAG_DELETE_ON_CLOSE | FLAG_OLD_PATH_TRUNCATED,
        KIND_RENAME => FLAG_OLD_PATH_TRUNCATED | FLAG_NEW_PATH_TRUNCATED,
        other => return Err(WireError::UnknownKind(other)),
    };
    if flags & !allowed_flags != 0 {
        return Err(WireError::FlagsForKind { kind, flags });
    }
    let lengths_fit = match kind {
        KIND_HEARTBEAT => old_len == 0 && new_len == 0,
        KIND_DELETE => old_len > 0 && new_len == 0,
        _ => old_len > 0 && new_len > 0,
    };
    if !lengths_fit {
        return Err(WireError::PathLengthsForKind {
            kind,
            old: old_len,
            new: new_len,
        });
    }
    for len in [old_len, new_len] {
        if usize::from(len) > MAX_PATH_UNITS {
            return Err(WireError::PathTooLong(len));
        }
    }
    let expected = HEADER_LEN + 2 * (usize::from(old_len) + usize::from(new_len));
    if bytes.len() != expected {
        return Err(WireError::LengthMismatch {
            expected,
            actual: bytes.len(),
        });
    }
    if seq == 0 {
        return Err(WireError::ZeroSequence);
    }
    let timestamp_ns = filetime_to_unix_ns(timestamp)?;

    let old_path = r.utf16(old_len);
    let new_path = r.utf16(new_len);
    let body = match kind {
        KIND_HEARTBEAT => Body::Heartbeat,
        KIND_DELETE => Body::Delete {
            path: old_path,
            on_close: flags & FLAG_DELETE_ON_CLOSE != 0,
            truncated: flags & FLAG_OLD_PATH_TRUNCATED != 0,
        },
        _ => Body::Rename {
            old_path,
            new_path,
            old_truncated: flags & FLAG_OLD_PATH_TRUNCATED != 0,
            new_truncated: flags & FLAG_NEW_PATH_TRUNCATED != 0,
        },
    };
    Ok(Message {
        seq,
        timestamp_ns,
        pid,
        tid,
        counters,
        body,
    })
}

/// `KeQuerySystemTimePrecise` (100 ns since 1601) to nanoseconds since 1970.
fn filetime_to_unix_ns(filetime: i64) -> Result<u64, WireError> {
    let since_epoch = filetime
        .checked_sub(FILETIME_UNIX_EPOCH)
        .filter(|t| *t >= 0)
        .ok_or(WireError::TimestampBeforeEpoch(filetime))?;
    // A non-negative i64 of 100 ns units times 100 can overflow u64 (i64::MAX * 100 is
    // roughly 50x u64::MAX): reject rather than silently clamp to u64::MAX, which would
    // make an attacker-controlled or corrupted far-future timestamp indistinguishable
    // from a genuinely maximal one (#853 review).
    u64::try_from(since_epoch)
        .ok()
        .and_then(|units| units.checked_mul(100))
        .ok_or(WireError::TimestampOverflow(filetime))
}

/// Little-endian reads over a buffer whose length the caller has already checked; every read
/// stays in bounds by construction, and the `get` keeps it so if a caller gets that wrong.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        if let Some(src) = self.bytes.get(self.at..self.at + N) {
            out.copy_from_slice(src);
        }
        self.at += N;
        out
    }

    fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.take())
    }

    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take())
    }

    fn i64(&mut self) -> i64 {
        i64::from_le_bytes(self.take())
    }

    /// `units` UTF-16LE code units, decoded lossily (an unpaired surrogate becomes U+FFFD).
    fn utf16(&mut self, units: u16) -> String {
        let end = self.at + 2 * usize::from(units);
        let raw = self.bytes.get(self.at..end).unwrap_or(&[]);
        self.at = end;
        let code_units = raw
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
        char::decode_utf16(code_units)
            .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect()
    }
}

/// Encodes a message the way the driver does. For tests and the fuzz target's seed corpus
/// only; the agent never sends to the driver.
#[cfg(test)]
pub(crate) fn encode(message: &Message, raw_timestamp: i64) -> Vec<u8> {
    let (kind, flags, old, new): (u16, u16, Vec<u16>, Vec<u16>) = match &message.body {
        Body::Heartbeat => (KIND_HEARTBEAT, 0, Vec::new(), Vec::new()),
        Body::Delete {
            path,
            on_close,
            truncated,
        } => (
            KIND_DELETE,
            (u16::from(*on_close) * FLAG_DELETE_ON_CLOSE)
                | (u16::from(*truncated) * FLAG_OLD_PATH_TRUNCATED),
            path.encode_utf16().collect(),
            Vec::new(),
        ),
        Body::Rename {
            old_path,
            new_path,
            old_truncated,
            new_truncated,
        } => (
            KIND_RENAME,
            (u16::from(*old_truncated) * FLAG_OLD_PATH_TRUNCATED)
                | (u16::from(*new_truncated) * FLAG_NEW_PATH_TRUNCATED),
            old_path.encode_utf16().collect(),
            new_path.encode_utf16().collect(),
        ),
    };
    let mut out = Vec::with_capacity(HEADER_LEN + 2 * (old.len() + new.len()));
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&message.seq.to_le_bytes());
    out.extend_from_slice(&raw_timestamp.to_le_bytes());
    out.extend_from_slice(&message.pid.to_le_bytes());
    out.extend_from_slice(&message.tid.to_le_bytes());
    out.extend_from_slice(&message.counters.dropped_queue_full.to_le_bytes());
    out.extend_from_slice(&message.counters.dropped_send_failed.to_le_bytes());
    out.extend_from_slice(&message.counters.not_connected.to_le_bytes());
    out.extend_from_slice(&u16::try_from(old.len()).unwrap().to_le_bytes());
    out.extend_from_slice(&u16::try_from(new.len()).unwrap().to_le_bytes());
    out.extend_from_slice(&message.counters.dropped_capture_failed.to_le_bytes());
    for unit in old.iter().chain(&new) {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// 2025-10-12T12:00:00Z as a FILETIME, and the same instant in Unix ns.
    const RAW_TS: i64 = FILETIME_UNIX_EPOCH + 17_602_704_000_000_000;
    const UNIX_NS: u64 = 1_760_270_400_000_000_000;

    fn message(body: Body) -> Message {
        Message {
            seq: 7,
            timestamp_ns: UNIX_NS,
            pid: 4_242,
            tid: 4_243,
            counters: Counters {
                dropped_queue_full: 1,
                dropped_send_failed: 2,
                not_connected: 3,
                dropped_capture_failed: 4,
            },
            body,
        }
    }

    fn delete() -> Message {
        message(Body::Delete {
            path: r"\Device\HarddiskVolume3\Users\alice\report.docx".into(),
            on_close: false,
            truncated: false,
        })
    }

    fn rename() -> Message {
        message(Body::Rename {
            old_path: r"\Device\HarddiskVolume3\data\x.docx".into(),
            new_path: r"\Device\HarddiskVolume3\data\x.docx.locked".into(),
            old_truncated: false,
            new_truncated: true,
        })
    }

    #[test]
    fn the_header_is_seventy_two_bytes() {
        assert_eq!(encode(&message(Body::Heartbeat), RAW_TS).len(), HEADER_LEN);
    }

    #[test]
    fn each_kind_round_trips() {
        for m in [message(Body::Heartbeat), delete(), rename()] {
            assert_eq!(decode(&encode(&m, RAW_TS)), Ok(m));
        }
        // #136 ADS slice 2: a named stream's `:streamname` suffix is an
        // ordinary part of the path string on the wire — nothing strips or
        // escapes a colon, so a delete or a rename of a stream round-trips
        // exactly like any other path. The property test below excludes `:`
        // from its generated paths, so this is the only coverage for it.
        let stream_delete = message(Body::Delete {
            path: r"\Device\HarddiskVolume3\Users\alice\report.docx:hidden".into(),
            on_close: false,
            truncated: false,
        });
        assert_eq!(decode(&encode(&stream_delete, RAW_TS)), Ok(stream_delete));
        let stream_rename = message(Body::Rename {
            old_path: r"\Device\HarddiskVolume3\data\x.docx:hidden".into(),
            new_path: r"\Device\HarddiskVolume3\data\x.docx:renamed".into(),
            old_truncated: false,
            new_truncated: false,
        });
        assert_eq!(decode(&encode(&stream_rename, RAW_TS)), Ok(stream_rename));
        let on_close = message(Body::Delete {
            path: "x".into(),
            on_close: true,
            truncated: true,
        });
        assert_eq!(decode(&encode(&on_close, RAW_TS)), Ok(on_close));
    }

    #[test]
    fn the_timestamp_is_converted_from_filetime_to_unix_ns() {
        assert_eq!(
            decode(&encode(&delete(), RAW_TS)).unwrap().timestamp_ns,
            UNIX_NS
        );
        let at_epoch = decode(&encode(&delete(), FILETIME_UNIX_EPOCH)).unwrap();
        assert_eq!(at_epoch.timestamp_ns, 0);
        assert_eq!(
            decode(&encode(&delete(), FILETIME_UNIX_EPOCH - 1)),
            Err(WireError::TimestampBeforeEpoch(FILETIME_UNIX_EPOCH - 1))
        );
        assert_eq!(
            decode(&encode(&delete(), i64::MIN)),
            Err(WireError::TimestampBeforeEpoch(i64::MIN))
        );
        // A far-future timestamp whose nanosecond count would overflow u64 is refused,
        // not silently clamped to u64::MAX (#853 review).
        assert_eq!(
            decode(&encode(&delete(), i64::MAX)),
            Err(WireError::TimestampOverflow(i64::MAX))
        );
    }

    #[test]
    fn every_truncation_of_a_valid_message_is_refused() {
        let bytes = encode(&rename(), RAW_TS);
        for len in 0..bytes.len() {
            assert!(
                decode(&bytes[..len]).is_err(),
                "prefix of {len} bytes was accepted"
            );
        }
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut bytes = encode(&delete(), RAW_TS);
        bytes.extend_from_slice(&[0, 0]);
        assert!(matches!(
            decode(&bytes),
            Err(WireError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn a_message_longer_than_the_largest_is_refused_before_reading_it() {
        let bytes = vec![0u8; MAX_MESSAGE_LEN + 1];
        assert_eq!(decode(&bytes), Err(WireError::TooLong(MAX_MESSAGE_LEN + 1)));
    }

    #[test]
    fn path_lengths_must_fit_the_kind() {
        let set_lengths = |mut bytes: Vec<u8>, old: u16, new: u16| {
            bytes[60..62].copy_from_slice(&old.to_le_bytes());
            bytes[62..64].copy_from_slice(&new.to_le_bytes());
            bytes
        };
        let heartbeat = encode(&message(Body::Heartbeat), RAW_TS);
        assert!(matches!(
            decode(&set_lengths(heartbeat, 1, 0)),
            Err(WireError::PathLengthsForKind { .. })
        ));
        let del = encode(&delete(), RAW_TS);
        let old = u16::from_le_bytes([del[60], del[61]]);
        assert!(matches!(
            decode(&set_lengths(del.clone(), 0, 0)),
            Err(WireError::PathLengthsForKind { .. })
        ));
        assert!(matches!(
            decode(&set_lengths(del, old, 1)),
            Err(WireError::PathLengthsForKind { .. })
        ));
        let ren = encode(&rename(), RAW_TS);
        assert!(matches!(
            decode(&set_lengths(ren, 5, 0)),
            Err(WireError::PathLengthsForKind { .. })
        ));
    }

    #[test]
    fn a_length_field_at_its_maximum_is_refused_without_reading_past_the_buffer() {
        let mut bytes = encode(&delete(), RAW_TS);
        bytes[60..62].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(decode(&bytes), Err(WireError::PathTooLong(u16::MAX)));
    }

    #[test]
    fn unknown_kinds_and_flags_are_refused() {
        let mut bytes = encode(&delete(), RAW_TS);
        bytes[0..2].copy_from_slice(&3u16.to_le_bytes());
        assert_eq!(decode(&bytes), Err(WireError::UnknownKind(3)));

        let mut bytes = encode(&delete(), RAW_TS);
        bytes[2..4].copy_from_slice(&0x0008u16.to_le_bytes());
        assert_eq!(decode(&bytes), Err(WireError::UnknownFlags(0x0008)));
    }

    #[test]
    fn flags_that_do_not_apply_to_the_kind_are_refused() {
        // delete-on-close on a rename, a new-path truncation on a delete, anything on a heartbeat
        for (body, flags) in [
            (rename(), FLAG_DELETE_ON_CLOSE),
            (delete(), FLAG_NEW_PATH_TRUNCATED),
            (message(Body::Heartbeat), FLAG_OLD_PATH_TRUNCATED),
        ] {
            let mut bytes = encode(&body, RAW_TS);
            bytes[2..4].copy_from_slice(&flags.to_le_bytes());
            assert!(
                matches!(decode(&bytes), Err(WireError::FlagsForKind { .. })),
                "{flags:#x} accepted on {:?}",
                body.body
            );
        }
    }

    #[test]
    fn sequence_zero_is_refused() {
        let mut m = delete();
        m.seq = 0;
        assert_eq!(decode(&encode(&m, RAW_TS)), Err(WireError::ZeroSequence));
    }

    #[test]
    fn the_capture_failed_counter_sits_at_byte_64_and_paths_start_at_72() {
        // Pins the v3 layout byte by byte, independently of `encode`: the driver's C_ASSERTs
        // put the fourth counter after the two path lengths (60 and 62).
        let mut bytes = encode(&delete(), RAW_TS);
        bytes[64..72].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        let message = decode(&bytes).unwrap();
        assert_eq!(
            message.counters.dropped_capture_failed,
            0x0102_0304_0506_0708
        );
        assert_eq!(HEADER_LEN, 72);
        let path_units = u16::from_le_bytes([bytes[60], bytes[61]]);
        assert_eq!(bytes.len(), 72 + 2 * usize::from(path_units));
    }

    #[test]
    fn an_unpaired_surrogate_is_replaced_not_refused() {
        let mut bytes = encode(&delete(), RAW_TS);
        // Overwrite the first path unit with a lone high surrogate.
        bytes[HEADER_LEN..HEADER_LEN + 2].copy_from_slice(&0xD800u16.to_le_bytes());
        let Body::Delete { path, .. } = decode(&bytes).unwrap().body else {
            panic!("not a delete");
        };
        assert!(path.starts_with(char::REPLACEMENT_CHARACTER));
    }

    #[test]
    fn a_maximal_rename_is_accepted() {
        let long = "a".repeat(MAX_PATH_UNITS);
        let m = message(Body::Rename {
            old_path: long.clone(),
            new_path: long,
            old_truncated: true,
            new_truncated: true,
        });
        let bytes = encode(&m, RAW_TS);
        assert_eq!(bytes.len(), MAX_MESSAGE_LEN);
        assert_eq!(decode(&bytes), Ok(m));
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            let _ = decode(&bytes);
        }

        #[test]
        fn arbitrary_headers_with_consistent_lengths_never_panic(
            header in prop::collection::vec(any::<u8>(), HEADER_LEN),
            old in 0u16..64,
            new in 0u16..64,
            fill in any::<u8>(),
        ) {
            let mut bytes = header;
            bytes[60..62].copy_from_slice(&old.to_le_bytes());
            bytes[62..64].copy_from_slice(&new.to_le_bytes());
            bytes.resize(HEADER_LEN + 2 * (usize::from(old) + usize::from(new)), fill);
            let _ = decode(&bytes);
        }

        #[test]
        fn any_valid_rename_round_trips(
            old in "[a-zA-Z0-9\\\\. ]{1,200}",
            new in "[a-zA-Z0-9\\\\. ]{1,200}",
            seq in 1u64..,
            pid in any::<u64>(),
            secs in 0i64..4_000_000_000,
        ) {
            let m = Message {
                seq,
                timestamp_ns: u64::try_from(secs).unwrap() * 1_000_000_000,
                pid,
                tid: pid ^ 1,
                counters: Counters::default(),
                body: Body::Rename { old_path: old, new_path: new, old_truncated: false, new_truncated: false },
            };
            let raw = FILETIME_UNIX_EPOCH + secs * 10_000_000;
            prop_assert_eq!(decode(&encode(&m, raw)), Ok(m));
        }
    }
}
