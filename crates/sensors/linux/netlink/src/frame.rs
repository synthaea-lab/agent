//! Splits one received netlink buffer into its messages. Pure: bytes in, `(type, payload)`
//! pairs out, no socket and no I/O, so the framing can be tested and fuzzed without a kernel.
//!
//! A datagram read from a netlink socket holds one or more messages back to back, each one a
//! 16-byte [`NlMsgHeader`] followed by its payload and padded to a 4-byte boundary
//! (`NLMSG_ALIGN`). Every reader in this crate walks its buffer the same way, so this is the
//! one place that does.

use crate::wire::{NLMSG_HDR_LEN, NlMsgHeader};

/// A message whose header cannot be trusted. The rest of the buffer is not walked after one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[allow(missing_docs)] // #362
pub enum FrameError {
    /// The header's length field is smaller than the header itself.
    #[error("netlink message length {len} is shorter than its {NLMSG_HDR_LEN}-byte header")]
    ShorterThanHeader { len: u32 },
    /// The header's length field reaches past the end of the received bytes.
    #[error("netlink message of {len} bytes overruns the {available} bytes received")]
    Overrun { len: u32, available: usize },
}

/// Iterates over the messages in `buf` as `(msg_type, payload)`, payload being the bytes after the
/// header and before the padding.
///
/// - Fewer than [`NLMSG_HDR_LEN`] bytes left is the end of the buffer, not an error: a reader
///   walking a stream cannot tell trailing padding from a message it has not finished receiving.
/// - A header that claims an impossible length yields one [`FrameError`] and then nothing: the
///   position of the next message is unknown, so none is guessed.
/// - The padding after the last message may be missing. Nothing past the end of `buf` is read.
///
/// Never panics, whatever `buf` holds.
#[must_use]
pub fn netlink_messages(buf: &[u8]) -> NetlinkMessages<'_> {
    NetlinkMessages { rest: buf }
}

/// The iterator returned by [`netlink_messages`].
#[derive(Debug, Clone)]
pub struct NetlinkMessages<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for NetlinkMessages<'a> {
    type Item = Result<(u16, &'a [u8]), FrameError>;

    fn next(&mut self) -> Option<Self::Item> {
        let header = NlMsgHeader::parse(self.rest)?;
        let len = header.len as usize;
        let failure = if len < NLMSG_HDR_LEN {
            Some(FrameError::ShorterThanHeader { len: header.len })
        } else if len > self.rest.len() {
            Some(FrameError::Overrun {
                len: header.len,
                available: self.rest.len(),
            })
        } else {
            None
        };
        if let Some(error) = failure {
            self.rest = &[];
            return Some(Err(error));
        }

        let payload = &self.rest[NLMSG_HDR_LEN..len];
        // NLMSG_ALIGN. `get` rather than a slice: the padding of the last message may be missing,
        // and `len` is only known to fit in `rest`, not its aligned size.
        self.rest = self.rest.get((len + 3) & !3..).unwrap_or(&[]);
        Some(Ok((header.msg_type, payload)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{NLMSG_DONE, NLMSG_ERROR};

    /// One message as the kernel lays it out: header, payload, zero padding to 4 bytes.
    fn message(msg_type: u16, payload: &[u8], padded: bool) -> Vec<u8> {
        let header = NlMsgHeader {
            len: (NLMSG_HDR_LEN + payload.len()) as u32,
            msg_type,
            flags: 0,
            seq: 1,
            pid: 0,
        };
        let mut out = header.to_bytes().to_vec();
        out.extend_from_slice(payload);
        if padded {
            while !out.len().is_multiple_of(4) {
                out.push(0);
            }
        }
        out
    }

    fn collect(buf: &[u8]) -> Vec<Result<(u16, Vec<u8>), FrameError>> {
        netlink_messages(buf)
            .map(|item| item.map(|(msg_type, payload)| (msg_type, payload.to_vec())))
            .collect()
    }

    #[test]
    fn an_empty_buffer_has_no_messages() {
        assert!(collect(&[]).is_empty());
    }

    #[test]
    fn fewer_bytes_than_a_header_are_the_end_not_an_error() {
        assert!(collect(&[0u8; NLMSG_HDR_LEN - 1]).is_empty());
    }

    #[test]
    fn one_message_with_an_aligned_payload() {
        let buf = message(20, &[1, 2, 3, 4], true);
        assert_eq!(collect(&buf), [Ok((20, vec![1, 2, 3, 4]))]);
    }

    #[test]
    fn a_message_without_payload_is_a_message() {
        let buf = message(NLMSG_DONE, &[], true);
        assert_eq!(collect(&buf), [Ok((NLMSG_DONE, vec![]))]);
    }

    #[test]
    fn padding_is_skipped_to_find_the_next_message() {
        // A 5-byte payload: the length field says 21, the next header starts at 24.
        let mut buf = message(20, &[1, 2, 3, 4, 5], true);
        assert_eq!(buf.len(), 24);
        buf.extend(message(NLMSG_DONE, &[], true));
        assert_eq!(
            collect(&buf),
            [Ok((20, vec![1, 2, 3, 4, 5])), Ok((NLMSG_DONE, vec![]))]
        );
    }

    #[test]
    fn the_last_message_may_lack_its_padding() {
        // The length field says 21 and the buffer ends at 21: the aligned end (24) is past it.
        // Walking on from there must stop, not slice out of range.
        let buf = message(20, &[1, 2, 3, 4, 5], false);
        assert_eq!(buf.len(), 21);
        assert_eq!(collect(&buf), [Ok((20, vec![1, 2, 3, 4, 5]))]);
    }

    #[test]
    fn bytes_after_the_last_message_that_cannot_hold_a_header_are_ignored() {
        let mut buf = message(20, &[1, 2, 3, 4], true);
        buf.extend_from_slice(&[0xAA; NLMSG_HDR_LEN - 1]);
        assert_eq!(collect(&buf), [Ok((20, vec![1, 2, 3, 4]))]);
    }

    #[test]
    fn an_error_message_carries_its_payload() {
        // `struct nlmsgerr`: a negated errno (-EPERM, i.e. -1) then the echoed request header.
        let mut payload = (-1i32).to_ne_bytes().to_vec();
        payload.extend_from_slice(&[0u8; NLMSG_HDR_LEN]);
        let buf = message(NLMSG_ERROR, &payload, true);
        assert_eq!(collect(&buf), [Ok((NLMSG_ERROR, payload))]);
    }

    #[test]
    fn a_length_shorter_than_the_header_ends_the_walk() {
        let mut buf = message(20, &[1, 2, 3, 4], true);
        let mut bad = message(21, &[], true);
        bad[0..4].copy_from_slice(&(NLMSG_HDR_LEN as u32 - 1).to_ne_bytes());
        buf.extend(bad);
        buf.extend(message(22, &[9, 9, 9, 9], true));

        assert_eq!(
            collect(&buf),
            [
                Ok((20, vec![1, 2, 3, 4])),
                Err(FrameError::ShorterThanHeader {
                    len: NLMSG_HDR_LEN as u32 - 1
                }),
            ],
            "nothing after the bad header is trusted"
        );
    }

    #[test]
    fn a_zero_length_does_not_loop() {
        let buf = [0u8; 64];
        assert_eq!(
            collect(&buf),
            [Err(FrameError::ShorterThanHeader { len: 0 })]
        );
    }

    #[test]
    fn a_length_past_the_end_of_the_buffer_is_an_overrun() {
        let mut buf = message(20, &[1, 2, 3, 4], true);
        let full = buf.len();
        buf.truncate(full - 1);
        assert_eq!(
            collect(&buf),
            [Err(FrameError::Overrun {
                len: full as u32,
                available: full - 1
            })]
        );
    }

    #[test]
    fn the_largest_length_does_not_overflow() {
        let mut buf = message(20, &[], true);
        buf[0..4].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert_eq!(
            collect(&buf),
            [Err(FrameError::Overrun {
                len: u32::MAX,
                available: NLMSG_HDR_LEN
            })]
        );
    }

    #[test]
    fn arbitrary_bytes_never_panic_and_always_end() {
        // xorshift: reproducible, no dependency. Small lengths and a header-shaped bias make
        // the interesting cases (length near the buffer size, near the alignment boundary) common.
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..20_000 {
            let len = (next() % 96) as usize;
            let mut buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if buf.len() >= 4 && next().is_multiple_of(2) {
                let claimed = (next() % (len as u64 + 8)) as u32;
                buf[0..4].copy_from_slice(&claimed.to_ne_bytes());
            }
            // Each yielded message consumes at least a header, so the walk is bounded.
            let yielded = netlink_messages(&buf).count();
            assert!(yielded <= len / NLMSG_HDR_LEN + 1, "{buf:?}");
        }
    }
}
