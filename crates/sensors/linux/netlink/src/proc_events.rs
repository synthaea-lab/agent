//! Byte-level encode/decode for `NETLINK_CONNECTOR`'s proc-connector sub-protocol
//! (`<linux/connector.h>` + `<linux/cn_proc.h>`): the `cn_msg` envelope every
//! connector message wears, and the `struct proc_event` payload the kernel
//! broadcasts for fork/exec/exit. Pure, allocation-light, and unit-tested against
//! synthetic byte layouts pinned to the kernel headers (there is no equivalent of
//! `wire.rs`'s real captured socket record here — a proc-connector broadcast is
//! transient and root-only to observe, see `proc_socket`'s test for the live
//! round trip instead).
//!
//! Field endianness: like [`crate::wire`], every integer here is host byte order
//! (`to_ne_bytes`/`from_ne_bytes`) — `cn_msg` and `proc_event` are local kernel↔
//! userspace structs, not a wire protocol with a fixed byte order.

/// `cb_id.idx` for the process-events connector — see `CN_IDX_PROC` in
/// `<linux/cn_proc.h>`.
pub const CN_IDX_PROC: u32 = 0x1;
/// `cb_id.val` for the process-events connector — `CN_VAL_PROC`.
pub const CN_VAL_PROC: u32 = 0x1;

/// `enum proc_cn_mcast_op` — sent as the sole payload of a subscribe/unsubscribe
/// `cn_msg` to turn broadcast delivery on or off for this socket.
pub const PROC_CN_MCAST_LISTEN: u32 = 1;
#[allow(dead_code)] // not sent yet — sockets are one-shot subscribers, closed to unsubscribe
pub const PROC_CN_MCAST_IGNORE: u32 = 2;

/// `struct cb_id` (`idx` + `val`, 4 bytes each) followed by `seq`/`ack` (4 bytes
/// each) and `len`/`flags` (2 bytes each) — `sizeof(struct cn_msg)`, not counting
/// its flexible `data[]` tail.
pub const CN_MSG_HDR_LEN: usize = 20;

/// `struct cn_msg` — the envelope every connector message (request or broadcast)
/// wears, wrapping a `NETLINK_CONNECTOR`-specific `data[]` payload inside the
/// generic `nlmsghdr` from [`crate::wire`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CnMsgHeader {
    pub idx: u32,
    pub val: u32,
    pub seq: u32,
    pub ack: u32,
    /// Length of the `data[]` tail that follows this header, not including it.
    pub len: u16,
    pub flags: u16,
}

impl CnMsgHeader {
    #[must_use]
    pub fn to_bytes(self) -> [u8; CN_MSG_HDR_LEN] {
        let mut buf = [0u8; CN_MSG_HDR_LEN];
        buf[0..4].copy_from_slice(&self.idx.to_ne_bytes());
        buf[4..8].copy_from_slice(&self.val.to_ne_bytes());
        buf[8..12].copy_from_slice(&self.seq.to_ne_bytes());
        buf[12..16].copy_from_slice(&self.ack.to_ne_bytes());
        buf[16..18].copy_from_slice(&self.len.to_ne_bytes());
        buf[18..20].copy_from_slice(&self.flags.to_ne_bytes());
        buf
    }

    /// Parses the first [`CN_MSG_HDR_LEN`] bytes of `buf`. `None` if `buf` is too
    /// short.
    #[must_use]
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < CN_MSG_HDR_LEN {
            return None;
        }
        // Indexed byte-by-byte (not `try_into().unwrap()` on a slice) so there
        // is no explicit panic point to document: the length check above
        // already guarantees every index used below is in bounds — see
        // `wire::DiagMsg::parse` for the same discipline.
        Some(Self {
            idx: u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]),
            val: u32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]),
            seq: u32::from_ne_bytes([buf[8], buf[9], buf[10], buf[11]]),
            ack: u32::from_ne_bytes([buf[12], buf[13], buf[14], buf[15]]),
            len: u16::from_ne_bytes([buf[16], buf[17]]),
            flags: u16::from_ne_bytes([buf[18], buf[19]]),
        })
    }
}

/// `what` + `cpu` (4 bytes each) + `timestamp_ns` (8 bytes, naturally 8-byte
/// aligned right after them) — `struct proc_event`'s fixed header, before the
/// `event_data` union this module cares about.
pub const PROC_EVENT_HDR_LEN: usize = 16;

pub const PROC_EVENT_FORK: u32 = 0x0000_0001;
pub const PROC_EVENT_EXEC: u32 = 0x0000_0002;
pub const PROC_EVENT_EXIT: u32 = 0x8000_0000;

/// One `struct proc_event` broadcast, decoded to the three event kinds this
/// crate's eBPF cross-check needs (see the crate doc). `PROC_EVENT_UID`/`_GID`/
/// `_SID`/`_PTRACE`/`_COMM`/`_COREDUMP` all exist in the kernel enum too, but
/// none of them map onto anything the `sensor-linux-ebpf` stream also reports —
/// nothing to cross-check them against yet, so they fold into [`Other`](ProcEvent::Other)
/// rather than getting their own dead variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcEvent {
    Fork {
        parent_pid: u32,
        parent_tgid: u32,
        child_pid: u32,
        child_tgid: u32,
    },
    Exec {
        pid: u32,
        tgid: u32,
    },
    /// `exit_proc_event` also carries `parent_pid`/`parent_tgid`, dropped here:
    /// the eBPF lineage stream (issue #53/#111) is the authoritative source for
    /// parentage, this cross-check only needs "did this pid exit, with what
    /// code/signal".
    Exit {
        pid: u32,
        tgid: u32,
        exit_code: u32,
        exit_signal: u32,
    },
    /// An event kind this module doesn't decode further, carrying the raw
    /// `what` bit so a caller can at least log/count it.
    Other(u32),
}

impl ProcEvent {
    /// Parses a `struct proc_event` from `payload` — the bytes of a `cn_msg`'s
    /// `data[]` tail, i.e. everything after [`CnMsgHeader`]. `None` if `payload`
    /// is shorter than [`PROC_EVENT_HDR_LEN`], or a recognized `what` doesn't
    /// have enough trailing bytes for its own union member (a malformed or
    /// truncated broadcast — silently dropping it is the same discipline
    /// `DiagMsg::parse` uses for a short `payload`).
    #[must_use]
    pub fn parse(payload: &[u8]) -> Option<Self> {
        if payload.len() < PROC_EVENT_HDR_LEN {
            return None;
        }
        // Byte-by-byte, not `try_into().unwrap()` — see `CnMsgHeader::parse`.
        let what = u32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let body = &payload[PROC_EVENT_HDR_LEN..];

        // A `match` with length guards (`PROC_EVENT_FORK if body.len() >= 16`)
        // would silently fall through to the `other` catch-all when a
        // recognized `what` has a too-short body — decoding a truncated FORK
        // as an opaque `Other(PROC_EVENT_FORK)` instead of rejecting it. Each
        // arm checks its own length and returns `None` explicitly instead.
        match what {
            PROC_EVENT_FORK => {
                if body.len() < 16 {
                    return None;
                }
                Some(Self::Fork {
                    parent_pid: u32::from_ne_bytes([body[0], body[1], body[2], body[3]]),
                    parent_tgid: u32::from_ne_bytes([body[4], body[5], body[6], body[7]]),
                    child_pid: u32::from_ne_bytes([body[8], body[9], body[10], body[11]]),
                    child_tgid: u32::from_ne_bytes([body[12], body[13], body[14], body[15]]),
                })
            }
            PROC_EVENT_EXEC => {
                if body.len() < 8 {
                    return None;
                }
                Some(Self::Exec {
                    pid: u32::from_ne_bytes([body[0], body[1], body[2], body[3]]),
                    tgid: u32::from_ne_bytes([body[4], body[5], body[6], body[7]]),
                })
            }
            PROC_EVENT_EXIT => {
                if body.len() < 16 {
                    return None;
                }
                Some(Self::Exit {
                    pid: u32::from_ne_bytes([body[0], body[1], body[2], body[3]]),
                    tgid: u32::from_ne_bytes([body[4], body[5], body[6], body[7]]),
                    exit_code: u32::from_ne_bytes([body[8], body[9], body[10], body[11]]),
                    exit_signal: u32::from_ne_bytes([body[12], body[13], body[14], body[15]]),
                })
            }
            other => Some(Self::Other(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc_event_bytes(what: u32, cpu: u32, timestamp_ns: u64, body: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(PROC_EVENT_HDR_LEN + body.len());
        buf.extend_from_slice(&what.to_ne_bytes());
        buf.extend_from_slice(&cpu.to_ne_bytes());
        buf.extend_from_slice(&timestamp_ns.to_ne_bytes());
        buf.extend_from_slice(body);
        buf
    }

    #[test]
    fn cn_msg_header_round_trips() {
        let header = CnMsgHeader {
            idx: CN_IDX_PROC,
            val: CN_VAL_PROC,
            seq: 0,
            ack: 0,
            len: 4,
            flags: 0,
        };
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), CN_MSG_HDR_LEN);
        assert_eq!(CnMsgHeader::parse(&bytes), Some(header));
    }

    #[test]
    fn cn_msg_header_parse_rejects_a_short_buffer() {
        assert_eq!(CnMsgHeader::parse(&[0u8; CN_MSG_HDR_LEN - 1]), None);
    }

    #[test]
    fn parses_a_fork_event() {
        let mut body = Vec::new();
        body.extend_from_slice(&100u32.to_ne_bytes()); // parent_pid
        body.extend_from_slice(&100u32.to_ne_bytes()); // parent_tgid
        body.extend_from_slice(&4242u32.to_ne_bytes()); // child_pid
        body.extend_from_slice(&4242u32.to_ne_bytes()); // child_tgid
        let bytes = proc_event_bytes(PROC_EVENT_FORK, 0, 123_456_789, &body);

        assert_eq!(
            ProcEvent::parse(&bytes),
            Some(ProcEvent::Fork {
                parent_pid: 100,
                parent_tgid: 100,
                child_pid: 4242,
                child_tgid: 4242,
            })
        );
    }

    #[test]
    fn parses_an_exec_event() {
        let mut body = Vec::new();
        body.extend_from_slice(&4242u32.to_ne_bytes()); // process_pid
        body.extend_from_slice(&4242u32.to_ne_bytes()); // process_tgid
        let bytes = proc_event_bytes(PROC_EVENT_EXEC, 1, 123_456_789, &body);

        assert_eq!(
            ProcEvent::parse(&bytes),
            Some(ProcEvent::Exec {
                pid: 4242,
                tgid: 4242,
            })
        );
    }

    #[test]
    fn parses_an_exit_event_and_drops_its_parent_fields() {
        let mut body = Vec::new();
        body.extend_from_slice(&4242u32.to_ne_bytes()); // process_pid
        body.extend_from_slice(&4242u32.to_ne_bytes()); // process_tgid
        body.extend_from_slice(&0u32.to_ne_bytes()); // exit_code
        body.extend_from_slice(&0u32.to_ne_bytes()); // exit_signal
        body.extend_from_slice(&100u32.to_ne_bytes()); // parent_pid — dropped by parse
        body.extend_from_slice(&100u32.to_ne_bytes()); // parent_tgid — dropped by parse
        let bytes = proc_event_bytes(PROC_EVENT_EXIT, 0, 123_456_789, &body);

        assert_eq!(
            ProcEvent::parse(&bytes),
            Some(ProcEvent::Exit {
                pid: 4242,
                tgid: 4242,
                exit_code: 0,
                exit_signal: 0,
            })
        );
    }

    #[test]
    fn unrecognized_what_becomes_other() {
        let bytes = proc_event_bytes(0x0000_0200, 0, 0, &[]); // PROC_EVENT_COMM, not decoded
        assert_eq!(
            ProcEvent::parse(&bytes),
            Some(ProcEvent::Other(0x0000_0200))
        );
    }

    #[test]
    fn truncated_header_is_rejected() {
        assert_eq!(ProcEvent::parse(&[0u8; PROC_EVENT_HDR_LEN - 1]), None);
    }

    #[test]
    fn a_recognized_what_with_a_truncated_body_is_rejected_not_garbage_decoded() {
        // PROC_EVENT_FORK claimed, but only 4 of the 16 required body bytes present.
        let bytes = proc_event_bytes(PROC_EVENT_FORK, 0, 0, &[0u8; 4]);
        assert_eq!(ProcEvent::parse(&bytes), None);
    }
}
