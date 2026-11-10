//! Rebuilds one exec's argv from the kernel's `EXECVE` records (#51).
//!
//! `audit_log_execve_info` writes `aN="..."` (or bare hex) only for an argument that
//! fits in the current record. Anything longer becomes `aN_len=<wire length>` followed
//! by pieces `aN[0]=`, `aN[1]=`, ... A long argv continues in further `EXECVE`
//! records that share the event's serial, and only the first of them carries `argc`:
//!
//! ```text
//! audit(...:5): argc=3 a0="sh" a1="-c" a2_len=16010 a2[0]=<hex>
//! audit(...:5): a2[1]=<hex>
//! audit(...:5): a2[2]=<hex>
//! ```
//!
//! Reading only `aN` from the first record dropped such an exec outright, so padding
//! one argument past ~7.5 KB hid the exec from every rule on the auditd path.
//! [`ExecveAssembler`] holds an event's `EXECVE` records until the next record of
//! another type or serial (the kernel writes them back to back, then `CWD`, `PATH`,
//! `PROCTITLE`, `EOE`), then rebuilds the argv. An argv it cannot rebuild whole is
//! still emitted with what arrived, flagged incomplete: truncation, never rejection.

// The assembler's only user is `sensor.rs`, which is Linux-only; `assemble` itself
// also serves `classify` everywhere.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::HashMap;

use crate::{
    classify::{AUDIT_EXECVE, AuditEvent, decoded_field, hex_decode},
    parse::AuditRecord,
};

/// Wire bytes of field values held for one exec before further `EXECVE` records
/// are discarded. Hex doubles the size, so four times [`schema::ARGV_CAPTURE_BUDGET`]
/// still holds a full budget of hex-encoded argv plus the other fields, after which
/// `bound_argv` cuts the rest anyway.
const MAX_PENDING_BYTES: usize = 4 * schema::ARGV_CAPTURE_BUDGET;

/// Charged per held record on top of its values, so a run of empty records is
/// bounded too.
const RECORD_OVERHEAD: usize = 64;

/// An exec rebuilt from its `EXECVE` records, with the first record's timestamp.
#[derive(Debug)]
pub(crate) struct AssembledExec {
    pub(crate) event: AuditEvent,
    pub(crate) timestamp_sec: u64,
    pub(crate) timestamp_ms: u32,
}

/// Holds the `EXECVE` records of the exec in progress; see the module doc.
#[derive(Debug, Default)]
pub(crate) struct ExecveAssembler {
    pending: Option<Pending>,
}

#[derive(Debug)]
struct Pending {
    seq: u64,
    records: Vec<AuditRecord>,
    held_bytes: usize,
    /// A record was discarded at [`MAX_PENDING_BYTES`].
    overflowed: bool,
}

impl ExecveAssembler {
    /// Takes the next record off the socket. Returns the previous exec once this
    /// record shows its `EXECVE` records are over; an `EXECVE` record itself is held,
    /// not classified.
    pub(crate) fn push(&mut self, record: &AuditRecord) -> Option<AssembledExec> {
        let is_execve = record.record_type == AUDIT_EXECVE;
        let continues = is_execve && self.pending.as_ref().is_some_and(|p| p.seq == record.seq);
        if continues {
            if let Some(pending) = self.pending.as_mut() {
                pending.hold(record);
            }
            return None;
        }
        let done = self.finish();
        if is_execve {
            let mut pending = Pending {
                seq: record.seq,
                records: Vec::new(),
                held_bytes: 0,
                overflowed: false,
            };
            pending.hold(record);
            self.pending = Some(pending);
        }
        done
    }

    /// Rebuilds the exec in progress, if any. For the sensor's exit, when no next
    /// record will come to close it.
    pub(crate) fn finish(&mut self) -> Option<AssembledExec> {
        let pending = self.pending.take()?;
        let first = pending.records.first()?;
        let (timestamp_sec, timestamp_ms) = (first.timestamp_sec, first.timestamp_ms);
        let event = assemble(&pending.records, pending.overflowed)?;
        Some(AssembledExec {
            event,
            timestamp_sec,
            timestamp_ms,
        })
    }
}

impl Pending {
    fn hold(&mut self, record: &AuditRecord) {
        let cost = record
            .fields
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .fold(RECORD_OVERHEAD, usize::saturating_add);
        if cost > MAX_PENDING_BYTES.saturating_sub(self.held_bytes) {
            self.overflowed = true;
            return;
        }
        self.held_bytes += cost;
        self.records.push(record.clone());
    }
}

/// Rebuilds an exec from the `EXECVE` records of one event, first record first.
///
/// `None` without `argc` on the first record (a continuation whose head was lost
/// is not an exec this can attribute) or without a first argument.
pub(crate) fn assemble(records: &[AuditRecord], overflowed: bool) -> Option<AuditEvent> {
    let first = records.first()?;
    let argc: usize = first.fields.get("argc")?.parse().ok()?;

    // The earliest record wins a key the kernel never repeats anyway.
    let by_key: HashMap<&str, &AuditRecord> = records
        .iter()
        .rev()
        .flat_map(|record| record.fields.keys().map(move |key| (key.as_str(), record)))
        .collect();

    let mut argv = Vec::new();
    let mut incomplete = overflowed;
    for index in 0..argc {
        match argument(&by_key, index) {
            Some((value, whole)) => {
                argv.push(value);
                if !whole {
                    incomplete = true;
                    break;
                }
            }
            None => {
                incomplete = true;
                break;
            }
        }
    }

    let image_path = argv.first()?.clone();
    let id = |key: &str| {
        first
            .fields
            .get(key)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    };
    Some(AuditEvent::Exec {
        pid: id("pid"),
        uid: id("uid"),
        gid: id("gid"),
        image_path,
        argv,
        argv_incomplete: incomplete,
    })
}

/// Argument `index` and whether it arrived whole: `aN`, or the run of pieces
/// `aN[0]`, `aN[1]`, ... checked against `aN_len`.
fn argument(by_key: &HashMap<&str, &AuditRecord>, index: usize) -> Option<(String, bool)> {
    let key = format!("a{index}");
    if let Some(record) = by_key.get(key.as_str()) {
        return decoded_field(record, &key).map(|value| (value, true));
    }

    let mut bytes = Vec::new();
    let mut wire_len = 0usize;
    for piece in 0usize.. {
        let piece_key = format!("a{index}[{piece}]");
        let Some(record) = by_key.get(piece_key.as_str()) else {
            break;
        };
        let Some(value) = record.fields.get(&piece_key) else {
            break;
        };
        wire_len = wire_len.saturating_add(value.len());
        // A piece the kernel hex-encoded arrives unquoted; it is decoded on its own
        // (the kernel splits on an even number of hex digits), and the bytes are
        // joined before UTF-8 decoding so a character cut between pieces survives.
        match record
            .unquoted_fields
            .contains(&piece_key)
            .then(|| hex_decode(value).ok())
            .flatten()
        {
            Some(decoded) => bytes.extend_from_slice(&decoded),
            None => bytes.extend_from_slice(value.as_bytes()),
        }
    }
    if wire_len == 0 && !by_key.contains_key(format!("a{index}[0]").as_str()) {
        return None;
    }

    let declared = by_key
        .get(format!("a{index}_len").as_str())
        .and_then(|record| record.fields.get(&format!("a{index}_len")))
        .and_then(|len| len.parse::<usize>().ok());
    let whole = declared.is_some_and(|len| wire_len >= len);
    Some((String::from_utf8_lossy(&bytes).into_owned(), whole))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{build_wire_message, parse_audit_message};

    const AUDIT_CWD: u16 = 1307;

    fn record(record_type: u16, seq: u64, fields: &str) -> AuditRecord {
        let raw = build_wire_message(record_type, &format!("audit(1000.250:{seq}): {fields}"));
        parse_audit_message(&raw).expect("test record parses")
    }

    fn hex(s: &str) -> String {
        s.bytes().map(|b| format!("{b:02X}")).collect()
    }

    fn exec_of(assembled: Option<AssembledExec>) -> (Vec<String>, bool) {
        match assembled.map(|a| a.event) {
            Some(AuditEvent::Exec {
                argv,
                argv_incomplete,
                ..
            }) => (argv, argv_incomplete),
            other => panic!("expected an exec, got {other:?}"),
        }
    }

    /// Feeds `records`, then a `CWD` record of the same serial, as the kernel does.
    fn run(records: &[AuditRecord]) -> Option<AssembledExec> {
        let mut assembler = ExecveAssembler::default();
        for r in records {
            assert!(assembler.push(r).is_none(), "nothing is due before the CWD");
        }
        let seq = records.first().map_or(0, |r| r.seq);
        assembler.push(&record(AUDIT_CWD, seq, "cwd=\"/\""))
    }

    #[test]
    fn a_split_argument_across_three_records_is_rebuilt() {
        // #51: the kernel's shape for `sh -c "true <8,000 chars>"` (Alpine 6.18).
        let script = format!("true {}", "A".repeat(8000));
        let encoded = hex(&script);
        let (p0, rest) = encoded.split_at(7400);
        let (p1, p2) = rest.split_at(7400);
        let records = [
            record(
                1309,
                5,
                &format!(
                    "argc=3 a0=\"sh\" a1=\"-c\" a2_len={} a2[0]={p0}",
                    encoded.len()
                ),
            ),
            record(1309, 5, &format!("a2[1]={p1}")),
            record(1309, 5, &format!("a2[2]={p2}")),
        ];
        let (argv, incomplete) = exec_of(run(&records));
        assert_eq!(argv, ["sh", "-c", script.as_str()]);
        assert!(!incomplete);
    }

    #[test]
    fn a_long_argv_continues_in_the_next_record() {
        let records = [
            record(1309, 9, "argc=4 a0=\"/bin/echo\" a1=\"one\""),
            record(1309, 9, "a2=\"two\" a3=74687265652066"),
        ];
        let (argv, incomplete) = exec_of(run(&records));
        assert_eq!(argv, ["/bin/echo", "one", "two", "three f"]);
        assert!(!incomplete);
    }

    #[test]
    fn a_short_argument_cut_at_a_record_boundary_is_one_quoted_piece() {
        // Debian 6.1, `/bin/true` with 600 arguments (serial 194 in
        // vm-debian12/results/r51): the argument that straddles the record end is
        // logged as `aN_len` plus a single quoted piece, and the next record resumes
        // at aN+1.
        let records = [
            record(1309, 194, "argc=4 a0=\"/bin/true\" a1=\"y1\""),
            record(1309, 194, " a2_len=21 a2[0]=\"yyyyyyyyyyyyyyyyyy518\""),
            record(1309, 194, " a3=\"yyyyyyyyyyyyyyyyyy519\""),
        ];
        let (argv, incomplete) = exec_of(run(&records));
        assert_eq!(
            argv,
            [
                "/bin/true",
                "y1",
                "yyyyyyyyyyyyyyyyyy518",
                "yyyyyyyyyyyyyyyyyy519"
            ]
        );
        assert!(!incomplete);
    }

    #[test]
    fn quoted_pieces_are_joined_as_written() {
        let records = [
            record(1309, 3, "argc=2 a0=\"/bin/true\" a1_len=6 a1[0]=\"abc\""),
            record(1309, 3, "a1[1]=\"def\""),
        ];
        let (argv, incomplete) = exec_of(run(&records));
        assert_eq!(argv, ["/bin/true", "abcdef"]);
        assert!(!incomplete);
    }

    #[test]
    fn a_character_cut_between_hex_pieces_survives() {
        // "é" is C3 A9: the kernel's split may fall between the two bytes.
        let records = [record(
            1309,
            4,
            "argc=2 a0=\"/bin/echo\" a1_len=6 a1[0]=78C3 a1[1]=A978",
        )];
        let (argv, _) = exec_of(run(&records));
        assert_eq!(argv[1], "x\u{e9}x");
    }

    #[test]
    fn a_missing_piece_still_emits_the_exec_flagged_incomplete() {
        // The kernel dropped the second record (backlog): the exec must not vanish.
        let records = [record(
            1309,
            6,
            "argc=3 a0=\"sh\" a1=\"-c\" a2_len=20 a2[0]=\"0123456789\"",
        )];
        let (argv, incomplete) = exec_of(run(&records));
        assert_eq!(argv, ["sh", "-c", "0123456789"]);
        assert!(incomplete);
    }

    #[test]
    fn a_missing_argument_keeps_the_head_flagged_incomplete() {
        let records = [record(1309, 7, "argc=3 a0=\"sh\" a1=\"-c\"")];
        let (argv, incomplete) = exec_of(run(&records));
        assert_eq!(argv, ["sh", "-c"]);
        assert!(incomplete);
    }

    #[test]
    fn records_beyond_the_hold_bound_are_dropped_and_flagged() {
        let piece = "41".repeat(3700);
        let mut records = vec![record(
            1309,
            8,
            &format!("argc=2 a0=\"x\" a1_len=99999999 a1[0]={piece}"),
        )];
        for k in 1..100 {
            records.push(record(1309, 8, &format!("a1[{k}]={piece}")));
        }
        let (argv, incomplete) = exec_of(run(&records));
        assert!(incomplete);
        assert!(
            argv[1].len() <= MAX_PENDING_BYTES / 2,
            "the hold is bounded"
        );
    }

    #[test]
    fn a_new_serial_closes_the_previous_exec() {
        let mut assembler = ExecveAssembler::default();
        assert!(
            assembler
                .push(&record(1309, 1, "argc=1 a0=\"/bin/id\""))
                .is_none()
        );
        let (argv, _) = exec_of(assembler.push(&record(1309, 2, "argc=1 a0=\"/bin/ls\"")));
        assert_eq!(argv, ["/bin/id"]);
        let (argv, _) = exec_of(assembler.finish());
        assert_eq!(argv, ["/bin/ls"]);
        assert!(assembler.finish().is_none());
    }

    #[test]
    fn a_continuation_without_its_head_is_not_an_exec() {
        let mut assembler = ExecveAssembler::default();
        assert!(assembler.push(&record(1309, 4, "a2[1]=4142")).is_none());
        assert!(assembler.push(&record(AUDIT_CWD, 4, "cwd=\"/\"")).is_none());
    }

    #[test]
    fn the_exec_keeps_its_first_record_timestamp() {
        let assembled = run(&[record(1309, 5, "argc=1 a0=\"/bin/id\"")]).expect("an exec");
        assert_eq!(
            (assembled.timestamp_sec, assembled.timestamp_ms),
            (1000, 250)
        );
    }

    #[test]
    fn hostile_piece_shapes_never_panic() {
        let payloads = [
            "argc=18446744073709551615 a0=\"x\"",
            "argc=2 a0=\"x\" a1_len=18446744073709551615 a1[0]=4",
            "argc=2 a0=\"x\" a1_len=-1 a1[0]=ZZ a1[1]=\"\"",
            "argc=2 a0=\"x\" a1[1]=41 a1[3]=42",
            "argc=1 a0[0]=FF a0_len=2",
            "argc=0",
            "argc=1",
        ];
        for payload in payloads {
            let _ = run(&[record(1309, 1, payload)]);
        }
    }
}
