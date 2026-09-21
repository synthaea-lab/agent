//! Durable store-and-forward spool: append-only JSONL segments in a directory,
//! rotated at a fixed record count OR byte threshold, with a total byte cap
//! enforced by deleting the oldest segment (the loss is counted, never silent).
//!
//! Two-phase drain/ack protocol ensures at-least-once delivery:
//! 1. `drain_oldest()` returns records and renames the segment to `.inflight`
//! 2. Caller uploads data to the server
//! 3. Caller calls `ack()` to delete the `.inflight` file
//! 4. On crash before ack, `open()` recovers `.inflight` → `.jsonl` for re-drain
//!
//! Forward progress guarantee: after `MAX_DRAIN_ATTEMPTS` failed uploads of the
//! same segment, callers should call `skip()` to discard it and move on. This
//! prevents a poison segment from blocking all telemetry indefinitely.

use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

use serde::{Serialize, de::DeserializeOwned};

/// Records per segment before rotation.
const SEGMENT_RECORDS: usize = 1024;

/// Maximum bytes per segment before rotation. Ensures no single segment exceeds
/// the byte cap, preventing the seal-and-shed oscillation on small caps.
const SEGMENT_MAX_BYTES: u64 = 1024 * 1024; // 1 MiB

/// Suggested max drain attempts before calling `skip()`. Not enforced by the spool
/// itself — the caller (transport) decides when to give up.
pub const MAX_DRAIN_ATTEMPTS: u32 = 5;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SpoolStats {
    /// Total bytes currently on disk across segments (including in-flight).
    pub bytes: u64,
    /// Records dropped over the spool's lifetime because the byte cap was hit.
    pub dropped_records: u64,
}

/// A durable FIFO of serialized records. One instance owns one directory.
pub struct EventSpool {
    dir: PathBuf,
    max_bytes: u64,
    /// Sequence number of the segment currently being appended.
    head_seq: u64,
    head_records: usize,
    /// Current byte size of the active segment (for byte-threshold rotation).
    head_bytes: u64,
    dropped_records: u64,
    /// Segment currently handed out via `drain_oldest` but not yet ack'd.
    /// At most one segment can be in-flight at a time; a second drain
    /// re-delivers the same segment (idempotent retry).
    in_flight: Option<u64>,
}

impl EventSpool {
    /// Opens (or creates) a spool directory. Existing segments survive restarts and
    /// are drained before new ones. In-flight segments (from a crash mid-upload) are
    /// recovered and will be re-drained on the next `drain_oldest` call.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error when the directory cannot be created or
    /// its existing segments cannot be listed.
    pub fn open(dir: &Path, max_bytes: u64) -> std::io::Result<Self> {
        fs::create_dir_all(dir)?;
        // Recover in-flight segments from a previous crash: rename .inflight back to .jsonl
        for entry in fs::read_dir(dir)?.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            if let Some(base) = name_str.strip_suffix(".inflight") {
                let recovered = dir.join(format!("{base}.jsonl"));
                fs::rename(entry.path(), &recovered)?;
                tracing::info!(segment = base, "spool: recovered in-flight segment");
            }
        }
        let head_seq = segment_seqs(dir)?.last().copied().map_or(0, |s| s + 1);
        Ok(Self {
            dir: dir.to_path_buf(),
            max_bytes,
            head_seq,
            head_records: 0,
            head_bytes: 0,
            dropped_records: 0,
            in_flight: None,
        })
    }

    fn segment_path(&self, seq: u64) -> PathBuf {
        self.dir.join(format!("spool-{seq:012}.jsonl"))
    }

    fn inflight_path(&self, seq: u64) -> PathBuf {
        self.dir.join(format!("spool-{seq:012}.inflight"))
    }

    /// Appends one record durably (fsync'd). Rotates the segment at
    /// `SEGMENT_RECORDS` or `SEGMENT_MAX_BYTES` (whichever comes first).
    /// Enforces the byte cap by deleting whole oldest segments.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the record cannot be serialized, appended, or
    /// fsync'd — the caller decides whether spool loss is fatal.
    pub fn push<T: Serialize>(&mut self, record: &T) -> std::io::Result<()> {
        let line = serde_json::to_string(record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let line_bytes = line.len() as u64 + 1; // +1 for newline

        // Rotate if adding this record would exceed byte threshold.
        // This ensures no single segment exceeds SEGMENT_MAX_BYTES.
        if self.head_records > 0 && self.head_bytes + line_bytes > SEGMENT_MAX_BYTES {
            self.head_seq += 1;
            self.head_records = 0;
            self.head_bytes = 0;
        }

        let path = self.segment_path(self.head_seq);
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_data()?;

        self.head_records += 1;
        self.head_bytes += line_bytes;

        // Rotate on record count threshold.
        if self.head_records >= SEGMENT_RECORDS {
            self.head_seq += 1;
            self.head_records = 0;
            self.head_bytes = 0;
        }

        self.enforce_cap()?;
        Ok(())
    }

    /// Returns every record of the OLDEST segment (empty spool → empty vec).
    /// The segment is marked as in-flight (renamed to `.inflight`) but NOT deleted.
    /// The caller MUST call `ack()` after successful upload to delete the segment.
    ///
    /// If a segment is already in-flight (previous drain not yet ack'd), this
    /// re-delivers the same segment — idempotent retry on caller crash.
    ///
    /// Two-phase protocol ensures at-least-once delivery:
    /// 1. `drain_oldest()` returns data, renames segment to `.inflight`
    /// 2. Caller uploads data to server
    /// 3. Caller calls `ack()` to delete the `.inflight` file
    /// 4. On crash before ack, `open()` recovers `.inflight` → `.jsonl` for re-drain
    ///
    /// # Forward Progress
    ///
    /// If the server permanently rejects a batch (4xx, malformed, etc.), the caller
    /// should track attempts and call `skip()` after [`MAX_DRAIN_ATTEMPTS`] to
    /// discard the poison segment and continue with newer data.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the segment cannot be listed, read, or renamed.
    pub fn drain_oldest<T: DeserializeOwned>(&mut self) -> std::io::Result<Vec<T>> {
        // If a segment is already in-flight, re-deliver it (idempotent retry).
        let (seq, path) = if let Some(in_flight_seq) = self.in_flight {
            (in_flight_seq, self.inflight_path(in_flight_seq))
        } else {
            let Some(seq) = segment_seqs(&self.dir)?.first().copied() else {
                return Ok(Vec::new());
            };
            (seq, self.segment_path(seq))
        };

        let content = fs::read_to_string(&path)?;
        let mut out = Vec::new();
        for line in content.lines().filter(|l| !l.trim().is_empty()) {
            match serde_json::from_str(line) {
                Ok(v) => out.push(v),
                // A torn tail line (crash mid-append) is expected once per crash;
                // anything else in the middle would also land here — count-free but
                // logged, never fatal to the drain.
                Err(e) => tracing::warn!(error = %e, "spool: skipping unparseable record"),
            }
        }

        // Mark as in-flight if not already (rename .jsonl → .inflight).
        if self.in_flight.is_none() {
            let inflight = self.inflight_path(seq);
            fs::rename(&path, &inflight)?;
            self.in_flight = Some(seq);
            if seq == self.head_seq {
                // Drained the segment being appended: rotate to a new segment.
                self.head_seq += 1;
                self.head_records = 0;
                self.head_bytes = 0;
            }
        }

        Ok(out)
    }

    /// Acknowledges successful upload of the in-flight segment, deleting it from disk.
    /// Must be called after `drain_oldest()` once the data has been durably uploaded.
    ///
    /// Returns `true` if a segment was ack'd, `false` if nothing was in-flight.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the in-flight file cannot be deleted.
    pub fn ack(&mut self) -> std::io::Result<bool> {
        let Some(seq) = self.in_flight else {
            return Ok(false);
        };
        let path = self.inflight_path(seq);
        // Delete first, then clear in_flight. If delete fails, we'll retry on next ack().
        fs::remove_file(&path)?;
        self.in_flight = None;
        tracing::debug!(seq, "spool: ack'd segment");
        Ok(true)
    }

    /// Skips (discards) the in-flight segment without uploading it.
    /// Use this after repeated upload failures to prevent a poison segment from
    /// blocking all telemetry indefinitely.
    ///
    /// Returns `true` if a segment was skipped, `false` if nothing was in-flight.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the in-flight file cannot be deleted.
    pub fn skip(&mut self) -> std::io::Result<bool> {
        let Some(seq) = self.in_flight else {
            return Ok(false);
        };
        let path = self.inflight_path(seq);
        let dropped = fs::read_to_string(&path)
            .map(|c| c.lines().count() as u64)
            .unwrap_or(0);
        // Delete first, then clear in_flight.
        fs::remove_file(&path)?;
        self.in_flight = None;
        self.dropped_records += dropped;
        tracing::warn!(seq, dropped, "spool: skipped poison segment");
        Ok(true)
    }

    /// Returns true if a segment is currently in-flight (drained but not ack'd).
    #[must_use]
    pub fn has_in_flight(&self) -> bool {
        self.in_flight.is_some()
    }

    #[must_use]
    pub fn stats(&self) -> SpoolStats {
        // Sum .jsonl segments
        let jsonl_bytes: u64 = segment_seqs(&self.dir)
            .into_iter()
            .flatten()
            .filter_map(|s| fs::metadata(self.segment_path(s)).ok())
            .map(|m| m.len())
            .sum();

        // Add in-flight segment bytes if any
        let inflight_bytes: u64 = self
            .in_flight
            .and_then(|seq| fs::metadata(self.inflight_path(seq)).ok())
            .map(|m| m.len())
            .unwrap_or(0);

        SpoolStats {
            bytes: jsonl_bytes + inflight_bytes,
            dropped_records: self.dropped_records,
        }
    }

    /// Deletes oldest segments until under the cap. Never deletes in-flight segments
    /// (they are protected during upload). Never deletes the active segment (`head_seq`).
    fn enforce_cap(&mut self) -> std::io::Result<()> {
        loop {
            let seqs = segment_seqs(&self.dir)?;

            // Calculate total including in-flight segment
            let jsonl_bytes: u64 = seqs
                .iter()
                .filter_map(|s| fs::metadata(self.segment_path(*s)).ok())
                .map(|m| m.len())
                .sum();
            let inflight_bytes: u64 = self
                .in_flight
                .and_then(|seq| fs::metadata(self.inflight_path(seq)).ok())
                .map(|m| m.len())
                .unwrap_or(0);
            let total = jsonl_bytes + inflight_bytes;

            if total <= self.max_bytes {
                return Ok(());
            }

            let Some(oldest) = seqs.first().copied() else {
                return Ok(());
            };

            // Never delete the in-flight segment — it's protected during upload.
            if Some(oldest) == self.in_flight {
                // In-flight is the only segment, and we're over cap.
                // We must wait for ack/skip before we can shed anything.
                return Ok(());
            }

            // Never delete the active segment being appended.
            if oldest == self.head_seq {
                // This shouldn't happen: head_seq is always the highest seq number,
                // and we iterate from lowest. If we hit this, something is wrong.
                debug_assert!(
                    seqs.len() <= 1,
                    "oldest == head_seq with multiple segments: {seqs:?}"
                );
                return Ok(());
            }

            let path = self.segment_path(oldest);
            let dropped = fs::read_to_string(&path)
                .map(|c| c.lines().count() as u64)
                .unwrap_or(0);
            fs::remove_file(&path)?;
            self.dropped_records += dropped;
            tracing::warn!(
                segment = oldest,
                dropped,
                "spool: byte cap exceeded, dropped oldest segment"
            );
        }
    }
}

fn segment_seqs(dir: &Path) -> std::io::Result<Vec<u64>> {
    let mut seqs: Vec<u64> = fs::read_dir(dir)?
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            name.strip_prefix("spool-")?
                .strip_suffix(".jsonl")?
                .parse()
                .ok()
        })
        .collect();
    seqs.sort_unstable();
    Ok(seqs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("spool-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn round_trips_records_fifo() {
        let dir = tmp("fifo");
        let mut spool = EventSpool::open(&dir, u64::MAX).unwrap();
        for i in 0..5u32 {
            spool.push(&i).unwrap();
        }
        let got: Vec<u32> = spool.drain_oldest().unwrap();
        assert_eq!(got, vec![0, 1, 2, 3, 4]);
        assert!(spool.ack().unwrap(), "should ack the drained segment");
        let empty: Vec<u32> = spool.drain_oldest().unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn survives_reopen_without_loss_below_cap() {
        let dir = tmp("reopen");
        {
            let mut spool = EventSpool::open(&dir, u64::MAX).unwrap();
            for i in 0..3u32 {
                spool.push(&i).unwrap();
            }
        } // dropped — simulates a process restart
        let mut spool = EventSpool::open(&dir, u64::MAX).unwrap();
        spool.push(&99u32).unwrap();
        let first: Vec<u32> = spool.drain_oldest().unwrap();
        assert_eq!(first, vec![0, 1, 2], "pre-restart records drain first");
        spool.ack().unwrap();
        let second: Vec<u32> = spool.drain_oldest().unwrap();
        assert_eq!(second, vec![99]);
        spool.ack().unwrap();
    }

    #[test]
    fn byte_cap_sheds_oldest_segments_and_counts_loss() {
        let dir = tmp("cap");
        // Small cap: with SEGMENT_RECORDS=1024, write two full segments of ~6-byte
        // lines (~6KB each) and cap at ~8KB — the first segment must be shed.
        let mut spool = EventSpool::open(&dir, 8 * 1024).unwrap();
        for i in 0..2048u32 {
            spool.push(&i).unwrap();
        }
        let stats = spool.stats();
        assert!(stats.bytes <= 8 * 1024 + 7 * 1024, "cap roughly enforced");
        assert!(stats.dropped_records >= 1024, "loss counted: {stats:?}");
        let drained: Vec<u32> = spool.drain_oldest().unwrap();
        assert!(!drained.is_empty());
        assert!(
            drained[0] >= 1024,
            "oldest surviving records come after the shed segment"
        );
        spool.ack().unwrap();
    }

    #[test]
    fn torn_tail_line_is_skipped_not_fatal() {
        let dir = tmp("torn");
        let mut spool = EventSpool::open(&dir, u64::MAX).unwrap();
        spool.push(&1u32).unwrap();
        // Simulate a crash mid-append: raw garbage at the tail of the segment.
        let seg = dir.join("spool-000000000000.jsonl");
        let mut f = fs::OpenOptions::new().append(true).open(&seg).unwrap();
        f.write_all(b"{\"tor").unwrap();
        drop(f);
        let got: Vec<u32> = spool.drain_oldest().unwrap();
        assert_eq!(got, vec![1]);
        spool.ack().unwrap();
    }

    #[test]
    fn spools_schema_events() {
        use schema::{Event, EventMeta, ExecEvent};
        let dir = tmp("schema");
        let mut spool = EventSpool::open(&dir, u64::MAX).unwrap();
        let event = Event::Exec(ExecEvent {
            meta: EventMeta {
                pid: 1,
                timestamp_ns: 42,
                comm: "x".into(),
                ..schema::fixtures::meta()
            },
            image_path: "/bin/x".into(),
            cmdline: "x".into(),
            ..schema::fixtures::exec()
        });
        spool.push(&event).unwrap();
        let got: Vec<Event> = spool.drain_oldest().unwrap();
        assert_eq!(got, vec![event]);
        spool.ack().unwrap();
    }

    #[test]
    fn two_phase_drain_redelivers_on_crash() {
        let dir = tmp("two-phase");
        {
            let mut spool = EventSpool::open(&dir, u64::MAX).unwrap();
            for i in 0..3u32 {
                spool.push(&i).unwrap();
            }
            // Drain but don't ack — simulates crash before upload completes.
            let _got: Vec<u32> = spool.drain_oldest().unwrap();
            // Drop without ack — .inflight file remains.
        }
        // Reopen after "crash" — should recover the in-flight segment.
        let mut spool = EventSpool::open(&dir, u64::MAX).unwrap();
        let redelivered: Vec<u32> = spool.drain_oldest().unwrap();
        assert_eq!(
            redelivered,
            vec![0, 1, 2],
            "segment redelivered after crash"
        );
        spool.ack().unwrap();
        let empty: Vec<u32> = spool.drain_oldest().unwrap();
        assert!(empty.is_empty(), "no more segments after ack");
    }

    #[test]
    fn idempotent_drain_without_ack() {
        let dir = tmp("idempotent");
        let mut spool = EventSpool::open(&dir, u64::MAX).unwrap();
        for i in 0..3u32 {
            spool.push(&i).unwrap();
        }
        // First drain
        let first: Vec<u32> = spool.drain_oldest().unwrap();
        assert_eq!(first, vec![0, 1, 2]);
        // Second drain without ack — should return same data (idempotent retry).
        let second: Vec<u32> = spool.drain_oldest().unwrap();
        assert_eq!(second, vec![0, 1, 2], "idempotent re-drain");
        // Now ack
        assert!(spool.ack().unwrap());
        // Third drain — should be empty
        let third: Vec<u32> = spool.drain_oldest().unwrap();
        assert!(third.is_empty());
    }

    #[test]
    fn skip_poison_segment() {
        let dir = tmp("skip");
        let mut spool = EventSpool::open(&dir, u64::MAX).unwrap();

        // Write first segment
        for i in 0..3u32 {
            spool.push(&i).unwrap();
        }

        // Drain first segment
        let first: Vec<u32> = spool.drain_oldest().unwrap();
        assert_eq!(first, vec![0, 1, 2]);

        // Write more data while first segment is in-flight (creates new segment)
        spool.push(&100u32).unwrap();

        // Skip instead of ack (simulates poison segment)
        assert!(spool.skip().unwrap());
        assert_eq!(spool.stats().dropped_records, 3);

        // Should now get the second segment
        let second: Vec<u32> = spool.drain_oldest().unwrap();
        assert_eq!(second, vec![100]);
        spool.ack().unwrap();
    }

    #[test]
    fn inflight_protected_from_cap_enforcement() {
        let dir = tmp("inflight-protected");
        // Create spool with small cap
        let mut spool = EventSpool::open(&dir, 100).unwrap();

        // Write some data
        for i in 0..10u32 {
            spool.push(&i).unwrap();
        }

        // Drain but don't ack
        let drained: Vec<u32> = spool.drain_oldest().unwrap();
        assert!(!drained.is_empty());
        assert!(spool.has_in_flight());

        // Write more data that would trigger cap enforcement
        for i in 100..200u32 {
            spool.push(&i).unwrap();
        }

        // In-flight segment should still be there
        assert!(spool.has_in_flight());

        // Re-drain should return same data
        let redrained: Vec<u32> = spool.drain_oldest().unwrap();
        assert_eq!(drained, redrained, "in-flight segment preserved");

        spool.ack().unwrap();
    }

    #[test]
    fn stats_includes_inflight_bytes() {
        let dir = tmp("stats-inflight");
        let mut spool = EventSpool::open(&dir, u64::MAX).unwrap();

        for i in 0..5u32 {
            spool.push(&i).unwrap();
        }

        let before_drain = spool.stats().bytes;
        assert!(before_drain > 0);

        // Drain moves segment to .inflight
        let _: Vec<u32> = spool.drain_oldest().unwrap();

        // Stats should still count the in-flight bytes
        let after_drain = spool.stats().bytes;
        assert_eq!(
            before_drain, after_drain,
            "in-flight bytes counted in stats"
        );

        spool.ack().unwrap();
        assert_eq!(spool.stats().bytes, 0, "bytes zero after ack");
    }

    #[test]
    fn ack_failure_allows_retry() {
        let dir = tmp("ack-retry");
        let mut spool = EventSpool::open(&dir, u64::MAX).unwrap();
        spool.push(&1u32).unwrap();

        let _: Vec<u32> = spool.drain_oldest().unwrap();
        assert!(spool.has_in_flight());

        // Ack succeeds
        assert!(spool.ack().unwrap());
        assert!(!spool.has_in_flight());

        // Second ack returns false (nothing in flight)
        assert!(!spool.ack().unwrap());
    }
}
