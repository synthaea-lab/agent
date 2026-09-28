//! Mark-of-the-web (#365): the `Zone.Identifier` alternate data stream a
//! browser, mail client or archiver writes next to a downloaded file — the
//! Windows counterpart of macOS's `com.apple.quarantine` xattr, surfaced as the
//! same `schema::FileQuarantineEvent`.
//!
//! Platform-independent on purpose: the stream content is attacker-controlled
//! (anything can write an ADS), so the parser is unit-tested on every CI leg
//! and has a never-panic suite in `tests/robustness.rs`. Only the ETW hook
//! lives in the Windows-gated `providers`: it queues each write on
//! [`MarkQueue`], and a worker ([`run_mark_reader`]) does the read-back, off the
//! Kernel-File callback thread (#439).
//!
//! Lab-confirmed (2026-09-23, local Windows 11): Kernel-File reports a write to
//! the stream as a create/write on `C:\…\file.exe:Zone.Identifier`, for both a
//! `Set-Content -Stream` and a plain `CreateFileW` on `file:Zone.Identifier` —
//! two or three records per write, hence [`QuarantineDedup`].

use std::{
    collections::HashMap,
    fmt::Write as _,
    hash::{BuildHasher, RandomState},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
};

use schema::{Event, EventMeta, FileQuarantineEvent};

/// Stream suffix on the path Kernel-File reports. Matched case-insensitively;
/// an explicit `:$DATA` stream type is accepted too.
const STREAM_SUFFIX: &str = ":Zone.Identifier";
const STREAM_TYPE_SUFFIX: &str = ":$DATA";

/// Read-back cap: real streams are a few hundred bytes (`ZoneId`, two URLs);
/// anything larger is truncated rather than read whole.
pub const MAX_STREAM_BYTES: u64 = 8 * 1024;

/// Per-value cap, in characters (after escaping). URLs past this are cut,
/// never dropped — the prefix still names the host.
const MAX_VALUE_CHARS: usize = 2048;

/// The file the mark belongs to, when `path` names its `Zone.Identifier`
/// stream (`C:\d\a.exe:Zone.Identifier` → `C:\d\a.exe`). `None` for any other
/// path, including a bare `:Zone.Identifier` with no file in front.
#[must_use]
pub fn stream_host_path(path: &str) -> Option<&str> {
    let path = strip_suffix_ignore_ascii_case(path, STREAM_TYPE_SUFFIX).unwrap_or(path);
    let host = strip_suffix_ignore_ascii_case(path, STREAM_SUFFIX)?;
    (!host.is_empty() && !host.ends_with(['\\', '/', ':'])).then_some(host)
}

fn strip_suffix_ignore_ascii_case<'a>(s: &'a str, suffix: &str) -> Option<&'a str> {
    let split = s.len().checked_sub(suffix.len())?;
    let tail = s.get(split..)?;
    tail.eq_ignore_ascii_case(suffix).then(|| &s[..split])
}

/// What a `Zone.Identifier` stream says. Every field is optional: writers
/// differ (some record no URL), and a read that races the writer sees an
/// empty stream — the mark alone is still the signal.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct ZoneIdentifier {
    /// URL zone: 0 local machine, 1 intranet, 2 trusted, 3 internet,
    /// 4 restricted.
    pub zone_id: Option<u32>,
    /// `HostUrl` — where the file was downloaded from. Control characters,
    /// line/paragraph separators and bidi controls are percent-encoded (see
    /// [`parse`]).
    pub host_url: Option<String>,
    /// `ReferrerUrl` — the page that linked to it. Escaped like `host_url`.
    pub referrer_url: Option<String>,
}

impl ZoneIdentifier {
    /// True unless the stream positively places the file in a local, intranet
    /// or trusted zone (0–2). An unknown zone (empty or raced read, garbage
    /// value) counts as external: the stream exists, so something marked it.
    #[must_use]
    pub fn is_external(&self) -> bool {
        self.zone_id.is_none_or(|zone| zone >= 3)
    }
}

/// Parses stream content: an INI with a `[ZoneTransfer]` section. Decodes a
/// UTF-16LE or UTF-8 BOM, otherwise UTF-8 lossily; keys are
/// case-insensitive; keys under any other section are ignored, keys before
/// any section header are accepted. Never fails — unparseable input yields
/// empty fields.
///
/// A lone `\r` ends a line, as it does for an INI reader. The URLs end up in
/// alert messages that plain-text consumers (logs, terminals) render, so any
/// control character, Unicode line/paragraph separator or bidi control left
/// in a value is percent-encoded: a stream cannot forge a line or reorder
/// what an analyst reads, and the escaped byte is still evidence.
#[must_use]
pub fn parse(bytes: &[u8]) -> ZoneIdentifier {
    let text = decode(bytes);
    let mut out = ZoneIdentifier::default();
    let mut in_zone_section = true;
    for line in text.split(['\r', '\n']) {
        let line = line.trim();
        if let Some(section) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            in_zone_section = section.trim().eq_ignore_ascii_case("ZoneTransfer");
            continue;
        }
        if !in_zone_section {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            k if k.eq_ignore_ascii_case("ZoneId") => out.zone_id = value.parse().ok(),
            k if k.eq_ignore_ascii_case("HostUrl") => out.host_url = bounded_value(value),
            k if k.eq_ignore_ascii_case("ReferrerUrl") => out.referrer_url = bounded_value(value),
            _ => {}
        }
    }
    out
}

fn decode(bytes: &[u8]) -> String {
    if let Some(utf16) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = utf16
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    String::from_utf8_lossy(bytes).into_owned()
}

fn bounded_value(value: &str) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    let mut out = String::new();
    let mut chars = 0;
    for c in value.chars() {
        let escaped = needs_escape(c);
        let width = if escaped { 3 * c.len_utf8() } else { 1 };
        // Whole escapes only: a cut `%E2%8` would read as a different byte.
        if chars + width > MAX_VALUE_CHARS {
            break;
        }
        chars += width;
        if escaped {
            for byte in c.encode_utf8(&mut [0; 4]).bytes() {
                let _ = write!(out, "%{byte:02X}");
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

/// C0/C1 controls (incl. NEL), line/paragraph separators, and the bidi
/// marks, embeddings, overrides and isolates (Trojan Source's set).
fn needs_escape(c: char) -> bool {
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

/// Decides which `Zone.Identifier` reads become a `FileQuarantine`: external
/// marks only, one per stream write (a write produces two or three
/// Kernel-File records).
///
/// A mark is remembered only once it is reported, keyed by the (case-folded)
/// host path *and* a digest of what the stream said. So a dropped local-zone
/// write never shadows an internet re-download of the same path inside the
/// window, and a read that raced the writer (empty stream) doesn't hide the
/// complete read that follows — at worst a second event, never a lost one.
/// The digest key is random per instance, so a stream's author cannot craft
/// a collision that suppresses their next mark. Pruned on every call and
/// hard-capped: past the cap a new path is reported without being remembered
/// (again a possible duplicate, never a loss) and the skip is counted.
#[cfg_attr(not(windows), allow(dead_code))] // driven by the Windows-only provider
pub(crate) struct QuarantineDedup {
    /// Case-folded host path → (last report, content digest).
    seen: HashMap<String, (u64, u64)>,
    digest_key: RandomState,
    window_ns: u64,
    cap: usize,
    unremembered: u64,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl QuarantineDedup {
    pub(crate) fn new(window_ns: u64, cap: usize) -> Self {
        Self {
            seen: HashMap::new(),
            digest_key: RandomState::new(),
            window_ns,
            cap,
            unremembered: 0,
        }
    }

    /// `zone`, if the mark it describes on `host_path` must be reported: it is
    /// external and not the same mark already reported within the window.
    pub(crate) fn admit(
        &mut self,
        host_path: &str,
        zone: ZoneIdentifier,
        now_ns: u64,
    ) -> Option<ZoneIdentifier> {
        if !zone.is_external() {
            return None;
        }
        let cutoff = now_ns.saturating_sub(self.window_ns);
        self.seen.retain(|_, &mut (t, _)| t >= cutoff);
        let key = host_path.to_lowercase();
        let digest = self.digest_key.hash_one(&zone);
        if let Some(entry) = self.seen.get_mut(&key) {
            if entry.1 == digest {
                return None;
            }
            *entry = (now_ns, digest);
            return Some(zone);
        }
        if self.seen.len() >= self.cap {
            self.unremembered += 1;
            // Powers of two only: a burst must not flood the log.
            if self.unremembered.is_power_of_two() {
                tracing::warn!(
                    cap = self.cap,
                    unremembered_total = self.unremembered,
                    "quarantine dedup at its cap — marks reported without dedup"
                );
            }
            return Some(zone);
        }
        self.seen.insert(key, (now_ns, digest));
        Some(zone)
    }

    /// New paths reported without being remembered because the cap was hit.
    #[cfg_attr(not(test), allow(dead_code))] // read by a future health surface
    pub(crate) fn unremembered(&self) -> u64 {
        self.unremembered
    }
}

/// The stream at `stream_path`, at most [`MAX_STREAM_BYTES`] of it. `None` if
/// it cannot be opened or read (gone, sharing violation, unreachable share).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn read_stream(stream_path: &str) -> Option<Vec<u8>> {
    use std::io::Read as _;
    let file = std::fs::File::open(stream_path).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_STREAM_BYTES).read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

/// One `Zone.Identifier` write seen by the Kernel-File callback, handed to the
/// read-back worker. `meta` is built on the callback thread: it carries the
/// writer's token identity, which a later read could no longer resolve once
/// the process has exited.
#[cfg_attr(not(windows), allow(dead_code))] // built by the Windows-only provider
pub(crate) struct MarkWrite {
    pub(crate) stream_path: String,
    pub(crate) host: String,
    pub(crate) meta: EventMeta,
}

/// Callback side of the `Zone.Identifier` read-back (#439): hands each mark to
/// the worker without ever blocking. The first cut read the stream on the
/// Kernel-File callback thread, so a mark on a slow or unreachable SMB share
/// stalled every file event behind it and risked real-time buffer loss.
///
/// A full queue drops the mark, counts it and logs at powers of two, like
/// [`QuarantineDedup`]'s cap. That's a lost `FileQuarantine`, never a stalled
/// trace; the `FileOpen` record for the stream is still emitted by the caller.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) struct MarkQueue {
    tx: SyncSender<MarkWrite>,
    dropped: AtomicU64,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl MarkQueue {
    /// A queue holding up to `capacity` pending marks, and the receiving end
    /// for [`run_mark_reader`].
    pub(crate) fn bounded(capacity: usize) -> (Self, Receiver<MarkWrite>) {
        let (tx, rx) = mpsc::sync_channel(capacity);
        (
            Self {
                tx,
                dropped: AtomicU64::new(0),
            },
            rx,
        )
    }

    /// Queues `mark` for the worker, or drops and counts it if the queue is
    /// full or the worker is gone. Never blocks.
    pub(crate) fn offer(&self, mark: MarkWrite) {
        let reason = match self.tx.try_send(mark) {
            Ok(()) => return,
            Err(TrySendError::Full(_)) => "queue full",
            Err(TrySendError::Disconnected(_)) => "reader gone",
        };
        let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        // Powers of two only: a burst must not flood the log.
        if dropped.is_power_of_two() {
            tracing::warn!(
                reason,
                dropped_total = dropped,
                "Zone.Identifier read-back queue dropped a mark"
            );
        }
    }

    /// Marks dropped so far.
    #[cfg_attr(not(test), allow(dead_code))] // read by a future health surface
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Worker side: reads each queued mark's stream (`read`, bounded by the
/// caller), deduplicates it and emits the `FileQuarantine`. Returns once every
/// [`MarkQueue`] is dropped, which happens when the trace's callbacks go.
/// Ordering against the stream's `FileOpen` does not matter: the T1204.002
/// join keys on path and time.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn run_mark_reader(
    marks: &Receiver<MarkWrite>,
    read: impl Fn(&str) -> Option<Vec<u8>>,
    mut dedup: QuarantineDedup,
    emit: impl Fn(Event),
) {
    for mark in marks {
        if let Some(event) = quarantine_event(mark, &read, &mut dedup) {
            emit(event);
        }
    }
}

/// The `FileQuarantine` for one mark, or `None` for a duplicate record or a
/// stream placing the file in a local, intranet or trusted zone.
///
/// Best-effort, like the macOS sibling: a read that loses the race with the
/// writer (empty stream, sharing violation) still reports the mark alone.
/// `agent` is the writing process: Windows records no downloader name in the
/// stream, and the writer is exactly that.
fn quarantine_event(
    mark: MarkWrite,
    read: impl Fn(&str) -> Option<Vec<u8>>,
    dedup: &mut QuarantineDedup,
) -> Option<Event> {
    let zone = read(&mark.stream_path)
        .map(|bytes| parse(&bytes))
        .unwrap_or_default();
    let zone = dedup.admit(&mark.host, zone, mark.meta.timestamp_ns)?;
    let agent = Some(mark.meta.comm.clone());
    Some(Event::FileQuarantine(FileQuarantineEvent {
        meta: mark.meta,
        path: mark.host,
        agent,
        origin_url: zone.host_url,
        referrer_url: zone.referrer_url,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BROWSER_STREAM: &str = "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.test/page\r\nHostUrl=https://example.test/payload.exe\r\n";

    #[test]
    fn host_path_is_the_file_in_front_of_the_stream() {
        assert_eq!(
            stream_host_path(r"C:\Users\u\Downloads\a.exe:Zone.Identifier"),
            Some(r"C:\Users\u\Downloads\a.exe")
        );
    }

    #[test]
    fn host_path_matches_case_insensitively_and_with_stream_type() {
        assert_eq!(
            stream_host_path(r"C:\d\a.exe:zone.identifier:$DATA"),
            Some(r"C:\d\a.exe")
        );
    }

    #[test]
    fn other_paths_and_bare_streams_are_not_marks() {
        assert_eq!(stream_host_path(r"C:\d\a.exe"), None);
        assert_eq!(stream_host_path(r"C:\d\Zone.Identifier"), None);
        assert_eq!(stream_host_path(r"C:\d\a.exe:other"), None);
        assert_eq!(stream_host_path(":Zone.Identifier"), None);
        assert_eq!(stream_host_path(r"C:\d\:Zone.Identifier"), None);
        assert_eq!(stream_host_path(""), None);
    }

    #[test]
    fn parses_a_browser_stream() {
        let zone = parse(BROWSER_STREAM.as_bytes());
        assert_eq!(zone.zone_id, Some(3));
        assert_eq!(
            zone.host_url.as_deref(),
            Some("https://example.test/payload.exe")
        );
        assert_eq!(
            zone.referrer_url.as_deref(),
            Some("https://example.test/page")
        );
        assert!(zone.is_external());
    }

    #[test]
    fn parses_a_utf16le_stream_with_bom() {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in BROWSER_STREAM.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(parse(&bytes), parse(BROWSER_STREAM.as_bytes()));
    }

    #[test]
    fn keys_in_other_sections_are_ignored() {
        let zone = parse(b"[Other]\nHostUrl=https://decoy.test/\n[ZoneTransfer]\nZoneId=3\n");
        assert_eq!(zone.host_url, None);
        assert_eq!(zone.zone_id, Some(3));
    }

    #[test]
    fn empty_or_raced_stream_still_counts_as_external() {
        let zone = parse(b"");
        assert_eq!(zone, ZoneIdentifier::default());
        assert!(zone.is_external());
    }

    #[test]
    fn local_intranet_and_trusted_zones_are_not_external() {
        for zone in 0..3 {
            let text = format!("[ZoneTransfer]\nZoneId={zone}\n");
            assert!(!parse(text.as_bytes()).is_external(), "zone {zone}");
        }
        assert!(parse(b"[ZoneTransfer]\nZoneId=4\n").is_external());
    }

    #[test]
    fn oversized_values_are_truncated_not_dropped() {
        let long = format!("[ZoneTransfer]\nHostUrl=https://{}\n", "a".repeat(10_000));
        let url = parse(long.as_bytes()).host_url.expect("kept");
        assert_eq!(url.chars().count(), MAX_VALUE_CHARS);
        assert!(url.starts_with("https://a"));
    }

    #[test]
    fn a_lone_carriage_return_cannot_smuggle_a_line_into_a_url() {
        let zone =
            parse(b"[ZoneTransfer]\r\nHostUrl=https://evil.test/\rFAKE: injected\r\nZoneId=3\r\n");
        assert_eq!(zone.host_url.as_deref(), Some("https://evil.test/"));
        assert_eq!(zone.zone_id, Some(3));
    }

    #[test]
    fn control_separator_and_bidi_chars_in_urls_are_percent_encoded() {
        let stream =
            "[ZoneTransfer]\nHostUrl=https://a.test/x\u{85}y\u{2028}z\u{202E}exe.txt\tq\u{1b}[2J\n";
        assert_eq!(
            parse(stream.as_bytes()).host_url.as_deref(),
            Some("https://a.test/x%C2%85y%E2%80%A8z%E2%80%AEexe.txt%09q%1B[2J")
        );
    }

    #[test]
    fn truncation_never_splits_an_escape() {
        let prefix = "a".repeat(MAX_VALUE_CHARS - 4);
        let stream = format!("[ZoneTransfer]\nHostUrl={prefix}\u{2028}tail\n");
        assert_eq!(
            parse(stream.as_bytes()).host_url,
            Some(prefix),
            "the 9-char escape doesn't fit in the last 4"
        );
    }

    fn internet(url: &str) -> ZoneIdentifier {
        ZoneIdentifier {
            zone_id: Some(3),
            host_url: Some(url.to_string()),
            referrer_url: None,
        }
    }

    #[test]
    fn one_stream_write_reports_one_quarantine() {
        let mut dedup = QuarantineDedup::new(5_000_000_000, 16);
        let zone = internet("https://example.test/a.exe");
        assert!(dedup.admit(r"C:\d\a.exe", zone.clone(), 1_000).is_some());
        assert!(dedup.admit(r"C:\D\A.EXE", zone.clone(), 2_000).is_none());
        assert!(dedup.admit(r"C:\d\a.exe", zone, 6_000_001_000).is_some());
    }

    #[test]
    fn a_dropped_local_zone_mark_does_not_shadow_an_internet_redownload() {
        let mut dedup = QuarantineDedup::new(5_000_000_000, 16);
        let intranet = ZoneIdentifier {
            zone_id: Some(1),
            ..ZoneIdentifier::default()
        };
        assert_eq!(dedup.admit(r"C:\d\report.docx", intranet, 1_000), None);
        let redownload = internet("https://evil.test/report.docx");
        assert_eq!(
            dedup.admit(r"C:\d\report.docx", redownload.clone(), 2_000),
            Some(redownload)
        );
    }

    #[test]
    fn a_raced_empty_read_does_not_hide_the_complete_mark() {
        let mut dedup = QuarantineDedup::new(5_000_000_000, 16);
        let raced = ZoneIdentifier::default();
        assert!(dedup.admit(r"C:\d\a.exe", raced, 1_000).is_some());
        let complete = internet("https://example.test/a.exe");
        assert!(
            dedup
                .admit(r"C:\d\a.exe", complete.clone(), 2_000)
                .is_some()
        );
        assert!(dedup.admit(r"C:\d\a.exe", complete, 3_000).is_none());
    }

    #[test]
    fn dedup_past_its_cap_reports_and_counts_instead_of_growing() {
        let mut dedup = QuarantineDedup::new(u64::MAX, 2);
        let zone = internet("https://example.test/");
        assert!(dedup.admit("a", zone.clone(), 1).is_some());
        assert!(dedup.admit("b", zone.clone(), 1).is_some());
        assert!(dedup.admit("c", zone.clone(), 1).is_some());
        assert!(
            dedup.admit("c", zone, 1).is_some(),
            "unremembered, so reported again"
        );
        assert_eq!(dedup.unremembered(), 2);
        assert_eq!(dedup.seen.len(), 2);
    }

    // ── Read-back off the callback thread (#439) ──

    fn mark(host: &str, seconds: u64) -> MarkWrite {
        MarkWrite {
            stream_path: format!("{host}:Zone.Identifier"),
            host: host.to_string(),
            meta: EventMeta {
                comm: "msedge.exe".to_string(),
                timestamp_ns: seconds * 1_000_000_000,
                ..schema::fixtures::meta()
            },
        }
    }

    fn reader_dedup() -> QuarantineDedup {
        QuarantineDedup::new(5_000_000_000, 1_024)
    }

    #[test]
    fn offering_to_a_full_queue_drops_and_counts_instead_of_blocking() {
        // Regression (#439): the read ran on the Kernel-File callback thread, so a
        // slow read stalled every file event. Nothing drains this queue, standing
        // in for a worker stuck on an unreachable share: `offer` must still return.
        let (queue, _stuck_reader) = MarkQueue::bounded(2);
        for i in 0..5 {
            queue.offer(mark(&format!(r"C:\d\{i}.exe"), 0));
        }
        assert_eq!(queue.dropped(), 3);
    }

    #[test]
    fn offering_after_the_reader_is_gone_drops_and_counts() {
        let (queue, reader) = MarkQueue::bounded(4);
        drop(reader);
        queue.offer(mark(r"C:\d\a.exe", 0));
        assert_eq!(queue.dropped(), 1);
    }

    #[test]
    fn the_reader_emits_one_quarantine_event_per_write() {
        // A write yields 2-3 records for the same stream: one event out.
        let (queue, reader) = MarkQueue::bounded(8);
        for _ in 0..3 {
            queue.offer(mark(r"C:\Users\u\Downloads\a.exe", 1));
        }
        drop(queue);
        let emitted = std::cell::RefCell::new(Vec::new());
        run_mark_reader(
            &reader,
            |path| {
                assert_eq!(path, r"C:\Users\u\Downloads\a.exe:Zone.Identifier");
                Some(BROWSER_STREAM.as_bytes().to_vec())
            },
            reader_dedup(),
            |event| emitted.borrow_mut().push(event),
        );
        let emitted = emitted.into_inner();
        let [Event::FileQuarantine(event)] = emitted.as_slice() else {
            panic!("expected one FileQuarantine, got {emitted:?}");
        };
        assert_eq!(event.path, r"C:\Users\u\Downloads\a.exe");
        assert_eq!(event.agent.as_deref(), Some("msedge.exe"));
        assert_eq!(
            event.origin_url.as_deref(),
            Some("https://example.test/payload.exe")
        );
        assert_eq!(event.meta.timestamp_ns, 1_000_000_000);
    }

    #[test]
    fn the_reader_skips_marks_placing_the_file_in_a_trusted_zone() {
        let (queue, reader) = MarkQueue::bounded(8);
        queue.offer(mark(r"C:\intranet\a.exe", 1));
        drop(queue);
        let emitted = std::cell::Cell::new(0);
        run_mark_reader(
            &reader,
            |_| Some(b"[ZoneTransfer]\r\nZoneId=1\r\n".to_vec()),
            reader_dedup(),
            |_| emitted.set(emitted.get() + 1),
        );
        assert_eq!(emitted.get(), 0);
    }

    #[test]
    fn an_unreadable_stream_still_reports_the_mark_alone() {
        let (queue, reader) = MarkQueue::bounded(8);
        queue.offer(mark(r"\\slow-share\drop\a.exe", 1));
        drop(queue);
        let emitted = std::cell::RefCell::new(Vec::new());
        run_mark_reader(
            &reader,
            |_| None,
            reader_dedup(),
            |event| emitted.borrow_mut().push(event),
        );
        let emitted = emitted.into_inner();
        let [Event::FileQuarantine(event)] = emitted.as_slice() else {
            panic!("expected one FileQuarantine, got {emitted:?}");
        };
        assert_eq!(event.origin_url, None);
    }
}
