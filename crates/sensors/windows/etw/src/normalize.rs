//! Pure normalization helpers — platform-independent and unit-tested on every CI
//! leg; the Windows-only part of this crate is subscription and API access, not
//! this logic.

use std::collections::HashMap;

/// Windows FILETIME (100ns intervals since 1601-01-01) → Unix epoch nanoseconds.
#[must_use]
pub fn filetime_to_ns(ft: i64) -> u64 {
    const DELTA_100NS: i64 = 116_444_736_000_000_000;
    if ft <= DELTA_100NS {
        return 0;
    }
    ((ft - DELTA_100NS) * 100) as u64
}

/// Maps the NT create disposition (high byte of `CreateOptions`) to the Unix-style
/// flags the schema/file rules use. `O_WRONLY=0o1`, `O_CREAT=0o100` — same constants as
/// the correlator's T1105 rule.
#[must_use]
pub fn disposition_to_flags(disposition: u32) -> u32 {
    const O_WRONLY: u32 = 0o1;
    const O_CREAT: u32 = 0o100;
    match disposition {
        0 => O_CREAT | O_WRONLY, // FILE_SUPERSEDE
        1 => 0,                  // FILE_OPEN (read-only)
        2 => O_CREAT,            // FILE_CREATE
        3 => O_CREAT,            // FILE_OPEN_IF
        4 => O_WRONLY,           // FILE_OVERWRITE
        5 => O_CREAT | O_WRONLY, // FILE_OVERWRITE_IF
        _ => 0,
    }
}

/// Normalizes an NT kernel path against a real device→drive map (F-5: the old code
/// guessed `C:` for every volume; a second disk or mounted VHDX — a common
/// payload-staging spot — produced wrong paths). Longest-prefix match; unknown
/// devices keep the raw path (honest, greppable) rather than a fabricated drive.
#[must_use]
pub fn normalize_nt_path(path: &str, volume_map: &HashMap<String, String>) -> String {
    let mut best: Option<(&str, &str)> = None;
    for (device, drive) in volume_map {
        if path.len() >= device.len()
            && path[..device.len()].eq_ignore_ascii_case(device)
            && best.is_none_or(|(d, _)| device.len() > d.len())
        {
            best = Some((device.as_str(), drive.as_str()));
        }
    }
    match best {
        Some((device, drive)) => format!("{drive}{}", &path[device.len()..]),
        None => path.to_string(),
    }
}

/// Session names are randomized per start (F-2): a fixed name documented its own
/// kill command. Entropy source is deliberately boring (time ^ pid) — this is
/// anti-fingerprinting of the session *name*, not cryptography.
#[must_use]
pub fn random_session_name(seed_ns: u128, pid: u32) -> String {
    let mix = (seed_ns as u64) ^ ((pid as u64) << 17) ^ 0x9E37_79B9_7F4A_7C15;
    format!("wtrace-{:016x}", mix.wrapping_mul(0xBF58_476D_1CE4_E5B9))
}

/// Short-window connect dedup (F-7): stacks that emit both Connect (42/58) and the
/// first Send (12/26) for one connection must not double-count the beacon counter.
pub struct ConnectDedup {
    /// Keyed by the full flow (pid, sport, daddr, dport) — F-7: two distinct
    /// sockets from the same process to the same destination are two flows, and
    /// deduping them together undercounts beacon candidates.
    seen: HashMap<(u32, u16, std::net::IpAddr, u16), u64>,
    window_ns: u64,
}

impl ConnectDedup {
    #[must_use]
    pub fn new(window_ns: u64) -> Self {
        Self {
            seen: HashMap::new(),
            window_ns,
        }
    }

    /// True if this (pid, daddr, dport) was already reported within the window.
    /// Records the sighting either way; entries older than the window are pruned
    /// opportunistically to keep the map bounded by live traffic.
    pub fn is_duplicate(
        &mut self,
        pid: u32,
        sport: u16,
        daddr: std::net::IpAddr,
        dport: u16,
        now_ns: u64,
    ) -> bool {
        let cutoff = now_ns.saturating_sub(self.window_ns);
        self.seen.retain(|_, &mut t| t >= cutoff);
        match self.seen.insert((pid, sport, daddr, dport), now_ns) {
            Some(prev) => prev >= cutoff,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_epoch_conversion() {
        assert_eq!(filetime_to_ns(116_444_736_000_000_000), 0);
        // One second past the Unix epoch.
        assert_eq!(filetime_to_ns(116_444_736_010_000_000), 1_000_000_000);
        assert_eq!(filetime_to_ns(0), 0, "pre-epoch clamps to 0");
    }

    #[test]
    fn dispositions_map_like_the_old_sensor() {
        assert_eq!(disposition_to_flags(1), 0, "FILE_OPEN is read-only");
        assert_eq!(disposition_to_flags(2), 0o100);
        assert_eq!(disposition_to_flags(5), 0o101);
    }

    #[test]
    fn nt_paths_normalize_per_volume_not_hardcoded_c() {
        let mut map = HashMap::new();
        map.insert(r"\Device\HarddiskVolume3".to_string(), "C:".to_string());
        map.insert(r"\Device\HarddiskVolume7".to_string(), "D:".to_string());
        assert_eq!(
            normalize_nt_path(r"\Device\HarddiskVolume3\Windows\notepad.exe", &map),
            r"C:\Windows\notepad.exe"
        );
        // The F-5 regression: a second volume must NOT become C:.
        assert_eq!(
            normalize_nt_path(r"\Device\HarddiskVolume7\staging\payload.exe", &map),
            r"D:\staging\payload.exe"
        );
        // Unknown device: keep the truth rather than fabricate a drive.
        assert_eq!(
            normalize_nt_path(r"\Device\Mup\share\x", &map),
            r"\Device\Mup\share\x"
        );
    }

    #[test]
    fn session_names_differ_across_starts() {
        let a = random_session_name(1, 100);
        let b = random_session_name(2, 100);
        assert_ne!(a, b);
        assert!(a.starts_with("wtrace-"));
    }

    #[test]
    fn connect_send_pairs_dedup_within_window() {
        let mut d = ConnectDedup::new(2_000_000_000);
        let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        assert!(
            !d.is_duplicate(100, 5555, ip, 4444, 1_000_000_000),
            "connect"
        );
        assert!(
            d.is_duplicate(100, 5555, ip, 4444, 1_500_000_000),
            "first send dup"
        );
        // Past the window: a genuinely new connection counts again.
        assert!(!d.is_duplicate(100, 5555, ip, 4444, 9_000_000_000));
        // A different source port is a different flow, never a duplicate.
        assert!(!d.is_duplicate(100, 6666, ip, 4444, 9_100_000_000));
    }
}
