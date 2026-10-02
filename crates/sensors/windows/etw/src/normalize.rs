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

/// Normalizes an NT registry key path to the familiar Win32 hive prefix.
///
/// The ETW Kernel-Registry provider emits full NT paths
/// (`\REGISTRY\MACHINE\SOFTWARE\...`); these are more useful in detections and
/// UI as the standard Win32 forms (`HKLM\SOFTWARE\...`).
///
/// Unknown roots (e.g. `\REGISTRY\A\`) are returned unchanged — honest and
/// greppable rather than fabricated.
#[must_use]
pub fn normalize_registry_key(raw: &str) -> String {
    const MACHINE: &str = r"\REGISTRY\MACHINE\";
    const USER: &str = r"\REGISTRY\USER\";

    if raw.len() >= MACHINE.len() && raw[..MACHINE.len()].eq_ignore_ascii_case(MACHINE) {
        return format!(r"HKLM\{}", &raw[MACHINE.len()..]);
    }
    if raw.len() >= USER.len() && raw[..USER.len()].eq_ignore_ascii_case(USER) {
        // Includes SID-prefixed HKCU paths (e.g. HKU\S-1-5-21-...\...) and
        // the machine-wide .DEFAULT hive — left with SID rather than guessing HKCU.
        return format!(r"HKU\{}", &raw[USER.len()..]);
    }
    raw.to_string()
}

/// Session names are randomized per start (F-2): a fixed name documented its own
/// kill command. Entropy source is deliberately boring (time ^ pid) — this is
/// anti-fingerprinting of the session *name*, not cryptography.
#[must_use]
pub fn random_session_name(seed_ns: u128, pid: u32) -> String {
    let mix = (seed_ns as u64) ^ ((pid as u64) << 17) ^ 0x9E37_79B9_7F4A_7C15;
    format!("wtrace-{:016x}", mix.wrapping_mul(0xBF58_476D_1CE4_E5B9))
}

/// Parses `logman query -ets`' stdout and returns every session name matching
/// our own `wtrace-` prefix (issue #408): every ETW session we could have
/// orphaned, across any number of consecutive unclean shutdowns — not just the
/// single most recent one a persisted-name file can track.
///
/// Pure and locale-independent: `logman`'s "Type"/"Status" columns are
/// translated (`Suivi`/`Tracking`, `En cours d'exécution`/`Running`, …) but the
/// session-name column always comes first and is never translated, so taking
/// each line's first whitespace-separated token is safe on any Windows display
/// language.
#[must_use]
pub fn parse_orphaned_sessions(logman_query_ets_output: &str) -> Vec<String> {
    logman_query_ets_output
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| name.starts_with("wtrace-"))
        .map(str::to_string)
        .collect()
}

/// Runs `start`, and on failure calls `stop_session(session)` before returning
/// the error (#408). `ferrisetw`'s `start_and_process` creates the session
/// (`StartTrace`), then enables each provider and opens the consumer; if one of
/// those steps fails it returns before building the `UserTrace`, so no `Drop`
/// ever stops the session it created. Left alone, every failed start (and the
/// watchdog retries one every few seconds) leaks a live ETW session.
///
/// # Errors
///
/// Whatever `start` returns, unchanged, after the session was stopped.
pub fn start_or_stop_session<T, E>(
    session: &str,
    start: impl FnOnce() -> Result<T, E>,
    stop_session: impl FnOnce(&str),
) -> Result<T, E> {
    let result = start();
    if result.is_err() {
        stop_session(session);
    }
    result
}

/// Describes our session's state from `logman query -ets` output, for the error
/// the liveness canary raises after 30 s of silence (#408). "Stopped from the
/// outside" and "still running but blind" call for different investigations, and
/// the old message ("trace stopped or tampered") didn't tell them apart. Other
/// `wtrace-` sessions at that point are not orphans (startup stopped those): they
/// belong to another running instance. `None`: logman itself failed.
#[must_use]
pub fn describe_silent_session(session: &str, logman_query_ets_output: Option<&str>) -> String {
    let Some(output) = logman_query_ets_output else {
        return format!("session {session}: state unknown (logman query -ets failed)");
    };
    let ours = parse_orphaned_sessions(output);
    let running = ours.iter().any(|name| name == session);
    let others = ours.iter().filter(|name| *name != session).count();
    let state = if running {
        "is still running but delivers no events (blind, not stopped)"
    } else {
        "is no longer running (stopped from outside the agent)"
    };
    format!("session {session} {state}; other wtrace- sessions running: {others}")
}

/// One session enabling one of our providers, as the OS reports it (#408).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderEnablement {
    /// Our provider's short name (e.g. `Kernel-Process`).
    pub provider: &'static str,
    /// The enabling session's name.
    pub session: String,
    /// The level it enabled the provider at (5 = verbose).
    pub level: u8,
    /// Its match-any keyword mask.
    pub match_any_keyword: u64,
}

/// A running session's mode and write counter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStats {
    /// The session name.
    pub name: String,
    /// Real-time mode (events delivered to a consumer, not a file).
    pub real_time: bool,
    /// Buffers flushed so far; a real-time session nobody consumes stays at 0.
    pub buffers_written: u32,
}

/// At most this many foreign sessions are named in a diagnosis.
const MAX_FOREIGN_NAMED: usize = 3;

/// The attribution half of the blind-session diagnosis (#408): the foreign
/// sessions that enable our providers, most of ours first. A real-time one
/// with no buffer written is flagged: a real-time session nobody consumes
/// stalls real-time delivery for every consumer on the host (lab, 2026-10-01),
/// so it is the prime suspect. Empty when no foreign session enables ours.
#[must_use]
pub fn describe_foreign_sessions(
    our_session: &str,
    enablements: &[ProviderEnablement],
    sessions: &[SessionStats],
) -> String {
    // session → (our providers it enables, highest level).
    let mut by_session: Vec<(&str, Vec<&'static str>, u8)> = Vec::new();
    for e in enablements.iter().filter(|e| e.session != our_session) {
        match by_session.iter_mut().find(|(s, _, _)| *s == e.session) {
            Some((_, providers, level)) => {
                if !providers.contains(&e.provider) {
                    providers.push(e.provider);
                }
                *level = (*level).max(e.level);
            }
            None => by_session.push((&e.session, vec![e.provider], e.level)),
        }
    }
    if by_session.is_empty() {
        return String::new();
    }
    let undrained = |name: &str| {
        sessions
            .iter()
            .any(|s| s.name == name && s.real_time && s.buffers_written == 0)
    };
    // Undrained first, then most of our providers, then name (stable output).
    by_session.sort_by(|a, b| {
        undrained(b.0)
            .cmp(&undrained(a.0))
            .then(b.1.len().cmp(&a.1.len()))
            .then(a.0.cmp(b.0))
    });
    let total = by_session.len();
    let named: Vec<String> = by_session
        .iter()
        .take(MAX_FOREIGN_NAMED)
        .map(|(name, providers, level)| {
            let flag = if undrained(name) {
                ", real-time with 0 buffers written: nobody consumes it"
            } else {
                ""
            };
            format!(
                "{name} ({} of our providers, level {level}{flag}: {})",
                providers.len(),
                providers.join(", ")
            )
        })
        .collect();
    let more = if total > MAX_FOREIGN_NAMED {
        format!(" and {} more", total - MAX_FOREIGN_NAMED)
    } else {
        String::new()
    };
    format!(
        "; foreign sessions enabling our providers: {}{more}",
        named.join("; ")
    )
}

/// LDAP-Client's `AttributeList` (EID 30, #364) split into attribute names.
/// The console shows the names space-separated, but a lab run (2026-10-02)
/// lost the second of two attributes with a whitespace-only split: the
/// separator is not (only) whitespace. Split on whitespace, NUL, `;` and `,`,
/// none of which can appear in an attribute name (RFC 4512 `descr`/OID).
#[must_use]
pub fn split_ldap_attributes(raw: &str) -> Vec<String> {
    raw.split(|c: char| c.is_whitespace() || matches!(c, '\0' | ';' | ','))
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect()
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
    fn ldap_attribute_lists_split_on_any_separator() {
        for raw in [
            "cn ms-Mcs-AdmPwd",
            "cn\0ms-Mcs-AdmPwd",
            "cn\0ms-Mcs-AdmPwd\0",
            "cn;ms-Mcs-AdmPwd",
            " cn,  ms-Mcs-AdmPwd ",
        ] {
            assert_eq!(
                split_ldap_attributes(raw),
                ["cn", "ms-Mcs-AdmPwd"],
                "{raw:?}"
            );
        }
        assert!(split_ldap_attributes("").is_empty());
    }

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
    fn parses_orphans_from_real_french_locale_logman_output() {
        // Captured live from `logman query -ets` on a French-locale Windows 11
        // host (2026-09-23) — real column headers and state text, not invented.
        // Two orphaned sessions from consecutive unclean shutdowns (#408),
        // interleaved with ordinary system sessions that must NOT match.
        let output = "Ensemble de collecteurs de donn\u{e9}es      Type                          \u{c9}tat\n\
             -------------------------------------------------------------------------------\n\
             Eventlog-Security                       Suivi                         En cours d'ex\u{e9}cution\n\
             wtrace-7f3a9c21b4e08d56                  Suivi                         En cours d'ex\u{e9}cution\n\
             NtfsLog                                 Suivi                         En cours d'ex\u{e9}cution\n\
             wtrace-a01c88ef235690bd                  Suivi                         En cours d'ex\u{e9}cution\n\
             WiFiSession                             Suivi                         En cours d'ex\u{e9}cution\n";
        let orphans = parse_orphaned_sessions(output);
        assert_eq!(
            orphans,
            vec!["wtrace-7f3a9c21b4e08d56", "wtrace-a01c88ef235690bd"]
        );
    }

    #[test]
    fn parses_orphans_from_english_locale_logman_output() {
        let output = "Data Collector Set                      Type                          Status\n\
             -------------------------------------------------------------------------------\n\
             EventLog-Security                       Trace                         Running\n\
             wtrace-deadbeefcafef00d                  Trace                         Running\n";
        let orphans = parse_orphaned_sessions(output);
        assert_eq!(orphans, vec!["wtrace-deadbeefcafef00d"]);
    }

    #[test]
    fn no_orphans_on_a_clean_host_is_empty() {
        let output = "Data Collector Set                      Type                          Status\n\
             -------------------------------------------------------------------------------\n\
             EventLog-Security                       Trace                         Running\n\
             NtfsLog                                 Trace                         Running\n";
        assert!(parse_orphaned_sessions(output).is_empty());
    }

    #[test]
    fn empty_logman_output_is_empty() {
        assert!(parse_orphaned_sessions("").is_empty());
        assert!(parse_orphaned_sessions("\n\n").is_empty());
    }

    #[test]
    fn many_consecutive_orphans_all_collected() {
        // The exact bug #408 describes: N unclean shutdowns in a row must not
        // lose track of the (N-1) oldest orphans.
        let mut output = String::from("Data Collector Set   Type    Status\n---\n");
        for i in 0..5u32 {
            output.push_str(&format!(
                "wtrace-{i:016x}                  Trace   Running\n"
            ));
        }
        let orphans = parse_orphaned_sessions(&output);
        assert_eq!(orphans.len(), 5);
        assert_eq!(orphans[0], "wtrace-0000000000000000");
        assert_eq!(orphans[4], "wtrace-0000000000000004");
    }

    #[test]
    fn a_name_merely_containing_the_prefix_but_not_starting_with_it_does_not_match() {
        // The match is on the session-name column's own prefix, not a substring
        // search across the whole line — a session whose name happens to embed
        // "wtrace-" elsewhere (or a status/type column containing it) must not
        // be swept up as one of ours.
        let output = "Data Collector Set   Type    Status\n---\n\
             MyApp-wtrace-shim    Trace   Running\n";
        assert!(parse_orphaned_sessions(output).is_empty());
    }

    #[test]
    fn a_failed_start_stops_the_session_it_may_have_created() {
        // #408: ferrisetw leaves the session running when a provider fails to
        // enable after StartTrace, so a failed start must stop it by name.
        let mut stopped = Vec::new();
        let result: Result<(), &str> = start_or_stop_session(
            "wtrace-0123456789abcdef",
            || Err("enable failed"),
            |s| {
                stopped.push(s.to_string());
            },
        );
        assert_eq!(result, Err("enable failed"));
        assert_eq!(stopped, vec!["wtrace-0123456789abcdef"]);
    }

    #[test]
    fn a_successful_start_leaves_the_session_alone() {
        let mut stopped = 0;
        let result: Result<u8, ()> = start_or_stop_session("wtrace-x", || Ok(7), |_| stopped += 1);
        assert_eq!(result, Ok(7));
        assert_eq!(stopped, 0);
    }

    #[test]
    fn a_silent_session_still_listed_is_reported_blind_not_stopped() {
        let output = "Data Collector Set                      Type                          Status\n\
             -------------------------------------------------------------------------------\n\
             EventLog-Security                       Trace                         Running\n\
             wtrace-aaaaaaaaaaaaaaaa                  Trace                         Running\n\
             wtrace-bbbbbbbbbbbbbbbb                  Trace                         Running\n";
        let text = describe_silent_session("wtrace-aaaaaaaaaaaaaaaa", Some(output));
        assert!(
            text.contains("still running but delivers no events"),
            "{text}"
        );
        assert!(
            text.ends_with("other wtrace- sessions running: 1"),
            "{text}"
        );
    }

    #[test]
    fn a_silent_session_gone_from_the_list_is_reported_stopped() {
        let output = "Data Collector Set   Type    Status\n---\n\
             EventLog-Security    Trace   Running\n";
        let text = describe_silent_session("wtrace-aaaaaaaaaaaaaaaa", Some(output));
        assert!(text.contains("no longer running"), "{text}");
        assert!(
            text.ends_with("other wtrace- sessions running: 0"),
            "{text}"
        );
    }

    #[test]
    fn a_failed_logman_says_the_state_is_unknown() {
        let text = describe_silent_session("wtrace-aaaaaaaaaaaaaaaa", None);
        assert!(text.contains("state unknown"), "{text}");
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
    fn registry_key_normalization() {
        assert_eq!(
            normalize_registry_key(
                r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            ),
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        );
        assert_eq!(
            normalize_registry_key(r"\REGISTRY\USER\S-1-5-21-1234\SOFTWARE\Run"),
            r"HKU\S-1-5-21-1234\SOFTWARE\Run"
        );
        // Case-insensitive prefix match.
        assert_eq!(
            normalize_registry_key(r"\registry\machine\SYSTEM\CurrentControlSet\Services"),
            r"HKLM\SYSTEM\CurrentControlSet\Services"
        );
        // Unknown root: keep the truth.
        assert_eq!(
            normalize_registry_key(r"\REGISTRY\A\something"),
            r"\REGISTRY\A\something"
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

    fn enables(provider: &'static str, session: &str, level: u8) -> ProviderEnablement {
        ProviderEnablement {
            provider,
            session: session.to_string(),
            level,
            match_any_keyword: u64::MAX,
        }
    }

    fn stats(name: &str, real_time: bool, buffers_written: u32) -> SessionStats {
        SessionStats {
            name: name.to_string(),
            real_time,
            buffers_written,
        }
    }

    #[test]
    fn no_foreign_session_adds_nothing() {
        let ours = [enables("Kernel-Process", "wtrace-x", 5)];
        assert_eq!(
            describe_foreign_sessions("wtrace-x", &ours, &[stats("wtrace-x", true, 0)]),
            ""
        );
    }

    #[test]
    fn the_undrained_real_time_session_is_named_first_and_flagged() {
        // The 2026-10-01 lab shape: one foreign real-time session nobody
        // consumes on all our providers, next to a legitimate drained one.
        let enablements = [
            enables("Kernel-Process", "wtrace-x", 5),
            enables("Kernel-Process", "EventLog-System", 4),
            enables("Kernel-File", "EventLog-System", 4),
            enables("Kernel-Process", "lab408b-allnine", 5),
            enables("Kernel-Process", "lab408b-allnine", 5),
        ];
        let sessions = [
            stats("wtrace-x", true, 0),
            stats("EventLog-System", true, 40),
            stats("lab408b-allnine", true, 0),
        ];
        let text = describe_foreign_sessions("wtrace-x", &enablements, &sessions);
        assert!(
            text.starts_with("; foreign sessions enabling our providers: lab408b-allnine (1 of our providers, level 5, real-time with 0 buffers written: nobody consumes it: Kernel-Process)"),
            "{text}"
        );
        assert!(
            text.contains(
                "EventLog-System (2 of our providers, level 4: Kernel-Process, Kernel-File)"
            ),
            "{text}"
        );
        assert!(
            !text.contains("wtrace-x"),
            "our own session is never a suspect: {text}"
        );
    }

    #[test]
    fn only_three_sessions_are_named() {
        let enablements: Vec<_> = ["a", "b", "c", "d", "e"]
            .iter()
            .map(|s| enables("Kernel-File", s, 4))
            .collect();
        let text = describe_foreign_sessions("wtrace-x", &enablements, &[]);
        assert!(text.ends_with(" and 2 more"), "{text}");
        assert!(
            text.contains("a (") && text.contains("c (") && !text.contains("d ("),
            "{text}"
        );
    }
}
