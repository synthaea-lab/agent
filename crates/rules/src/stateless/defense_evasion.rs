//! Defense Evasion (TA0005): command lines not captured whole, hidden data streams,
//! raw volume access, masquerading.

use schema::{ExecEvent, FileOpenEvent, RawVolumeOpenEvent, detection::Severity};

use crate::{Alert, has_write_intent};

/// Bytes of the kept command line quoted in a [`check_truncated_cmdline`] alert:
/// enough to recognise the interpreter and the shape of the padding, without
/// putting up to 32 KiB of attacker-chosen text into every alert message.
const TRUNCATED_CMDLINE_QUOTE_BYTES: usize = 256;

/// T1027.010 — Obfuscated Files or Information: Command Obfuscation, sub-case a
/// command line the sensor could not capture whole, so every content rule (the
/// `base64` decode, encoded `PowerShell`, the Sigma content) is blind to part of it.
/// Padding is attacker-controlled on both sides, so no fixed window (head, or head
/// and tail) can guarantee the payload is kept; the cut itself is the signal. Two
/// causes, graded and worded apart:
///
/// - **The bytes between the Linux probe's head and tail windows** (ADR-0045,
///   `argv_omitted_bytes = Some(n > 0)`): any argument block over 1 KiB. **Low**, as
///   ADR-0045 fixed it: in #1112's sample at most 3 of 3,451 execs exceed 1 KiB, and
///   none of 1,592 lab execs did, but both samples are small and from lab hosts.
/// - **Any other cut** (`argv_omitted_bytes = None`): the 32 KiB budget of #1112
///   (Alpine sample: p99.9 347 B, max 1,661 B, none over 4 KiB), or a sensor that
///   keeps a bounded number of arguments (macOS ES). **Medium**: none was benign in
///   that sample. The size of such a cut is not measured, so the message does not
///   claim one.
///
/// `cmdline_truncated == false` means "no cut seen", not "the whole command line
/// was seen": a process gone before its argv was read has an empty argv and no
/// flag (<https://github.com/synthaea-lab/agent/issues/48>), so this rule cannot see that case.
#[must_use]
pub(crate) fn check_truncated_cmdline(event: &ExecEvent) -> Option<Alert> {
    if !event.cmdline_truncated {
        return None;
    }
    let mut quote_end = event.cmdline.len().min(TRUNCATED_CMDLINE_QUOTE_BYTES);
    while !event.cmdline.is_char_boundary(quote_end) {
        quote_end -= 1;
    }
    let (severity, cause) = match event.argv_omitted_bytes {
        Some(omitted) if omitted > 0 => (
            Severity::Low,
            format!("{omitted} bytes between its head and its tail were not captured"),
        ),
        _ => (
            Severity::Medium,
            "it was cut at capture, by an amount the sensor did not measure".to_owned(),
        ),
    };
    Some(Alert {
        technique: "T1027.010",
        severity,
        message: format!(
            "pid={} comm={} image={}: command line not captured whole, {cause}; content \
             rules did not see all of it ({} bytes kept, {} args): {}",
            event.meta.pid,
            event.meta.comm,
            event.image_path,
            event.cmdline.len(),
            event.argv.len(),
            &event.cmdline[..quote_end],
        ),
    })
}

/// T1564.004 (#136, ADS slice 1) — Hide Artifacts: NTFS File Attributes. A
/// write-intent open on an NTFS alternate data stream: the final path
/// component carries a `:streamname` suffix, which only exists as a way to
/// attach a second, normally-invisible data fork to a file (`dir`/Explorer
/// show only the unnamed stream's size; the named one does not appear in a
/// directory listing). Malware uses this to stash a payload, a dropped tool,
/// or staged exfil data on a file that still looks ordinary.
///
/// Windows only: the colon-suffixed stream syntax is NTFS-specific. The
/// sensor already restricts `FileOpenEvent` to write-intent opens
/// ([`has_write_intent`]; a pure read never reaches this far), so every event
/// here already represents something being written into the stream, not
/// merely read back.
///
/// **The one documented, high-volume exception is `Zone.Identifier`**: every
/// browser, mail client, and Explorer's own "download from the internet"
/// marking writes one on nearly every downloaded file (`#365`/`#439`
/// already track this stream specifically for the mark-of-the-web). Excluding
/// it by name is the same evidence-gated-exclusion bar the rest of this crate
/// holds everything else to (`CLAUDE.md`) — it is the only stream name with
/// that evidence today. Other legitimate stream producers (backup tools,
/// some antivirus quarantine formats, older Office OLE property sets) are a
/// known, accepted gap until one is actually observed and named, the same
/// unbounded-tail trade-off ADR-0028 documents for `policy`'s interpreter
/// blocklist. Severity is Medium, not High, for the same reason: a named
/// stream alone is a weak, easily-legitimate signal without more context.
#[must_use]
pub(crate) fn check_alternate_data_stream_write(event: &FileOpenEvent) -> Option<Alert> {
    // The colon-suffixed stream syntax is NTFS-specific; a colon is ordinary
    // in a Linux or macOS file name (a timestamp, a log name) and must not be
    // read as a stream there (#943 review).
    if !matches!(event.meta.user, schema::User::Windows { .. }) || !has_write_intent(event.flags) {
        return None;
    }
    let name = event.path.rsplit(['\\', '/']).next().unwrap_or("");
    // The drive-letter colon (`C:`) never appears after the last separator;
    // only a real stream suffix does. A bare `name:` with nothing after it,
    // or a name starting with `:` (no base file name), is not a real stream.
    let (base, rest) = name.split_once(':')?;
    if base.is_empty() || rest.is_empty() {
        return None;
    }
    // A type tag (`:$DATA`, `:$INDEX_ALLOCATION`, ...) can follow the stream
    // name; strip it the same way Windows's own `dir /r` output does.
    // `file.txt::$DATA` (an explicit, unremarkable open of the file's own
    // unnamed stream) leaves `stream` empty rather than a real name — not a
    // hidden stream, so it must not alert either (#943 review).
    let stream = rest.split_once(':').map_or(rest, |(stream, _tag)| stream);
    if stream.is_empty() || stream.eq_ignore_ascii_case("Zone.Identifier") {
        return None;
    }
    Some(Alert {
        technique: "T1564.004",
        severity: Severity::Medium,
        message: format!(
            "pid={} comm={}: wrote to alternate data stream {stream:?} of {base} — \
             data hidden outside the file's visible contents",
            event.meta.pid, event.meta.comm,
        ),
    })
}

/// T1006 — Direct Volume Access: mounted logical-volume open. This is requested
/// access, not proof of granted rights or subsequent raw I/O; the event carries no trusted image.
#[must_use]
pub fn evaluate_raw_volume_open(event: &RawVolumeOpenEvent) -> Vec<Alert> {
    const FILE_WRITE_DATA: u32 = 0x0000_0002;
    const FILE_WRITE_EA: u32 = 0x0000_0010;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
    const FILE_APPEND_DATA: u32 = 0x0000_0004;
    const DELETE: u32 = 0x0001_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
    const READ_CAPABILITIES: u32 = 0xA000_0029; // FILE_READ_DATA/EA, FILE_EXECUTE, GENERIC_READ/EXECUTE
    // Every right that can modify the volume's data or its own protection, not just the
    // narrower "write data" case (#1007 review, SherlockOmss): a caller with WRITE_DAC or
    // WRITE_OWNER alone can reassign the volume's ACL/owner and grant itself write access
    // in a second step, and DELETE/FILE_WRITE_EA/FILE_WRITE_ATTRIBUTES are real tamper
    // capabilities a narrower mask would silently drop (e.g. `0x100` alone used to alert
    // on nothing).
    const WRITE_CAPABILITIES: u32 = FILE_WRITE_DATA
        | FILE_WRITE_EA
        | FILE_WRITE_ATTRIBUTES
        | FILE_APPEND_DATA
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER
        | GENERIC_WRITE
        | GENERIC_ALL;

    let severity = if event.desired_access & (WRITE_CAPABILITIES | MAXIMUM_ALLOWED) != 0 {
        // MAXIMUM_ALLOWED resolves to whatever the caller's token grants; a caller able to
        // open a raw volume at all already needs an elevated privilege (SeBackupPrivilege or
        // administrator), so in practice this almost always includes write — bucketing it
        // with read-only understates it (#1007 review).
        Some(Severity::Medium)
    } else if event.desired_access & READ_CAPABILITIES != 0 {
        Some(Severity::Low)
    } else {
        None
    };
    severity
        .into_iter()
        .map(|severity| Alert {
            technique: "T1006",
            severity,
            message: format!(
                "pid={} comm={}: opened mounted volume {} with requested access {:#010x}",
                event.meta.pid, event.meta.comm, event.volume, event.desired_access,
            ),
        })
        .collect()
}

/// System-binary names an attacker impersonates, with the directory prefixes
/// the real binary lives under. Unix side (Linux + macOS — both checked, a
/// path matching either platform's legitimate home is fine; the *mismatch*
/// is the signal, not the platform).
const MASQUERADE_UNIX: &[(&str, &[&str])] = &[
    ("bash", &["/bin/", "/usr/bin/", "/usr/local/bin/"]),
    ("sh", &["/bin/", "/usr/bin/"]),
    ("zsh", &["/bin/", "/usr/bin/"]),
    (
        "sshd",
        &[
            "/usr/sbin/",
            "/usr/libexec/",
            "/usr/lib/ssh/",
            "/usr/lib/openssh/",
        ],
    ),
    ("sudo", &["/usr/bin/", "/bin/"]),
    ("systemd", &["/usr/lib/systemd/", "/lib/systemd/"]),
    ("launchd", &["/sbin/"]),
    ("cron", &["/usr/sbin/", "/usr/bin/"]),
    ("login", &["/usr/bin/", "/bin/"]),
];

/// Windows side — compared case-insensitively (NTFS is), against lowercase
/// prefixes.
const MASQUERADE_WINDOWS: &[(&str, &[&str])] = &[
    (
        "svchost.exe",
        &["c:\\windows\\system32\\", "c:\\windows\\syswow64\\"],
    ),
    ("lsass.exe", &["c:\\windows\\system32\\"]),
    ("services.exe", &["c:\\windows\\system32\\"]),
    ("csrss.exe", &["c:\\windows\\system32\\"]),
    ("winlogon.exe", &["c:\\windows\\system32\\"]),
    ("smss.exe", &["c:\\windows\\system32\\"]),
    (
        "explorer.exe",
        &["c:\\windows\\", "c:\\windows\\syswow64\\"],
    ),
    (
        "powershell.exe",
        &[
            "c:\\windows\\system32\\windowspowershell\\",
            "c:\\windows\\syswow64\\windowspowershell\\",
        ],
    ),
    (
        "rundll32.exe",
        &["c:\\windows\\system32\\", "c:\\windows\\syswow64\\"],
    ),
];

/// T1036.005 — Masquerading: Match Legitimate Name or Location. A binary
/// *named* like a core system process executing from outside that binary's
/// legitimate directories (`svchost.exe` in a temp dir, `bash` in
/// `/tmp`). The name lists are deliberately short and high-value: every
/// entry is a binary attackers actually impersonate, and the allowed-prefix
/// sets are the platform's real install locations — no heuristics, so the
/// only false-positive surface is a user legitimately naming their own
/// binary `lsass.exe`, which is itself worth an alert.
///
/// Relative or truncated paths (the Linux `dfd` limitation
/// [`check_persistence_write`](super::check_persistence_write) documents) are
/// skipped, not guessed: a masquerade verdict needs the real absolute location.
#[must_use]
pub(crate) fn check_masquerading(event: &ExecEvent) -> Option<Alert> {
    let path = &event.image_path;
    let name = path.rsplit(['/', '\\']).next().unwrap_or("");
    if name.is_empty() {
        return None;
    }

    let (matched, allowed): (&str, &[&str]) = if path.starts_with('/') {
        let entry = MASQUERADE_UNIX.iter().find(|(n, _)| *n == name)?;
        (entry.0, entry.1)
    } else {
        // Windows paths only — anything else (relative, dfd-truncated) is
        // skipped per the doc above.
        let lower_name = name.to_ascii_lowercase();
        let drive_absolute = path.as_bytes().get(1) == Some(&b':');
        if !drive_absolute {
            return None;
        }
        let entry = MASQUERADE_WINDOWS.iter().find(|(n, _)| *n == lower_name)?;
        (entry.0, entry.1)
    };

    let lower_path = path.to_ascii_lowercase();
    let legitimate = allowed.iter().any(|prefix| lower_path.starts_with(prefix));
    if legitimate {
        return None;
    }
    Some(Alert {
        technique: "T1036.005",
        severity: Severity::High,
        message: format!(
            "pid={} comm={}: system-binary name `{matched}` executing from outside its \
             legitimate location: {path}",
            event.meta.pid, event.meta.comm,
        ),
    })
}
