//! Calibration catalogues for the stateful rules: process lists, thresholds,
//! windows, and exclusions. Every exclusion entry documents WHY it exists, with
//! the date and lab scenario that produced the false positive — and name-keyed
//! exclusions only apply through `policy::name_exclusion_applies` (a rename in
//! %TEMP% must not inherit them).

/// Processes whose file writes feed the T1105 download-then-exec join: tools that
/// write the downloaded file themselves. Windows names carry `.exe` (the ETW
/// `comm` is the image's file name); the first cut listed only `curl`/`wget`, so
/// the rule never saw a Windows download (#442).
///
/// Not listed, on purpose: `bitsadmin`/BITS jobs (the BITS service, a
/// `svchost.exe`, writes the file, not `bitsadmin.exe`; BITS telemetry is #284),
/// and `PowerShell` `Invoke-WebRequest` (`powershell.exe` writes far too many files
/// for one of its writes to mean "download"). Browsers and mail clients are
/// covered by the mark-of-the-web join (T1204.002) instead.
pub(crate) const DOWNLOADER_COMMS: &[&str] =
    &["curl", "wget", "curl.exe", "wget.exe", "certutil.exe"];
pub(crate) const SHELL_COMMS: &[&str] = &["sh", "bash", "dash", "zsh", "ash"];

/// Service processes whose direct-child shell is a strong compromise signal
/// (T1059), exact-`comm` match. `nginx`/`apache2`/`httpd` are the original web
/// server rule; `mysqld`/`mariadbd`/`postgres` extend it to database services
/// (issue #478, Level 1): `mysqld`/`mariadbd` spawning a shell is command
/// execution through a UDF (`sys_exec`-style), `postgres` spawning one is the
/// classic `COPY PROGRAM`/`plpythonu` escape. See [`SERVICE_COMM_PREFIXES`]
/// for `php-fpm`, which doesn't fit an exact-match list.
pub(crate) const SERVICE_COMMS: &[&str] = &[
    "nginx", "apache2", "httpd", "mysqld", "mariadbd", "postgres",
];

/// Prefix-matched service names, checked in addition to [`SERVICE_COMMS`].
/// `php-fpm`'s worker `comm` is the pool binary's own file name, which several
/// distros suffix with the PHP version (Debian/Ubuntu: `php-fpm7.4`,
/// `php-fpm8.1`, ...; RHEL/Fedora ship a bare `php-fpm`) — an exact-match
/// entry would only ever catch one distro family. A shell spawned directly by
/// php-fpm is the same T1059 signal either way, and closes a real gap the
/// plain web-server list left open: php-fpm's own parent is the fpm master,
/// not nginx/Apache, so a webshell's `system()`/`exec()` call spawning a shell
/// under php-fpm never matched [`SERVICE_COMMS`] at all (issue #478).
pub(crate) const SERVICE_COMM_PREFIXES: &[&str] = &["php-fpm"];

/// Correlation window between the write of a downloaded file and its execution: past
/// this delay, the two events are no longer linked (avoids keeping an unbounded
/// history, and an execution hours later is no longer the same "download & run"
/// scenario anyway).
pub(crate) const DOWNLOAD_EXEC_WINDOW_NS: u64 = 60_000_000_000; // 60s

/// Correlation window between a `memfd_create(2)` and an exec via
/// `/proc/(self|<pid>)/fd/<n>` of the same pid that still counts as the same
/// fileless-exec sequence (T1620, issue #497). A real memfd payload is
/// created, written, then exec'd back-to-back within one short-lived
/// process's own syscall sequence — microseconds to low milliseconds apart in
/// practice — so this is generous headroom for scheduling jitter while
/// staying short enough that pid reuse (a new, unrelated process reusing the
/// same pid number well after the original exited) can't plausibly land
/// inside it. Uncalibrated against fleet traffic (first cut, 2026-09-28).
pub(crate) const MEMFD_EXEC_WINDOW_NS: u64 = 5_000_000_000; // 5s

/// Window between a download-provenance mark (`FileQuarantine`: macOS quarantine
/// xattr, Windows `Zone.Identifier`) and an exec of the marked file that still
/// counts as "downloaded, then run" (T1204.002, #365). Wider than
/// [`DOWNLOAD_EXEC_WINDOW_NS`]: a user opens a download minutes later, not
/// within a script's seconds.
///
/// Justified, not calibrated (#441): there is no fleet telemetry to calibrate
/// against yet. The window bounds how long a mark stays fresh, not the noise:
/// the installer noise it used to let through is now removed by the signature
/// gate on Windows (a chain-verified image does not alert), so widening it
/// would mostly add unsigned tools run long after download, and narrowing it
/// would lose the user who reads the mail, then runs the attachment. Ten
/// minutes stays; macOS, without the gate, keeps the noise.
pub(crate) const QUARANTINE_EXEC_WINDOW_NS: u64 = 600_000_000_000; // 10 min

// ── Windows constants (ETW rules — T1059/T1218/T1071) ───────────────────────

/// SELF-SPAWN threshold and window (T1059): N spawns of the same name in X seconds.
pub(crate) const SELF_SPAWN_THRESHOLD: u32 = 3;
pub(crate) const SELF_SPAWN_WINDOW_NS: u64 = 30_000_000_000; // 30s
/// SELF-SPAWN threshold when both the parent and the child image live at a trusted
/// system path (#432). Calibrated 2026-09-28 on the 2026-09-07 Windows Server
/// captures plus #432's Win11 lab observations: every benign system→system group
/// peaked at 3 (`taskhostw.exe`, `slui.exe`, `MusNotification.exe`, `svchost.exe`,
/// `schtasks.exe`, an operator's `cli.exe`), while the one real storm with a
/// system child (`malware3.exe` → `powershell.exe`) reached 20. That storm is
/// caught at [`SELF_SPAWN_THRESHOLD`] anyway through its untrusted parent; this
/// tier is for the same storm launched from a system parent.
pub(crate) const SELF_SPAWN_TRUSTED_THRESHOLD: u32 = 10;
/// Script hosts that keep [`SELF_SPAWN_THRESHOLD`] as SELF-SPAWN children even
/// when both images are system ones (#494 review): a malicious `.ps1` looping
/// `powershell.exe` 3-9 times from a system shell would otherwise stay under
/// [`SELF_SPAWN_TRUSTED_THRESHOLD`]. Replayed 2026-09-29 on the same captures:
/// no benign group reaching 3 has a script-host child, and the only one that
/// does is the `malware3.exe` storm. Deliberately narrower than
/// [`SUSPECT_CHILDREN_WIN`]: `msiexec.exe` and `rundll32.exe` loop
/// legitimately (installs, shell extensions).
pub(crate) const SELF_SPAWN_SCRIPT_HOSTS: &[&str] = &[
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
];

/// BEACON threshold and window (T1071/T1041): N connections to the same dest in X seconds.
/// T1110 — failed authentications per (target user, source) inside
/// [`AUTH_FAILURE_WINDOW_NS`] before the burst alerts. 5-in-60s clears any
/// human fumbling a password (2-3 tries then a reset) while catching even a
/// slow scripted spray.
pub(crate) const AUTH_FAILURE_THRESHOLD: u32 = 5;
/// Sliding window for [`AUTH_FAILURE_THRESHOLD`].
pub(crate) const AUTH_FAILURE_WINDOW_NS: u64 = 60_000_000_000; // 60s
/// T1021.001 — successful RDP authentication from a source after this many
/// authentication failures from the same source, across all accounts.
/// Five failures catches a credential guess/spray that eventually succeeds
/// while tolerating ordinary one-off authentication errors.
pub(crate) const RDP_SUCCESS_AFTER_FAILURES_THRESHOLD: u32 = 5;
/// Sliding look-back window for [`RDP_SUCCESS_AFTER_FAILURES_THRESHOLD`]. A
/// five-minute interval includes slower interactive guessing while limiting
/// stale failures that are no longer meaningful evidence for a later success.
pub(crate) const RDP_SUCCESS_AFTER_FAILURES_WINDOW_NS: u64 = 300_000_000_000; // 300s
/// A local privilege-escalation success (`sudo`/`su`) after this many
/// authentication failures joined to it (`crates/rules/src/sudo.rs`'s module
/// doc: `sudo` joins on the trusted invoker uid, `su` on the real target
/// name — not necessarily "the account escalated to" in either case).
/// Reported as T1548.003 for `sudo`, T1110.001 for `su` (review of #838,
/// Sollykhan 2026-10-19, non-blocking: `su` is not sudo caching).
/// Same reasoning as [`RDP_SUCCESS_AFTER_FAILURES_THRESHOLD`]: tolerates a
/// human mistyping their password a couple of times before getting it right,
/// catches a scripted or sustained guess that eventually succeeds.
///
/// The opposite of a noise source, confirmed live (Fedora 43, sudo 1.9.17p2,
/// review of #838, Sollykhan 2026-10-19): `pam_unix` logs exactly **one**
/// `authentication failure` line per sudo *invocation*, however many of the
/// (default `passwd_tries=3`) password prompts within it were wrong — three
/// wrong passwords at one prompt is one failure here, not three. So this
/// counts per invocation, the opposite of what a prior version of this
/// comment claimed, and the real effect is lower sensitivity, not alert
/// noise: an attacker needs 5 separate sudo invocations (up to 15 wrong
/// passwords) to cross this threshold, not 5 wrong passwords. Not re-tuned
/// here; lowering the threshold would be the fix if this proves insensitive
/// in practice.
pub(crate) const SUDO_SUCCESS_AFTER_FAILURES_THRESHOLD: u32 = 5;
/// Sliding look-back window for [`SUDO_SUCCESS_AFTER_FAILURES_THRESHOLD`].
pub(crate) const SUDO_SUCCESS_AFTER_FAILURES_WINDOW_NS: u64 = 300_000_000_000; // 300s
pub(crate) const BEACON_THRESHOLD: u32 = 3;
pub(crate) const BEACON_WINDOW_NS: u64 = 60_000_000_000; // 60s

/// EGRESS-VOLUME threshold and window (T1041/T1048, #380): this many bytes sent by one
/// process name to one public address inside the window. **Provisional**: 512 MiB in 10
/// minutes is far above an interactive session and below a bulk exfiltration of a
/// home directory, but no lab capture of ordinary uploads (backups, `rsync` to a remote
/// host, a container registry push, a video call) exists to calibrate it, so those
/// are the false positives to watch for live. Raise it before lowering it.
pub(crate) const EGRESS_BYTES_THRESHOLD: u64 = 512 * 1024 * 1024;
/// Sliding look-back window for [`EGRESS_BYTES_THRESHOLD`].
pub(crate) const EGRESS_WINDOW_NS: u64 = 600_000_000_000; // 10 min

/// ARCHIVE-EXFIL (T1560/T1041, #380): a file whose name ends in an archive or compression
/// extension, opened for writing by a pid that then writes at least this many bytes, is a
/// **staged archive**. **Provisional**: 100 MiB is the size at which an archive stops being a
/// config bundle and starts being a collection, with no lab measurement behind it.
pub(crate) const ARCHIVE_STAGED_BYTES: u64 = 100 * 1024 * 1024;
/// How long after it was staged an archive can be read by another process and still count.
pub(crate) const ARCHIVE_READ_WINDOW_NS: u64 = 3_600_000_000_000; // 1 h
/// How long after reading a staged archive a process can connect to a public address and
/// still complete the chain.
pub(crate) const ARCHIVE_EGRESS_WINDOW_NS: u64 = 600_000_000_000; // 10 min
/// Name endings of an archive or a compressed stream, compared in lowercase. A name is a
/// choice of the writer (`.dat` evades it) and is the stated gap of the rule, not a claim.
pub(crate) const ARCHIVE_SUFFIXES: &[&str] = &[
    ".zip", ".tar", ".tgz", ".7z", ".rar", ".gz", ".bz2", ".xz", ".zst", ".tbz2", ".txz",
];

/// SCAN-SPREAD threshold and window (T1046/T1210, issue #465): N distinct
/// destinations on the same (pid, dport) in X seconds. Calibrated against
/// the live Mirai detonation that surfaced this gap (309 connections to
/// 300+ distinct IPs on port 23 in ~30s) — 20-in-10s clears that burst with
/// comfortable margin (the real one crossed 20 distinct destinations in
/// under 2s) while giving a slower, throttled scanner still well inside "a
/// worm/spray pattern" a full 10s to be counted, unlike BEACON's window this
/// isn't recalibrated against a broader legitimate-traffic capture yet — a
/// busy client hitting many distinct servers on the same non-standard port
/// in a burst (a mail relay fanning out on 587, a monitoring agent probing a
/// fleet) is the plausible false positive to watch for live.
pub(crate) const SCAN_SPREAD_THRESHOLD: u32 = 20;
/// Sliding window for [`SCAN_SPREAD_THRESHOLD`].
pub(crate) const SCAN_SPREAD_WINDOW_NS: u64 = 10_000_000_000; // 10s

/// SCAN-VERTICAL threshold and window (T1046, #378): N distinct destination ports on one
/// (pid, daddr) in X seconds — the vertical mirror of SCAN-SPREAD (one host, many ports,
/// where SCAN-SPREAD is many hosts, one port). Same 20-in-10s as SCAN-SPREAD: a TCP connect
/// scan covers hundreds of ports a second, and an ordinary client talks to a host on a
/// handful of ports (a service and its dependencies, FTP data connections). Loopback
/// destinations are not counted: a single-host stack (compose files, local exporters,
/// IDE debuggers) connects to many local ports by design, and scanning localhost is a weak
/// lateral signal. Calibration choice, not a measurement.
pub(crate) const SCAN_VERTICAL_THRESHOLD: u32 = 20;
/// Sliding window for [`SCAN_VERTICAL_THRESHOLD`].
pub(crate) const SCAN_VERTICAL_WINDOW_NS: u64 = 10_000_000_000; // 10s

/// RANSOMWARE-RENAME threshold and window (T1486): N renames by the same pid, each
/// adding a new suffix onto its own old path (`document.docx` →
/// `document.docx.locked`), in X seconds. 20-in-5s clears any plausible benign bulk
/// rename (a script tagging a handful of its own output files) while staying well
/// under what a real encryptor manages on modern storage — issue #262's own example
/// ("100+ files modified in 10s") is a full order of magnitude higher than this
/// threshold, so this alerts well before that volume is reached.
pub(crate) const RANSOMWARE_RENAME_THRESHOLD: u32 = 20;
pub(crate) const RANSOMWARE_RENAME_WINDOW_NS: u64 = 5_000_000_000; // 5s
/// A pid contributes to the per-ppid (shell-loop) counter only while it has renamed
/// at most this many files in the window. A loop's `mv` child renames exactly one
/// file and exits, so it always qualifies; a single busy encryptor climbs past this
/// almost immediately and is caught by the per-pid counter instead — this keeps one
/// process's burst from also driving the shared per-ppid counter to a second alert.
pub(crate) const RANSOMWARE_LOOP_CHILD_MAX: u32 = 3;

// ── Ransomware write-volume corroboration (T1486, issue #82) ───────────────
// Second, independent signal alongside check_mass_rename_pattern's shape check:
// heavy write volume + a rename burst, regardless of the rename shape. Reuses
// RANSOMWARE_RENAME_THRESHOLD/_WINDOW_NS above for "what counts as a burst" so the
// two signals agree on calibration.

/// 100MB written in the same window as `RANSOMWARE_RENAME_THRESHOLD` renames is the
/// "full kill chain" signal: encrypt = read + heavy write + rename.
pub(crate) const BURST_WRITE_BYTES_THRESHOLD: u64 = 100 * 1024 * 1024;

/// Compression temp files land here — the one documented FP source for a
/// heavy-write + mass-rename shape (archive extraction/creation). Path-based, not
/// name-keyed, so it doesn't need the evidence-gating `check_mass_rename_pattern`'s
/// doc describes for `comm`-based exclusions.
pub(crate) const RANSOMWARE_EXCLUDED_PATH_PREFIXES: &[&str] = &["/tmp/", "/var/tmp/"];

/// Suffixes a package manager (or an editor's atomic-save convention) appends
/// to a file it's about to replace, then renames away — the *reverse*
/// relationship from `check_mass_rename_pattern`'s ransomware shape
/// (`old_path` + suffix = `new_path`, e.g. `document.docx` ->
/// `document.docx.locked`): here `old_path` = `new_path` + suffix
/// (`lib.so.dpkg-new` -> `lib.so`). Confirmed live (#496): a package upgrade
/// renaming a batch of `.dpkg-new` staging files into place, alongside the
/// large writes that staged their content (120MB across 30 files in the
/// capture), cleared both of `check_burst_write_volume`'s gates — rename
/// count and byte volume — and false-positived T1486. `apk`'s equivalent
/// suffix is included on the same reasoning, not independently captured live.
/// rsync's own temp-file convention plausibly hits the same false positive
/// (also named in the #496 report) but isn't a fixed suffix on the final
/// name the way these are, so it isn't covered here — add it if a live
/// capture shows the actual shape.
pub(crate) const PACKAGE_MANAGER_TEMP_RENAME_SUFFIXES: &[&str] = &[".dpkg-new", ".apk-new"];

/// The prefix apk-tools actually stages under, confirmed live (#500 review,
/// Jihair, real `apk fix` reinstall on Alpine): apk does *not* use the
/// `.apk-new` suffix above for its own package-file replacement — that string
/// is the sidecar it leaves next to a locally modified config file, which it
/// never renames onto anything. The real staging shape extracts each file to
/// a hidden name in the *same directory* as the final path (not derived from
/// it by suffix) and renames that onto the final name, e.g.
/// `usr/bin/.apk.e9a41015f8b7e04a3f02df6f500e89f18738758051d63799` ->
/// `usr/bin/c89`. Without this, coalescing `SlidingSum` correctly (this same
/// PR) made every apk upgrade over ~100MB in 5s a live false T1486 (806/810
/// renames in the capture had this shape, zero had `.apk-new`).
pub(crate) const APK_STAGING_FILE_PREFIX: &str = ".apk.";

/// `comm` values a real Debian/Alpine package manager runs the staging-rename
/// dance under. Required *alongside* [`PACKAGE_MANAGER_TEMP_RENAME_SUFFIXES`]
/// before `check_burst_write_volume` excludes a burst (#500 review, Nikolas):
/// the suffix convention alone is just a filename shape the process being
/// renamed-and-written controls — a real encryptor can name its own staging
/// file `target.dpkg-new` then rename onto `target` purely to dodge this
/// signal. `comm` is spoofable too (`prctl`/`argv[0]`), so this doesn't make
/// the exclusion unspoofable — it raises the bar from "match one filename
/// convention" to "also make the process look like the exact package manager
/// that convention belongs to", which is what corroboration means here, not
/// a claim of unforgeability. `dpkg-deb`/`apt`/`apt-get` shell out to `dpkg`
/// for the actual file replacement, so `dpkg` alone already covers Debian;
/// listed anyway since callers observing themselves is cheaper than the debate
/// over whether they always do.
pub(crate) const PACKAGE_MANAGER_COMMS: &[&str] = &["dpkg", "dpkg-deb", "apt", "apt-get", "apk"];

/// `comm` values of in-place stream-edit tools whose `-i.<suffix>`/`-i .<suffix>`
/// backup convention (`sed -i.bak 's/old/new/' *.conf`) matches `check_mass_rename_pattern`'s ransomware shape exactly: one pid,
/// prefix-preserving, lettered suffix, 20+ files in one command (#459 part 1,
/// #455 review). Gated on `comm` + `policy::name_exclusion_applies` together,
/// never `comm` alone (CLAUDE.md — an encryptor can set `comm=sed` for free;
/// [`FileRenameEvent::executable_path`] existing is what makes gating on the
/// trusted-system-path half possible at all here, where before there was
/// nothing to gate against).
///
/// `sed` only, not `perl`: `sed -i<suffix>` can do nothing but write a backup copy of
/// the original, while `perl` is an interpreter and the trusted binary named `perl`
/// runs whatever script it is given, so listing it would let any mass rename written
/// in Perl through, with any suffix (#528 review, live on Alpine). The cost is small:
/// measured on perl 5.42, `perl -i.bak` does not rename the original to `f.bak` at all
/// (it writes a temp file and renames that onto the original), so it never matched the
/// appended-suffix shape; only a perl older than 5.28, which did rename the original,
/// alerts on 20+ files as a consequence. Recognising the real `-i` shape (the original re-created by the same pid right after the rename)
/// would settle both tools but needs the create history the rename rule does not
/// consult.
pub(crate) const IN_PLACE_EDIT_COMMS: &[&str] = &["sed"];

/// Valid Maildir flag letters (Draft/Flagged/Passed/Replied/Seen/Trashed —
/// the Maildir spec's own convention, unrelated to any ATT&CK id despite the
/// same letters) appended after a message filename's `:2,` info marker
/// (#459 part 1): `check_mass_rename_pattern`'s other known false positive,
/// "mark all read" on a large folder renaming every message's flags in one
/// IMAP pid. See [`crate::state::is_maildir_flag_change`]'s doc for why this
/// one is deliberately not also comm-gated.
pub(crate) const MAILDIR_FLAG_LETTERS: &[u8] = b"DFPRST";

/// `comm` values of compression tools. Their normal operation is exactly the
/// write-new-then-unlink shape (`gzip f` creates `f.gz`, then unlinks `f`), and one
/// process handles a whole `*.log` glob: measured live (Debian 13, #512 part B),
/// `gzip`, `xz`, `bzip2` and `zstd` each reached a burst of 30 in 5 s over 30 files,
/// the same as an encryptor. Gated on `comm` + a trusted exec-time image path together,
/// failing closed, never on `comm` or on the output suffix alone (CLAUDE.md: an
/// encryptor can set `comm=gzip`, or name its output `.gz`, for free).
pub(crate) const COMPRESSOR_COMMS: &[&str] = &[
    "gzip", "bzip2", "xz", "zstd", "lz4", "pigz", "pbzip2", "lzma",
];

/// `comm` values of tools that compress by *driving* a compressor rather than being one:
/// `logrotate` with `compress` opens the `.gz` output itself, forks, `dup2`s it onto the
/// child's stdout, execs `gzip` on stdin and unlinks the original itself, so the create
/// and the unlink both carry `comm=logrotate` and [`COMPRESSOR_COMMS`] never applies
/// (measured live on Alpine, #527 review; daily on any Debian/Ubuntu host rotating 20+
/// logs). Gated like the compressors (trusted binary named `comm`) **and** on the new
/// file's suffix being a compression extension ([`COMPRESSION_SUFFIXES`]).
pub(crate) const COMPRESSION_DRIVER_COMMS: &[&str] = &["logrotate"];

/// Suffixes a compression driver appends. Only meaningful together with
/// [`COMPRESSION_DRIVER_COMMS`]: on their own they are free for an encryptor to copy.
pub(crate) const COMPRESSION_SUFFIXES: &[&str] = &[".gz", ".xz", ".bz2", ".zst", ".lz4", ".lzma"];

/// How long a creation and the unlink of the file it replaced may be apart and still
/// count as one write-new-then-unlink (#512 part B). Generous on purpose: an encryptor
/// creates `f.locked` at the start of a file and unlinks `f` only once the whole
/// content is written, which for a large file is seconds, not milliseconds.
pub(crate) const CREATE_UNLINK_PAIR_WINDOW_NS: u64 = 60_000_000_000; // 60s

/// Creations and unmatched unlinks remembered per pid for that pairing. The open and
/// delete ring buffers are drained independently, so a whole burst of one kind can be
/// processed before the other (live, #512: 30 unlinks first, then 30 creations): the
/// history must hold more than [`RANSOMWARE_RENAME_THRESHOLD`] entries or the burst can
/// never be paired up to the threshold. 64 leaves headroom for a batch of about three
/// times the threshold.
pub(crate) const CREATE_UNLINK_HISTORY_PER_PID: usize = 64;

/// Pids tracked for that pairing. A dedicated, smaller bound than the pid tables: each
/// entry holds up to [`CREATE_UNLINK_HISTORY_PER_PID`] path strings, so the worst case
/// (`cap x per-pid x path`, two maps) stays around ten MB rather than the ~200 MB the
/// 65k-pid tables would allow.
pub(crate) const CREATE_UNLINK_PID_CAP: usize = 1_024;

/// Renames and deletions remembered per pid for the damage manifest of a ransomware
/// detection (issue #82): the newest this many, as the events themselves so a detection
/// can carry them.
pub(crate) const TOUCHED_FILES_PER_PID: usize = 100;

/// Pids tracked for that manifest. Each entry holds up to [`TOUCHED_FILES_PER_PID`]
/// events (a few hundred bytes each), so 64 pids stay near two MB at the worst; a process
/// pushed out by 64 busier ones loses its manifest (counted in the map's eviction counter,
/// like every other bound here), not its detection.
pub(crate) const TOUCHED_FILES_PID_CAP: usize = 64;

/// Pairing window for one scheduled-task registration seen on both Security 4698
/// and TaskScheduler/Operational 106 (#422, T1053.005). The two are normalized by
/// separate poll threads, each on a 2s cadence, so their timestamps land a few
/// seconds apart in either order. 60s covers a slow poll with ample margin, while a
/// real re-registration of the same task with the same action inside it adds
/// nothing an analyst would miss. Uncalibrated against fleet traffic (2026-09-25).
pub(crate) const TASK_REGISTRATION_DEDUP_WINDOW_NS: u64 = 60_000_000_000; // 60s

/// Processes excluded from SELF-SPAWN (child side) — frequent legitimate self-spawn
/// confirmed in lab.
/// MpCmdRun.exe (Defender): false positive observed during the 2026-08-24 tests.
/// wermgr.exe / WerFault.exe: Windows Error Reporting — respawns in a loop when a
/// process keeps crashing (e.g. malware with no reachable C2). The spawn comes from WER
/// itself, not from direct malicious behavior — false positive observed during the
/// 2026-08-25 VM tests.
/// `SecurityHealthH` = SecurityHealthHost.exe (ETW-truncated to 15 chars) — Windows
/// Defender Health service, repeatedly respawned by svchost (ppid=956) under normal
/// conditions — `NjRAT` FP 2026-08-28.
pub(crate) const SELF_SPAWN_EXCLUSIONS: &[&str] = &[
    "MpCmdRun.exe",
    "mpcmdrun.exe",
    "TiWorker.exe",
    "svchost.exe",
    "wermgr.exe",
    "WerFault.exe",
    "WerFaultSecure.exe",
    "SecurityHealthH",
    "SecurityHealthHost.exe",
];

/// Parents excluded from SELF-SPAWN — some system processes legitimately spawn the
/// same child in a loop, with no link to malicious activity.
/// RuntimeBroker.exe: UWP permissions broker, spawns `PowerShell` for system tasks
/// (notifications, policies) — false positive observed in lab 2026-08-25.
pub(crate) const SELF_SPAWN_PARENT_EXCLUSIONS: &[&str] = &["RuntimeBroker.exe"];

/// The agent's own known children — narrower than [`SELF_SPAWN_EXCLUSIONS`]: only
/// applies when the spawning `ppid` is the agent's own seeded pid (issue #403).
/// `wevtutil.exe`: the Event Log sensor's `wevtutil qe` poll loop, one spawn every
/// 2s per enabled channel — ~60 spawns/30s across the default four channels, well
/// past `SELF_SPAWN_THRESHOLD`. `auditpol.exe`: run once at startup per channel
/// needing an audit subcategory enabled. Both false-positived on the agent itself
/// in the 2026-09-23 live lab validation of #391. `logman.exe`: the ETW sensor's
/// startup orphan sweep (#408) — one `logman query -ets` plus one `logman stop` per
/// orphan, so two orphans already reach `SELF_SPAWN_THRESHOLD`. Never a blanket "ignore every
/// child of the agent": `ppid` alone is spoofable
/// (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`), so `check_self_spawn` also requires
/// the image to live at a trusted system path (`policy::name_exclusion_applies`),
/// same pairing as `SELF_SPAWN_EXCLUSIONS`.
pub(crate) const AGENT_CHILD_EXCLUSIONS: &[&str] = &["wevtutil.exe", "auditpol.exe", "logman.exe"];

/// `LOLBins` abused for shellcode injection or executing unsigned code (T1218/T1127).
pub(crate) const LOLBINS: &[&str] = &[
    "aspnet_compiler.exe",
    "aspnet_compiler", // truncated by Windows ETW (20 → 15 chars)
    "msbuild.exe",
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
    "ieexec.exe",
    "msdeploy.exe",
    "dfsvc.exe",
    "cmstp.exe",
    "wab.exe",
    "odbcconf.exe",
];

/// Legitimate parents allowed to spawn `LOLBins` (dev environments).
pub(crate) const LOLBIN_LEGIT_PARENTS: &[&str] =
    &["devenv.exe", "msbuild.exe", "dotnet.exe", "nuget.exe"];

/// Office/PDF applications often exploited to spawn interpreters (T1204/T1059).
pub(crate) const SUSPECT_PARENTS_WIN: &[&str] = &[
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "acrord32.exe",
    "acrobat.exe",
    "foxit.exe",
    "iexplore.exe",
];

/// Interpreters and tools frequently launched by Windows macros/exploits.
pub(crate) const SUSPECT_CHILDREN_WIN: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "certutil.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "bitsadmin.exe",
    "wmic.exe",
    "msiexec.exe",
];

/// Standard ports — connections ignored for BEACON (expected legitimate traffic).
/// 137 = NetBIOS-NS, 138 = NetBIOS-DGM, 5353 = mDNS, 5355 = LLMNR — native Windows
/// network protocols emitted in a loop by the System process and legitimate services,
/// not C2.
/// 3478 = STUN/TURN — used by `CrossDeviceService`, Teams, WebRTC for NAT traversal,
/// legitimate beaconing observed in lab (false positive, `NjRAT` capture 2026-08-28).
pub(crate) const STANDARD_PORTS: &[u16] = &[
    80, 443, 53, 8080, 8443, 8000, 25, 587, 465, 993, 995, 143, 137, 138, 5353, 5355, 3478,
];

/// Browsers — repeated outbound connections = normal behavior, not beaconing.
pub(crate) const BROWSERS: &[&str] = &[
    "chrome.exe",
    "firefox.exe",
    "msedge.exe",
    "opera.exe",
    "brave.exe",
    "iexplore.exe",
    "vivaldi.exe",
];

/// New-shape alerts POLICY-DENIAL-DRIFT raises **per subject type** per
/// [`POLICY_DENIAL_ALERT_WINDOW_NS`] (#812, per subject since #840):
/// `known_policy_denials` bounds the rule's memory of what it has seen, not its alert
/// volume, so a flood of distinct shapes (one domain probing thousands of object types)
/// could otherwise emit one alert per shape, unbounded. The key is (mechanism, subject
/// context, object context, object class, action); since #813 added the requested
/// permission set to it, one (type, type, class) triple produces one shape per permission set
/// the kernel denies for it, not one shape overall.
///
/// The budget belongs to the subject's type (`user:role:type`, see
/// [`POLICY_DENIAL_SUBJECT_CAP`]): one noisy domain (`httpd_t` probing 512 types) spends its own
/// budget and nobody else's, so the first new shape of an untouched domain still alerts
/// (#840; it used to be one counter for the whole host).
///
/// 2048 is a reasoned bound, **not a measured one**: a few hundred distinct triples times a
/// handful of permission sets each was the estimate when it was chosen, and nobody has
/// compared it with the denial volume of a real `SELinux`-enforcing fleet. It was a host-wide
/// figure and is now a per-subject one, unchanged for lack of data. Shapes past it are
/// counted (`policy_denial_alerts_shed`) and, not being remembered, can alert in a later
/// window. Revisit with real denial data.
pub(crate) const POLICY_DENIAL_ALERT_CAP: u64 = 2048;

/// How long [`POLICY_DENIAL_ALERT_CAP`] lasts before a subject's budget refills: one hour of
/// event time (`meta.timestamp_ns`). Long enough that a flood stays bounded to the cap per hour,
/// short enough that a genuinely new denial after a noisy period is not silenced for the whole
/// run.
pub(crate) const POLICY_DENIAL_ALERT_WINDOW_NS: u64 = 3_600_000_000_000;

/// Subject types whose alert budget POLICY-DENIAL-DRIFT tracks at once (#840), least recently
/// seen out first like every other map of the rule state. A subject type is a type of the loaded
/// policy, assigned by the kernel and not written by a process, so a host has a few hundred to
/// a few thousand of them; 2048 holds a stock policy's confined domains. Past it the least recently
/// seen subject's budget is forgotten (counted and logged), so a domain that was noisy and then
/// quiet can alert again sooner than its window: bounded loss, never unbounded growth.
///
/// What this gives up, named: the alert volume is bounded per subject
/// ([`POLICY_DENIAL_ALERT_CAP`]) and the number of subjects is bounded by the policy, so the
/// worst case is `cap x subjects`, not one host-wide ceiling any more.
pub(crate) const POLICY_DENIAL_SUBJECT_CAP: usize = 2048;

/// One alert per (pid, kind of credential file) per this window. A scanner or a `grep -r` over
/// `/home` opens the same credential files again and again, and the first open is the finding.
/// Sliding (timestamp-based), never a reset bucket. Uncalibrated (first cut, 2026-10-21).
pub(crate) const CREDENTIAL_READ_ALERT_WINDOW_NS: u64 = 300_000_000_000; // 5 min

/// STAGING-DIR (T1074.001, #380): distinct user-data files one pid must open for reading
/// inside [`STAGING_WINDOW_NS`] ...
///
/// **All four numbers are provisional**: there is no lab capture of an ordinary copy, build
/// or backup to calibrate against, so they are set above what a person does by hand
/// (copying a folder of a few dozen files) and below a sweep. A `SlidingDistinct` holds 256
/// values, so no threshold may exceed that.
pub(crate) const STAGING_READ_FILES: u32 = 100;
/// ... spread over at least this many distinct directories (a build of one source tree reads
/// many files from few directories; a collection walks trees) ...
pub(crate) const STAGING_READ_DIRS: usize = 10;
/// ... and the same pid must have created this many distinct files in one staging directory.
pub(crate) const STAGING_WRITE_FILES: u32 = 50;
/// The window of all three counts.
pub(crate) const STAGING_WINDOW_NS: u64 = 600_000_000_000; // 10 min
/// Pids tracked by STAGING-DIR, for the reads and for the staging directories alike. Each
/// entry holds up to 256 paths, so 256 pids stay near ten MB at the worst; a pid pushed out
/// by 256 busier ones loses its history (counted in the map's eviction counter).
pub(crate) const STAGING_PID_CAP: usize = 256;
/// Temp roots whose subdirectories are staging places, as lowercase `/`-joined segments
/// from the filesystem root (the drive of a Windows path left out). macOS per-user temp
/// (`/var/folders/.../T/`) is a stated gap.
pub(crate) const STAGING_TEMP_ROOTS: &[&str] = &[
    "tmp",
    "var/tmp",
    "dev/shm",
    "private/tmp",
    "private/var/tmp",
    "windows/temp",
];
/// Temp roots inside a profile, from the profile directory (`C:\Users\<u>\`).
pub(crate) const STAGING_PROFILE_TEMP_ROOTS: &[&str] = &["appdata/local/temp"];
/// Directory names that are never a staging place however hidden: a version-control store
/// (`git add` of a large tree writes thousands of objects) and a program's cache. Path-based,
/// not name-keyed on the process, so no evidence gate is needed. Stated gap: `~/.cache` is a
/// place an attacker can stage in as well.
pub(crate) const STAGING_EXCLUDED_DIR_NAMES: &[&str] = &[".git", ".cache", ".trash"];

/// EGRESS-DOMAIN (T1567, #380): bytes one process sends to an address that its own DNS lookup
/// resolved from a storage or paste service, inside [`EGRESS_WINDOW_NS`]. Far below
/// [`EGRESS_BYTES_THRESHOLD`] because the destination is already what an exfiltration picks.
/// **Provisional**: 25 MiB in 10 minutes is above what a script or an API client sends to a
/// storage service and below a home directory, but no capture of ordinary uploads exists to
/// calibrate it. A sync client (Dropbox, `rclone`, `rsync` to a bucket) or a backup tool crosses it
/// by design, and is the false positive to expect. Raise it before narrowing the domain list.
pub(crate) const EGRESS_CLASSED_BYTES_THRESHOLD: u64 = 25 * 1024 * 1024;
/// How long after a process resolved a listed service the address it got still names that service
/// for EGRESS-DOMAIN. A connection outlives its lookup, so this is long; a new lookup renews it.
/// Provisional.
pub(crate) const DNS_CLASS_WINDOW_NS: u64 = 3_600_000_000_000; // 1 h
/// Linux browsers whose uploads to a storage service are a user's own action, excluded from
/// EGRESS-DOMAIN. Only on evidence: the exclusion applies through
/// `policy::name_exclusion_applies`, so a `chrome` run from `/tmp` is not excluded. A browser
/// installed outside the system directories (Snap, Flatpak) is therefore not excluded either, and
/// alerts on its own uploads: a known false positive.
pub(crate) const EGRESS_DOMAIN_BROWSER_COMMS: &[&str] = &[
    "chrome",
    "chromium",
    "firefox",
    "firefox-bin",
    "brave",
    "msedge",
    "opera",
    "vivaldi",
];
