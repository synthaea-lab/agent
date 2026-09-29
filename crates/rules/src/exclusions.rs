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
/// within a script's seconds. Uncalibrated first cut (2026-09-23) — every
/// legitimate installer run inside the window alerts too; revisit against
/// fleet volume.
pub(crate) const QUARANTINE_EXEC_WINDOW_NS: u64 = 600_000_000_000; // 10 min

// ── Windows constants (ETW rules — T1059/T1218/T1071) ───────────────────────

/// SELF-SPAWN threshold and window (T1059): N spawns of the same name in X seconds.
pub(crate) const SELF_SPAWN_THRESHOLD: u32 = 3;
pub(crate) const SELF_SPAWN_WINDOW_NS: u64 = 30_000_000_000; // 30s

/// BEACON threshold and window (T1071/T1041): N connections to the same dest in X seconds.
/// T1110 — failed authentications per (target user, source) inside
/// [`AUTH_FAILURE_WINDOW_NS`] before the burst alerts. 5-in-60s clears any
/// human fumbling a password (2-3 tries then a reset) while catching even a
/// slow scripted spray.
pub(crate) const AUTH_FAILURE_THRESHOLD: u32 = 5;
/// Sliding window for [`AUTH_FAILURE_THRESHOLD`].
pub(crate) const AUTH_FAILURE_WINDOW_NS: u64 = 60_000_000_000; // 60s
pub(crate) const BEACON_THRESHOLD: u32 = 3;
pub(crate) const BEACON_WINDOW_NS: u64 = 60_000_000_000; // 60s

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
/// backup convention (`sed -i.bak 's/old/new/' *.conf`, `perl -i.orig -pe … *`)
/// matches `check_mass_rename_pattern`'s ransomware shape exactly: one pid,
/// prefix-preserving, lettered suffix, 20+ files in one command (#459 part 1,
/// #455 review). Gated on `comm` + `policy::name_exclusion_applies` together,
/// never `comm` alone (CLAUDE.md — an encryptor can set `comm=sed` for free;
/// [`FileRenameEvent::executable_path`] existing is what makes gating on the
/// trusted-system-path half possible at all here, where before there was
/// nothing to gate against).
pub(crate) const IN_PLACE_EDIT_COMMS: &[&str] = &["sed", "perl"];

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
