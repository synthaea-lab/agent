//! Process execution, what a process loads and runs, and signals between processes.

use super::*;

/// Bytes of argv, one separator per token included, a sensor keeps for one exec
/// ([`bound_argv`], #1112).
///
/// Without it, one unprivileged exec with a ~2 MiB padded argv (the Linux kernel's
/// quarter-stack ceiling) is carried twice per [`ExecEvent`] (`cmdline` and
/// `argv`), then expanded up to 6× by JSON escaping: a 21.6 MB detection the
/// server's 8 MiB body limit refuses with a permanent 413, and the agent drops
/// the whole spool segment it was batched in, every unrelated detection with it.
///
/// 32 KiB, from data (#1112, Alpine lab VM, 3,451 benign execs): p99.9 347 B,
/// max 1,661 B, none over 4 KiB. It also matches the order of Windows' own
/// `CreateProcess` ceiling (32,766 UTF-16 units), so the long encoded-PowerShell
/// command lines F-1/F-4 protects are never near it. Worst case one exec then
/// serializes to about 2 × 32 KiB × 6 = 384 KiB.
pub const ARGV_CAPTURE_BUDGET: usize = 32 * 1024;

/// Cuts `argv` to [`ARGV_CAPTURE_BUDGET`], keeping its head, and returns whether
/// anything was cut — the value for [`ExecEvent::cmdline_truncated`].
///
/// Each token costs its length plus one separator (the space of
/// [`ExecEvent::cmdline`], the NUL of [`ExecEvent::ml_cmdline`]), so a flood of
/// empty arguments is bounded too. The token that crosses the budget is kept up
/// to it, cut on a character boundary, rather than dropped: the head of a long
/// encoded payload is what a rule matches on. Truncation, never rejection — a
/// rejected event is a detection the attacker chose to erase.
#[must_use]
pub fn bound_argv(argv: &mut Vec<String>) -> bool {
    let mut used = 0usize;
    let mut crossing = None;
    for (index, token) in argv.iter().enumerate() {
        let cost = token.len().saturating_add(1);
        if cost > ARGV_CAPTURE_BUDGET - used {
            crossing = Some(index);
            break;
        }
        used += cost;
    }
    let Some(index) = crossing else {
        return false;
    };
    let mut keep = (ARGV_CAPTURE_BUDGET - used).saturating_sub(1);
    let token = &mut argv[index];
    while !token.is_char_boundary(keep) {
        keep -= 1;
    }
    token.truncate(keep);
    let kept = if keep == 0 { index } else { index + 1 };
    argv.truncate(kept);
    true
}

/// Process execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Full path of the executed image, as the platform reports it (normalized to a
    /// drive-letter path on Windows — audit F-5).
    pub image_path: String,
    /// The command line as one string (audit F-1/F-4: this field is what the base64
    /// rule, encoded-PowerShell Sigma rules, and the ML cmdline features evaluate —
    /// it must never be a truncated placeholder for the image path). Not cut by the
    /// schema; a Linux sensor bounds the argv it renders from at capture
    /// ([`bound_argv`], #1112) and says so in [`Self::cmdline_truncated`].
    pub cmdline: String,
    /// Argument vector where the platform provides one (Unix execve). Empty on
    /// platforms that only have a flat command line (Windows); consumers fall back
    /// to [`ExecEvent::cmdline`].
    pub argv: Vec<String>,
    /// `true` when the sensor knows some bytes of the argument block were not
    /// captured: [`Self::argv_omitted_bytes`] is `Some(n)` with `n > 0`, or the
    /// command line was cut to [`ARGV_CAPTURE_BUDGET`] (#1112). A rule that finds no
    /// match in a cut command line has not seen all of it: the missing part is where
    /// a padded exec would hide its payload. `false` means "no cut seen", not "the
    /// whole command line was seen": see [`Self::argv_omitted_bytes`]'s `None`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cmdline_truncated: bool,
    /// How many bytes of the argument block the sensor did not capture (<https://github.com/synthaea-lab/agent/issues/48>): `Some(0)` when it captured the whole block, `Some(n)` when `n` bytes
    /// between a head and a tail window were not read, `None` when unknown (the
    /// sensor saw nothing to measure against, or a cut whose size it did not
    /// measure). A rule must never read `None` as "complete".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argv_omitted_bytes: Option<u32>,
    /// Parent process short name, captured by the sensor *at exec time*. Lineage is a
    /// first-class detection input (parent→child transition rarity, ancestry
    /// features — see "Behavior over time" in `docs/detection/ml.md`); sensors that
    /// can attribute the parent fill this rather than leaving consumers to join on
    /// `meta.ppid` later, which races against pid reuse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_comm: Option<String>,
    /// Full image path of the parent, where the platform resolves it (ETW and
    /// `EndpointSecurity` provide it; eBPF may only have the parent `comm`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_image_path: Option<String>,
    /// SHA-256 of the executed image, filled by the agent's enrichment stage (not by
    /// sensors) — the join key for IOC hash matching and fleet-level correlation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Code-signature verdict for the executed image, filled by enrichment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
    /// `OriginalFilename` from the executed image's PE version resource, filled by
    /// the agent's enrichment stage (issue #983) — the `SigmaHQ` `process_creation`
    /// catalogue's primary renamed-binary signal (49% of its Windows rules use it:
    /// `cmd.exe` renamed to `svchost.exe` still carries its real original name in the
    /// resource). Windows only: PE version resources are a Windows concept, so this
    /// is always `None` on Linux/macOS (no Mach-O/ELF equivalent). `None` on Windows
    /// too when the image has no version resource, enrichment could not read it
    /// (over [`crate`]'s size budget, or a malformed/absent resource), or the image
    /// was never enriched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_file_name: Option<String>,
    /// `CompanyName` from the same PE version resource as
    /// [`Self::original_file_name`] — read in the same pass since the cost is
    /// already paid once the resource is open. Same `None` rules, same posture
    /// (19 rules in the catalogue's `process_creation` category use it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub company_name: Option<String>,
    /// `FileDescription` from the same PE version resource. Same `None` rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_description: Option<String>,
    /// `ProductName` from the same PE version resource. Same `None` rules (70 rules
    /// in the catalogue's `process_creation` category use it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_name: Option<String>,
    /// Identity of the file the image ran from, captured by the sensor *at exec
    /// time* (#688): `"{volume serial:016x}:{file id:032x}"`, opaque to consumers.
    /// The enrichment worker verifies the file at `image_path` some time later; a
    /// verdict only speaks for the image that ran when the file it verified has
    /// this identity (a running image can be renamed on Windows and a signed copy
    /// put at its path). Windows only; `None` when the sensor could not open the
    /// image, and on every other platform.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_file_id: Option<String>,
    /// Security-relevant environment variables present at exec time, `(name, value)`
    /// pairs (#363) — the dynamic-linker-hijack family: `LD_PRELOAD`,
    /// `LD_LIBRARY_PATH`, `LD_AUDIT` (the quieter sibling of `LD_PRELOAD`),
    /// `LD_DEBUG_OUTPUT` (arbitrary-file-write via the linker's own debug tracing),
    /// and `GLIBC_TUNABLES` (the CVE-2023-4911 "Looney Tunables" vector). A fixed
    /// allowlist, never the whole environment — environments carry secrets and
    /// multi-KB noise — and present-only: a name absent from the process's actual
    /// environment is simply not in this list, never an empty-value entry. Empty on
    /// every platform/sensor that has not opted into this capture (Linux/eBPF only,
    /// so far).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_security: Vec<(String, String)>,
}

impl ExecEvent {
    /// The command line in the one canonical form the ML cmdline scorer and its
    /// training pipeline agree on: `argv` tokens joined (and terminated) by NUL.
    ///
    /// This is deliberately **not** [`ExecEvent::cmdline`]: sensors are free to put a
    /// display/Sigma-friendly string there (the Linux userspace sensor space-joins
    /// argv), and the cmdline feature extractor splits tokens on NUL — feeding it a
    /// space-joined string silently collapses `token_count` to 1 and inflates
    /// `max_token_length`. Every ML consumer (`ml::features::cmdline`, the agent's
    /// scorer wiring, `synthaea_ml`) must build its input from here.
    ///
    /// Fallback when `argv` is empty (Windows/ETW has only a flat command line):
    /// [`ExecEvent::cmdline`] verbatim, as one token. Mirror of
    /// `synthaea_ml.data.canonical.ml_cmdline_from_record`.
    #[must_use]
    pub fn ml_cmdline(&self) -> String {
        if self.argv.is_empty() {
            return self.cmdline.clone();
        }
        let mut s = String::with_capacity(self.cmdline.len() + self.argv.len());
        for tok in &self.argv {
            s.push_str(tok);
            s.push('\0');
        }
        s
    }
}

/// Code-signature verdict (Authenticode on Windows, codesign on macOS; Linux has no
/// standard equivalent and reports `Unsupported`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Signature {
    /// Signed and the chain verified.
    Valid,
    /// Signed but verification failed (broken chain, revoked, tampered).
    Invalid,
    /// No signature present.
    Unsigned,
    /// The platform has no signature scheme, or verification errored.
    Unsupported,
}

/// WMI activity — query execution (EID 23) or method invocation (EID 24) from the
/// Microsoft-Windows-WMI-Activity provider.
///
/// Covers T1047 (`Win32_Process.Create` via WMI) and WMI-based reconnaissance
/// (`SELECT * FROM Win32_Process`). Exactly one of `query` or `method` is `Some`
/// depending on the event ID; the other is `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WmiActivityEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// WMI namespace (e.g. `ROOT\\CIMv2`).
    pub namespace: String,
    /// WQL query string for EID 23 (`ExecQuery`). `None` for EID 24.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// Method invocation for EID 24, formatted as `ClassName.MethodName`
    /// (e.g. `Win32_Process.Create`). `None` for EID 23.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

/// `PowerShell` script block logged by EID 4104 of the Microsoft-Windows-PowerShell
/// provider.
///
/// The provider decodes `base64 -EncodedCommand` payloads before logging — this
/// event sees the plain-text script regardless of obfuscation, making it the
/// primary signal for encoded-PowerShell detections (T1059.001, T1027).
///
/// Large scripts are split across multiple ETW records. Each fragment shares the
/// same `script_block_id`; reassemble by ordering on `(script_block_id,
/// message_number)`. Single-record scripts have `message_number = message_total = 1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptBlockEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Opaque identifier shared by all fragments of the same script block.
    pub script_block_id: String,
    /// Source file path when the script was loaded from disk; `None` for
    /// interactive / inline invocations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Decoded script text for this fragment.
    pub text: String,
    /// 1-based fragment index. Equal to `message_total` when the script fits in
    /// one ETW record.
    pub message_number: u32,
    /// Total number of fragments for this script block.
    pub message_total: u32,
}

/// Content a runtime handed to AMSI before running it, from EID 1101 of the
/// Microsoft-Antimalware-Scan-Interface provider (#282).
///
/// AMSI sees the **post-decoding** buffer: a Base64/XOR/format-string obfuscated
/// payload is readable here, from every runtime that scans through AMSI
/// (`PowerShell`, Windows Script Host's `VBScript`/`JScript`, Office VBA, .NET
/// Framework 4.8+ assembly loads). Complements [`ScriptBlockEvent`], which only
/// covers the `PowerShell` runtime and only what it logs.
///
/// What a runtime hands over differs: `PowerShell` passes every script and
/// command, de-obfuscated; Windows Script Host passes only its sensitive
/// runtime calls with their arguments (`IWshShell3.Run("cmd /c …")`,
/// `VBScript` `Execute` content), not the whole script (lab, 2026-10-01).
///
/// `meta` is the scanning process (AMSI runs in-process). Identical content is
/// rescanned constantly, so the sensor deduplicates on [`Self::content_hash`]
/// and rate-limits per process; see the sensor's `amsi` module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmsiContentEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// AMSI session handle: scans that belong together (e.g. the fragments of
    /// one `PowerShell` command) share it. Opaque.
    pub session: u64,
    /// The runtime that asked for the scan, as AMSI reports it
    /// (`PowerShell_C:\…\powershell.exe_10.0…`, `VBScript`, `JScript`,
    /// `DotNet`, `OFFICE_VBA`, …).
    pub app_name: String,
    /// The content's name when the runtime gave one (a script path, a URL);
    /// `None` for inline content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_name: Option<String>,
    /// Size in bytes of the scanned buffer as AMSI reports it.
    pub content_size: u32,
    /// Size in bytes of the content before the runtime's own processing, as
    /// AMSI reports it.
    pub original_size: u32,
    /// The scanned content decoded as text (UTF-16LE, as the script runtimes
    /// hand it over), cut to the sensor's limit. `None` when the buffer is not
    /// text (a .NET assembly image, Office VBA p-code) or AMSI filtered it out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// `true` when [`Self::text`] was cut to the sensor's limit.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub text_truncated: bool,
    /// SHA-256 of the scanned buffer, lowercase hex, as AMSI computed it.
    pub content_hash: String,
    /// The `AMSI_RESULT` the antimalware provider returned (0 clean,
    /// `>= 32768` detected / blocked by admin policy).
    pub scan_result: u32,
}

/// Image (DLL or EXE) loaded into a process address space.
///
/// Emitted on EID 5 of the Microsoft-Windows-Kernel-Process provider, which is
/// already subscribed for process start/end events. Covers DLL hijacking, side-loading,
/// `LOLBin` chains (e.g. `wscript.exe` → `scrobj.dll`), and AMSI bypass via patching
/// (first seen as a load of `amsi.dll` into an unexpected process).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageLoadEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Full path of the loaded image, normalized to drive-letter form (same
    /// normalization as [`ExecEvent::image_path`], audit F-5).
    pub image_path: String,
}

/// In-memory .NET assembly load — the primary signal for execute-assembly /
/// fileless .NET injection (T1620, T1055).
///
/// Emitted on EID 154 (`AssemblyLoad`) of the `Microsoft-Windows-DotNETRuntime`
/// provider, filtered to dynamic (in-memory) assemblies only (`flags & 0x2 != 0`).
/// File-backed assemblies are high-volume noise with low detection value at this
/// tier — they are dropped at the sensor, not forwarded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssemblyLoadEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Fully qualified assembly name (e.g. `MyPayload, Version=0.0.0.0, ...`).
    pub assembly_name: String,
    /// Assembly load flags from the runtime (`0x2` = dynamic/in-memory,
    /// `0x8` = collectible). In-memory loads always have bit `0x2` set.
    pub flags: u32,
}

/// Shell type for readline capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellType {
    /// GNU Bash.
    Bash,
    /// Z shell.
    Zsh,
}

/// Interactive shell command capture — commands typed at a shell prompt that may
/// not trigger execve (issue #90).
///
/// Emitted by Linux uprobes on bash/zsh readline functions. Captures shell builtins
/// (`cd`, `export`, `alias`) and interactive commands that do not spawn child processes.
/// Complements `ExecEvent` for complete shell activity visibility.
///
/// Note: Multi-line commands are captured as typed (newlines included). Command
/// history navigation (up-arrow) triggers multiple readline events; deduplication
/// is the consumer's responsibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadlineInputEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Shell type (bash or zsh).
    pub shell_type: ShellType,
    /// Full command line as typed by the user. UTF-8 validated by the sensor.
    pub input: String,
}

/// A signal was sent to a monitored security process. Emitted by
/// `sensor-macos` (#96), filtered at the source to targets that are
/// `EndpointSecurity` clients — i.e. this agent and other security tools:
/// the tamper-attempt subset of the platform's full (and enormous) signal
/// stream, per the sensor's volume discipline. Platform-neutral shape; Linux reuses it for the
/// agent's own pid (the `kill`/`tgkill` probes, #362) and for the processes of the listed security
/// units (the `signal_generate` tracepoint, #1103, which fills `target_unit`).
///
/// `meta` is the *sender* — the interesting party in a tamper attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Signal number, platform-native (SIGKILL=9, SIGTERM=15, ...).
    pub signal: u32,
    /// Pid of the process the signal is sent to.
    pub target_pid: u32,
    /// Image path of the targeted process, when the platform resolves it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_image_path: Option<String>,
    /// The systemd unit the targeted process belongs to, as listed in
    /// [`SECURITY_SERVICES`] (lowercase, no `.service`), when the source resolves it (Linux,
    /// from the unit's cgroup, #1103). `None` where the platform has no unit, and for the
    /// agent's own pid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_unit: Option<String>,
    /// The sender is the watchdog that supervises the agent (Linux,
    /// <https://github.com/synthaea-lab/agent/issues/322>), which kills it on a stalled heartbeat
    /// or a rollback: its pid is the agent's parent's, and that parent was already running when
    /// the signal was sent, so the pid cannot have been another process's. Neither the sender's
    /// name nor its cgroup is trusted for this: root can choose both. Absent (false) elsewhere,
    /// for an agent started without its watchdog, and in an older event.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sender_is_watchdog: bool,
    /// The sender in `meta` may not be the process that sent the signal (Linux, #1103): the
    /// siginfo's `si_code` was `SI_TIMER`, `SI_MESGQ` or `SI_ASYNCIO`, which the kernel sets from
    /// interrupt or completion context, where the current task is a bystander. A process can also
    /// forge those codes with `rt_sigqueueinfo` or `pidfd_send_signal`, so the event is reported
    /// and not dropped. Absent (false) elsewhere and in an older event.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sender_unreliable: bool,
    /// Not a signal: the sensor's report that this many signals to security tools were lost
    /// because the signal ring buffer was full (Linux, #1103, T1562.001). A flood of lethal
    /// signals ahead of a kill is how a tool is ended unseen, so the loss is itself a finding.
    /// Non-zero only on that report, which carries `signal: 0` and `target_pid: 0`. It is a field
    /// of its own, not a flag on a `FileOpenEvent`: that event's `flags` are the raw `open(2)`
    /// flags on Linux (unknown bits pass through `openat`), so any bit there can be set by an
    /// unprivileged open, as `O_TMPFILE` set the first cut's bit. A kernel signal event never
    /// has this field. Absent (0) elsewhere and in an older event.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub signals_lost: u64,
}

fn is_zero_u64(n: &u64) -> bool {
    *n == 0
}

/// macOS XPC connection — a process connected to an XPC service by name.
/// Emitted by `sensor-macos` (#96, macOS 14+). High-volume by nature; rules
/// should match on sensitive `service_name`s (e.g. TCC, launchd control,
/// screen capture services) rather than alerting per event. macOS-only
/// family, per the v19 precedent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XpcConnectEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// The requested service name (e.g. `com.apple.tccd`).
    pub service_name: String,
    /// Raw `es_xpc_domain_type_t` (1 = system, 2 = user, ... 7 = pid) — kept
    /// as the platform reports it, uninterpreted.
    pub domain_type: u32,
}

#[cfg(test)]
mod bound_argv_tests {
    use super::{ARGV_CAPTURE_BUDGET, bound_argv};

    fn cost(argv: &[String]) -> usize {
        argv.iter().map(|token| token.len() + 1).sum()
    }

    #[test]
    fn an_argv_within_the_budget_is_left_alone() {
        let mut argv = vec!["curl".to_string(), "-fsSL".into(), "https://x.test".into()];
        let before = argv.clone();
        assert!(!bound_argv(&mut argv));
        assert_eq!(argv, before);
    }

    #[test]
    fn an_argv_exactly_at_the_budget_is_not_truncated() {
        let mut argv = vec!["a".repeat(ARGV_CAPTURE_BUDGET - 1)];
        assert!(!bound_argv(&mut argv));
        assert_eq!(argv[0].len(), ARGV_CAPTURE_BUDGET - 1);
    }

    #[test]
    fn a_padded_argv_keeps_its_head_and_is_flagged() {
        let payload = format!("echo {}", "Q".repeat(2 * 1024 * 1024));
        let mut argv = vec!["sh".to_string(), "-c".into(), payload];
        assert!(bound_argv(&mut argv));
        assert_eq!(cost(&argv), ARGV_CAPTURE_BUDGET);
        assert_eq!(argv[..2], ["sh", "-c"]);
        assert!(
            argv[2].starts_with("echo QQQ"),
            "the crossing token keeps its head"
        );
    }

    #[test]
    fn a_flood_of_empty_arguments_is_bounded() {
        let mut argv = vec![String::new(); 1_000_000];
        assert!(bound_argv(&mut argv));
        assert_eq!(argv.len(), ARGV_CAPTURE_BUDGET);
    }

    #[test]
    fn the_cut_lands_on_a_character_boundary() {
        // 'é' is two bytes: with an odd byte budget left, a byte cut would split it.
        let mut argv = vec!["x".into(), "é".repeat(ARGV_CAPTURE_BUDGET)];
        assert!(bound_argv(&mut argv));
        assert!(cost(&argv) <= ARGV_CAPTURE_BUDGET);
        assert!(argv[1].chars().all(|c| c == 'é'));
    }

    #[test]
    fn no_room_left_drops_the_crossing_token_instead_of_keeping_it_empty() {
        let mut argv = vec!["a".repeat(ARGV_CAPTURE_BUDGET - 1), "tail".into()];
        assert!(bound_argv(&mut argv));
        assert_eq!(argv.len(), 1);
    }
}
