//! Pure `/proc` text parsing: cmdline blobs and `stat` lines. No eBPF, no
//! caching, no I/O beyond the reads themselves — the drain loop (`sensor`) and
//! the lineage seeding (`ebpf`) call in here. Split out of `sensor.rs` when
//! that file had accumulated five concerns.

/// Splits a NUL-separated `/proc/<pid>/cmdline` blob into argv tokens. The kernel
/// gives exactly the `execve` argument vector, each element NUL-terminated; a trailing
/// empty element from the final NUL is dropped, and any interior empty argument is
/// kept (a process is free to pass `""`). Non-UTF-8 bytes are replaced, never fatal.
pub(crate) fn parse_proc_cmdline(blob: &[u8]) -> Vec<String> {
    let trimmed = blob.strip_suffix(b"\0").unwrap_or(blob);
    if trimmed.is_empty() {
        return Vec::new();
    }
    trimmed
        .split(|&b| b == 0)
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

/// argv of `pid`, read from `/proc/<pid>/cmdline` when the `exec` event is drained.
///
/// Deliberately not read in the probe: that needed a `mm_struct` frozen offset, the
/// last non-portable read (issue #152). Two consequences, both accepted because
/// `cmdline`/`argv` are display/analysis inputs and never an identity — that is
/// `image_path`, still read authoritatively in the probe at `sched_process_exec`:
///
/// - **Race.** A process that exits in the few milliseconds before userspace drains
///   the ring buffer leaves no `/proc` entry (empty argv); if its pid is already
///   reused in that window the argv is the successor's.
/// - **Not exec-time.** `/proc/<pid>/cmdline` reflects `mm->arg_*` *now*, not at
///   `execve`. A process can rewrite its own argv region (write through
///   `arg_start..arg_end`, or move the pointers with `prctl(PR_SET_MM_ARG_*)`) between
///   exec and the drain, so a cmdline-substring rule (base64 decode, `curl | sh`) can
///   be evaded or spoofed by a process willing to scribble its own stack. The old
///   probe-side read captured argv atomically at exec and did not have this gap.
///   Tightening it — a `/proc` read triggered from the probe via task-work, or an
///   `arg_start` snapshot once aya has CO-RE — is a separate follow-up, not this
///   change.
///
/// Not usable on `WSL2`: kernel 6.6 returns `ENOENT` here for every pid, including
/// a live `sleep 60` with a confirmed parent — the `WSL` interop layer between the
/// eBPF context and the agent's `/proc` view, not the drain race. `WSL2` is not a
/// supported platform; recorded so it is not re-investigated (Nikolas, 2026-09-10).
///
/// Reads at most one byte past [`schema::ARGV_CAPTURE_BUDGET`] (#1112): enough for
/// `normalize::exec`'s cut to see the argv is over and flag it, without copying a
/// padded exec's ~2 MiB on every drain.
pub(crate) fn read_proc_cmdline(pid: u32) -> Vec<String> {
    match read_cmdline_file(&format!("/proc/{pid}/cmdline")) {
        Ok(argv) => argv,
        // The expected exit race (process already gone) is silent; anything else
        // (EACCES, EIO) is worth a line when tracing a capture gap on some kernel.
        Err(e) if is_proc_exit_race(&e) => Vec::new(),
        Err(e) => {
            tracing::debug!(pid, error = %e, "read /proc/<pid>/cmdline failed");
            Vec::new()
        }
    }
}

/// The argv in a `cmdline`-shaped file, read up to one byte past
/// [`schema::ARGV_CAPTURE_BUDGET`] so the cut in `normalize::exec` can tell an
/// argv that is over the budget from one that fits exactly.
fn read_cmdline_file(path: &str) -> std::io::Result<Vec<String>> {
    read_capped(path, schema::ARGV_CAPTURE_BUDGET + 1).map(|blob| parse_proc_cmdline(&blob))
}

/// The first `limit` bytes of the file at `path`.
fn read_capped(path: &str, limit: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let mut blob = Vec::new();
    std::fs::File::open(path)?
        .take(u64::try_from(limit).unwrap_or(u64::MAX))
        .read_to_end(&mut blob)?;
    Ok(blob)
}

/// The argv of an exec event and how many bytes of its argument block were not captured
/// (<https://github.com/synthaea-lab/agent/issues/48>, ADR-0045's truth table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExecArgvCapture {
    pub(crate) argv: Vec<String>,
    /// `Some(0)`: the whole block. `Some(n)`: `n` bytes between the windows were not read.
    /// `None`: unknown, the sensor saw nothing to measure against.
    pub(crate) omitted_bytes: Option<u32>,
}

/// argv of an exec event (<https://github.com/synthaea-lab/agent/issues/48>): the probe's exec-time windows when it read them, else
/// [`read_proc_cmdline`] now (the fallback rows of ADR-0045's table). A block over the window
/// is never completed from `/proc`: that read is not exec-time, and a process can rewrite its
/// argument region before it (ADR-0045, Consequences).
pub(crate) fn exec_argv(
    event: &sensor_linux_wire::ExecEvent,
    windows: &sensor_linux_wire::ExecArgv<'_>,
) -> ExecArgvCapture {
    if windows.head.is_empty() {
        let argv = read_proc_cmdline(event.meta.pid);
        // A live process gave its whole argv (a cut past the 32 KiB budget is turned into
        // `None` by `normalize::exec`); an empty read is a process already gone: unknown.
        let omitted_bytes = (!argv.is_empty()).then_some(0);
        return ExecArgvCapture {
            argv,
            omitted_bytes,
        };
    }
    argv_from_windows(windows)
}

/// The pure half of [`exec_argv`], for windows the probe read (a non-empty head).
///
/// Tokens are split on NUL. A token cut by a window edge is kept with the bytes that were
/// read: the last token of the head, and the first token of the tail (the tail is not known to
/// start on a token boundary). The two windows stay separate tokens, never fused, and no marker
/// is added: the loss is carried by `omitted_bytes`, which a process cannot forge by writing a
/// marker into its own arguments.
fn argv_from_windows(windows: &sensor_linux_wire::ExecArgv<'_>) -> ExecArgvCapture {
    let mut argv = parse_proc_cmdline(windows.head);
    let captured = windows.head.len() + windows.tail.len();
    if !windows.tail.is_empty() {
        let mut tail = parse_proc_cmdline(windows.tail);
        // A tail that starts exactly on a separator begins with an empty piece: the end of a
        // token the head already holds, not an empty argument of its own.
        if windows.tail.first() == Some(&0) && tail.first().is_some_and(String::is_empty) {
            tail.remove(0);
        }
        argv.extend(tail);
    }
    let total = windows.total as usize;
    let omitted_bytes = u32::try_from(total.saturating_sub(captured)).unwrap_or(u32::MAX);
    ExecArgvCapture {
        argv,
        omitted_bytes: Some(omitted_bytes),
    }
}

/// Environment variable names the sensor captures at exec time (`ExecEvent::env_security`,
/// issue #363) — the dynamic-linker-hijack family: `LD_PRELOAD`/`LD_LIBRARY_PATH` force a
/// chosen shared object or search path onto every dynamically linked exec, `LD_AUDIT` is
/// the quieter rt-audit-interface sibling of `LD_PRELOAD`, `LD_DEBUG_OUTPUT` can be abused
/// to write attacker-controlled content to an arbitrary path via the dynamic linker's own
/// debug tracing, and `GLIBC_TUNABLES` is the CVE-2023-4911 ("Looney Tunables") vector.
/// Deliberately an allowlist capture, never the whole environment — environments carry
/// secrets and multi-KB noise; only names on this list are ever read out of
/// `/proc/<pid>/environ`, and only when present.
const SECURITY_ENV_NAMES: [&str; 5] = [
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_DEBUG_OUTPUT",
    "GLIBC_TUNABLES",
];

/// Splits a NUL-separated `/proc/<pid>/environ` blob into `(name, value)` pairs, keeping
/// only names in [`SECURITY_ENV_NAMES`] — same present-only, allowlist-only discipline as
/// that constant's doc. An entry without a `=` is skipped (should not happen for a real
/// environment, but procfs makes no format guarantee worth trusting blindly).
pub(crate) fn parse_proc_environ_security(blob: &[u8]) -> Vec<(String, String)> {
    let trimmed = blob.strip_suffix(b"\0").unwrap_or(blob);
    if trimmed.is_empty() {
        return Vec::new();
    }
    trimmed
        .split(|&b| b == 0)
        .filter_map(|entry| {
            let text = String::from_utf8_lossy(entry);
            let (name, value) = text.split_once('=')?;
            SECURITY_ENV_NAMES
                .contains(&name)
                .then(|| (name.to_string(), value.to_string()))
        })
        .collect()
}

/// Security-relevant environment of `pid`, read from `/proc/<pid>/environ` when the
/// `exec` event is drained. Same timing/race/non-portability tradeoffs as
/// [`read_proc_cmdline`] (same file family, same drain-time read) — see that function's
/// doc: a process that has already exited yields an empty result, not an error.
pub(crate) fn read_proc_environ_security(pid: u32) -> Vec<(String, String)> {
    match std::fs::read(format!("/proc/{pid}/environ")) {
        Ok(blob) => parse_proc_environ_security(&blob),
        Err(e) if is_proc_exit_race(&e) => Vec::new(),
        Err(e) => {
            tracing::debug!(pid, error = %e, "read /proc/<pid>/environ failed");
            Vec::new()
        }
    }
}

/// Whether an error from reading `/proc/<pid>/*` is the process having already exited
/// (the accepted race) rather than a real capture gap. `open()` on a dead pid gives
/// `ENOENT`; a `read()` that loses the task mid-flight can surface `ESRCH`, which
/// `std::io` maps to `Uncategorized`, not `NotFound` — so the raw errno is checked too.
fn is_proc_exit_race(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::NotFound || e.raw_os_error() == Some(libc::ESRCH)
}

/// Splits a `/proc/<pid>/stat` line into `(ppid, comm)`. `comm` is parenthesised and
/// may itself contain spaces and `)` (e.g. `(a )b)`), so the fields after it are read
/// from the last `)`, not by whitespace-splitting the whole line.
pub(crate) fn parse_stat_ppid_comm(stat: &str) -> Option<(u32, &str)> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let comm = stat.get(open + 1..close)?;
    // After ") " comes: state (1 field), then ppid.
    let rest = stat.get(close + 1..)?;
    let mut fields = rest.split_whitespace();
    let _state = fields.next()?;
    let ppid: u32 = fields.next()?.parse().ok()?;
    Some((ppid, comm))
}

/// The generation stamp of a process that predates the agent: its `starttime`, tagged so
/// it can never equal a live `bpf_ktime_get_ns()` stamp (issue #519). `0` ("no stamp")
/// when `starttime` is unreadable: better unknown than wrong. One definition for the
/// `PROC_LINEAGE` priming and the parent-image priming, which must agree.
pub(crate) fn primed_generation(stat: &str) -> u64 {
    parse_stat_starttime(stat).map_or(0, |ticks| ticks | sensor_linux_wire::PRIMED_GENERATION_BIT)
}

/// Every running process's `(pid, primed generation, executable path)`, read from
/// `/proc`, for seeding the parent-image cache (#768). Best effort: a process that
/// vanishes mid-scan, a kernel thread (no `exe`) or an unreadable link is skipped, and
/// so is one whose stamp is unknown. Stops after `limit` entries.
pub(crate) fn read_proc_images(limit: usize) -> Vec<(u32, u64, String)> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut images = Vec::new();
    for entry in entries.flatten() {
        if images.len() >= limit {
            break;
        }
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(exe) = std::fs::read_link(entry.path().join("exe")) else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let generation = primed_generation(&stat);
        if generation != 0 {
            images.push((pid, generation, exe.to_string_lossy().into_owned()));
        }
    }
    images
}

/// `starttime` (field 22 of `/proc/<pid>/stat`: clock ticks since boot at which the
/// process started), the identity stamp for a process that predates the agent
/// (issue #519). Fields after the closing `)` are counted from the state (field 3):
/// `starttime` is the 20th of them.
pub(crate) fn parse_stat_starttime(stat: &str) -> Option<u64> {
    let close = stat.rfind(')')?;
    stat.get(close + 1..)?
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use sensor_linux_wire::{ARGV_HEAD_BYTES, ARGV_TAIL_BYTES, ARGV_WINDOW_BYTES, ExecArgv};

    use super::{
        argv_from_windows, is_proc_exit_race, parse_proc_cmdline, parse_proc_environ_security,
        parse_stat_ppid_comm, parse_stat_starttime, primed_generation, read_cmdline_file,
        read_proc_images,
    };

    /// Writes `blob` to a fresh file under the temp dir and returns its path.
    fn cmdline_file(name: &str, blob: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sensor-linux-cmdline-{}-{name}",
            std::process::id()
        ));
        std::fs::write(&path, blob).expect("write the test cmdline file");
        path
    }

    fn read_and_bound(name: &str, blob: &[u8]) -> (Vec<String>, bool) {
        let path = cmdline_file(name, blob);
        let mut argv = read_cmdline_file(path.to_str().expect("utf-8 temp path"))
            .expect("read the test cmdline file");
        std::fs::remove_file(&path).ok();
        let cut = schema::bound_argv(&mut argv);
        (argv, cut)
    }

    #[test]
    fn a_cmdline_one_short_token_past_an_exact_fit_is_read_far_enough_to_be_flagged() {
        // `<BUDGET-1 bytes>\0x\0`: the first token alone costs exactly the budget.
        // A read capped at BUDGET bytes (an off-by-one) would stop on its NUL, see an
        // argv that fits and never flag the trailing `x`.
        let mut blob = vec![b'a'; schema::ARGV_CAPTURE_BUDGET - 1];
        blob.extend_from_slice(b"\0x\0");
        let (argv, cut) = read_and_bound("over", &blob);
        assert!(cut, "an argv one token past the budget must be flagged");
        assert_eq!(argv.len(), 1);
    }

    #[test]
    fn a_cmdline_that_fits_the_budget_exactly_is_read_whole_and_not_flagged() {
        let mut blob = vec![b'a'; schema::ARGV_CAPTURE_BUDGET - 1];
        blob.push(0);
        let (argv, cut) = read_and_bound("exact", &blob);
        assert!(!cut);
        assert_eq!(argv[0].len(), schema::ARGV_CAPTURE_BUDGET - 1);
    }

    #[test]
    fn stat_starttime_is_the_twentieth_field_after_the_comm() {
        // Real shape: state ppid pgrp session tty tpgid flags minflt cminflt majflt
        // cmajflt utime stime cutime cstime priority nice threads itrealvalue starttime
        let stat =
            "123 (bash) S 1 123 123 34816 123 4194304 100 0 0 0 1 2 0 0 20 0 1 0 98765 1000 200";
        assert_eq!(parse_stat_starttime(stat), Some(98765));
    }

    #[test]
    fn stat_starttime_survives_a_comm_with_spaces_and_parens() {
        let stat = "7 (a ) b) S 1 7 7 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 42 0 0";
        assert_eq!(parse_stat_starttime(stat), Some(42));
    }

    #[test]
    fn stat_starttime_rejects_a_truncated_or_malformed_line() {
        assert_eq!(parse_stat_starttime("1 (x) S 0 1 1"), None);
        assert_eq!(parse_stat_starttime("not a stat line"), None);
        let stat = "1 (x) S 0 1 1 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 notanumber 0 0";
        assert_eq!(parse_stat_starttime(stat), None);
    }

    fn windows<'a>(total: usize, head: &'a [u8], tail: &'a [u8]) -> ExecArgv<'a> {
        ExecArgv {
            total: u32::try_from(total).unwrap(),
            head,
            tail,
        }
    }

    #[test]
    fn a_block_that_fits_the_window_is_the_whole_argv_with_nothing_omitted() {
        let block = b"systemctl\0stop\0osqueryd\0";
        let got = argv_from_windows(&windows(block.len(), block, b""));
        assert_eq!(got.argv, ["systemctl", "stop", "osqueryd"]);
        assert_eq!(got.omitted_bytes, Some(0));
    }

    /// ADR-0045's padding case: a payload at the end of a long `sh -c` argument is still seen,
    /// and the cut argument is kept as two partial tokens instead of being dropped.
    #[test]
    fn a_payload_after_padding_is_kept_in_the_tail_and_the_middle_is_counted() {
        let mut block = b"sh\0-c\0".to_vec();
        block.extend(std::iter::repeat_n(b'A', 3000));
        block.extend_from_slice(b"; run-the-payload\0");
        let (head, tail) = (
            &block[..ARGV_HEAD_BYTES],
            &block[block.len() - ARGV_TAIL_BYTES..],
        );
        let got = argv_from_windows(&windows(block.len(), head, tail));
        assert_eq!(got.argv[..2], ["sh", "-c"]);
        assert_eq!(
            got.argv.len(),
            4,
            "head and tail stay separate tokens: {:?}",
            got.argv
        );
        assert!(got.argv[2].bytes().all(|b| b == b'A'));
        assert!(got.argv[3].ends_with("; run-the-payload"));
        assert_eq!(
            got.omitted_bytes,
            Some(u32::try_from(block.len() - ARGV_WINDOW_BYTES).unwrap())
        );
    }

    #[test]
    fn a_tail_that_starts_on_a_separator_does_not_invent_an_empty_argument() {
        let got = argv_from_windows(&windows(2000, b"a\0b", b"\0c\0"));
        assert_eq!(got.argv, ["a", "b", "c"]);
    }

    #[test]
    fn an_empty_argument_inside_a_window_is_kept() {
        let block = b"printf\0\0x\0";
        let got = argv_from_windows(&windows(block.len(), block, b""));
        assert_eq!(got.argv, ["printf", "", "x"]);
    }

    #[test]
    fn a_failed_tail_read_keeps_the_head_and_counts_everything_after_it() {
        let head = b"python3\0-c\0impo";
        let got = argv_from_windows(&windows(5000, head, b""));
        assert_eq!(got.argv, ["python3", "-c", "impo"]);
        assert_eq!(
            got.omitted_bytes,
            Some(u32::try_from(5000 - head.len()).unwrap())
        );
    }

    #[test]
    fn cmdline_splits_on_nul_and_drops_trailing_empty() {
        assert_eq!(
            parse_proc_cmdline(b"curl\0-o\0/tmp/x\0"),
            ["curl", "-o", "/tmp/x"]
        );
    }

    #[test]
    fn cmdline_without_trailing_nul() {
        // The kernel normally NUL-terminates the last arg, but be liberal.
        assert_eq!(parse_proc_cmdline(b"ls\0-la"), ["ls", "-la"]);
    }

    #[test]
    fn cmdline_empty_for_kernel_thread_or_dead_process() {
        assert!(parse_proc_cmdline(b"").is_empty());
        assert!(parse_proc_cmdline(b"\0").is_empty());
    }

    #[test]
    fn cmdline_keeps_interior_empty_argument() {
        assert_eq!(parse_proc_cmdline(b"sh\0\0-c\0"), ["sh", "", "-c"]);
    }

    #[test]
    fn cmdline_non_utf8_is_lossy_not_fatal() {
        let out = parse_proc_cmdline(b"\xff\xfe\0-x\0");
        assert_eq!(out.len(), 2);
        assert!(out[0].contains('\u{fffd}'));
        assert_eq!(out[1], "-x");
    }

    #[test]
    fn proc_exit_race_is_silent_for_enoent_and_esrch_only() {
        use std::io::{Error, ErrorKind};
        // open() on a dead pid — mapped to NotFound
        assert!(is_proc_exit_race(&Error::from(ErrorKind::NotFound)));
        // read() losing the task mid-flight — ESRCH, which std::io leaves Uncategorized
        assert!(is_proc_exit_race(&Error::from_raw_os_error(libc::ESRCH)));
        // a real capture gap on some kernel must still get logged
        assert!(!is_proc_exit_race(&Error::from_raw_os_error(libc::EACCES)));
        assert!(!is_proc_exit_race(&Error::from_raw_os_error(libc::EIO)));
    }

    #[test]
    fn stat_simple() {
        let stat = "1234 (bash) S 1000 1234 1234 34816 1789 4194304 ...";
        assert_eq!(parse_stat_ppid_comm(stat), Some((1000, "bash")));
    }

    #[test]
    fn stat_comm_with_spaces_and_parens() {
        // The kernel does not sanitise comm; `)` and spaces inside it are why the
        // fields are read from the last `)`, not by splitting the whole line.
        let stat = "42 (a ) b) S 7 42 42 0 -1 4194560 100 0 0 0";
        assert_eq!(parse_stat_ppid_comm(stat), Some((7, "a ) b")));
    }

    #[test]
    fn stat_kernel_thread_ppid_zero() {
        let stat = "2 (kthreadd) S 0 0 0 0 -1 2129984 0 0";
        assert_eq!(parse_stat_ppid_comm(stat), Some((0, "kthreadd")));
    }

    #[test]
    fn stat_garbage_is_none() {
        assert_eq!(parse_stat_ppid_comm("not a stat line"), None);
        assert_eq!(parse_stat_ppid_comm("123 (x) S notanumber"), None);
    }

    #[test]
    fn environ_keeps_only_allowlisted_names() {
        let blob = b"LD_PRELOAD=/tmp/evil.so\0HOME=/root\0PATH=/usr/bin\0LD_AUDIT=/tmp/audit.so\0";
        assert_eq!(
            parse_proc_environ_security(blob),
            [
                ("LD_PRELOAD".to_string(), "/tmp/evil.so".to_string()),
                ("LD_AUDIT".to_string(), "/tmp/audit.so".to_string()),
            ]
        );
    }

    #[test]
    fn environ_plain_exec_carries_nothing() {
        let blob = b"HOME=/root\0PATH=/usr/bin\0SHELL=/bin/bash\0";
        assert!(parse_proc_environ_security(blob).is_empty());
    }

    #[test]
    fn environ_all_five_names_captured() {
        let blob = b"LD_PRELOAD=/tmp/a.so\0LD_LIBRARY_PATH=/tmp/lib\0LD_AUDIT=/tmp/b.so\0LD_DEBUG_OUTPUT=/tmp/dbg\0GLIBC_TUNABLES=glibc.malloc.check=1\0";
        assert_eq!(
            parse_proc_environ_security(blob),
            [
                ("LD_PRELOAD".to_string(), "/tmp/a.so".to_string()),
                ("LD_LIBRARY_PATH".to_string(), "/tmp/lib".to_string()),
                ("LD_AUDIT".to_string(), "/tmp/b.so".to_string()),
                ("LD_DEBUG_OUTPUT".to_string(), "/tmp/dbg".to_string()),
                (
                    "GLIBC_TUNABLES".to_string(),
                    "glibc.malloc.check=1".to_string()
                ),
            ]
        );
    }

    #[test]
    fn environ_empty_or_no_nul_is_empty() {
        assert!(parse_proc_environ_security(b"").is_empty());
        assert!(parse_proc_environ_security(b"\0").is_empty());
    }

    #[test]
    fn environ_entry_without_equals_is_skipped() {
        // Not expected from a real environment, but procfs guarantees nothing —
        // a malformed entry must not panic or produce a bogus pair.
        let blob = b"LD_PRELOAD\0LD_AUDIT=/tmp/b.so\0";
        assert_eq!(
            parse_proc_environ_security(blob),
            [("LD_AUDIT".to_string(), "/tmp/b.so".to_string())]
        );
    }

    #[test]
    fn the_running_test_process_is_among_the_primed_images_with_a_primed_stamp() {
        let images = read_proc_images(usize::MAX);
        let (_, generation, image) = images
            .iter()
            .find(|(pid, _, _)| *pid == std::process::id())
            .expect("this process is listed");
        assert_ne!(generation & sensor_linux_wire::PRIMED_GENERATION_BIT, 0);
        assert_eq!(
            std::path::Path::new(image),
            std::env::current_exe().unwrap().as_path()
        );
    }

    #[test]
    fn priming_images_stops_at_its_limit() {
        assert!(read_proc_images(1).len() <= 1);
    }

    #[test]
    fn a_primed_stamp_needs_a_readable_starttime() {
        assert_eq!(primed_generation("1 (x) S 0 1 1"), 0);
        let stat = "42 (bash) S 1 42 42 0 -1 4194560 100 0 0 0 1 1 0 0 20 0 1 0 98765 1 1 0";
        assert_eq!(
            primed_generation(stat),
            98765 | sensor_linux_wire::PRIMED_GENERATION_BIT
        );
    }
}
