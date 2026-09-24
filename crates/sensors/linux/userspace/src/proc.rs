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
/// eBPF context and the agent's `/proc` view, not the drain race. `WSL2` is out of
/// `lab/MATRIX.md`; recorded so it is not re-investigated (Nikolas, 2026-09-10, #155).
pub(crate) fn read_proc_cmdline(pid: u32) -> Vec<String> {
    match std::fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(blob) => parse_proc_cmdline(&blob),
        // The expected exit race (process already gone) is silent; anything else
        // (EACCES, EIO) is worth a line when tracing a capture gap on some kernel.
        Err(e) if is_proc_exit_race(&e) => Vec::new(),
        Err(e) => {
            tracing::debug!(pid, error = %e, "read /proc/<pid>/cmdline failed");
            Vec::new()
        }
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

#[cfg(test)]
mod tests {
    use super::{
        is_proc_exit_race, parse_proc_cmdline, parse_proc_environ_security, parse_stat_ppid_comm,
    };

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
}
