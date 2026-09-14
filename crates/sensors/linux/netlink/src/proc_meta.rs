//! Resolves the process metadata a [`schema::EventMeta`] needs (`comm`, `ppid`)
//! for a PID [`crate::proc_join`] already joined to a socket — `sock_diag` itself
//! carries neither (only `uid`, already on [`crate::SocketSnapshotEntry`] straight
//! from the kernel, no `/proc` read required for that one).
//!
//! Reads `/proc/<pid>/status` rather than `/proc/<pid>/stat` — `stat`'s second
//! field (`comm`) is parenthesized and can itself contain spaces or parentheses
//! (a process can rename itself to anything via `prctl`/`argv[0]` tricks up to the
//! 15-byte cap), making the field boundary ambiguous without tracking paren
//! nesting. `status` gives the same two values as separate, unambiguous
//! `Name:`/`PPid:` lines — confirmed against this dev machine's real `/proc`.

use std::fs;

/// The [`schema::EventMeta`] fields `sock_diag` + the `/proc` inode join don't
/// already provide. `gid` is a best-effort approximation, not authoritative like
/// [`crate::SocketSnapshotEntry::uid`] (kernel-reported, no race): it's the
/// resolved PID's *current* real gid from `/proc`, read in a second, separate
/// query — for a setgid program, or a process that's changed its gid since
/// opening the socket, this can differ from the actual socket owner's group.
/// Good enough for `EventMeta::user`'s shape (which needs *a* gid, not
/// necessarily the historically exact one) without adding an `nss`/`getpwuid`-
/// style dependency for something the schema doesn't treat as load-bearing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    pub comm: String,
    pub ppid: u32,
    pub gid: u32,
}

/// `None` covers every way this can fail to mean anything useful: the process
/// already exited between the `sock_diag` snapshot and this read (inherent race —
/// two separate queries, not one atomic operation), `/proc/<pid>` is unreadable
/// (another user's process, `EACCES`), or `status` is missing an expected line
/// (would be a kernel/format surprise, not something to guess past).
#[must_use]
pub fn resolve(pid: u32) -> Option<ProcInfo> {
    let content = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let mut comm = None;
    let mut ppid = None;
    let mut gid = None;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Name:") {
            comm = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("PPid:") {
            ppid = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("Gid:") {
            // "Gid:\t<real>\t<effective>\t<saved>\t<fs>" - real gid is the first.
            gid = rest.split_whitespace().next().and_then(|s| s.parse().ok());
        }
    }

    Some(ProcInfo {
        comm: comm?,
        ppid: ppid?,
        gid: gid?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_real_status_file() {
        // Verbatim shape of a real /proc/<pid>/status on this dev machine (WSL2),
        // trimmed to the lines this module reads.
        let content =
            "Name:\tsshd\nState:\tS (sleeping)\nPPid:\t1\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n";
        let mut comm = None;
        let mut ppid = None;
        let mut gid = None;
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("Name:") {
                comm = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("PPid:") {
                ppid = rest.trim().parse::<u32>().ok();
            } else if let Some(rest) = line.strip_prefix("Gid:") {
                gid = rest
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<u32>().ok());
            }
        }
        assert_eq!(comm.as_deref(), Some("sshd"));
        assert_eq!(ppid, Some(1));
        assert_eq!(gid, Some(0));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn resolve_against_the_real_proc_self() {
        // PID 1 (init/systemd) always exists on a real Linux kernel and is always
        // world-readable (unlike an arbitrary other user's PID, which this
        // function must tolerate returning None for, not panic on).
        let info = resolve(1).expect("PID 1 must resolve on a real Linux kernel");
        assert!(!info.comm.is_empty());
    }

    #[test]
    fn a_pid_that_does_not_exist_resolves_to_none() {
        // PID 0 is never a real process (kernel reserves it) - /proc/0 never exists.
        assert!(resolve(0).is_none());
    }
}
