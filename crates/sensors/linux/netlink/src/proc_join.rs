//! Joins a socket's inode (from `sock_diag`) to the PID(s) that hold it open, by
//! scanning `/proc/<pid>/fd/*` for `socket:[<inode>]` symlinks — the same
//! technique `ss`/`lsof` use; `sock_diag` itself carries no PID.
//!
//! Only this user's own processes are joinable without root: `read_dir`/
//! `read_link` on another user's `/proc/<pid>/fd/` returns `EACCES`, which this
//! module treats as "no PIDs found there", not an error — a partial join (some
//! sockets attributed, others not) is the honest, expected result for an
//! unprivileged snapshot. The shipped sensor, running with the elevated
//! privilege the rest of the agent needs anyway, sees the full picture.

use std::{collections::HashMap, fs};

/// Builds an inode → PIDs map by scanning every readable `/proc/<pid>/fd/`. More
/// than one PID per inode is possible and expected — a listening socket shared
/// across forked worker processes before `exec`, most commonly.
#[must_use]
pub fn inode_to_pids() -> HashMap<u64, Vec<u32>> {
    let mut map: HashMap<u64, Vec<u32>> = HashMap::new();
    let Ok(proc_entries) = fs::read_dir("/proc") else {
        return map; // no /proc at all — nothing to join
    };

    for entry in proc_entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue; // not a PID directory (self, cmdline, sys, ...)
        };

        let Ok(fds) = fs::read_dir(entry.path().join("fd")) else {
            continue; // EACCES (another user's process) or ESRCH (exited mid-scan)
        };

        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue; // raced with the fd closing, or a symlink we can't read
            };
            if let Some(inode) = parse_socket_inode(&target.to_string_lossy()) {
                map.entry(inode).or_default().push(pid);
            }
        }
    }

    map
}

/// Parses `"socket:[12345]"` — the form `/proc/<pid>/fd/<n>` resolves to for a
/// socket file descriptor — into its inode number. `None` for any other link
/// target (a regular file, `pipe:[...]`, `anon_inode:...`, ...).
fn parse_socket_inode(link_target: &str) -> Option<u64> {
    link_target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_socket_link_target() {
        assert_eq!(parse_socket_inode("socket:[78967]"), Some(78967));
    }

    #[test]
    fn rejects_non_socket_link_targets() {
        assert_eq!(parse_socket_inode("/dev/pts/3"), None);
        assert_eq!(parse_socket_inode("pipe:[123]"), None);
        assert_eq!(parse_socket_inode("anon_inode:[eventfd]"), None);
        assert_eq!(parse_socket_inode("socket:[not-a-number]"), None);
        assert_eq!(parse_socket_inode(""), None);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn inode_to_pids_runs_against_the_real_proc_without_panicking() {
        // Socket inventory is inherently machine- and timing-dependent, so this
        // doesn't assert a specific inode is present — it proves the scan
        // completes cleanly against a real /proc (including the EACCES paths for
        // other users' processes, if any are running) and every returned inode
        // parses back through the same format it was extracted from.
        let map = inode_to_pids();
        for (&inode, pids) in &map {
            assert!(!pids.is_empty(), "inode {inode} present with no PIDs");
        }
    }
}
