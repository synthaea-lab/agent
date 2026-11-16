//! A `SIGKILL` of the agent, read back from auditd's log after the restart (#275).
//!
//! The audit fallback cannot attribute a `SIGKILL` live: the agent dies before it reads the
//! record. The eBPF sensor keeps the event in a pinned map for the restarted agent; here the
//! record stays in `audit.log`, written by auditd when an operator loads
//! `packaging/linux/audit/synthaea-kill.rules` (the sensor never sends rule commands). The
//! restarted agent finds it by the pid its predecessor left in a marker file, and replays it as
//! an `Event::Signal`, so the same rule attributes it as it does for eBPF.
//!
//! What is read: `SYSCALL` records keyed [`KILL_KEY`], for `kill(2)` and `tgkill(2)` with signal 9
//! and `success=yes`. `tkill(2)` takes a thread id, which cannot be compared with a process id
//! (the eBPF probe leaves it out for the same reason). A `systemctl kill` leaves no such record
//! (captured on Rocky 9.8, systemd 252: the signal is not sent through these syscalls), so it is
//! not attributed.
//!
//! Pure functions over text and files, so they run on every platform and are tested on lines
//! captured from a real auditd.

use std::{
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use crate::parse::{parse_fields, parse_msg_header};

/// The audit rule key of `packaging/linux/audit/synthaea-kill.rules`.
pub const KILL_KEY: &str = "synthaea-kill";

/// Where auditd writes by default: the live log, then the one it rotated out of.
#[must_use]
pub fn default_log_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/var/log/audit/audit.log"),
        PathBuf::from("/var/log/audit/audit.log.1"),
    ]
}

/// How far back from the end of each log file is read: a restart follows the kill by seconds, so
/// the record is near the end, and the cap bounds the work on a busy host.
const MAX_TAIL_BYTES: u64 = 16 * 1024 * 1024;

/// A restart later than this after the kill is not attributed: the pid may have been reused.
pub const REPLAY_WINDOW_NS: u64 = 10 * 60 * 1_000_000_000;

const SIGKILL: u64 = 9;
/// The audit `arch` values (`AUDIT_ARCH_X86_64`, `AUDIT_ARCH_AARCH64`) and their syscall numbers.
const ARCH_X86_64: &str = "c000003e";
const ARCH_AARCH64: &str = "c00000b7";
const AUDIT_UNSET: u64 = 4_294_967_295;

/// One `SIGKILL` sent with `kill(2)` or `tgkill(2)`, as auditd recorded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigkillRecord {
    pub timestamp_ns: u64,
    /// The sender.
    pub sender_pid: u32,
    pub sender_ppid: u32,
    pub uid: u32,
    pub gid: u32,
    /// The login uid, `None` when auditd reports it unset.
    pub auid: Option<u32>,
    pub comm: String,
    pub exe: Option<String>,
    pub target_pid: u32,
}

/// Parses one `audit.log` line, `None` unless it is a successful `SIGKILL` of a process by the
/// [`KILL_KEY`] rule.
#[must_use]
pub fn parse_kill_log_line(line: &str) -> Option<SigkillRecord> {
    // ENRICHED log lines append a `\x1d`-separated block of resolved names to the kernel's
    // record; only the kernel part is read.
    let line = line.split('\u{1d}').next()?;
    if !line.starts_with("type=SYSCALL ") {
        return None;
    }
    let (sec, ms, _seq) = parse_msg_header(line).ok()?;
    let (fields, unquoted) = parse_fields(line).ok()?;
    if fields.get("key").map(String::as_str) != Some(KILL_KEY)
        || fields.get("success").map(String::as_str) != Some("yes")
    {
        return None;
    }
    let hex = |name: &str| u64::from_str_radix(fields.get(name)?, 16).ok();
    let dec = |name: &str| fields.get(name)?.parse::<u64>().ok();
    let syscall = dec("syscall")?;
    let (target, signal) = match (fields.get("arch")?.as_str(), syscall) {
        // kill(pid, sig)
        (ARCH_X86_64, 62) | (ARCH_AARCH64, 129) => (hex("a0")?, hex("a1")?),
        // tgkill(tgid, tid, sig)
        (ARCH_X86_64, 234) | (ARCH_AARCH64, 131) => (hex("a0")?, hex("a2")?),
        _ => return None,
    };
    if signal != SIGKILL {
        return None;
    }
    let comm = fields.get("comm")?;
    let comm = if unquoted.contains("comm") {
        decode_hex(comm)?
    } else {
        comm.clone()
    };
    let exe = fields.get("exe").map(|exe| {
        if unquoted.contains("exe") {
            decode_hex(exe).unwrap_or_else(|| exe.clone())
        } else {
            exe.clone()
        }
    });
    let auid = dec("auid").filter(|auid| *auid != AUDIT_UNSET);
    Some(SigkillRecord {
        timestamp_ns: sec * 1_000_000_000 + u64::from(ms) * 1_000_000,
        sender_pid: u32::try_from(dec("pid")?).ok()?,
        sender_ppid: u32::try_from(dec("ppid")?).ok()?,
        uid: u32::try_from(dec("uid")?).ok()?,
        gid: u32::try_from(dec("gid")?).ok()?,
        auid: auid.and_then(|a| u32::try_from(a).ok()),
        comm,
        exe,
        target_pid: u32::try_from(target).ok()?,
    })
}

/// A value auditd hex-encoded because it holds a space or a non-printable byte.
fn decode_hex(value: &str) -> Option<String> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return None;
    }
    let bytes = (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(value.get(i..i + 2)?, 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// The latest record of a `SIGKILL` aimed at `target` among `lines`, sent in `[since_ns, until_ns]`.
pub fn last_sigkill_of<'a>(
    target: u32,
    since_ns: u64,
    until_ns: u64,
    lines: impl IntoIterator<Item = &'a str>,
) -> Option<SigkillRecord> {
    lines
        .into_iter()
        .filter_map(parse_kill_log_line)
        .filter(|r| {
            r.target_pid == target && r.timestamp_ns >= since_ns && r.timestamp_ns <= until_ns
        })
        .max_by_key(|r| r.timestamp_ns)
}

/// [`last_sigkill_of`] over the tail of each file in `paths`, newest file first; a file that
/// cannot be read (no auditd, no permission) is skipped.
#[must_use]
pub fn read_sigkill_of(
    target: u32,
    since_ns: u64,
    until_ns: u64,
    paths: &[PathBuf],
) -> Option<SigkillRecord> {
    paths.iter().find_map(|path| {
        let text = read_tail(path)?;
        last_sigkill_of(target, since_ns, until_ns, text.lines())
    })
}

fn read_tail(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    let start = len.saturating_sub(MAX_TAIL_BYTES);
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_TAIL_BYTES).read_to_end(&mut bytes).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// The marker a running audit-fallback agent keeps in its state directory: its pid and when it
/// started. Only a kill leaves it behind; a clean stop removes it, so a restart that finds none
/// has nothing to attribute.
const MARKER: &str = "audit-agent.pid";

/// The marker left by the previous instance, `(pid, started_ns)`.
#[must_use]
pub fn read_marker(state_dir: &Path) -> Option<(u32, u64)> {
    let text = std::fs::read_to_string(state_dir.join(MARKER)).ok()?;
    let mut parts = text.split_whitespace();
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}

/// Records this instance (atomically: a torn marker would blame the wrong pid).
///
/// # Errors
///
/// The write or the rename failed.
pub fn write_marker(state_dir: &Path, pid: u32, started_ns: u64) -> std::io::Result<()> {
    let tmp = state_dir.join(format!("{MARKER}.tmp"));
    std::fs::write(&tmp, format!("{pid} {started_ns}\n"))?;
    std::fs::rename(tmp, state_dir.join(MARKER))
}

/// Removes the marker: this instance ended on its own.
pub fn remove_marker(state_dir: &Path) {
    let _ = std::fs::remove_file(state_dir.join(MARKER));
}

/// The record to replay for the predecessor of this instance, if it was `SIGKILL`ed: the marker's
/// pid, a record sent after that instance started and within [`REPLAY_WINDOW_NS`] of `now_ns`.
/// A marker with this instance's own pid (a recycled pid) attributes nothing.
#[must_use]
pub fn previous_instance_kill(
    marker: Option<(u32, u64)>,
    own_pid: u32,
    now_ns: u64,
    paths: &[PathBuf],
) -> Option<SigkillRecord> {
    let (pid, started_ns) = marker.filter(|(pid, _)| *pid != own_pid)?;
    let since = started_ns.max(now_ns.saturating_sub(REPLAY_WINDOW_NS));
    read_sigkill_of(pid, since, now_ns, paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The line captured on Rocky 9.8 (kernel 5.14, auditd 3.1.5, ENRICHED), with the rule key
    /// of this module: `kill -KILL 2253` (a0=8cd) from a root shell, `auid` 1000.
    const REAL: &str = "type=SYSCALL msg=audit(1794826302.839:128): arch=c000003e syscall=62 success=yes exit=0 a0=8cd a1=9 a2=0 a3=7fe3bcb9fac0 items=0 ppid=2237 pid=2241 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4 comm=\"bash\" exe=\"/usr/bin/bash\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=\"synthaea-kill\"\u{1d}ARCH=x86_64 SYSCALL=kill AUID=\"edr-lab\" UID=\"root\" GID=\"root\" EUID=\"root\" SUID=\"root\" FSUID=\"root\" EGID=\"root\" SGID=\"root\" FSGID=\"root\"";

    fn line(syscall: u32, a0: &str, a1: &str, a2: &str, tail: &str) -> String {
        format!(
            "type=SYSCALL msg=audit(1000.500:7): arch=c000003e syscall={syscall} success=yes exit=0 a0={a0} a1={a1} a2={a2} a3=0 items=0 ppid=10 pid=20 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4 comm=\"sh\" exe=\"/bin/sh\" key=\"{KILL_KEY}\"{tail}"
        )
    }

    #[test]
    fn a_real_enriched_kill_record_is_read() {
        let record = parse_kill_log_line(REAL).expect("a SIGKILL record");
        assert_eq!(record.target_pid, 0x8cd);
        assert_eq!(record.sender_pid, 2241);
        assert_eq!(record.sender_ppid, 2237);
        assert_eq!(record.auid, Some(1000));
        assert_eq!(record.comm, "bash");
        assert_eq!(record.exe.as_deref(), Some("/usr/bin/bash"));
        assert_eq!(record.timestamp_ns, 1_794_826_302_839_000_000);
    }

    #[test]
    fn kill_and_tgkill_with_signal_9_are_read_and_the_target_is_a0() {
        let kill = parse_kill_log_line(&line(62, "ff", "9", "0", "")).unwrap();
        assert_eq!(kill.target_pid, 0xff);
        // tgkill(tgid, tid, sig): the signal is a2, the process is a0.
        let tgkill = parse_kill_log_line(&line(234, "ff", "100", "9", "")).unwrap();
        assert_eq!(tgkill.target_pid, 0xff);
    }

    #[test]
    fn anything_else_is_not_a_sigkill_record() {
        // SIGTERM, tkill (a thread id), an unknown syscall, a failed call, another key, another
        // record type.
        assert!(parse_kill_log_line(&line(62, "ff", "f", "0", "")).is_none());
        assert!(parse_kill_log_line(&line(234, "ff", "100", "f", "")).is_none());
        assert!(parse_kill_log_line(&line(200, "ff", "9", "0", "")).is_none());
        assert!(parse_kill_log_line(&line(1, "ff", "9", "0", "")).is_none());
        assert!(
            parse_kill_log_line(&line(62, "ff", "9", "0", "").replace("success=yes", "success=no"))
                .is_none()
        );
        assert!(
            parse_kill_log_line(&line(62, "ff", "9", "0", "").replace(KILL_KEY, "other")).is_none()
        );
        assert!(
            parse_kill_log_line(
                &line(62, "ff", "9", "0", "").replace("type=SYSCALL", "type=EXECVE")
            )
            .is_none()
        );
        assert!(parse_kill_log_line("").is_none());
        assert!(parse_kill_log_line("type=SYSCALL garbage").is_none());
    }

    #[test]
    fn aarch64_numbers_are_read() {
        let l = line(129, "ff", "9", "0", "").replace("c000003e", "c00000b7");
        assert_eq!(parse_kill_log_line(&l).unwrap().target_pid, 0xff);
        let l = line(131, "ff", "100", "9", "").replace("c000003e", "c00000b7");
        assert_eq!(parse_kill_log_line(&l).unwrap().target_pid, 0xff);
        // x86_64's kill number is not aarch64's.
        let l = line(62, "ff", "9", "0", "").replace("c000003e", "c00000b7");
        assert!(parse_kill_log_line(&l).is_none());
    }

    #[test]
    fn an_unset_login_uid_and_a_hex_encoded_comm_are_read() {
        let l = line(62, "ff", "9", "0", "")
            .replace("auid=1000", "auid=4294967295")
            .replace("comm=\"sh\"", "comm=6D79206261736821");
        let record = parse_kill_log_line(&l).unwrap();
        assert_eq!(record.auid, None);
        assert_eq!(record.comm, "my bash!");
    }

    #[test]
    fn the_latest_matching_record_in_the_window_wins() {
        let at = |sec: u32, a0: &str| {
            line(62, a0, "9", "0", "").replace("audit(1000.500:7)", &format!("audit({sec}.000:7)"))
        };
        let lines = [at(100, "ff"), at(200, "ff"), at(300, "aa"), at(900, "ff")];
        let ns = |s: u64| s * 1_000_000_000;
        let found = |since, until| {
            last_sigkill_of(0xff, ns(since), ns(until), lines.iter().map(String::as_str))
                .map(|r| r.timestamp_ns / 1_000_000_000)
        };
        assert_eq!(found(0, 1000), Some(900));
        assert_eq!(found(0, 500), Some(200));
        assert_eq!(found(250, 500), None);
        assert_eq!(found(0, 50), None);
    }

    #[test]
    fn the_marker_round_trips_and_a_clean_stop_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_marker(dir.path()), None);
        write_marker(dir.path(), 4242, 777).unwrap();
        assert_eq!(read_marker(dir.path()), Some((4242, 777)));
        remove_marker(dir.path());
        assert_eq!(read_marker(dir.path()), None);
    }

    #[test]
    fn the_previous_instances_kill_is_found_in_the_log_files() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("audit.log");
        let rotated = dir.path().join("audit.log.1");
        // pid 0xff was killed at 1000.500; a later record aims at another process.
        std::fs::write(
            &live,
            format!(
                "{}\n{}\n",
                line(62, "aa", "9", "0", ""),
                line(62, "bb", "9", "0", "")
            ),
        )
        .unwrap();
        std::fs::write(&rotated, format!("{}\n", line(62, "ff", "9", "0", ""))).unwrap();
        let paths = [live, rotated];
        let ns = |s: u64| s * 1_000_000_000;
        // marker: pid 255 started at t=500 s; the restart happens at t=1010 s.
        let found = previous_instance_kill(Some((0xff, ns(500))), 1, ns(1010), &paths);
        assert_eq!(found.map(|r| r.sender_pid), Some(20));
        // started after the record: it was not aimed at this instance.
        assert!(previous_instance_kill(Some((0xff, ns(1001))), 1, ns(1010), &paths).is_none());
        // restarted too late: the pid may have been reused.
        let late = ns(1000) + REPLAY_WINDOW_NS + ns(5);
        assert!(previous_instance_kill(Some((0xff, ns(500))), 1, late, &paths).is_none());
        // a recycled pid: the marker holds this instance's own pid.
        assert!(previous_instance_kill(Some((0xff, ns(500))), 0xff, ns(1010), &paths).is_none());
        // no marker, no files.
        assert!(previous_instance_kill(None, 1, ns(1010), &paths).is_none());
        assert!(
            previous_instance_kill(
                Some((0xff, ns(500))),
                1,
                ns(1010),
                &[PathBuf::from("/nonexistent")]
            )
            .is_none()
        );
    }
}
