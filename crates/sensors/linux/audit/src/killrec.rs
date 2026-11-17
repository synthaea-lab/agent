//! A `SIGKILL` of the agent, read back from auditd's log after the restart (#275).
//!
//! The audit fallback cannot attribute a `SIGKILL` live: the agent dies before it reads the
//! record. The eBPF sensor keeps the event in a pinned map for the restarted agent; here the
//! record stays in `audit.log`, written by auditd when an operator loads
//! `packaging/linux/audit/synthaea-kill.rules` (the sensor never sends rule commands). The
//! restarted agent finds it by the pid its predecessor left in a marker file, and replays it as
//! an `Event::Signal`, so the same rule attributes it as it does for eBPF.
//!
//! What is read: `SYSCALL` records keyed [`KILL_KEY`], for `kill(2)`, `tkill(2)` and `tgkill(2)`
//! with signal 9 and `success=yes`. Three shapes of target count as a kill of the agent: its pid,
//! its process group (`kill -9 -<pgid>`, `kill(-pgid, 9)`) and every process (`kill(-1, 9)`). A
//! `tkill` or `tgkill` thread id counts only when it equals the agent's pid, which is its main
//! thread, and `SIGKILL` is process-wide. A `systemctl kill` leaves no such record (captured on
//! Rocky 9.8, systemd 252: the signal is not sent through these syscalls), so it is not
//! attributed; neither are `rt_sigqueueinfo`, `rt_tgsigqueueinfo` and `pidfd_send_signal`.
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

/// Where auditd writes by default: the live log, then the files it rotated out of, newest first.
/// auditd keeps `num_logs` of them (5 by default); a file that does not exist is skipped.
#[must_use]
pub fn default_log_paths() -> Vec<PathBuf> {
    std::iter::once(PathBuf::from("/var/log/audit/audit.log"))
        .chain(
            (1..=MAX_ROTATED_LOGS).map(|n| PathBuf::from(format!("/var/log/audit/audit.log.{n}"))),
        )
        .collect()
}

/// The highest `audit.log.<n>` looked at.
const MAX_ROTATED_LOGS: u32 = 9;

/// How far back from the end of each log file is read: a restart follows the kill by seconds, so
/// the record is near the end, and the cap bounds the work on a busy host.
const MAX_TAIL_BYTES: u64 = 16 * 1024 * 1024;

const SIGKILL: u64 = 9;
/// The audit `arch` values (`AUDIT_ARCH_X86_64`, `AUDIT_ARCH_AARCH64`) and their syscall numbers.
const ARCH_X86_64: &str = "c000003e";
const ARCH_AARCH64: &str = "c00000b7";
const AUDIT_UNSET: u64 = 4_294_967_295;

/// What a `SIGKILL` was aimed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillTarget {
    /// A process (or a thread id: see [`KillTarget::hits`]).
    Process(u32),
    /// A process group, the positive value of the negative pid given to `kill(2)`.
    Group(u32),
    /// `kill(-1, 9)`: every process the sender may signal.
    AllProcesses,
}

impl KillTarget {
    /// Whether a process with this `pid`, in process group `pgid`, was hit. A thread id equals
    /// the pid only for the main thread, and `SIGKILL` kills the whole process either way.
    #[must_use]
    pub fn hits(self, pid: u32, pgid: u32) -> bool {
        match self {
            Self::Process(target) => target == pid,
            Self::Group(group) => group == pgid || group == pid,
            Self::AllProcesses => true,
        }
    }
}

/// One `SIGKILL` sent with `kill(2)`, `tkill(2)` or `tgkill(2)`, as auditd recorded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigkillRecord {
    /// When auditd recorded it, Unix nanoseconds.
    pub timestamp_ns: u64,
    /// The sender's pid.
    pub sender_pid: u32,
    /// The sender's parent pid.
    pub sender_ppid: u32,
    /// The sender's real uid.
    pub uid: u32,
    /// The sender's real gid.
    pub gid: u32,
    /// The login uid, `None` when auditd reports it unset.
    pub auid: Option<u32>,
    /// The sender's `comm`.
    pub comm: String,
    /// The sender's executable, when auditd recorded it.
    pub exe: Option<String>,
    /// What the signal was aimed at.
    pub target: KillTarget,
}

/// Parses one `audit.log` line, `None` unless it is a successful `SIGKILL` by the [`KILL_KEY`]
/// rule. Never panics, whatever the line holds.
#[must_use]
pub fn parse_kill_log_line(line: &str) -> Option<SigkillRecord> {
    // ENRICHED log lines append a `\x1d`-separated block of resolved names to the kernel's
    // record; only the kernel part is read.
    let line = line.split('\u{1d}').next()?;
    if !line.starts_with("type=SYSCALL ") {
        return None;
    }
    let (sec, ms, _seq) = parse_msg_header(line).ok()?;
    if ms > 999 {
        return None;
    }
    let timestamp_ns = sec
        .checked_mul(1_000_000_000)?
        .checked_add(u64::from(ms) * 1_000_000)?;
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
        // kill(pid, sig): a negative pid is a process group, -1 every process.
        (ARCH_X86_64, 62) | (ARCH_AARCH64, 129) => (signed_pid(hex("a0")?)?, hex("a1")?),
        // tkill(tid, sig)
        (ARCH_X86_64, 200) | (ARCH_AARCH64, 130) => (signed_pid(hex("a0")?)?, hex("a1")?),
        // tgkill(tgid, tid, sig)
        (ARCH_X86_64, 234) | (ARCH_AARCH64, 131) => (signed_pid(hex("a0")?)?, hex("a2")?),
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
        timestamp_ns,
        sender_pid: u32::try_from(dec("pid")?).ok()?,
        sender_ppid: u32::try_from(dec("ppid")?).ok()?,
        uid: u32::try_from(dec("uid")?).ok()?,
        gid: u32::try_from(dec("gid")?).ok()?,
        auid: auid.and_then(|a| u32::try_from(a).ok()),
        comm,
        exe,
        target,
    })
}

/// The target of a `kill`-family call from its `a0`, an `int` that auditd prints as the 32-bit
/// register (`-38445` is `ffff69d3`; some kernels print it sign-extended to 64 bits). Zero is the
/// sender's own group, which says nothing about the agent: not a target.
fn signed_pid(a0: u64) -> Option<KillTarget> {
    let low = u32::try_from(a0 & 0xffff_ffff).ok()?;
    if a0 > u64::from(u32::MAX) && a0 >> 32 != 0xffff_ffff {
        return None;
    }
    let pid = i32::from_ne_bytes(low.to_ne_bytes());
    match pid {
        0 => None,
        -1 => Some(KillTarget::AllProcesses),
        p if p > 0 => Some(KillTarget::Process(p.unsigned_abs())),
        p => Some(KillTarget::Group(p.unsigned_abs())),
    }
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

/// The latest record of a `SIGKILL` that hit the process `pid` (in group `pgid`) among `lines`,
/// recorded at or after `since_ns`. There is no upper bound: the restart's own wall clock is not
/// something to trust against the log's.
pub fn last_sigkill_of<'a>(
    pid: u32,
    pgid: u32,
    since_ns: u64,
    lines: impl IntoIterator<Item = &'a str>,
) -> Option<SigkillRecord> {
    lines
        .into_iter()
        .filter_map(parse_kill_log_line)
        .filter(|r| r.target.hits(pid, pgid) && r.timestamp_ns >= since_ns)
        .max_by_key(|r| r.timestamp_ns)
}

/// The timestamp of the newest line of `text` that has an audit header.
fn newest_timestamp_ns(text: &str) -> Option<u64> {
    text.lines().rev().find_map(|line| {
        let (sec, ms, _) = parse_msg_header(line).ok()?;
        sec.checked_mul(1_000_000_000)?
            .checked_add(u64::from(ms.min(999)) * 1_000_000)
    })
}

/// What a search of the log files found, and which files it could and could not read.
#[derive(Debug, Default)]
pub struct Replay {
    /// The record of the kill, if one was found.
    pub record: Option<SigkillRecord>,
    /// The files that were read.
    pub read: Vec<PathBuf>,
    /// The files that exist but could not be read (permission, an I/O error).
    pub unreadable: Vec<PathBuf>,
}

/// [`last_sigkill_of`] over the tail of each file in `paths`, newest first. A file that does not
/// exist is skipped; one that cannot be read is reported in [`Replay::unreadable`]. The walk
/// stops at the first file whose newest record is older than `since_ns`: the files after it are
/// older still, so a record rotated out of `audit.log` and `audit.log.1` is still found in
/// `audit.log.2`.
#[must_use]
pub fn read_sigkill_of(pid: u32, pgid: u32, since_ns: u64, paths: &[PathBuf]) -> Replay {
    let mut replay = Replay::default();
    for path in paths {
        let text = match read_tail(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                replay.unreadable.push(path.clone());
                continue;
            }
        };
        replay.read.push(path.clone());
        if let Some(record) = last_sigkill_of(pid, pgid, since_ns, text.lines()) {
            replay.record = Some(record);
            return replay;
        }
        if newest_timestamp_ns(&text).is_some_and(|newest| newest < since_ns) {
            break;
        }
    }
    replay
}

fn read_tail(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    file.seek(SeekFrom::Start(len.saturating_sub(MAX_TAIL_BYTES)))?;
    let mut bytes = Vec::new();
    file.take(MAX_TAIL_BYTES).read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// The marker a running audit-fallback agent keeps in its state directory. Only a kill leaves it
/// behind; a clean stop removes it, so a restart that finds none has nothing to attribute.
const MARKER: &str = "audit-agent.pid";

/// Where the kernel keeps this boot's random id.
const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";

/// What a running instance leaves for its successor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marker {
    /// The instance's pid.
    pub pid: u32,
    /// Its process group: `kill -9 -<pgid>` aims at it (it equals the pid for a systemd service).
    pub pgid: u32,
    /// When it started, Unix nanoseconds: a record older than this was not aimed at it.
    pub started_ns: u64,
    /// The boot it ran in. The kernel sets it, so it cannot be moved with the clock: a marker
    /// from another boot names a pid that now belongs to something else.
    pub boot_id: Option<String>,
}

/// This boot's id, `None` where the kernel gives none.
#[must_use]
pub fn current_boot_id() -> Option<String> {
    let id = std::fs::read_to_string(BOOT_ID).ok()?;
    let id = id.trim();
    (!id.is_empty()).then(|| id.to_string())
}

/// The marker left by the previous instance.
#[must_use]
pub fn read_marker(state_dir: &Path) -> Option<Marker> {
    let text = std::fs::read_to_string(state_dir.join(MARKER)).ok()?;
    let mut parts = text.split_whitespace();
    let pid = parts.next()?.parse().ok()?;
    let started_ns = parts.next()?.parse().ok()?;
    let pgid = parts.next()?.parse().ok()?;
    let boot_id = parts.next().filter(|id| *id != "-").map(str::to_string);
    Some(Marker {
        pid,
        pgid,
        started_ns,
        boot_id,
    })
}

/// Records this instance (atomically: a torn marker would blame the wrong pid), readable by its
/// owner only.
///
/// # Errors
///
/// The write or the rename failed.
pub fn write_marker(state_dir: &Path, marker: &Marker) -> std::io::Result<()> {
    use std::io::Write;

    let tmp = state_dir.join(format!("{MARKER}.tmp"));
    // A leftover from a crash must not block the write, and `create_new` must not follow a
    // link someone planted at the fixed name.
    let _ = std::fs::remove_file(&tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    writeln!(
        file,
        "{} {} {} {}",
        marker.pid,
        marker.started_ns,
        marker.pgid,
        marker.boot_id.as_deref().unwrap_or("-")
    )?;
    std::fs::rename(tmp, state_dir.join(MARKER))
}

/// Removes the marker: this instance ended on its own.
pub fn remove_marker(state_dir: &Path) {
    let _ = std::fs::remove_file(state_dir.join(MARKER));
}

/// The search for the kill of the predecessor `marker` names, or `None` when there is nothing to
/// look for: no marker, a marker with this instance's own pid (a recycled pid), or one from
/// another boot (`boot_id` is this boot's id). Otherwise a [`Replay`], whose `record` is the kill
/// sent after that instance started, so that a marker with no record can be reported.
#[must_use]
pub fn previous_instance_kill(
    marker: Option<&Marker>,
    own_pid: u32,
    boot_id: Option<&str>,
    paths: &[PathBuf],
) -> Option<Replay> {
    let marker = marker.filter(|m| m.pid != own_pid)?;
    if let (Some(then), Some(now)) = (marker.boot_id.as_deref(), boot_id)
        && then != now
    {
        return None;
    }
    Some(read_sigkill_of(
        marker.pid,
        marker.pgid,
        marker.started_ns,
        paths,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The line captured on Rocky 9.8 (kernel 5.14, auditd 3.1.5, ENRICHED), with the rule key
    /// of this module: `kill -KILL 2253` (a0=8cd) from a root shell, `auid` 1000.
    const REAL: &str = "type=SYSCALL msg=audit(1794826302.839:128): arch=c000003e syscall=62 success=yes exit=0 a0=8cd a1=9 a2=0 a3=7fe3bcb9fac0 items=0 ppid=2237 pid=2241 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4 comm=\"bash\" exe=\"/usr/bin/bash\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=\"synthaea-kill\"\u{1d}ARCH=x86_64 SYSCALL=kill AUID=\"edr-lab\" UID=\"root\" GID=\"root\" EUID=\"root\" SUID=\"root\" FSUID=\"root\" EGID=\"root\" SGID=\"root\" FSGID=\"root\"";

    /// The group kill captured on Fedora 43 (kernel 7.2, auditd): `kill -9 -38445` records
    /// `a0=ffff69d3`, the 32-bit `-38445`.
    const GROUP_KILL_A0: &str = "ffff69d3";

    fn line(syscall: u32, a0: &str, a1: &str, a2: &str, tail: &str) -> String {
        format!(
            "type=SYSCALL msg=audit(1000.500:7): arch=c000003e syscall={syscall} success=yes exit=0 a0={a0} a1={a1} a2={a2} a3=0 items=0 ppid=10 pid=20 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4 comm=\"sh\" exe=\"/bin/sh\" key=\"{KILL_KEY}\"{tail}"
        )
    }

    fn target(l: &str) -> Option<KillTarget> {
        parse_kill_log_line(l).map(|r| r.target)
    }

    fn at(sec: u64, a0: &str) -> String {
        line(62, a0, "9", "0", "").replace("audit(1000.500:7)", &format!("audit({sec}.000:7)"))
    }

    fn ns(s: u64) -> u64 {
        s * 1_000_000_000
    }

    #[test]
    fn a_real_enriched_kill_record_is_read() {
        let record = parse_kill_log_line(REAL).expect("a SIGKILL record");
        assert_eq!(record.target, KillTarget::Process(0x8cd));
        assert_eq!(record.sender_pid, 2241);
        assert_eq!(record.sender_ppid, 2237);
        assert_eq!(record.auid, Some(1000));
        assert_eq!(record.comm, "bash");
        assert_eq!(record.exe.as_deref(), Some("/usr/bin/bash"));
        assert_eq!(record.timestamp_ns, 1_794_826_302_839_000_000);
    }

    #[test]
    fn kill_tkill_and_tgkill_with_signal_9_are_read_and_the_target_is_a0() {
        assert_eq!(
            target(&line(62, "ff", "9", "0", "")),
            Some(KillTarget::Process(0xff))
        );
        // tgkill(tgid, tid, sig): the signal is a2, the process is a0.
        assert_eq!(
            target(&line(234, "ff", "100", "9", "")),
            Some(KillTarget::Process(0xff))
        );
        // tkill(tid, sig): SIGKILL is process-wide, and the main thread's tid is the pid.
        assert_eq!(
            target(&line(200, "ff", "9", "0", "")),
            Some(KillTarget::Process(0xff))
        );
    }

    #[test]
    fn a_group_kill_of_the_agents_group_is_read_as_a_group() {
        // `kill -9 -<pgid>`: captured `a0=ffff69d3` is the 32-bit -38445, not pid 4294928851.
        let record = parse_kill_log_line(&line(62, GROUP_KILL_A0, "9", "0", "")).unwrap();
        assert_eq!(record.target, KillTarget::Group(38445));
        assert!(
            record.target.hits(1, 38445),
            "the group is the agent's pgid"
        );
        assert!(record.target.hits(38445, 1), "or its pid, a session leader");
        assert!(!record.target.hits(1, 2));
        // The same value sign-extended to 64 bits, as some kernels print an `int`.
        assert_eq!(
            target(&line(62, "ffffffffffff69d3", "9", "0", "")),
            Some(KillTarget::Group(38445))
        );
        // The other group shapes of tkill and tgkill follow the same rule.
        assert_eq!(
            target(&line(200, GROUP_KILL_A0, "9", "0", "")),
            Some(KillTarget::Group(38445))
        );
    }

    #[test]
    fn kill_minus_one_hits_every_process_and_zero_hits_none_in_particular() {
        let all = target(&line(62, "ffffffff", "9", "0", "")).unwrap();
        assert_eq!(all, KillTarget::AllProcesses);
        assert!(all.hits(123, 456));
        // `kill(0, 9)` is the sender's own group: it says nothing about the agent.
        assert_eq!(target(&line(62, "0", "9", "0", "")), None);
        // A value that is neither a 32-bit register nor its sign extension is not read.
        assert_eq!(target(&line(62, "1ffffffff", "9", "0", "")), None);
    }

    #[test]
    fn anything_else_is_not_a_sigkill_record() {
        // SIGTERM, an unknown syscall, a failed call, another key, another record type.
        assert!(parse_kill_log_line(&line(62, "ff", "f", "0", "")).is_none());
        assert!(parse_kill_log_line(&line(234, "ff", "100", "f", "")).is_none());
        assert!(parse_kill_log_line(&line(200, "ff", "f", "0", "")).is_none());
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
    fn a_timestamp_that_overflows_is_not_a_record() {
        // 18446744073 s * 1e9 overflows u64 nanoseconds: it panicked in a test build and wrapped
        // in a release one, possibly into a replay window.
        let l =
            line(62, "ff", "9", "0", "").replace("audit(1000.500:7)", "audit(18446744073.999:1)");
        assert!(parse_kill_log_line(&l).is_none());
        let l = line(62, "ff", "9", "0", "")
            .replace("audit(1000.500:7)", "audit(18446744073709551615.999:1)");
        assert!(parse_kill_log_line(&l).is_none());
        // Milliseconds are 0..=999.
        let l = line(62, "ff", "9", "0", "").replace("audit(1000.500:7)", "audit(1000.1000:1)");
        assert!(parse_kill_log_line(&l).is_none());
        let l = line(62, "ff", "9", "0", "").replace("audit(1000.500:7)", "audit(1000.999:1)");
        assert!(parse_kill_log_line(&l).is_some());
    }

    #[test]
    fn aarch64_numbers_are_read() {
        let l = line(129, "ff", "9", "0", "").replace("c000003e", "c00000b7");
        assert_eq!(target(&l), Some(KillTarget::Process(0xff)));
        let l = line(131, "ff", "100", "9", "").replace("c000003e", "c00000b7");
        assert_eq!(target(&l), Some(KillTarget::Process(0xff)));
        let l = line(130, "ff", "9", "0", "").replace("c000003e", "c00000b7");
        assert_eq!(target(&l), Some(KillTarget::Process(0xff)));
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
    fn the_latest_matching_record_since_the_start_wins_and_there_is_no_upper_bound() {
        let lines = [at(100, "ff"), at(200, "ff"), at(300, "aa"), at(900, "ff")];
        let found = |since| {
            last_sigkill_of(0xff, 0xff, ns(since), lines.iter().map(String::as_str))
                .map(|r| r.timestamp_ns / 1_000_000_000)
        };
        assert_eq!(found(0), Some(900));
        assert_eq!(found(250), Some(900));
        assert_eq!(found(901), None);
        // A record dated far after "now" (a clock set back after the kill) is still the kill.
        let far = [at(9_000_000_000, "ff")];
        assert!(last_sigkill_of(0xff, 0xff, ns(1), far.iter().map(String::as_str)).is_some());
    }

    #[test]
    fn the_marker_round_trips_with_its_group_and_boot_and_a_clean_stop_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_marker(dir.path()), None);
        let marker = Marker {
            pid: 4242,
            pgid: 4200,
            started_ns: 777,
            boot_id: Some("0f1e2d3c-aaaa-bbbb-cccc-1234567890ab".into()),
        };
        write_marker(dir.path(), &marker).unwrap();
        assert_eq!(read_marker(dir.path()), Some(marker.clone()));
        // Written again over a leftover temp file, and with no boot id.
        std::fs::write(dir.path().join(format!("{MARKER}.tmp")), "stale").unwrap();
        let bare = Marker {
            boot_id: None,
            ..marker
        };
        write_marker(dir.path(), &bare).unwrap();
        assert_eq!(read_marker(dir.path()), Some(bare));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(MARKER))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        remove_marker(dir.path());
        assert_eq!(read_marker(dir.path()), None);
    }

    fn marker(pid: u32, started_s: u64) -> Marker {
        Marker {
            pid,
            pgid: pid,
            started_ns: ns(started_s),
            boot_id: Some("boot-a".into()),
        }
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
        let find = |m: Option<&Marker>, own, boot| previous_instance_kill(m, own, boot, &paths);
        let found = find(Some(&marker(0xff, 500)), 1, Some("boot-a")).unwrap();
        assert_eq!(found.record.map(|r| r.sender_pid), Some(20));
        assert_eq!(found.read.len(), 2);
        assert!(found.unreadable.is_empty());
        // Started after the record: it was not aimed at this instance. A lookup was made.
        let none = find(Some(&marker(0xff, 1001)), 1, Some("boot-a")).unwrap();
        assert!(none.record.is_none());
        // A recycled pid: the marker holds this instance's own pid. Nothing to look for.
        assert!(find(Some(&marker(0xff, 500)), 0xff, Some("boot-a")).is_none());
        // Another boot: the pid names something else now.
        assert!(find(Some(&marker(0xff, 500)), 1, Some("boot-b")).is_none());
        // No marker.
        assert!(find(None, 1, Some("boot-a")).is_none());
    }

    #[test]
    fn a_group_kill_of_the_predecessor_is_found() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        // The agent's pid is 38445 (its own group, as a systemd service): `kill -9 -38445`.
        std::fs::write(&log, format!("{}\n", at(1000, GROUP_KILL_A0))).unwrap();
        let found =
            previous_instance_kill(Some(&marker(38445, 500)), 1, Some("boot-a"), &[log]).unwrap();
        assert_eq!(
            found.record.map(|r| r.target),
            Some(KillTarget::Group(38445))
        );
    }

    #[test]
    fn a_record_rotated_out_twice_is_still_found_and_an_old_file_ends_the_walk() {
        let dir = tempfile::tempdir().unwrap();
        let name = |n: Option<u32>| match n {
            None => dir.path().join("audit.log"),
            Some(n) => dir.path().join(format!("audit.log.{n}")),
        };
        // `kill -9` at t=1000, then two rotations: the record is in audit.log.2.
        std::fs::write(name(None), format!("{}\n", at(1200, "aa"))).unwrap();
        std::fs::write(name(Some(1)), format!("{}\n", at(1100, "aa"))).unwrap();
        std::fs::write(
            name(Some(2)),
            format!("{}\n{}\n", at(1000, "ff"), at(1001, "aa")),
        )
        .unwrap();
        let paths: Vec<_> = [None, Some(1), Some(2), Some(3)]
            .into_iter()
            .map(name)
            .collect();
        let found = read_sigkill_of(0xff, 0xff, ns(500), &paths);
        assert_eq!(found.record.map(|r| r.timestamp_ns), Some(ns(1000)));
        assert_eq!(found.read.len(), 3, "audit.log.3 does not exist: skipped");

        // A file whose newest record is older than the start ends the walk: nothing after it is
        // read, even a matching record (which could only be a pid reused long before).
        std::fs::write(name(Some(1)), format!("{}\n", at(100, "aa"))).unwrap();
        let found = read_sigkill_of(0xff, 0xff, ns(500), &paths);
        assert!(found.record.is_none());
        assert_eq!(found.read.len(), 2);
    }

    #[test]
    fn a_file_that_cannot_be_read_is_reported_not_silent() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        std::fs::write(&log, "").unwrap();
        // A directory opens and fails on read: the shape of a permission or I/O error.
        let broken = dir.path().join("audit.log.1");
        std::fs::create_dir(&broken).unwrap();
        let missing = dir.path().join("audit.log.2");
        let replay = read_sigkill_of(0xff, 0xff, 0, &[log.clone(), broken.clone(), missing]);
        assert!(replay.record.is_none());
        assert_eq!(replay.read, [log]);
        assert_eq!(replay.unreadable, [broken]);
    }
}
