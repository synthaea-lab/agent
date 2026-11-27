//! Whether a signal's sender is the agent's own watchdog (#322), for
//! `SignalEvent::sender_is_watchdog`.
//!
//! The watchdog spawns the agent, so it is the agent's parent. A sender is the watchdog when all
//! of these hold (so the kill on a stalled heartbeat, after which the same watchdog restarts the
//! agent, passes; the kill before a rollback, after which a new watchdog starts, does not):
//!
//! - **its executable is the installed watchdog**, the `watchdog` binary next to the agent's own
//!   (`resolve_agent_bin` puts the agent there). The environment variable the watchdog sets on its
//!   agent proves nothing: whoever starts the agent can set it, so a root shell that stops the
//!   watchdog, kills the agent and starts it again would otherwise be taken for the watchdog. A
//!   watchdog whose binary was replaced on disk since it started (`/proc/<pid>/exe` then ends in
//!   ` (deleted)`), or an agent started with an explicit `--agent-bin` from another directory,
//!   fails this check, and the kill stays High.
//! - **it has the watchdog's pid, and the watchdog had started when the signal was sent.** The
//!   start time is rounded up to the end of its clock tick, so a process started in the same tick
//!   as the signal does not pass. This matters for the `SIGKILL` replayed after a restart, whose
//!   sender pid may have been reused since.
//! - **the watchdog is still the agent's parent when the signal is judged.** A pid is not reused
//!   while its process lives, and a parent that dies is never the parent again (the agent is
//!   reparented), so a watchdog that was running before the signal and is still the parent after
//!   it held that pid throughout. This check is what makes the rule independent of
//!   `PR_SET_PDEATHSIG`: the watchdog sets it on the agent (`die_with_parent` in
//!   `apps/watchdog/src/supervise.rs`), so today the agent cannot outlive its watchdog, but a
//!   credential change in the agent clears it, and without either guard someone could kill the
//!   watchdog, take its pid (`ns_last_pid`, `clone3`'s `set_tid`) and have every kill read Low.
//!
//! Neither the sender's name nor its cgroup is used: a root sender chooses both.
//!
//! Root can still claim to be the watchdog by running the real watchdog binary, or by `ptrace` of
//! it; `systemctl kill` already reads Low through the service manager (pid 1).

use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::proc::parse_stat_starttime;

/// The watchdog binary's file name. It is installed next to the agent's.
const WATCHDOG_FILE_NAME: &str = "watchdog";

/// The watchdog supervising this agent: its pid, and the latest it can have started, in
/// boot-relative nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Watchdog {
    pid: u32,
    started_by_ns: u64,
}

/// A process table: `/proc` on a real host, a directory in tests.
pub(crate) struct ProcTable {
    root: PathBuf,
    ticks_per_second: u64,
}

impl ProcTable {
    pub(crate) fn new(root: impl Into<PathBuf>, ticks_per_second: u64) -> Self {
        Self {
            root: root.into(),
            ticks_per_second,
        }
    }

    /// The watchdog with `pid`, when that process runs the watchdog installed next to
    /// `agent_exe`. `None` otherwise, or when its executable or start time cannot be read: then
    /// no sender is taken for the watchdog.
    pub(crate) fn watchdog(&self, pid: u32, agent_exe: &Path) -> Option<Watchdog> {
        let process = self.root.join(pid.to_string());
        let exe = fs::read_link(process.join("exe")).ok()?;
        if exe != agent_exe.with_file_name(WATCHDOG_FILE_NAME) {
            return None;
        }
        let stat = fs::read_to_string(process.join("stat")).ok()?;
        let started_by_ns = tick_end_ns(parse_stat_starttime(&stat)?, self.ticks_per_second)?;
        Some(Watchdog { pid, started_by_ns })
    }
}

impl Watchdog {
    /// Whether this watchdog is the sender `sender_pid` of a signal sent at `sent_ns`
    /// (`bpf_ktime_get_ns`), given the agent's parent now. `starttime` counts suspended time and
    /// `ktime` does not, so after a suspend the start can look later than it was: that only fails
    /// toward "not the watchdog", which keeps the alert High.
    pub(crate) fn sent(&self, sender_pid: u32, sent_ns: u64, current_parent: u32) -> bool {
        current_parent == self.pid && sender_pid == self.pid && self.started_by_ns <= sent_ns
    }
}

/// The end of the clock tick `starttime` names, as nanoseconds since boot: `starttime` is
/// rounded down to the tick, so the process started at the latest just before this. `None` on a
/// zero tick rate or overflow.
fn tick_end_ns(ticks: u64, ticks_per_second: u64) -> Option<u64> {
    let nanos_per_tick = 1_000_000_000u64.checked_div(ticks_per_second)?;
    ticks.checked_add(1)?.checked_mul(nanos_per_tick)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    const TICKS_PER_SECOND: u64 = 100;
    const WATCHDOG_PID: u32 = 4242;
    const AGENT_EXE: &str = "/opt/synthaea/current/agent";
    const WATCHDOG_EXE: &str = "/opt/synthaea/current/watchdog";

    /// A `/proc/<pid>/stat` line whose `starttime` is `ticks`; the comm holds a `) (` to
    /// check the fields are counted from the last `)`.
    fn stat_line(ticks: u64) -> String {
        format!(
            "{WATCHDOG_PID} (watch) (dog) S 1 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {ticks} 0 0"
        )
    }

    /// A process table holding one process, `WATCHDOG_PID`, running `exe` since `ticks`.
    fn proc_with_process(exe: &str, ticks: u64) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join(WATCHDOG_PID.to_string());
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("stat"), stat_line(ticks)).unwrap();
        symlink(exe, dir.join("exe")).unwrap();
        root
    }

    fn watchdog_in(root: &tempfile::TempDir) -> Option<Watchdog> {
        ProcTable::new(root.path(), TICKS_PER_SECOND).watchdog(WATCHDOG_PID, Path::new(AGENT_EXE))
    }

    fn watchdog_started_by(started_by_ns: u64) -> Watchdog {
        Watchdog {
            pid: WATCHDOG_PID,
            started_by_ns,
        }
    }

    #[test]
    fn the_watchdog_started_by_the_end_of_the_tick_its_stat_names() {
        let root = proc_with_process(WATCHDOG_EXE, 250);
        assert_eq!(watchdog_in(&root), Some(watchdog_started_by(2_510_000_000)));
    }

    #[test]
    fn a_parent_running_another_binary_is_not_the_watchdog() {
        let root = proc_with_process("/usr/bin/bash", 250);
        assert_eq!(watchdog_in(&root), None);
    }

    #[test]
    fn a_watchdog_whose_binary_was_replaced_since_it_started_is_not_trusted() {
        let root = proc_with_process("/opt/synthaea/current/watchdog (deleted)", 250);
        assert_eq!(watchdog_in(&root), None);
    }

    #[test]
    fn a_watchdog_with_no_proc_entry_is_unknown() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(watchdog_in(&root), None);
    }

    #[test]
    fn a_zero_tick_rate_leaves_the_watchdog_unknown() {
        let root = proc_with_process(WATCHDOG_EXE, 250);
        let table = ProcTable::new(root.path(), 0);
        assert_eq!(table.watchdog(WATCHDOG_PID, Path::new(AGENT_EXE)), None);
    }

    #[test]
    fn a_signal_from_the_watchdogs_pid_after_it_started_is_the_watchdogs() {
        let watchdog = watchdog_started_by(1_000);
        assert!(watchdog.sent(WATCHDOG_PID, 1_000, WATCHDOG_PID));
        assert!(watchdog.sent(WATCHDOG_PID, 9_000, WATCHDOG_PID));
    }

    #[test]
    fn a_signal_sent_before_the_watchdog_started_came_from_an_earlier_holder_of_its_pid() {
        let watchdog = watchdog_started_by(1_000);
        assert!(!watchdog.sent(WATCHDOG_PID, 999, WATCHDOG_PID));
    }

    #[test]
    fn a_signal_in_the_tick_the_watchdog_started_is_not_the_watchdogs() {
        let root = proc_with_process(WATCHDOG_EXE, 250);
        let watchdog = watchdog_in(&root).unwrap();
        assert!(!watchdog.sent(WATCHDOG_PID, 2_505_000_000, WATCHDOG_PID));
    }

    #[test]
    fn a_signal_from_another_pid_is_not_the_watchdogs() {
        let watchdog = watchdog_started_by(1_000);
        assert!(!watchdog.sent(WATCHDOG_PID + 1, 9_000, WATCHDOG_PID));
    }

    #[test]
    fn once_the_watchdog_is_no_longer_the_parent_its_pid_proves_nothing() {
        let watchdog = watchdog_started_by(1_000);
        assert!(!watchdog.sent(WATCHDOG_PID, 9_000, 1));
    }
}
