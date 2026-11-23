//! Whether a signal's sender is the agent's own watchdog (#322), for
//! `SignalEvent::sender_is_watchdog`.
//!
//! The watchdog spawns the agent, so it is the agent's parent. A sender is the watchdog when it
//! has that pid **and** the watchdog was already running when the signal was sent: a pid is not
//! reused while its process lives, so no other process can have held it then. The second check
//! matters for the `SIGKILL` replayed after a restart, whose sender pid may have been reused since.
//! Neither the sender's name nor its cgroup is used: a root sender chooses both.

use std::{fs, path::Path};

use crate::proc::parse_stat_starttime;

/// The watchdog supervising this agent: its pid and its start time, in boot-relative
/// nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Watchdog {
    pid: u32,
    started_ns: u64,
}

impl Watchdog {
    /// The watchdog with `pid`, read under `proc_root` (`/proc` on a real host). `None` when its
    /// start time cannot be read: then no sender is taken for the watchdog.
    pub(crate) fn read(proc_root: &Path, pid: u32, ticks_per_second: u64) -> Option<Self> {
        let stat = fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
        let started_ns = start_ns(parse_stat_starttime(&stat)?, ticks_per_second)?;
        Some(Self { pid, started_ns })
    }

    /// Whether this watchdog is the sender `sender_pid` of a signal sent at `sent_ns`
    /// (`bpf_ktime_get_ns`). `starttime` counts suspended time and `ktime` does not, so after
    /// a suspend the start can look later than it was: that only fails toward "not the
    /// watchdog", which keeps the alert High.
    pub(crate) fn sent(&self, sender_pid: u32, sent_ns: u64) -> bool {
        sender_pid == self.pid && self.started_ns <= sent_ns
    }
}

/// `starttime` clock ticks as nanoseconds since boot; `None` on a zero tick rate or overflow.
fn start_ns(ticks: u64, ticks_per_second: u64) -> Option<u64> {
    let nanos_per_tick = 1_000_000_000u64.checked_div(ticks_per_second)?;
    ticks.checked_mul(nanos_per_tick)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TICKS_PER_SECOND: u64 = 100;
    const WATCHDOG_PID: u32 = 4242;

    /// A `/proc/<pid>/stat` line whose `starttime` is `ticks`; the comm holds a `) (` to
    /// check the fields are counted from the last `)`.
    fn stat_line(ticks: u64) -> String {
        format!(
            "{WATCHDOG_PID} (watch) (dog) S 1 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {ticks} 0 0"
        )
    }

    fn proc_with_watchdog(ticks: u64) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join(WATCHDOG_PID.to_string());
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("stat"), stat_line(ticks)).unwrap();
        root
    }

    #[test]
    fn the_watchdogs_start_time_is_read_from_its_stat() {
        let root = proc_with_watchdog(250);
        let watchdog = Watchdog::read(root.path(), WATCHDOG_PID, TICKS_PER_SECOND).unwrap();
        assert_eq!(
            watchdog,
            Watchdog {
                pid: WATCHDOG_PID,
                started_ns: 2_500_000_000
            }
        );
    }

    #[test]
    fn a_watchdog_with_no_proc_entry_is_unknown() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            Watchdog::read(root.path(), WATCHDOG_PID, TICKS_PER_SECOND),
            None
        );
    }

    #[test]
    fn a_zero_tick_rate_leaves_the_watchdog_unknown() {
        let root = proc_with_watchdog(250);
        assert_eq!(Watchdog::read(root.path(), WATCHDOG_PID, 0), None);
    }

    #[test]
    fn a_signal_from_the_watchdogs_pid_after_it_started_is_the_watchdogs() {
        let watchdog = Watchdog {
            pid: WATCHDOG_PID,
            started_ns: 1_000,
        };
        assert!(watchdog.sent(WATCHDOG_PID, 1_000));
        assert!(watchdog.sent(WATCHDOG_PID, 9_000));
    }

    #[test]
    fn a_signal_sent_before_the_watchdog_started_came_from_an_earlier_holder_of_its_pid() {
        let watchdog = Watchdog {
            pid: WATCHDOG_PID,
            started_ns: 1_000,
        };
        assert!(!watchdog.sent(WATCHDOG_PID, 999));
    }

    #[test]
    fn a_signal_from_another_pid_is_not_the_watchdogs() {
        let watchdog = Watchdog {
            pid: WATCHDOG_PID,
            started_ns: 1_000,
        };
        assert!(!watchdog.sent(WATCHDOG_PID + 1, 9_000));
    }
}
