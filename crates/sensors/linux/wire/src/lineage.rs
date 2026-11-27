//! What the `sched_process_fork` probe writes to `PROC_LINEAGE` (#372).
//!
//! The map is keyed by process id (the tgid), and every reader looks it up by a tgid: the
//! probes by `bpf_get_current_pid_tgid() >> 32`, userspace priming by `/proc/<pid>/stat`.
//! The tracepoint fires for every `clone`, threads included, and hands over two `task_struct`s
//! whose `pid` is a thread id. Deciding here, from plain ids, keeps the probe a sequence of reads
//! and lets the host test the rule.

/// A task's ids as the kernel keeps them (`task_struct.pid`/`tgid`, initial pid namespace).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskIds {
    /// The thread id.
    pub pid: u32,
    /// The id of the process the thread belongs to.
    pub tgid: u32,
}

/// A new process's lineage entry, as the fork probe stores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkedProcess {
    /// The new process's id, the key of its `PROC_LINEAGE` entry.
    pub pid: u32,
    /// The forking process's id (its tgid), never the id of the thread that called `fork`.
    pub ppid: u32,
}

/// The entry a `sched_process_fork` records, from the forking task and the new one.
///
/// `None` for a new thread (`CLONE_THREAD`: its pid is not its tgid): it joins a process that
/// already has an entry, and an entry under a thread id would name no process. A process forked
/// by any thread of its parent gets the parent's tgid as `ppid`, the id that `/proc/<pid>/stat`
/// priming and every lookup use.
#[inline(always)]
#[must_use]
pub const fn forked_process(parent: TaskIds, child: TaskIds) -> Option<ForkedProcess> {
    if child.pid != child.tgid {
        return None;
    }
    Some(ForkedProcess {
        pid: child.tgid,
        ppid: parent.tgid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAIN_THREAD: TaskIds = TaskIds {
        pid: 100,
        tgid: 100,
    };
    const SECONDARY_THREAD: TaskIds = TaskIds {
        pid: 105,
        tgid: 100,
    };
    const NEW_PROCESS: TaskIds = TaskIds {
        pid: 200,
        tgid: 200,
    };

    #[test]
    fn a_fork_by_the_main_thread_records_the_parent_process() {
        assert_eq!(
            forked_process(MAIN_THREAD, NEW_PROCESS),
            Some(ForkedProcess {
                pid: 200,
                ppid: 100
            })
        );
    }

    #[test]
    fn a_fork_by_a_secondary_thread_records_the_parent_process_not_the_thread() {
        assert_eq!(
            forked_process(SECONDARY_THREAD, NEW_PROCESS),
            Some(ForkedProcess {
                pid: 200,
                ppid: 100
            })
        );
    }

    #[test]
    fn a_new_thread_records_nothing() {
        let new_thread = TaskIds {
            pid: 201,
            tgid: 100,
        };
        assert_eq!(forked_process(MAIN_THREAD, new_thread), None);
        assert_eq!(forked_process(SECONDARY_THREAD, new_thread), None);
    }
}
