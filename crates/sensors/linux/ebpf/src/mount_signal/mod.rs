//! Mount/unmount and signal telemetry (issue #362), feeding the platform-neutral
//! `Event::Mount` and `Event::Signal`. `signal` also owns `SIGNAL_WATCH_PID`, the agent's own
//! pid, which `is_agent_own_pid` lends to the file and DNS probes. `raw.rs` routes the
//! syscalls to these handlers.

pub(crate) mod mount;
pub(crate) mod signal;
