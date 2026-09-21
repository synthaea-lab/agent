//! Kill-loudness (issue #71, capability 4): before the agent actually terminates on a
//! catchable signal, record who sent it, when, and how — "where the platform allows"
//! per the issue, since SIGKILL/SIGSTOP cannot be masked, caught, or attributed by the
//! dying process at all (POSIX: `pthread_sigmask`/`sigaction` silently cannot touch
//! them) — a real SIGKILL still kills the agent with zero attribution here, the same
//! honest gap every other #71 primitive documents for its own uncoverable edge.
//!
//! Mechanism: the catchable termination signals (SIGTERM/SIGHUP/SIGQUIT — **not**
//! SIGINT, deliberately: `sensor_linux::LinuxSensor::run` already owns Ctrl-C via
//! `tokio::signal::ctrl_c` for its own graceful stop, and blocking SIGINT here would
//! starve that handler of a signal it needs, turning every operator Ctrl-C into a
//! hard `process::exit` instead of the sensor's existing clean shutdown) are blocked
//! on the main thread before any other thread is spawned — Linux threads inherit
//! their creator's signal mask at creation time, so every thread `cmd_run` starts
//! afterward inherits the same block. A single dedicated thread then
//! synchronously waits for one via `sigwaitinfo(2)`, which hands back the sender's pid
//! in ordinary thread context — no async-signal-safety restrictions the way a real
//! signal handler would have, so a plain file write is safe here. Blocking suppressed
//! the signal's own default disposition, so after logging, this thread is now the one
//! responsible for actually terminating the process (the conventional 128+signal exit
//! code).
//!
//! Not unit-tested past the pure helpers below: the full mask-then-`sigwaitinfo`-then-
//! `exit` flow deliberately terminates the process, which would kill the `cargo test`
//! runner itself. Validated for real instead — see the issue/PR for a genuine `kill
//! -TERM` against a running `agent run` on the lab VM.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::path::{Path, PathBuf};

const WATCHED_SIGNALS: [i32; 3] = [libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

fn watched_signal_set() -> libc::sigset_t {
    // SAFETY: `set` is zero-initialized then only ever populated through
    // `sigemptyset`/`sigaddset` on signal numbers from `WATCHED_SIGNALS`, a documented
    // ffi-safe usage of both calls.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for &sig in &WATCHED_SIGNALS {
            libc::sigaddset(&mut set, sig);
        }
        set
    }
}

/// Blocks the watched signals on the calling thread. **Must run before any other
/// thread is spawned** — calling this late would leave already-running threads
/// exposed to the signals' default disposition (immediate, unattributed death),
/// since only threads created *after* this call inherit the new mask.
pub(crate) fn block_termination_signals() {
    let set = watched_signal_set();
    // SAFETY: `set` is a fully-initialized `sigset_t` from `watched_signal_set`; a
    // null `oldset` out-param is valid when the previous mask isn't needed.
    unsafe {
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
}

/// Spawns the dedicated thread that waits for one of the blocked signals and records
/// who sent it before actually terminating the process (blocking suppressed the
/// signal's own default disposition, so nothing else will end it).
pub(crate) fn spawn_watcher(alerts_path: PathBuf) {
    std::thread::Builder::new()
        .name("kill-loudness".into())
        .spawn(move || {
            let set = watched_signal_set();
            // SAFETY: `set` watches only the signals blocked by
            // `block_termination_signals`; `info` is an output-only `siginfo_t` the
            // kernel fills in on a successful return, read only after that return.
            let (signo, sender_pid) = unsafe {
                let mut info: libc::siginfo_t = std::mem::zeroed();
                let signo = libc::sigwaitinfo(&set, &mut info);
                (signo, info.si_pid())
            };
            if signo < 0 {
                // `sigwaitinfo` failed (e.g. interrupted by an unwatched signal) —
                // nothing to attribute, and the process is not terminating.
                return;
            }
            report_kill_attempt(&alerts_path, signo, sender_pid);
            std::process::exit(128 + signo);
        })
        .expect("spawning the kill-loudness watcher thread");
}

fn signal_name(signo: i32) -> &'static str {
    match signo {
        libc::SIGTERM => "SIGTERM",
        libc::SIGHUP => "SIGHUP",
        libc::SIGQUIT => "SIGQUIT",
        _ => "unknown",
    }
}

/// Best-effort process short name for `pid`, the same source (`/proc/<pid>/comm`)
/// `sensor_linux`'s own lineage priming reads. `None` if the sender has already
/// exited or `/proc` isn't readable — the pid alone is still useful attribution.
fn sender_comm(pid: i32) -> Option<String> {
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    let trimmed = comm.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Writes one alert line directly (no `DetectionSink`/`schema`/`sinks` dependency —
/// mirrors `watchdog::tamper::report_self_protection_event`'s reasoning: the normal
/// detection pipeline may be mid-teardown by the time a termination signal lands, and
/// this is one fixed-shape line, not a case for a structured writer).
fn report_kill_attempt(alerts_path: &Path, signo: i32, sender_pid: i32) {
    let message = match sender_comm(sender_pid) {
        Some(comm) => format!(
            "agent received signal {signo} ({}) from pid {sender_pid} (`{comm}`) — recording before exit",
            signal_name(signo)
        ),
        None => format!(
            "agent received signal {signo} ({}) from pid {sender_pid} — recording before exit",
            signal_name(signo)
        ),
    };
    eprintln!("\x1b[1;31m[ALERT] T1562 — {message}\x1b[0m");
    let now_ns = schema::time::now_ns();
    let line = format!(
        "{{\"timestamp_ns\":{now_ns},\"technique\":\"T1562\",\"message\":\"{}\"}}\n",
        escape_json_string(&message)
    );
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(alerts_path)
    {
        use std::io::Write as _;
        let _ = file.write_all(line.as_bytes());
    }
}

/// Manual escaping rather than a JSON-serialization dependency, matching
/// `watchdog::tamper::report_self_protection_event`: one fixed-shape line with a
/// single interpolated field doesn't need a full serializer, just its two special
/// characters handled.
fn escape_json_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_name_covers_every_watched_signal() {
        for &sig in &WATCHED_SIGNALS {
            assert_ne!(signal_name(sig), "unknown");
        }
        assert_eq!(signal_name(9999), "unknown");
    }

    #[test]
    fn sender_comm_resolves_our_own_pid() {
        assert!(sender_comm(std::process::id() as i32).is_some());
    }

    #[test]
    fn sender_comm_is_none_for_an_implausible_pid() {
        assert_eq!(sender_comm(i32::MAX), None);
    }

    #[test]
    fn report_kill_attempt_writes_a_well_shaped_alert_line() {
        let path = std::env::temp_dir().join(format!(
            "kill-loudness-test-{}-{}.ndjson",
            std::process::id(),
            std::thread::current().name().unwrap_or("t")
        ));
        let _ = std::fs::remove_file(&path);

        report_kill_attempt(&path, libc::SIGTERM, 4242);

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("\"technique\":\"T1562\""));
        assert!(written.contains("SIGTERM"));
        assert!(written.contains("4242"));
        assert!(written.trim_end().ends_with('}'));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn escape_json_string_handles_quotes_and_backslashes() {
        assert_eq!(
            escape_json_string(r#"binary at "C:\agent.exe" was swapped"#),
            r#"binary at \"C:\\agent.exe\" was swapped"#
        );
    }
}
