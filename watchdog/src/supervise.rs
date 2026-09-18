//! The supervision loop — layer 1 of kill resistance, identical on every OS: spawn
//! the agent, watch it, respawn on exit. (Layer 2 is the service manager restarting
//! the watchdog itself — see [`crate::service`].)
//!
//! Crash-loop dampening (#101): a fixed `restart_delay` alone means an agent that
//! crashes on startup (bad config, missing rules content, a panic on a corrupt
//! store) respawns in a tight loop forever — CPU/log/journal churn, with the
//! service-manager layer (layer 2: `sc failure`, `RestartSec`, launchd
//! `ThrottleInterval`) piling its own restarts on top. [`Backoff`] doubles the
//! delay (capped) on each *fast* crash and resets to the floor once the agent
//! has run long enough to be considered healthy again — see its doc for the
//! exact rule. The two layers stay out of each other's way: the watchdog owns
//! agent-level backoff here, the service manager still owns watchdog-level
//! restart at its own fixed cadence.
//!
//! Liveness (#102): a process can be alive (`try_wait` sees it running) and
//! still be doing nothing — deadlocked, wedged on a poisoned lock, its sensor
//! thread dead while the main thread parks. For an EDR that is the worst
//! failure mode: the endpoint looks protected while collecting nothing.
//! [`HeartbeatMonitor`] polls the progress-backed heartbeat file
//! `agent::heartbeat` writes (advances only when the sensor pipeline actually
//! processes an event end to end) and, after `miss_limit` consecutive checks
//! see no advance, kills the child — feeding the same [`Backoff`] a crash
//! would, per #102's "same path as a crash, feeding the backoff (#101)".

use std::{
    path::{Path, PathBuf},
    process::Child,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[cfg(unix)]
use anyhow::Context as _;

use crate::paths::{child_log_path, heartbeat_path_for, resolve_agent_bin};

/// Below this uptime, an exit counts as a "fast crash" for [`Backoff`]
/// purposes; at or above it, the agent ran long enough that a later crash
/// shouldn't inherit an elevated delay.
const FAST_CRASH_THRESHOLD: Duration = Duration::from_secs(10);

/// Backoff ceiling — the issue's "up to a few minutes" (#101).
const BACKOFF_CAP_SECS: u64 = 300;

/// `watch_child`'s child-alive poll granularity — [`HeartbeatMonitor`] counts
/// these ticks rather than reading a wall clock (see its doc).
const POLL_TICK: Duration = Duration::from_millis(500);

/// Exponential backoff for agent crash loops. `floor` is the existing
/// `restart_delay` (the CLI/service default of 5s, or whatever was
/// configured) — the backoff multiplies from it rather than replacing it, per
/// #101's "keep the existing `restart_delay` as the floor".
struct Backoff {
    floor: u64,
    current: u64,
}

/// Whether [`Backoff::record_exit`] classified an exit as a fast crash (the
/// delay it returns is the doubled/capped backoff) or a normal long-lived
/// exit (the delay it returns is always the floor).
#[derive(Debug, PartialEq, Eq)]
enum ExitClass {
    FastCrash,
    Healthy,
}

impl Backoff {
    fn new(floor: u64) -> Self {
        Self {
            floor,
            current: floor.max(1),
        }
    }

    /// Records one exit after the agent ran for `uptime`, returning the delay
    /// to sleep before the next restart and how this exit was classified.
    ///
    /// A fast crash (`uptime < FAST_CRASH_THRESHOLD`) returns the *current*
    /// delay and then doubles it (capped at [`BACKOFF_CAP_SECS`]) for next
    /// time — so consecutive fast crashes produce 5s → 10s → 20s → ... A
    /// normal exit (`uptime >= FAST_CRASH_THRESHOLD`) resets the delay back to
    /// the floor: a one-off crash after the agent has been healthy for a
    /// while must not inherit a stale long delay from an earlier crash loop.
    fn record_exit(&mut self, uptime: Duration) -> (u64, ExitClass) {
        if uptime < FAST_CRASH_THRESHOLD {
            let delay = self.current;
            self.current = self.current.saturating_mul(2).min(BACKOFF_CAP_SECS);
            (delay, ExitClass::FastCrash)
        } else {
            self.current = self.floor;
            (self.floor, ExitClass::Healthy)
        }
    }
}

/// Tracks a child's heartbeat file across polls, declaring it hung after
/// `miss_limit` consecutive checks see no advance in the counter (#102).
///
/// Driven by [`watch_child`]'s existing ~500ms poll loop (via [`Self::tick`])
/// rather than its own wall-clock timer: `ticks_per_check` counts how many
/// polls make up one heartbeat-check interval, so the actual miss-counting
/// state machine ([`Self::observe`]) needs no clock at all and is directly
/// unit-testable with a hand-fed sequence of readings — the same "fake clock"
/// approach [`Backoff`] uses.
struct HeartbeatMonitor {
    path: PathBuf,
    ticks_per_check: u32,
    miss_limit: u32,
    ticks_since_check: u32,
    last_value: Option<u64>,
    misses: u32,
}

impl HeartbeatMonitor {
    fn new(path: PathBuf, interval: Duration, miss_limit: u32) -> Self {
        // At least one tick per check even for a sub-POLL_TICK interval.
        let ticks_per_check = ((interval.as_millis() / POLL_TICK.as_millis()) as u32).max(1);
        Self {
            path,
            ticks_per_check,
            miss_limit: miss_limit.max(1),
            ticks_since_check: 0,
            last_value: None,
            misses: 0,
        }
    }

    /// Called once per `watch_child` poll (~[`POLL_TICK`]). Returns `true`
    /// once `miss_limit` consecutive no-progress checks have been observed —
    /// the caller should then kill and restart the child.
    fn tick(&mut self) -> bool {
        self.ticks_since_check += 1;
        if self.ticks_since_check < self.ticks_per_check {
            return false;
        }
        self.ticks_since_check = 0;
        self.observe(read_heartbeat(&self.path))
    }

    /// The pure state transition behind [`Self::tick`], split out so it is
    /// testable without a real heartbeat file on disk.
    fn observe(&mut self, current: Option<u64>) -> bool {
        match (current, self.last_value) {
            // A missing/unreadable file never itself counts as a miss — the
            // agent may not have written its first heartbeat yet (startup
            // grace), and a filesystem hiccup shouldn't kill a healthy agent.
            (None, _) => {}
            (Some(v), Some(prev)) if v == prev => self.misses += 1,
            (Some(v), _) => {
                self.last_value = Some(v);
                self.misses = 0;
            }
        }
        self.misses >= self.miss_limit
    }
}

/// Reads and parses the heartbeat file `agent::heartbeat` writes; `None` on
/// any I/O or parse failure (missing file, mid-write race the temp-file+
/// rename couldn't fully hide, garbage content) — treated as "no reading
/// yet", never as a miss (see [`HeartbeatMonitor::observe`]).
fn read_heartbeat(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Restarts the agent in a loop until `stop_flag` becomes true.
pub(crate) fn watchdog_loop(
    agent: &Path,
    alerts: &Path,
    restart_delay: u64,
    heartbeat_interval_secs: u64,
    heartbeat_miss_limit: u32,
    stop_flag: &AtomicBool,
) {
    let mut backoff = Backoff::new(restart_delay);
    let heartbeat_path = heartbeat_path_for(alerts);
    while !stop_flag.load(Ordering::SeqCst) {
        eprintln!("[watchdog] starting the agent...");
        let spawn_time = Instant::now();
        let mut heartbeat = HeartbeatMonitor::new(
            heartbeat_path.clone(),
            Duration::from_secs(heartbeat_interval_secs),
            heartbeat_miss_limit,
        );
        let mut child = match spawn_agent(agent, alerts) {
            Ok(c) => c,
            Err(e) => {
                // A spawn failure (missing binary, permission denied) is as
                // much a crash loop risk as an in-process panic — feed it
                // into the same backoff instead of hammering at a fixed
                // interval forever.
                let (delay, _) = backoff.record_exit(Duration::ZERO);
                eprintln!("[watchdog] spawn failed: {e}. Retrying in {delay}s...");
                if !sleep_unless_stopped(stop_flag, delay) {
                    return;
                }
                continue;
            }
        };
        if !watch_child(
            &mut child,
            spawn_time,
            &mut backoff,
            &mut heartbeat,
            stop_flag,
        ) {
            return;
        }
    }
}

/// Spawns one agent run with its output captured to the child log.
fn spawn_agent(agent: &Path, alerts: &Path) -> std::io::Result<Child> {
    // Force the working directory to the agent binary's folder. In a service
    // session (session 0 on Windows), the default working dir is System32 — the
    // agent would not find rules content nor write alerts.ndjson in the right
    // place.
    let work_dir = agent.parent().unwrap_or_else(|| Path::new("."));
    let log_out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(child_log_path())
        .ok();
    let mut cmd = std::process::Command::new(agent);
    cmd.arg("run")
        .arg("--alerts")
        .arg(alerts)
        .current_dir(work_dir);
    if let Some(f) = log_out {
        let f2 = f.try_clone().ok();
        cmd.stderr(std::process::Stdio::from(f));
        if let Some(f2) = f2 {
            cmd.stdout(std::process::Stdio::from(f2));
        }
    }
    #[cfg(target_os = "linux")]
    die_with_parent(&mut cmd);
    cmd.spawn()
}

/// Makes the agent die on its own the instant the watchdog does, even a SIGKILL
/// the watchdog's own handlers never get to react to (issue #216).
///
/// Without this, a killed watchdog leaves the agent reparented to PID 1 —
/// unsupervised but still running — because the OS does not kill children when a
/// parent dies. systemd's `KillMode=control-group` papers over this by sweeping
/// the unit's whole cgroup on every restart; `OpenRC` does not do this by default
/// (`rc_cgroup_cleanup="NO"`), so nothing else catches it there.
#[cfg(target_os = "linux")]
fn die_with_parent(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt as _;

    let watchdog_pid = std::process::id() as libc::pid_t;

    // SAFETY: `pre_exec` runs in the forked child, after `fork` and before
    // `exec`, with only this closure's stack in scope — no other threads, no
    // heap state shared with the parent to race on. `prctl`/`getppid` are plain
    // syscalls; passing a fixed signal constant and reading our own new pid
    // has no preconditions beyond a valid libc, guaranteed by this cfg.
    unsafe {
        cmd.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Close the fork/prctl race: if the watchdog died between fork and
            // this call, we've already been reparented (to the nearest
            // subreaper, usually PID 1) and PDEATHSIG registered above will
            // never fire for the watchdog we actually meant. Bail out instead
            // of exec-ing into an unsupervised agent.
            if libc::getppid() != watchdog_pid {
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }
            Ok(())
        });
    }
}

/// Watches one child until it exits or is killed for a stalled heartbeat (→
/// `true`: restart it) or the stop flag rises (→ `false`: kill it and end
/// supervision). Polls in short steps to react to the stop flag quickly.
fn watch_child(
    child: &mut Child,
    spawn_time: Instant,
    backoff: &mut Backoff,
    heartbeat: &mut HeartbeatMonitor,
    stop_flag: &AtomicBool,
) -> bool {
    loop {
        if stop_flag.load(Ordering::SeqCst) {
            let _ = child.kill();
            let _ = child.wait();
            return false;
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                let uptime = spawn_time.elapsed();
                let (delay, class) = backoff.record_exit(uptime);
                match class {
                    ExitClass::FastCrash => eprintln!(
                        "[watchdog] agent exited ({status}) after {:.1}s — fast crash, backing off {delay}s...",
                        uptime.as_secs_f64()
                    ),
                    ExitClass::Healthy => {
                        eprintln!("[watchdog] agent exited ({status}). Restarting in {delay}s...");
                    }
                }
                return sleep_unless_stopped(stop_flag, delay);
            }
            Ok(None) => {
                if heartbeat.tick() {
                    eprintln!(
                        "[watchdog] agent heartbeat stalled ({} consecutive misses) — \
                         killing and restarting (#102)",
                        heartbeat.miss_limit
                    );
                    let _ = child.kill();
                    let _ = child.wait();
                    let (delay, _) = backoff.record_exit(spawn_time.elapsed());
                    return sleep_unless_stopped(stop_flag, delay);
                }
                std::thread::sleep(POLL_TICK);
            }
            Err(e) => {
                eprintln!("[watchdog] try_wait error: {e}");
                return true;
            }
        }
    }
}

/// Sleeps `secs` in interruptible steps; `false` when the stop flag rose mid-wait.
fn sleep_unless_stopped(stop_flag: &AtomicBool, secs: u64) -> bool {
    for _ in 0..(secs * 2) {
        if stop_flag.load(Ordering::SeqCst) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    true
}

/// Subcommand `run`: direct supervision — the service entry point on Unix, and
/// the fallback without service rights everywhere.
pub(crate) fn cmd_run(
    agent_bin: Option<PathBuf>,
    alerts: PathBuf,
    restart_delay: u64,
    heartbeat_interval_secs: u64,
    heartbeat_miss_limit: u32,
) -> anyhow::Result<()> {
    let agent = resolve_agent_bin(agent_bin)?;
    anyhow::ensure!(agent.exists(), "agent not found: {}", agent.display());

    eprintln!(
        "[watchdog] supervising {} → alerts in {}",
        agent.display(),
        alerts.display()
    );

    let stop = Arc::new(AtomicBool::new(false));

    // Unix clean stop: systemd stop / launchctl bootout / Ctrl+C set the flag,
    // the loop kills the agent and exits — the same semantics the Windows SCM
    // control handler provides.
    #[cfg(unix)]
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        signal_hook::flag::register(sig, stop.clone())
            .with_context(|| format!("registering handler for signal {sig}"))?;
    }
    eprintln!("[watchdog] Ctrl+C / SIGTERM stops the watchdog (the agent will be stopped too)");

    watchdog_loop(
        &agent,
        &alerts,
        restart_delay,
        heartbeat_interval_secs,
        heartbeat_miss_limit,
        &stop,
    );
    eprintln!("[watchdog] stopped.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // "Fake clock": Backoff::record_exit and HeartbeatMonitor::observe take
    // their inputs as plain values rather than measuring real time/reading a
    // real file themselves, so these tests drive both schedules with
    // hand-picked values instead of real sleeps or a heartbeat file on disk.

    #[test]
    fn fast_crashes_double_the_delay_up_to_the_cap() {
        let mut backoff = Backoff::new(5);
        let fast = Duration::from_secs(1);

        let (d1, c1) = backoff.record_exit(fast);
        assert_eq!((d1, c1), (5, ExitClass::FastCrash));
        let (d2, c2) = backoff.record_exit(fast);
        assert_eq!((d2, c2), (10, ExitClass::FastCrash));
        let (d3, c3) = backoff.record_exit(fast);
        assert_eq!((d3, c3), (20, ExitClass::FastCrash));
        let (d4, _) = backoff.record_exit(fast);
        assert_eq!(d4, 40);
    }

    #[test]
    fn backoff_never_exceeds_the_cap() {
        let mut backoff = Backoff::new(5);
        let fast = Duration::from_secs(0);
        // Enough consecutive fast crashes to run past the cap several times over.
        let mut last = 0;
        for _ in 0..20 {
            let (delay, class) = backoff.record_exit(fast);
            assert_eq!(class, ExitClass::FastCrash);
            last = delay;
            assert!(delay <= BACKOFF_CAP_SECS);
        }
        assert_eq!(last, BACKOFF_CAP_SECS);
    }

    #[test]
    fn healthy_exit_resets_the_backoff_to_the_floor() {
        let mut backoff = Backoff::new(5);
        let fast = Duration::from_secs(2);
        let healthy = Duration::from_secs(3600); // ran an hour before exiting

        backoff.record_exit(fast); // -> 5s used, now at 10s
        backoff.record_exit(fast); // -> 10s used, now at 20s
        let (delay, class) = backoff.record_exit(healthy);
        assert_eq!((delay, class), (5, ExitClass::Healthy));

        // A later fast crash starts back at the floor, not at the inflated 20s.
        let (delay, class) = backoff.record_exit(fast);
        assert_eq!((delay, class), (5, ExitClass::FastCrash));
    }

    #[test]
    fn exit_exactly_at_the_threshold_counts_as_healthy() {
        let mut backoff = Backoff::new(5);
        let (delay, class) = backoff.record_exit(FAST_CRASH_THRESHOLD);
        assert_eq!((delay, class), (5, ExitClass::Healthy));
    }

    #[test]
    fn custom_floor_is_respected() {
        let mut backoff = Backoff::new(30);
        let fast = Duration::from_secs(0);
        let (d1, _) = backoff.record_exit(fast);
        assert_eq!(d1, 30);
        let (d2, _) = backoff.record_exit(fast);
        assert_eq!(d2, 60);
    }

    fn monitor(miss_limit: u32) -> HeartbeatMonitor {
        HeartbeatMonitor::new(PathBuf::from("/unused"), Duration::from_secs(5), miss_limit)
    }

    #[test]
    fn a_hung_agent_is_flagged_after_miss_limit_stalled_checks() {
        let mut m = monitor(3);
        assert!(!m.observe(Some(10))); // first reading, baseline
        assert!(!m.observe(Some(10))); // miss 1
        assert!(!m.observe(Some(10))); // miss 2
        assert!(m.observe(Some(10))); // miss 3 — hits the limit
    }

    #[test]
    fn advancing_progress_never_flags_a_hang() {
        let mut m = monitor(3);
        for n in 1..=100u64 {
            assert!(!m.observe(Some(n)), "progressing counter must never hang");
        }
    }

    #[test]
    fn a_missing_reading_is_never_itself_a_miss() {
        let mut m = monitor(2);
        assert!(!m.observe(Some(5)));
        assert!(!m.observe(None)); // startup grace / transient read failure
        assert!(!m.observe(None));
        // Misses stayed at 0 — the same value again only now counts as miss 1.
        assert!(!m.observe(Some(5)));
        assert!(m.observe(Some(5)));
    }

    #[test]
    fn progress_after_a_stall_resets_the_miss_count() {
        let mut m = monitor(3);
        assert!(!m.observe(Some(1)));
        assert!(!m.observe(Some(1))); // miss 1
        assert!(!m.observe(Some(2))); // progressed — resets
        assert!(!m.observe(Some(2))); // miss 1 again, not 2
        assert!(!m.observe(Some(2))); // miss 2
        assert!(m.observe(Some(2))); // miss 3 — hits the limit
    }

    #[test]
    fn tick_only_checks_the_file_once_per_interval() {
        // interval = 5s, POLL_TICK = 500ms -> 10 ticks per check.
        let mut m = monitor(1);
        let path = std::env::temp_dir()
            .join(format!("heartbeat-monitor-tick-test-{}.txt", std::process::id()));
        std::fs::write(&path, "1").unwrap();
        m.path = path.clone();
        for i in 1..10 {
            assert!(!m.tick(), "tick {i} should not have checked the file yet");
        }
        // The 10th tick performs the check: same value as the (nonexistent)
        // baseline read on first check -> not yet a miss (first real reading).
        assert!(!m.tick());
        std::fs::remove_file(&path).ok();
    }
}

/// Regression test for issue #216: a SIGKILL'd watchdog must not leave its agent
/// running unsupervised.
///
/// Re-execs this test binary as a stand-in "watchdog" (`FAKE_WATCHDOG_ENV` set)
/// that spawns a grandchild through the same [`die_with_parent`] path
/// [`spawn_agent`] uses, prints that grandchild's pid, then idles. The real test
/// process SIGKILLs the stand-in — the exact failure mode from the issue, which
/// bypasses any signal handler the stand-in might otherwise have run — and
/// asserts the grandchild disappears on its own shortly after.
#[cfg(all(test, target_os = "linux"))]
mod pdeathsig_tests {
    use std::io::BufRead as _;
    use std::time::{Duration, Instant};

    const FAKE_WATCHDOG_ENV: &str = "SYNTHAEA_TEST_FAKE_WATCHDOG";

    #[test]
    fn agent_dies_when_watchdog_is_sigkilled() {
        if std::env::var_os(FAKE_WATCHDOG_ENV).is_some() {
            run_as_fake_watchdog();
        }

        let exe = std::env::current_exe().expect("current_exe");
        let mut fake_watchdog = std::process::Command::new(exe)
            .arg("supervise::pdeathsig_tests::agent_dies_when_watchdog_is_sigkilled")
            .arg("--exact")
            .arg("--nocapture")
            .env(FAKE_WATCHDOG_ENV, "1")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn fake watchdog");

        // The test harness itself writes preamble lines ("running 1 test", a
        // blank line, ...) to stdout before our test body runs — skip past
        // those to find the one line we actually care about.
        let stdout = fake_watchdog.stdout.take().expect("piped stdout");
        let mut reader = std::io::BufReader::new(stdout);
        let mut grandchild_pid = None;
        for _ in 0..20 {
            let mut line = String::new();
            if reader.read_line(&mut line).expect("read line") == 0 {
                break; // EOF
            }
            if let Some(pid_str) = line.trim().strip_prefix("GRANDCHILD_PID=") {
                grandchild_pid = pid_str.parse::<libc::pid_t>().ok();
                break;
            }
        }
        let grandchild_pid =
            grandchild_pid.expect("fake watchdog never printed a GRANDCHILD_PID= line");

        // Give the grandchild a moment to actually spawn and register PDEATHSIG
        // before we pull the rug out from under its parent.
        std::thread::sleep(Duration::from_millis(300));

        // SAFETY: `kill` with a validated pid and a fixed signal constant has no
        // preconditions beyond a valid libc.
        unsafe {
            libc::kill(fake_watchdog.id() as libc::pid_t, libc::SIGKILL);
        }
        let _ = fake_watchdog.wait();

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            // SAFETY: signal 0 only probes liveness, no signal is actually sent.
            let alive = unsafe { libc::kill(grandchild_pid, 0) } == 0;
            if !alive {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "grandchild pid {grandchild_pid} survived its watchdog's SIGKILL \
                 — the issue #216 orphan bug has regressed"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// The stand-in "watchdog" role: spawn a grandchild the same way
    /// [`super::spawn_agent`] does, report its pid, then idle until killed.
    fn run_as_fake_watchdog() -> ! {
        let mut grandchild_cmd = std::process::Command::new("sleep");
        grandchild_cmd.arg("30");
        super::die_with_parent(&mut grandchild_cmd);
        let mut grandchild = grandchild_cmd.spawn().expect("spawn grandchild");
        println!("GRANDCHILD_PID={}", grandchild.id());
        loop {
            std::thread::sleep(Duration::from_secs(60));
            let _ = grandchild.try_wait();
        }
    }
}
