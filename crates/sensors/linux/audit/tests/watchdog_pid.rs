//! `watchdog_pid` against the real `prctl`, on the main thread (#342).
//!
//! The death signal a watchdog sets with `PR_SET_PDEATHSIG` belongs to the main thread of the
//! process it starts, and libtest runs every test on a thread of its own, so this test has its own
//! `main`. It starts itself the way the watchdog starts the agent and checks both sides.

#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt as _;

#[cfg(target_os = "linux")]
use sensor_linux_audit::killrec::watchdog_pid;

#[cfg(target_os = "linux")]
const CHILD: &str = "SYNTHAEA_WATCHDOG_PID_CHILD";

#[cfg(not(target_os = "linux"))]
fn main() {}

#[cfg(target_os = "linux")]
fn main() {
    if std::env::var_os(CHILD).is_some() {
        // SAFETY: `getppid(2)` takes no argument, cannot fail and touches no memory.
        let parent = unsafe { libc::getppid() };
        assert_eq!(
            watchdog_pid(),
            u32::try_from(parent).ok(),
            "started with SIGKILL as the death signal, the parent is the watchdog"
        );
        return;
    }

    assert_eq!(
        watchdog_pid(),
        None,
        "started by a test runner with no death signal there is no watchdog"
    );

    let mut child = std::process::Command::new(std::env::current_exe().unwrap());
    child.env(CHILD, "1");
    // SAFETY: the closure runs after `fork` and before `exec` and makes one `prctl` call, as the
    // watchdog's `die_with_parent` does.
    unsafe {
        child.pre_exec(|| {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = child.output().unwrap();
    assert!(
        out.status.success(),
        "child failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    println!("watchdog_pid: ok");
}
