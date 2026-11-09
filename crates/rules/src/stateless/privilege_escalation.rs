//! Privilege Escalation (TA0004): container escape through procfs, dynamic linker
//! hijacking.

use schema::{ExecEvent, FileOpenEvent, detection::Severity};

use crate::Alert;

/// T1611 — Escape to Host: a containerized process opening `/proc/<pid>/root` reaches
/// through procfs into another process's root filesystem — normal containerized
/// workloads have no legitimate reason to do this. The textbook path is a container
/// run with a shared/host PID namespace (`--pid=host`) reaching `/proc/1/root` to
/// read/write the host's own filesystem (issue #80's suggested example). This needs
/// the container attribution #80 built, since the signal is "a containerized process
/// did X", not X alone — host-side tooling reaches into other processes'
/// `/proc/<pid>/root` constantly and legitimately (procfs walkers, `nsenter`,
/// debuggers); a bare-metal process doing this is unremarkable, a containerized one
/// almost never has a legitimate reason to.
///
/// Needs `event.meta.container` to be populated. Originally had a coverage gap here,
/// confirmed against a real Docker daemon: the sensor's attribution lost a race for a
/// process whose entire lifetime was one `open()` then exit (a bare `cat <path>`),
/// because attribution was read from `/proc/<pid>/cgroup` at drain time, after the pid
/// could already be gone. Closed by issue #204 — attribution is now keyed off a cgroup
/// id captured kernel-side at syscall time (see `container_id_from_cgroupfs`'s doc
/// comment in `sensor-linux`), which does not depend on the pid still existing by
/// drain time.
#[must_use]
pub(crate) fn check_proc_root_escape(event: &FileOpenEvent) -> Option<Alert> {
    let container = event.meta.container.as_ref()?;

    let mut segments = event.path.split('/').filter(|s| !s.is_empty());
    let is_proc_pid_root = matches!(segments.next(), Some("proc"))
        && segments.next().is_some_and(|s| s.parse::<u64>().is_ok())
        && matches!(segments.next(), Some("root"));
    if !is_proc_pid_root {
        return None;
    }

    Some(Alert {
        technique: "T1611",
        severity: Severity::High,
        message: format!(
            "pid={} comm={} container={}: opened {} — containerized process reaching \
             into another process's root filesystem via procfs, a common \
             container-escape path",
            event.meta.pid, event.meta.comm, container.id, event.path,
        ),
    })
}

/// T1574.006 — Hijack Execution Flow: Dynamic Linker Hijacking. `LD_PRELOAD` (and its
/// quieter `LD_AUDIT` sibling) force the dynamic linker to load an attacker-chosen
/// shared object into every dynamically linked exec that inherits the variable; a path
/// outside the linker's own trust set is exactly that shape. The trust set is the
/// built-in baseline ([`crate::ld_trust::LD_TRUST_PREFIXES`]) plus `extra_trust`, the
/// directories the host's `/etc/ld.so.conf` declares — seeded once at startup by
/// [`crate::RuleState::seed_ld_trust_from_system`], which is why this runs from
/// [`crate::RuleState::on_exec`] rather than [`evaluate_exec`](super::evaluate_exec).
/// A path already inside the trust set is standard operational use (some distros
/// ship a legitimate preload this way) and does not fire — no heuristics beyond the
/// trust set, same false-positive posture as `check_masquerading`.
///
/// Evidence-gated on [`ExecEvent::env_security`] actually carrying the variable
/// (#363): capture is a fixed allowlist, so this never scans the full environment for
/// names it doesn't already have — it only ever judges what the sensor chose to keep.
#[must_use]
pub(crate) fn check_ld_preload_hijack(event: &ExecEvent, extra_trust: &[String]) -> Option<Alert> {
    let (name, value) = event
        .env_security
        .iter()
        .find(|(name, _)| name.as_str() == "LD_PRELOAD" || name.as_str() == "LD_AUDIT")?;
    if crate::ld_trust::all_paths_trusted(value, extra_trust) {
        return None;
    }
    Some(Alert {
        technique: "T1574.006",
        severity: Severity::High,
        message: format!(
            "pid={} comm={}: {name}={value} loads a shared object outside the dynamic \
             linker's trusted search path",
            event.meta.pid, event.meta.comm,
        ),
    })
}
