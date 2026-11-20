//! The systemd unit a signal's sender runs in (#322), for `SignalEvent::sender_unit`.
//!
//! Read from `/proc/<pid>/cgroup` when the event is drained, the same answer systemd gives to
//! "which unit is this process in", so the agent's own watchdog (same unit as the agent) is told
//! from an intruder. A sender that exited before the drain has no `/proc` entry and gets `None`,
//! which keeps the alert at its default severity: the unit can only lower it, never hide it.

use std::{fs, path::Path};

/// The unit of `pid` under `proc_root` (`/proc` on a real host), lowercase with no `.service`;
/// `None` when the process is gone or is not in a service.
pub(crate) fn unit_of_pid(proc_root: &Path, pid: u32) -> Option<String> {
    let cgroups = fs::read_to_string(proc_root.join(pid.to_string()).join("cgroup")).ok()?;
    unit_in_cgroups(&cgroups)
}

/// The service in a `/proc/<pid>/cgroup` listing, from the cgroup v2 line (`0::<path>`) or the v1
/// `name=systemd` line. A hybrid host has both, and there the v2 line is often just `/`, so the
/// first of the two that names a service wins.
fn unit_in_cgroups(cgroups: &str) -> Option<String> {
    cgroups
        .lines()
        .filter_map(systemd_path)
        .find_map(service_in_path)
}

/// The path of a v2 (`0::`) or v1 `name=systemd` line; `None` for any other controller.
fn systemd_path(line: &str) -> Option<&str> {
    let mut fields = line.splitn(3, ':');
    let (_, controllers, path) = (fields.next()?, fields.next()?, fields.next()?);
    matches!(controllers, "" | "name=systemd").then_some(path)
}

/// The first `.service` component of a cgroup path: services do not nest, only slices do, and
/// what lies below a service is its own sub-cgroups.
fn service_in_path(path: &str) -> Option<String> {
    path.split('/')
        .find_map(|component| component.strip_suffix(".service"))
        .filter(|unit| !unit.is_empty())
        .map(str::to_ascii_lowercase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_process_of_a_system_service_is_in_that_unit() {
        let cgroups = "0::/system.slice/synthaea-agent.service\n";
        assert_eq!(unit_in_cgroups(cgroups).as_deref(), Some("synthaea-agent"));
    }

    #[test]
    fn a_sub_cgroup_of_a_service_still_names_the_service() {
        let cgroups = "0::/system.slice/synthaea-agent.service/watchdog\n";
        assert_eq!(unit_in_cgroups(cgroups).as_deref(), Some("synthaea-agent"));
    }

    #[test]
    fn a_hybrid_host_is_read_from_its_systemd_hierarchy() {
        let cgroups = "12:memory:/system.slice/other.service\n\
                       1:name=systemd:/system.slice/auditd.service\n\
                       0::/\n";
        assert_eq!(unit_in_cgroups(cgroups).as_deref(), Some("auditd"));
    }

    #[test]
    fn a_process_outside_any_service_has_no_unit() {
        for cgroups in [
            "0::/user.slice/user-1000.slice/session-3.scope\n",
            "0::/\n",
            "0::/system.slice/.service\n",
            "",
            "garbage",
        ] {
            assert_eq!(unit_in_cgroups(cgroups), None, "{cgroups:?}");
        }
    }

    #[test]
    fn a_user_service_is_named_by_the_first_service_on_its_path() {
        let cgroups = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/foo.service\n";
        assert_eq!(unit_in_cgroups(cgroups).as_deref(), Some("user@1000"));
    }

    #[test]
    fn a_pid_with_no_proc_entry_has_no_unit() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(unit_of_pid(root.path(), 4242), None);
    }

    #[test]
    fn the_unit_is_read_from_the_pids_cgroup_file() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("4242")).unwrap();
        std::fs::write(
            root.path().join("4242/cgroup"),
            "0::/system.slice/synthaea-agent.service\n",
        )
        .unwrap();
        assert_eq!(
            unit_of_pid(root.path(), 4242).as_deref(),
            Some(schema::AGENT_UNIT)
        );
    }
}
