//! # policy
//!
//! The policy model: which rules and models are active, which response actions are
//! permitted, thresholds, per-host overrides. Policies are versioned and signed;
//! distributed by the control plane, enforced by the agent — this crate holds the
//! shared types and evaluation logic so both sides agree by construction.

/// Directories only privileged installers write to — the gate for name-keyed
/// detection exclusions. An exclusion list of process NAMES (`svchost.exe`,
/// `chrome.exe`, …) is a trivial bypass on its own: a payload renamed to a
/// name on the list inherits the exclusion. Requiring the image to actually
/// live in a trusted system location closes the rename-in-%TEMP% masquerade.
///
/// Path trust is a heuristic, not identity — the durable answer is signature
/// and expected-parent verification (tracked as a dedicated issue). Writable
/// subtrees of C:\Windows (Temp, Tasks, tracing) are explicitly untrusted.
#[must_use]
pub fn is_trusted_system_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    // Windows drive-letter grammar.
    if lower.as_bytes().get(1) == Some(&b':') {
        let rest = lower[2..].replace('/', "\\");
        if rest.starts_with("\\windows\\") {
            return !(rest.starts_with("\\windows\\temp\\")
                || rest.starts_with("\\windows\\tasks\\")
                || rest.starts_with("\\windows\\tracing\\"));
        }
        return rest.starts_with("\\program files\\")
            || rest.starts_with("\\program files (x86)\\");
    }
    // Unix/macOS grammar: root-owned system prefixes.
    [
        "/usr/",
        "/bin/",
        "/sbin/",
        "/lib/",
        "/opt/",
        "/system/",
        "/applications/",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
}

/// Whether a name-keyed exclusion may apply, given the image path the sensor
/// reported. An unknown or empty path keeps the exclusion (a sensor limitation
/// is not evidence of masquerade); a known path must be trusted.
#[must_use]
pub fn name_exclusion_applies(image_path: Option<&str>) -> bool {
    match image_path {
        None | Some("") => true,
        Some(path) => is_trusted_system_path(path),
    }
}

/// Expected parent processes for commonly-impersonated Windows system processes.
///
/// Returns the allowed parent `comm` values (basename, case-insensitive) for a
/// given process name. An empty slice means "no expectation — any parent is
/// acceptable" (e.g. user-space apps, or processes with legitimately variable
/// parents). Source: Windows process-tree documented in Microsoft documentation +
/// lab observations.
///
/// Note: the `System` pseudo-process (pid=4) is the implicit parent of `smss.exe`
/// at boot — represented here as `"system"`.
#[must_use]
pub fn expected_parents(comm: &str) -> &'static [&'static str] {
    let name = comm.rsplit('\\').next().unwrap_or(comm);
    match name.to_ascii_lowercase().as_str() {
        // Session Manager → spawned by System at boot only.
        "smss.exe" => &["system"],
        // Client/Server Runtime → spawned by smss.exe.
        "csrss.exe" => &["smss.exe"],
        // Windows Initialization → spawned by smss.exe.
        "wininit.exe" => &["smss.exe"],
        // Windows Logon → spawned by smss.exe (one per session).
        "winlogon.exe" => &["smss.exe"],
        // Service Control Manager and its children.
        "services.exe" => &["wininit.exe"],
        // svchost is exclusively spawned by services.exe (or services.exe via
        // svchost groups — but the direct parent is always services.exe).
        "svchost.exe" => &["services.exe"],
        // Task Host and Task Host Worker.
        "taskhostw.exe" | "taskhost.exe" => &["services.exe", "svchost.exe"],
        // Print Spooler.
        "spoolsv.exe" => &["services.exe"],
        // Local Security Authority Subsystem — spawned by wininit.exe.
        // Key detection value: lsass.exe spawned from anywhere else = credential-theft
        // (T1003, mimikatz injection) — never benign.
        "lsass.exe" => &["wininit.exe"],
        // User Initialization — spawned by winlogon.exe on interactive logon.
        "userinit.exe" => &["winlogon.exe"],
        // Explorer — spawned by userinit.exe (which then exits, leaving explorer
        // as a child of the session's logon process).
        "explorer.exe" => &["userinit.exe"],
        // All other processes: no parent expectation (user apps, services with
        // variable parents, Linux comms).
        _ => &[],
    }
}

/// Whether a parent-keyed exclusion applies, given the process `comm` and its
/// parent `comm` as reported by the sensor.
///
/// Rules:
/// - If `comm` has no parent expectation (`expected_parents` is empty): apply
///   the exclusion regardless of parent.
/// - If the parent is unknown/empty (sensor limitation, ETW race): keep the
///   exclusion — a missing parent is not evidence of masquerade.
/// - Otherwise: the parent's basename must appear in `expected_parents(comm)`.
///
/// Used alongside [`name_exclusion_applies`]: both must return `true` for an
/// exclusion to hold. Either failing alone is enough to trigger the masquerade
/// flag.
#[must_use]
pub fn parent_exclusion_applies(comm: &str, parent_comm: Option<&str>) -> bool {
    let expected = expected_parents(comm);
    if expected.is_empty() {
        return true;
    }
    match parent_comm {
        None | Some("") => true, // sensor limitation — not evidence of masquerade
        Some(parent) => {
            let parent_name = parent.rsplit('\\').next().unwrap_or(parent);
            expected
                .iter()
                .any(|&e| e.eq_ignore_ascii_case(parent_name))
        }
    }
}

/// Per-channel-group enablement for `sensor-windows-eventlog` — #94's
/// "policy-configurable channel allowlist". `sensor-*` crates may depend only
/// on `schema` (`tools/check-deps.py`), so this type cannot be read by the
/// sensor directly: the `agent` binary (unrestricted deps) reads it here and
/// converts it into the sensor's own `EventLogConfig` at construction time
/// (`agent/src/commands/windows.rs`). See
/// `docs/adr/0006-eventlog-channel-allowlist-and-volume-counters.md`.
///
/// The first struct this crate has ever held (previously pure functions
/// only) — deliberately without a `serde` derive: there is no policy-loading
/// or distribution mechanism anywhere in this workspace yet (`config` covers
/// only local, per-install settings — see its crate doc), so today this is a
/// plain in-code default, not yet the "versioned and signed" document this
/// crate's top-level doc describes. Add serialization when that mechanism
/// exists, rather than speculatively now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventLogPolicy {
    /// Event 7045 (T1543.003 — service install persistence).
    pub service_installs_enabled: bool,
    /// Event 4698 (T1053.005 — scheduled task persistence).
    pub scheduled_tasks_enabled: bool,
    /// Events 4624/4625/4648/4672 (logon/session, #94).
    pub logon_events_enabled: bool,
}

impl Default for EventLogPolicy {
    /// Every channel group enabled — matches `sensor-windows-eventlog`'s
    /// behavior before this policy existed.
    fn default() -> Self {
        Self {
            service_installs_enabled: true,
            scheduled_tasks_enabled: true,
            logon_events_enabled: true,
        }
    }
}

#[cfg(test)]
mod eventlog_policy_tests {
    use super::EventLogPolicy;

    #[test]
    fn default_enables_every_channel_group() {
        let policy = EventLogPolicy::default();
        assert!(policy.service_installs_enabled);
        assert!(policy.scheduled_tasks_enabled);
        assert!(policy.logon_events_enabled);
    }
}

#[cfg(test)]
mod exclusion_tests {
    use super::*;

    #[test]
    fn system_locations_are_trusted() {
        assert!(is_trusted_system_path("C:\\Windows\\System32\\svchost.exe"));
        assert!(is_trusted_system_path(
            "C:\\Program Files\\Google\\Chrome\\chrome.exe"
        ));
        assert!(is_trusted_system_path("/usr/bin/curl"));
    }

    #[test]
    fn masquerade_locations_are_not() {
        assert!(!is_trusted_system_path(
            "C:\\Users\\bob\\Downloads\\svchost.exe"
        ));
        assert!(!is_trusted_system_path("C:\\Windows\\Temp\\chrome.exe"));
        assert!(!is_trusted_system_path("/tmp/svchost.exe"));
        assert!(!is_trusted_system_path("/home/bob/chrome"));
    }

    #[test]
    fn unknown_path_keeps_the_exclusion() {
        assert!(name_exclusion_applies(None));
        assert!(name_exclusion_applies(Some("")));
        assert!(!name_exclusion_applies(Some("/tmp/svchost.exe")));
    }

    // ── parent_exclusion_applies ──────────────────────────────────────────

    #[test]
    fn svchost_from_services_is_legitimate() {
        assert!(parent_exclusion_applies(
            "svchost.exe",
            Some("services.exe")
        ));
    }

    #[test]
    fn svchost_from_cmd_is_masquerade() {
        assert!(!parent_exclusion_applies("svchost.exe", Some("cmd.exe")));
    }

    #[test]
    fn svchost_from_powershell_is_masquerade() {
        assert!(!parent_exclusion_applies(
            "svchost.exe",
            Some("powershell.exe")
        ));
    }

    #[test]
    fn lsass_from_wininit_is_legitimate() {
        assert!(parent_exclusion_applies("lsass.exe", Some("wininit.exe")));
    }

    #[test]
    fn lsass_from_cmd_is_masquerade() {
        // Classic mimikatz / credential-theft injection scenario.
        assert!(!parent_exclusion_applies("lsass.exe", Some("cmd.exe")));
    }

    #[test]
    fn unknown_parent_keeps_exclusion() {
        // Sensor limitation (ETW race) — not evidence of masquerade.
        assert!(parent_exclusion_applies("svchost.exe", None));
        assert!(parent_exclusion_applies("svchost.exe", Some("")));
    }

    #[test]
    fn process_with_no_expectation_allows_any_parent() {
        // chrome.exe can be spawned by explorer, another chrome, etc.
        assert!(parent_exclusion_applies("chrome.exe", Some("cmd.exe")));
        assert!(parent_exclusion_applies("chrome.exe", None));
    }

    #[test]
    fn parent_check_is_case_insensitive() {
        assert!(parent_exclusion_applies(
            "SVCHOST.EXE",
            Some("SERVICES.EXE")
        ));
        assert!(!parent_exclusion_applies("svchost.exe", Some("CMD.EXE")));
    }

    #[test]
    fn full_path_in_parent_comm_is_handled() {
        // ETW sometimes reports the full path rather than the basename.
        assert!(parent_exclusion_applies(
            "svchost.exe",
            Some("C:\\Windows\\System32\\services.exe")
        ));
    }
}
