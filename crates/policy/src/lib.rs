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
}
