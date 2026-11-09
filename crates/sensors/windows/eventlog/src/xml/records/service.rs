//! System 7045: a service was installed.

use crate::xml::scan::extract_between;

/// Fields extracted from a 7045 ("A service was installed in the system") `<Event>`
/// block — System log, no audit prerequisite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceInstallEvent {
    pub record_id: u64,
    pub service_name: String,
    /// As passed to `CreateService()`/`sc create` — already a normal Windows path
    /// (possibly with trailing arguments), not an NT kernel device path. Do NOT run
    /// this through an NT-path normalizer (`sensor-windows::normalize_nt_path`):
    /// that function looks for the 3rd backslash to splice in a drive letter, which
    /// truncates an already-normal path like `C:\Users\...\payload.exe` into
    /// `C:\...\payload.exe` (bug found and fixed during the original investigation).
    pub image_path: String,
    /// PID that requested the service creation (e.g. `services.exe`, `sc.exe`).
    pub pid: u32,
}

/// Parses one 7045 `<Event>` block. `None` if the block is missing a required field
/// (a genuinely different event matched the `XPath` filter, or a `wevtutil` output
/// shape change — treated the same way: skip rather than guess).
#[must_use]
pub fn parse_service_install_block(block: &str) -> Option<ServiceInstallEvent> {
    let record_id = extract_between(block, "<EventRecordID>", "</EventRecordID>")?
        .parse()
        .ok()?;
    let service_name = extract_between(block, "<Data Name='ServiceName'>", "</Data>")
        .unwrap_or_default()
        .to_string();
    let image_path = extract_between(block, "<Data Name='ImagePath'>", "</Data>")
        .unwrap_or_default()
        .trim()
        .to_string();
    let pid = extract_between(block, "ProcessID='", "'")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Some(ServiceInstallEvent {
        record_id,
        service_name,
        image_path,
        pid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::{fixtures::SERVICE_INSTALL_XML, scan::split_event_blocks};

    #[test]
    fn parses_a_real_shaped_service_install_block() {
        let block = split_event_blocks(SERVICE_INSTALL_XML)[0];
        let parsed = parse_service_install_block(block).expect("should parse");
        assert_eq!(parsed.record_id, 42);
        assert_eq!(parsed.service_name, "evilsvc");
        // trim() must strip the trailing space wevtutil sometimes emits.
        assert_eq!(
            parsed.image_path,
            r"C:\Users\victim\AppData\Roaming\payload.exe"
        );
        assert_eq!(parsed.pid, 956);
    }

    #[test]
    fn service_install_block_missing_record_id_does_not_parse() {
        let block = "<Event><EventData><Data Name='ServiceName'>x</Data></EventData></Event>";
        assert!(parse_service_install_block(block).is_none());
    }
}
