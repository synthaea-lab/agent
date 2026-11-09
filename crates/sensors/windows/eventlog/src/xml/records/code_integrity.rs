//! `CodeIntegrity` (WDAC) 3076/3077 verdicts.

use crate::xml::scan::{data_field, data_u32, extract_between};

/// Fields of one `Microsoft-Windows-CodeIntegrity/Operational` 3076/3077 event
/// (WDAC audit / enforced verdict, #283).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeIntegrityEvent {
    pub record_id: u64,
    pub event_id: u32,
    /// `File Name`: the image that failed the policy, as an **NT device path**
    /// (`\Device\HarddiskVolume3\...`), not a drive-letter path.
    pub file_name: Option<String>,
    /// `Process Name`: the process that tried to load it, also an NT path.
    pub process_name: Option<String>,
    /// `SI Signing Scenario`: 0 kernel mode, 1 user mode.
    pub signing_scenario: Option<u32>,
}

/// Parses one 3076/3077 `<Event>` block. `None` without an `EventRecordID`.
#[must_use]
pub fn parse_code_integrity_event(block: &str) -> Option<CodeIntegrityEvent> {
    let record_id = extract_between(block, "<EventRecordID>", "</EventRecordID>")?
        .parse()
        .ok()?;
    let event_id = extract_between(block, "<EventID>", "</EventID>")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    Some(CodeIntegrityEvent {
        record_id,
        event_id,
        file_name: data_field(block, "File Name"),
        process_name: data_field(block, "Process Name"),
        signing_scenario: data_u32(block, "SI Signing Scenario"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::scan::split_event_blocks;

    #[test]
    fn parses_a_wdac_enforced_block() {
        let xml = "<Event xmlns='x'><System><EventID>3077</EventID><EventRecordID>77</EventRecordID></System><EventData><Data Name='FileNameLength'>66</Data><Data Name='File Name'>\\Device\\HarddiskVolume3\\Users\\Public\\x.dll</Data><Data Name='ProcessNameLength'>74</Data><Data Name='Process Name'>\\Device\\HarddiskVolume3\\Windows\\System32\\rundll32.exe</Data><Data Name='Requested Signing Level'>8</Data><Data Name='Validated Signing Level'>1</Data><Data Name='Status'>0xC0E90002</Data><Data Name='SI Signing Scenario'>1</Data></EventData></Event>";
        let parsed = parse_code_integrity_event(split_event_blocks(xml)[0]).unwrap();
        assert_eq!((parsed.record_id, parsed.event_id), (77, 3077));
        assert_eq!(
            parsed.file_name.as_deref(),
            Some(r"\Device\HarddiskVolume3\Users\Public\x.dll")
        );
        assert_eq!(
            parsed.process_name.as_deref(),
            Some(r"\Device\HarddiskVolume3\Windows\System32\rundll32.exe")
        );
        assert_eq!(parsed.signing_scenario, Some(1));
    }

    #[test]
    fn wdac_block_without_fields_still_parses_with_nones() {
        let xml = "<Event xmlns='x'><System><EventID>3076</EventID><EventRecordID>5</EventRecordID></System><EventData></EventData></Event>";
        let parsed = parse_code_integrity_event(split_event_blocks(xml)[0]).unwrap();
        assert_eq!(parsed.file_name, None);
        assert_eq!(parsed.signing_scenario, None);
    }
}
