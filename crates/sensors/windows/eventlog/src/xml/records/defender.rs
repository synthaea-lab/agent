//! Microsoft Defender Antivirus Operational events.

use crate::xml::scan::{data_field, data_u32, extract_between};

/// Fields of one Microsoft Defender Antivirus Operational event (#283):
/// 1116/1117 (detection, action taken), 5001/5010/5012 (protection turned
/// off), 5007 (a setting changed). Which fields are present depends on the
/// event id; the others stay `None`.
///
/// The channel is **localized** (a French host writes `Severity Name` as
/// "Élevée", `Action Name` as "Supprimer"): only the numeric ids and the
/// untranslated `Threat Name` / `Path` are read, never the `* Name` texts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefenderLogEvent {
    pub record_id: u64,
    pub event_id: u32,
    /// `Detection ID`: the GUID a 1116 and its 1117 share.
    pub detection_id: Option<String>,
    pub threat_name: Option<String>,
    pub severity_id: Option<u32>,
    pub category_id: Option<u32>,
    pub action_id: Option<u32>,
    /// `Path`: the resource as Defender writes it (`file:_C:\x.exe`,
    /// `CmdLine:_...`). Not cut here.
    pub path: Option<String>,
    /// `Process Name`, without Defender's literal `Unknown` placeholder.
    pub process_name: Option<String>,
    pub detection_user: Option<String>,
    /// 5007 only: `<registry value path> = <data>` before and after.
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

/// Parses one Defender Operational `<Event>` block. `None` without an
/// `EventRecordID`, same convention as the other parsers here.
#[must_use]
pub fn parse_defender_event(block: &str) -> Option<DefenderLogEvent> {
    let record_id = extract_between(block, "<EventRecordID>", "</EventRecordID>")?
        .parse()
        .ok()?;
    let event_id = extract_between(block, "<EventID>", "</EventID>")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    Some(DefenderLogEvent {
        record_id,
        event_id,
        detection_id: data_field(block, "Detection ID"),
        threat_name: data_field(block, "Threat Name"),
        severity_id: data_u32(block, "Severity ID"),
        category_id: data_u32(block, "Category ID"),
        action_id: data_u32(block, "Action ID"),
        path: data_field(block, "Path"),
        process_name: data_field(block, "Process Name").filter(|p| p != "Unknown"),
        detection_user: data_field(block, "Detection User"),
        old_value: data_field(block, "Old Value"),
        new_value: data_field(block, "New Value"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::scan::split_event_blocks;

    /// Shape of a real 1117 captured on a French Windows 11 host (names kept
    /// localized on purpose; account and path replaced): the numeric ids and
    /// `Threat Name` are what the parser may rely on.
    const DEFENDER_1117_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Windows Defender' Guid='{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}'/><EventID>1117</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-10-01T14:38:47.6936386Z'/><EventRecordID>7272</EventRecordID><Correlation/><Execution ProcessID='6164' ThreadID='3192'/><Channel>Microsoft-Windows-Windows Defender/Operational</Channel><Computer>LabPC</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='Product Name'>Antivirus Microsoft Defender</Data><Data Name='Product Version'>4.18.26080.4</Data><Data Name='Detection ID'>{3F813A68-3FA3-456D-8818-54AB191C87B3}</Data><Data Name='Detection Time'>2026-10-01T14:37:46.365Z</Data><Data Name='Unused'></Data><Data Name='Unused2'></Data><Data Name='Threat ID'>2147741009</Data><Data Name='Threat Name'>HackTool:Win32/Mimikatz.I</Data><Data Name='Severity ID'>4</Data><Data Name='Severity Name'>Élevée</Data><Data Name='Category ID'>34</Data><Data Name='Category Name'>Outil</Data><Data Name='FWLink'>https://go.microsoft.com/fwlink/?linkid=37020&amp;name=HackTool:Win32/Mimikatz.I&amp;threatid=2147741009&amp;enterprise=0</Data><Data Name='Status Code'>4</Data><Data Name='Status Description'></Data><Data Name='State'>2</Data><Data Name='Source ID'>2</Data><Data Name='Source Name'>Système</Data><Data Name='Process Name'>Unknown</Data><Data Name='Detection User'>LAB\alice</Data><Data Name='Unused3'></Data><Data Name='Path'>file:_C:\Users\Public\a&amp;b.exe</Data><Data Name='Origin ID'>0</Data><Data Name='Origin Name'>Inconnu</Data><Data Name='Execution ID'>0</Data><Data Name='Execution Name'>Inconnu</Data><Data Name='Type ID'>0</Data><Data Name='Type Name'>Concret</Data><Data Name='Pre Execution Status'>0</Data><Data Name='Action ID'>3</Data><Data Name='Action Name'>Supprimer</Data><Data Name='Unused4'></Data><Data Name='Error Code'>0x00000000</Data><Data Name='Error Description'>L’opération a réussi. </Data></EventData></Event>"#;

    #[test]
    fn parses_a_real_shaped_localized_defender_1117() {
        let parsed = parse_defender_event(split_event_blocks(DEFENDER_1117_XML)[0]).unwrap();
        assert_eq!(parsed.record_id, 7272);
        assert_eq!(parsed.event_id, 1117);
        assert_eq!(
            parsed.detection_id.as_deref(),
            Some("{3F813A68-3FA3-456D-8818-54AB191C87B3}")
        );
        assert_eq!(
            parsed.threat_name.as_deref(),
            Some("HackTool:Win32/Mimikatz.I")
        );
        assert_eq!(
            (parsed.severity_id, parsed.category_id, parsed.action_id),
            (Some(4), Some(34), Some(3))
        );
        assert_eq!(
            parsed.path.as_deref(),
            Some(r"file:_C:\Users\Public\a&b.exe")
        );
        assert_eq!(parsed.detection_user.as_deref(), Some(r"LAB\alice"));
        assert_eq!(
            parsed.process_name, None,
            "Defender's `Unknown` is no process"
        );
        assert_eq!((parsed.old_value, parsed.new_value), (None, None));
    }

    #[test]
    fn parses_defender_5007_values_and_skips_empty_ones() {
        let xml = "<Event xmlns='x'><System><EventID>5007</EventID><EventRecordID>9001</EventRecordID></System><EventData><Data Name='Product Name'>Antivirus Microsoft Defender</Data><Data Name='Old Value'></Data><Data Name='New Value'>HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\Users\\Public = 0x0</Data></EventData></Event>";
        let parsed = parse_defender_event(split_event_blocks(xml)[0]).unwrap();
        assert_eq!(parsed.event_id, 5007);
        assert_eq!(parsed.old_value, None);
        assert_eq!(
            parsed.new_value.as_deref(),
            Some(
                r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\Public = 0x0"
            )
        );
    }

    #[test]
    fn defender_block_missing_record_id_does_not_parse() {
        assert!(parse_defender_event("<Event><EventData></EventData></Event>").is_none());
    }
}
