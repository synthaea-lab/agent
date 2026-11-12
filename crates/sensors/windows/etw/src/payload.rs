//! How the user-mode providers' records become schema events, decided on the record's named
//! payload fields alone: which fields are read, what a missing field means, and when a record
//! carries nothing worth forwarding. The callbacks in `providers` only fetch the record, spend
//! budgets and emit; field notes per provider are in `docs/sensors/windows/etw.md#providers`.

use std::net::IpAddr;

use schema::{
    AssemblyLoadEvent, DnsQueryEvent, EventMeta, LdapSearchEvent, NtlmAuthEvent, NtlmDirection,
    RegistrySetEvent, ScriptBlockEvent, SmbConnectEvent, WmiActivityEvent,
};

use crate::normalize;

/// The named payload fields of one ETW record. A field that is absent, or does not have the
/// asked type, reads as `None`.
pub(crate) trait PayloadFields {
    fn text(&self, name: &str) -> Option<String>;
    fn u16(&self, name: &str) -> Option<u16>;
    fn u32(&self, name: &str) -> Option<u32>;
    fn bytes(&self, name: &str) -> Option<Vec<u8>>;

    /// The text of `name`, empty when the field is absent.
    fn text_or_empty(&self, name: &str) -> String {
        self.text(name).unwrap_or_default()
    }
}

#[cfg(windows)]
impl PayloadFields for ferrisetw::parser::Parser<'_, '_> {
    fn text(&self, name: &str) -> Option<String> {
        self.try_parse(name).ok()
    }

    fn u16(&self, name: &str) -> Option<u16> {
        self.try_parse(name).ok()
    }

    fn u32(&self, name: &str) -> Option<u32> {
        self.try_parse(name).ok()
    }

    fn bytes(&self, name: &str) -> Option<Vec<u8>> {
        self.try_parse(name).ok()
    }
}

/// `REG_SZ`: the registry value types whose data is UTF-16 text.
const REG_SZ: u32 = 1;
/// `REG_EXPAND_SZ`.
const REG_EXPAND_SZ: u32 = 2;
/// `AssemblyFlags` bit of an assembly loaded from memory rather than from a file.
const ASSEMBLY_FLAG_DYNAMIC: u32 = 0x2;
/// How the NTLM provider spells "no value".
const NTLM_ABSENT: [&str; 4] = ["", "-", "Null", "(NULL)"];

/// DNS-Client EID 3008 (`QueryCompleted`); `None` without a query name.
pub(crate) fn dns_query(fields: &impl PayloadFields, meta: EventMeta) -> Option<DnsQueryEvent> {
    let query = non_empty(fields.text_or_empty("QueryName"))?;
    Some(DnsQueryEvent {
        meta,
        query,
        qtype: u32::from(fields.u16("QueryType").unwrap_or(0)),
        result: non_empty(fields.text_or_empty("QueryResults")),
        results: Vec::new(),
        results_truncated: false,
        status: fields.u32("QueryStatus").unwrap_or(0),
    })
}

/// Kernel-Registry EID 5 (`SetValueKey`); `None` when the kernel did not resolve the key
/// name. Only string data is decoded: raw DWORD or binary bytes have no text form for rules.
/// `CapturedData` is the part of the value the kernel captured, so long data is a prefix.
pub(crate) fn registry_set(
    fields: &impl PayloadFields,
    meta: EventMeta,
) -> Option<RegistrySetEvent> {
    let raw_key = non_empty(fields.text_or_empty("KeyName"))?;
    let data_type = fields.u32("Type").unwrap_or(0);
    let data = match data_type {
        REG_SZ | REG_EXPAND_SZ => {
            decode_reg_string(&fields.bytes("CapturedData").unwrap_or_default())
        }
        _ => None,
    };
    Some(RegistrySetEvent {
        meta,
        key: normalize::normalize_registry_key(&raw_key),
        value_name: fields.text_or_empty("ValueName"),
        data_type,
        data,
    })
}

/// A `REG_SZ` / `REG_EXPAND_SZ` value: UTF-16 LE, trailing NULs dropped. `None` for an
/// empty or odd-length buffer.
fn decode_reg_string(bytes: &[u8]) -> Option<String> {
    let (units, rest) = bytes.as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    let units: Vec<u16> = units.iter().map(|unit| u16::from_le_bytes(*unit)).collect();
    non_empty(
        String::from_utf16_lossy(&units)
            .trim_end_matches('\0')
            .to_string(),
    )
}

/// PowerShell EID 4104 (`ScriptBlockLogging`), one fragment of a script block; `None`
/// without script text. A record missing its fragment numbers is a whole script (1 of 1).
pub(crate) fn script_block(
    fields: &impl PayloadFields,
    meta: EventMeta,
) -> Option<ScriptBlockEvent> {
    let text = non_empty(fields.text_or_empty("ScriptBlockText"))?;
    Some(ScriptBlockEvent {
        meta,
        script_block_id: fields.text_or_empty("ScriptBlockId"),
        path: non_empty(fields.text_or_empty("Path")),
        text,
        message_number: fields.u32("MessageNumber").unwrap_or(1),
        message_total: fields.u32("MessageTotal").unwrap_or(1),
    })
}

/// The two WMI-Activity operations the sensor forwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WmiOperation {
    /// EID 23: a WQL query.
    ExecQuery,
    /// EID 24: a method call, such as `Win32_Process.Create`.
    ExecMethod,
}

impl WmiOperation {
    /// Every id [`Self::from_id`] reads: the provider's event-id filter.
    pub(crate) const EVENT_IDS: [u16; 2] = [23, 24];

    pub(crate) fn from_id(event_id: u16) -> Option<Self> {
        match event_id {
            23 => Some(Self::ExecQuery),
            24 => Some(Self::ExecMethod),
            _ => None,
        }
    }
}

/// A WMI-Activity operation; `None` when it names neither a query nor a method. A method
/// reads `Class.Method`.
pub(crate) fn wmi_activity(
    operation: WmiOperation,
    fields: &impl PayloadFields,
    meta: EventMeta,
) -> Option<WmiActivityEvent> {
    let (query, method) = match operation {
        WmiOperation::ExecQuery => (Some(non_empty(fields.text_or_empty("Query"))?), None),
        WmiOperation::ExecMethod => (None, Some(wmi_method(fields)?)),
    };
    Some(WmiActivityEvent {
        meta,
        namespace: fields.text_or_empty("NamespaceName"),
        query,
        method,
    })
}

fn wmi_method(fields: &impl PayloadFields) -> Option<String> {
    let class = fields.text_or_empty("ObjectPath");
    let method = fields.text_or_empty("MethodName");
    (!class.is_empty() || !method.is_empty()).then(|| format!("{class}.{method}"))
}

/// `DotNETRuntime` EID 154 (`AssemblyLoad`); `None` for a file-backed assembly (high-volume
/// noise) or one without a name. Only in-memory loads mark execute-assembly and fileless
/// .NET injection.
pub(crate) fn assembly_load(
    fields: &impl PayloadFields,
    meta: EventMeta,
) -> Option<AssemblyLoadEvent> {
    let flags = fields.u32("AssemblyFlags").unwrap_or(0);
    if flags & ASSEMBLY_FLAG_DYNAMIC == 0 {
        return None;
    }
    Some(AssemblyLoadEvent {
        meta,
        assembly_name: non_empty(fields.text_or_empty("FullyQualifiedAssemblyName"))?,
        flags,
    })
}

/// `SMBClient` EID 30704 (connection established); `None` without a server name.
pub(crate) fn smb_connect(fields: &impl PayloadFields, meta: EventMeta) -> Option<SmbConnectEvent> {
    Some(SmbConnectEvent {
        meta,
        server_name: non_empty(fields.text_or_empty("ServerName"))?,
    })
}

/// The process of an LDAP-Client record: its `ProcessId` field, which the manifest promises,
/// else the record header's.
pub(crate) fn ldap_pid(fields: &impl PayloadFields, header_pid: u32) -> u32 {
    fields.u32("ProcessId").unwrap_or(header_pid)
}

/// LDAP-Client EID 30, a search request.
pub(crate) fn ldap_search(fields: &impl PayloadFields, meta: EventMeta) -> LdapSearchEvent {
    LdapSearchEvent {
        meta,
        filter: fields.text_or_empty("SearchFilter"),
        base_dn: fields.text_or_empty("DistinguishedName"),
        scope: fields.u32("ScopeOfSearch").unwrap_or(0),
        attributes: normalize::split_ldap_attributes(&fields.text_or_empty("AttributeList")),
    }
}

/// Every id [`ntlm_direction`] reads: the provider's event-id filter.
pub(crate) const NTLM_EVENT_IDS: [u16; 6] = [4020, 4021, 4022, 4023, 4026, 4027];

/// The direction of an NTLM record: 4020/4021/4026/4027 this host authenticated out,
/// 4022/4023 a client authenticated in.
pub(crate) fn ntlm_direction(event_id: u16) -> Option<NtlmDirection> {
    match event_id {
        4020 | 4021 | 4026 | 4027 => Some(NtlmDirection::Outgoing),
        4022 | 4023 => Some(NtlmDirection::Incoming),
        _ => None,
    }
}

/// The process of an NTLM record, else the record header's. `ProcessPID` is an integer the
/// event viewer displays in hex (`0x4`): read as an integer first, its text form as a
/// fallback (lab: a string-only parse fell back to the header pid, lsass).
pub(crate) fn ntlm_pid(fields: &impl PayloadFields, header_pid: u32) -> u32 {
    fields
        .u32("ProcessPID")
        .or_else(|| normalize::parse_ntlm_pid(&fields.text_or_empty("ProcessPID")))
        .unwrap_or(header_pid)
}

/// The process name an NTLM record carries, for a pid the sensor has not seen.
pub(crate) fn ntlm_process_name(fields: &impl PayloadFields) -> String {
    fields.text_or_empty("ProcessName")
}

/// An NTLM authentication. The target is the service (`cifs/127.0.0.1`), else the machine;
/// the remote address is the target's going out and the client's coming in; only an incoming
/// record has a status.
pub(crate) fn ntlm_auth(
    direction: NtlmDirection,
    fields: &impl PayloadFields,
    meta: EventMeta,
) -> NtlmAuthEvent {
    let service = fields.text_or_empty("TargetService");
    let target = if NTLM_ABSENT.contains(&service.trim()) {
        fields.text_or_empty("TargetMachine")
    } else {
        service
    };
    let (address_field, status) = match direction {
        NtlmDirection::Outgoing => ("TargetIP", None),
        NtlmDirection::Incoming => ("ClientIP", ntlm_status(fields)),
    };
    NtlmAuthEvent {
        meta,
        direction,
        user: normalize::ntlm_account(
            &fields.text_or_empty("Username"),
            &fields.text_or_empty("DomainName"),
        ),
        target,
        remote_address: fields
            .text_or_empty(address_field)
            .trim()
            .parse::<IpAddr>()
            .ok(),
        ntlm_version: fields.text_or_empty("NtlmVersion"),
        status,
    }
}

/// An incoming record's `Status` as `0x` + eight hex digits. Like `ProcessPID` it is an
/// integer displayed in hex; its text form is kept only when it is hex.
fn ntlm_status(fields: &impl PayloadFields) -> Option<String> {
    fields
        .u32("Status")
        .map(|status| format!("{status:#010x}"))
        .or_else(|| {
            fields
                .text("Status")
                .filter(|status| status.starts_with("0x"))
        })
}

fn non_empty(text: String) -> Option<String> {
    (!text.is_empty()).then_some(text)
}

#[cfg(test)]
mod tests;
