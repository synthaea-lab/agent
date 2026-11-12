use std::collections::HashMap;

use proptest::prelude::*;
use schema::{EventMeta, NtlmDirection, fixtures};

use super::*;

/// A field value with its ETW type: reading it as another type gives `None`, as `Parser`'s
/// size check does.
#[derive(Debug, Clone)]
enum Value {
    Text(String),
    U16(u16),
    U32(u32),
    Bytes(Vec<u8>),
}

#[derive(Debug, Default)]
struct Fields(HashMap<&'static str, Value>);

impl Fields {
    fn of(fields: &[(&'static str, Value)]) -> Self {
        Self(fields.iter().cloned().collect())
    }
}

impl PayloadFields for Fields {
    fn text(&self, name: &str) -> Option<String> {
        match self.0.get(name)? {
            Value::Text(text) => Some(text.clone()),
            _ => None,
        }
    }

    fn u16(&self, name: &str) -> Option<u16> {
        match self.0.get(name)? {
            Value::U16(value) => Some(*value),
            _ => None,
        }
    }

    fn u32(&self, name: &str) -> Option<u32> {
        match self.0.get(name)? {
            Value::U32(value) => Some(*value),
            _ => None,
        }
    }

    fn bytes(&self, name: &str) -> Option<Vec<u8>> {
        match self.0.get(name)? {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        }
    }
}

fn text_value(text: &str) -> Value {
    Value::Text(text.to_string())
}

fn meta() -> EventMeta {
    fixtures::meta()
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

mod dns {
    use super::*;

    #[test]
    fn a_completed_query_carries_its_name_type_answer_and_status() {
        let fields = Fields::of(&[
            ("QueryName", text_value("example.org")),
            ("QueryType", Value::U16(28)),
            ("QueryResults", text_value("::1;")),
            ("QueryStatus", Value::U32(0)),
        ]);

        let event = dns_query(&fields, meta()).expect("named query");

        assert_eq!(event.query, "example.org");
        assert_eq!(event.qtype, 28);
        assert_eq!(event.result.as_deref(), Some("::1;"));
        assert_eq!(event.status, 0);
    }

    #[test]
    fn a_negative_answer_has_no_result_and_keeps_its_status() {
        let fields = Fields::of(&[
            ("QueryName", text_value("nx.example.org")),
            ("QueryResults", text_value("")),
            ("QueryStatus", Value::U32(9003)),
        ]);

        let event = dns_query(&fields, meta()).expect("named query");

        assert_eq!(event.result, None);
        assert_eq!(event.status, 9003);
    }

    #[test]
    fn a_query_without_type_or_status_reads_as_type_0_and_success() {
        let fields = Fields::of(&[("QueryName", text_value("example.org"))]);

        let event = dns_query(&fields, meta()).expect("named query");

        assert_eq!((event.qtype, event.status), (0, 0));
    }

    #[test]
    fn a_record_without_a_query_name_is_dropped() {
        assert!(dns_query(&Fields::default(), meta()).is_none());
        let empty = Fields::of(&[("QueryName", text_value(""))]);
        assert!(dns_query(&empty, meta()).is_none());
    }
}

mod registry {
    use super::*;

    fn set_value(data_type: u32, data: Vec<u8>) -> Fields {
        Fields::of(&[
            (
                "KeyName",
                text_value(r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            ),
            ("ValueName", text_value("updater")),
            ("DataType", Value::U32(data_type)),
            ("Data", Value::Bytes(data)),
        ])
    }

    #[test]
    fn a_string_value_is_decoded_under_its_win32_key() {
        let fields = set_value(REG_SZ, utf16("C:\\evil.exe\0"));

        let event = registry_set(&fields, meta()).expect("named key");

        assert_eq!(
            event.key,
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        );
        assert_eq!(event.value_name, "updater");
        assert_eq!(event.data_type, REG_SZ);
        assert_eq!(event.data.as_deref(), Some("C:\\evil.exe"));
    }

    #[test]
    fn an_expandable_string_value_is_decoded() {
        let fields = set_value(REG_EXPAND_SZ, utf16("%TEMP%\\a.exe"));

        let event = registry_set(&fields, meta()).expect("named key");

        assert_eq!(event.data.as_deref(), Some("%TEMP%\\a.exe"));
    }

    #[test]
    fn a_binary_or_dword_value_has_no_text() {
        const REG_DWORD: u32 = 4;
        let event =
            registry_set(&set_value(REG_DWORD, vec![1, 0, 0, 0]), meta()).expect("named key");

        assert_eq!(event.data_type, REG_DWORD);
        assert_eq!(event.data, None);
    }

    #[test]
    fn odd_length_or_all_nul_string_data_has_no_text() {
        let odd = registry_set(&set_value(REG_SZ, vec![b'a', 0, b'b']), meta());
        let nul = registry_set(&set_value(REG_SZ, vec![0, 0, 0, 0]), meta());

        assert_eq!(odd.expect("named key").data, None);
        assert_eq!(nul.expect("named key").data, None);
    }

    #[test]
    fn a_record_whose_key_was_not_resolved_is_dropped() {
        assert!(registry_set(&Fields::default(), meta()).is_none());
    }
}

mod powershell {
    use super::*;

    #[test]
    fn a_fragment_carries_its_block_id_path_and_position() {
        let fields = Fields::of(&[
            ("ScriptBlockText", text_value("Invoke-Mimikatz")),
            ("ScriptBlockId", text_value("7f1c...")),
            ("Path", text_value(r"C:\t\a.ps1")),
            ("MessageNumber", Value::U32(2)),
            ("MessageTotal", Value::U32(3)),
        ]);

        let event = script_block(&fields, meta()).expect("script text");

        assert_eq!(event.text, "Invoke-Mimikatz");
        assert_eq!(event.script_block_id, "7f1c...");
        assert_eq!(event.path.as_deref(), Some(r"C:\t\a.ps1"));
        assert_eq!((event.message_number, event.message_total), (2, 3));
    }

    #[test]
    fn an_interactive_block_without_fragment_numbers_is_one_whole_script() {
        let fields = Fields::of(&[
            ("ScriptBlockText", text_value("whoami")),
            ("Path", text_value("")),
        ]);

        let event = script_block(&fields, meta()).expect("script text");

        assert_eq!(event.path, None);
        assert_eq!((event.message_number, event.message_total), (1, 1));
    }

    #[test]
    fn a_block_without_text_is_dropped() {
        assert!(script_block(&Fields::default(), meta()).is_none());
    }
}

mod wmi {
    use super::*;

    #[test]
    fn only_exec_query_and_exec_method_are_read() {
        assert_eq!(WmiOperation::from_id(23), Some(WmiOperation::ExecQuery));
        assert_eq!(WmiOperation::from_id(24), Some(WmiOperation::ExecMethod));
        assert_eq!(WmiOperation::from_id(11), None);
        assert_eq!(WmiOperation::from_id(22), None);
        assert_eq!(WmiOperation::from_id(25), None);
    }

    #[test]
    fn a_query_carries_its_namespace_and_wql() {
        let fields = Fields::of(&[
            ("NamespaceName", text_value(r"root\cimv2")),
            ("Query", text_value("SELECT * FROM AntiVirusProduct")),
        ]);

        let event = wmi_activity(WmiOperation::ExecQuery, &fields, meta()).expect("query");

        assert_eq!(event.namespace, r"root\cimv2");
        assert_eq!(
            event.query.as_deref(),
            Some("SELECT * FROM AntiVirusProduct")
        );
        assert_eq!(event.method, None);
    }

    #[test]
    fn a_method_call_reads_class_dot_method() {
        let fields = Fields::of(&[
            ("ObjectPath", text_value("Win32_Process")),
            ("MethodName", text_value("Create")),
        ]);

        let event = wmi_activity(WmiOperation::ExecMethod, &fields, meta()).expect("method");

        assert_eq!(event.method.as_deref(), Some("Win32_Process.Create"));
        assert_eq!(event.query, None);
    }

    #[test]
    fn a_method_call_naming_only_its_class_or_only_its_method_is_kept() {
        let class_only = Fields::of(&[("ObjectPath", text_value("Win32_Process"))]);
        let method_only = Fields::of(&[("MethodName", text_value("Create"))]);

        let class = wmi_activity(WmiOperation::ExecMethod, &class_only, meta());
        let method = wmi_activity(WmiOperation::ExecMethod, &method_only, meta());

        assert_eq!(
            class.and_then(|event| event.method).as_deref(),
            Some("Win32_Process.")
        );
        assert_eq!(
            method.and_then(|event| event.method).as_deref(),
            Some(".Create")
        );
    }

    #[test]
    fn an_operation_naming_neither_query_nor_method_is_dropped() {
        assert!(wmi_activity(WmiOperation::ExecQuery, &Fields::default(), meta()).is_none());
        assert!(wmi_activity(WmiOperation::ExecMethod, &Fields::default(), meta()).is_none());
    }
}

mod dotnet {
    use super::*;

    #[test]
    fn an_in_memory_assembly_is_forwarded_with_its_name_and_flags() {
        let fields = Fields::of(&[
            ("AssemblyFlags", Value::U32(ASSEMBLY_FLAG_DYNAMIC | 0x1)),
            (
                "FullyQualifiedAssemblyName",
                text_value("Seatbelt, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null"),
            ),
        ]);

        let event = assembly_load(&fields, meta()).expect("dynamic assembly");

        assert!(event.assembly_name.starts_with("Seatbelt,"));
        assert_eq!(event.flags, ASSEMBLY_FLAG_DYNAMIC | 0x1);
    }

    #[test]
    fn a_file_backed_assembly_is_dropped() {
        let fields = Fields::of(&[
            ("AssemblyFlags", Value::U32(0x1)),
            ("FullyQualifiedAssemblyName", text_value("System.Core")),
        ]);

        assert!(assembly_load(&fields, meta()).is_none());
    }

    #[test]
    fn an_in_memory_assembly_without_a_name_is_dropped() {
        let fields = Fields::of(&[("AssemblyFlags", Value::U32(ASSEMBLY_FLAG_DYNAMIC))]);

        assert!(assembly_load(&fields, meta()).is_none());
    }
}

mod smb {
    use super::*;

    #[test]
    fn a_connection_carries_its_server_name() {
        let fields = Fields::of(&[("ServerName", text_value("FILESRV01"))]);

        let event = smb_connect(&fields, meta()).expect("named server");

        assert_eq!(event.server_name, "FILESRV01");
    }

    #[test]
    fn a_connection_without_a_server_name_is_dropped() {
        assert!(smb_connect(&Fields::default(), meta()).is_none());
    }
}

mod ldap {
    use super::*;

    #[test]
    fn the_pid_is_the_process_id_field_else_the_header() {
        let with_field = Fields::of(&[("ProcessId", Value::U32(812))]);

        assert_eq!(ldap_pid(&with_field, 4), 812);
        assert_eq!(ldap_pid(&Fields::default(), 4), 4);
    }

    #[test]
    fn a_search_carries_its_filter_base_scope_and_attributes() {
        let fields = Fields::of(&[
            ("SearchFilter", text_value("(objectClass=user)")),
            ("DistinguishedName", text_value("DC=corp,DC=local")),
            ("ScopeOfSearch", Value::U32(2)),
            ("AttributeList", text_value("sAMAccountName;memberOf")),
        ]);

        let event = ldap_search(&fields, meta());

        assert_eq!(event.filter, "(objectClass=user)");
        assert_eq!(event.base_dn, "DC=corp,DC=local");
        assert_eq!(event.scope, 2);
        assert_eq!(event.attributes, ["sAMAccountName", "memberOf"]);
    }

    #[test]
    fn a_search_with_no_fields_is_a_base_scope_search_with_nothing_named() {
        let event = ldap_search(&Fields::default(), meta());

        assert_eq!(event.filter, "");
        assert_eq!(event.scope, 0);
        assert!(event.attributes.is_empty());
    }
}

mod ntlm {
    use super::*;

    #[test]
    fn the_direction_follows_the_event_id() {
        for id in [4020, 4021, 4026, 4027] {
            assert_eq!(ntlm_direction(id), Some(NtlmDirection::Outgoing));
        }
        for id in [4022, 4023] {
            assert_eq!(ntlm_direction(id), Some(NtlmDirection::Incoming));
        }
        assert_eq!(ntlm_direction(4001), None);
    }

    #[test]
    fn the_pid_is_read_as_an_integer_then_as_hex_text_then_from_the_header() {
        let integer = Fields::of(&[("ProcessPID", Value::U32(4))]);
        let hex_text = Fields::of(&[("ProcessPID", text_value("0x2a8"))]);

        assert_eq!(ntlm_pid(&integer, 700), 4);
        assert_eq!(ntlm_pid(&hex_text, 700), 0x2a8);
        assert_eq!(ntlm_pid(&Fields::default(), 700), 700);
    }

    #[test]
    fn an_outgoing_authentication_targets_the_service_at_the_target_ip() {
        let fields = Fields::of(&[
            ("Username", text_value("alice")),
            ("DomainName", text_value("CORP")),
            ("TargetService", text_value("cifs/10.0.0.5")),
            ("TargetMachine", text_value("FILESRV01")),
            ("TargetIP", text_value("10.0.0.5")),
            ("ClientIP", text_value("10.0.0.9")),
            ("NtlmVersion", text_value("NTLMv2")),
            ("Status", Value::U32(0xc000_006d)),
        ]);

        let event = ntlm_auth(NtlmDirection::Outgoing, &fields);

        assert_eq!(event.user, r"CORP\alice");
        assert_eq!(event.target, "cifs/10.0.0.5");
        assert_eq!(event.remote_address, "10.0.0.5".parse().ok());
        assert_eq!(event.ntlm_version, "NTLMv2");
        assert_eq!(event.status, None, "only an incoming record has a status");
    }

    #[test]
    fn a_target_service_spelled_as_absent_falls_back_to_the_machine() {
        for absent in ["", "-", "Null", "(NULL)"] {
            let fields = Fields::of(&[
                ("TargetService", text_value(absent)),
                ("TargetMachine", text_value("FILESRV01")),
            ]);

            let event = ntlm_auth(NtlmDirection::Outgoing, &fields);

            assert_eq!(event.target, "FILESRV01", "service {absent:?}");
        }
    }

    #[test]
    fn an_incoming_authentication_is_from_the_client_ip_with_its_status_in_hex() {
        let fields = Fields::of(&[
            ("ClientIP", text_value(" 10.0.0.9 ")),
            ("TargetIP", text_value("10.0.0.5")),
            ("Status", Value::U32(0xc000_006d)),
        ]);

        let event = ntlm_auth(NtlmDirection::Incoming, &fields);

        assert_eq!(event.remote_address, "10.0.0.9".parse().ok());
        assert_eq!(event.status.as_deref(), Some("0xc000006d"));
    }

    #[test]
    fn an_integer_status_is_padded_to_eight_hex_digits() {
        let fields = Fields::of(&[("Status", Value::U32(4))]);

        let status = ntlm_auth(NtlmDirection::Incoming, &fields).status;

        assert_eq!(status.as_deref(), Some("0x00000004"));
    }

    #[test]
    fn the_event_carries_the_authentication_and_the_process_meta() {
        let fields = Fields::of(&[
            ("Username", text_value("alice")),
            ("TargetService", text_value("cifs/srv")),
            ("NtlmVersion", text_value("NTLMv2")),
        ]);
        let auth = ntlm_auth(NtlmDirection::Outgoing, &fields);

        let event = auth.clone().into_event(meta());

        assert_eq!(event.meta, meta());
        assert_eq!(
            (
                event.direction,
                event.user,
                event.target,
                event.ntlm_version
            ),
            (auth.direction, auth.user, auth.target, auth.ntlm_version)
        );
    }

    #[test]
    fn a_failure_and_the_success_after_it_are_two_dedup_keys() {
        let failure = Fields::of(&[
            ("Username", text_value("alice")),
            ("Status", Value::U32(0xc000_006d)),
        ]);
        let success = Fields::of(&[("Username", text_value("alice")), ("Status", Value::U32(0))]);
        let failure = ntlm_auth(NtlmDirection::Incoming, &failure);
        let success = ntlm_auth(NtlmDirection::Incoming, &success);

        assert_ne!(failure.dedup_key(4023), success.dedup_key(4022));
        assert_ne!(failure.dedup_key(4023), failure.dedup_key(4022));
        assert_eq!(failure.dedup_key(4023), failure.clone().dedup_key(4023));
    }

    #[test]
    fn an_incoming_status_given_as_text_is_kept_only_when_hex() {
        let hex = Fields::of(&[("Status", text_value("0xc000006d"))]);
        let word = Fields::of(&[("Status", text_value("Success"))]);

        let hex_status = ntlm_auth(NtlmDirection::Incoming, &hex).status;
        let word_status = ntlm_auth(NtlmDirection::Incoming, &word).status;

        assert_eq!(hex_status.as_deref(), Some("0xc000006d"));
        assert_eq!(word_status, None);
    }

    #[test]
    fn an_unparsable_address_is_absent() {
        let fields = Fields::of(&[("TargetIP", text_value("-"))]);

        assert_eq!(
            ntlm_auth(NtlmDirection::Outgoing, &fields).remote_address,
            None
        );
    }

    #[test]
    fn the_process_name_is_the_process_name_field() {
        let fields = Fields::of(&[("ProcessName", text_value("System"))]);

        assert_eq!(ntlm_process_name(&fields), "System");
        assert_eq!(ntlm_process_name(&Fields::default()), "");
    }
}

/// Every payload field is written by the provider for whatever process it observes: any
/// value of any type, under any name, must decode or drop, never panic on the callback thread.
mod never_panics {
    use super::*;

    const NAMES: [&str; 35] = [
        "Username",
        "DomainName",
        "TargetService",
        "TargetMachine",
        "TargetIP",
        "ClientIP",
        "NtlmVersion",
        "ProcessName",
        "ScopeOfSearch",
        "ProcessId",
        "SearchFilter",
        "DistinguishedName",
        "MessageTotal",
        "QueryName",
        "QueryType",
        "QueryResults",
        "QueryStatus",
        "KeyName",
        "ValueName",
        "DataType",
        "Data",
        "ScriptBlockText",
        "ScriptBlockId",
        "Path",
        "MessageNumber",
        "NamespaceName",
        "Query",
        "ObjectPath",
        "MethodName",
        "AssemblyFlags",
        "FullyQualifiedAssemblyName",
        "ServerName",
        "AttributeList",
        "ProcessPID",
        "Status",
    ];

    fn any_value() -> impl Strategy<Value = Value> {
        prop_oneof![
            any::<String>().prop_map(Value::Text),
            any::<u16>().prop_map(Value::U16),
            any::<u32>().prop_map(Value::U32),
            prop::collection::vec(any::<u8>(), 0..64).prop_map(Value::Bytes),
        ]
    }

    fn any_fields() -> impl Strategy<Value = Fields> {
        prop::collection::vec((prop::sample::select(NAMES.to_vec()), any_value()), 0..12)
            .prop_map(|fields| Fields(fields.into_iter().collect()))
    }

    proptest! {
        #[test]
        fn decoding_arbitrary_fields_never_panics(fields in any_fields(), data in prop::collection::vec(any::<u8>(), 0..64)) {
            let _ = dns_query(&fields, meta());
            let _ = registry_set(&fields, meta());
            let _ = decode_reg_string(&data);
            let _ = script_block(&fields, meta());
            let _ = wmi_activity(WmiOperation::ExecQuery, &fields, meta());
            let _ = wmi_activity(WmiOperation::ExecMethod, &fields, meta());
            let _ = assembly_load(&fields, meta());
            let _ = smb_connect(&fields, meta());
            let _ = ldap_pid(&fields, 0);
            let _ = ldap_search(&fields, meta());
            let _ = ntlm_pid(&fields, 0);
            let _ = ntlm_auth(NtlmDirection::Outgoing, &fields);
            let _ = ntlm_auth(NtlmDirection::Incoming, &fields).dedup_key(4022);
        }
    }
}
