#![cfg(windows)]
//! `DotNETRuntime`, enabled as the sensor enables it (`LoaderKeyword` and an event-id filter
//! on 154), delivers an in-memory assembly load as EID 154 and nothing else from the process:
//! the keyword mask and the event-id filter are both honored by a user-mode provider (#91).

use std::{
    collections::BTreeSet,
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ferrisetw::{
    EventRecord,
    parser::Parser,
    provider::{EventFilter, Provider},
    schema_locator::SchemaLocator,
    trace::UserTrace,
};

const DOTNET_RUNTIME_GUID: &str = "e13c0d23-ccbc-4e12-931b-d9cc2eee27e4";
const LOADER_KEYWORD: u64 = 0x8;
const ASSEMBLY_LOAD: u16 = 154;
const ASSEMBLY_FLAG_DYNAMIC: u32 = 0x2;

#[derive(Default)]
struct Observed {
    event_ids: BTreeSet<u16>,
    dynamic_assemblies: Vec<String>,
}

#[test]
#[ignore = "requires an elevated Windows process to enable Microsoft-Windows-DotNETRuntime"]
fn an_in_memory_assembly_load_is_the_only_event_delivered() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    let marker = format!("SynthaeaProbe{unique}");
    let probe_pid = Arc::new(Mutex::new(None::<u32>));
    let observed = Arc::new(Mutex::new(Observed::default()));
    let (callback_pid, callback_observed) = (Arc::clone(&probe_pid), Arc::clone(&observed));
    let provider = Provider::by_guid(DOTNET_RUNTIME_GUID)
        .any(LOADER_KEYWORD)
        .add_filter(EventFilter::ByEventIds(vec![ASSEMBLY_LOAD]))
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            let Ok(pid) = callback_pid.lock() else {
                return;
            };
            if *pid != Some(record.process_id()) {
                return;
            }
            let Ok(mut observed) = callback_observed.lock() else {
                return;
            };
            observed.event_ids.insert(record.event_id());
            let Ok(schema) = locator.event_schema(record) else {
                return;
            };
            let parser = Parser::create(record, &schema);
            let flags: u32 = parser.try_parse("AssemblyFlags").unwrap_or(0);
            if flags & ASSEMBLY_FLAG_DYNAMIC != 0 {
                observed.dynamic_assemblies.push(
                    parser
                        .try_parse("FullyQualifiedAssemblyName")
                        .unwrap_or_default(),
                );
            }
        })
        .build();

    let trace = UserTrace::new()
        .named(format!("synthaea-dotnet-filter-{unique}"))
        .enable(provider)
        .start_and_process()
        .expect("start a real-time DotNETRuntime ETW session");
    thread::sleep(Duration::from_millis(500));

    // The child waits for its pid to be registered before it defines the assembly.
    let script = format!(
        "Start-Sleep -Milliseconds 1500; \
         [AppDomain]::CurrentDomain.DefineDynamicAssembly(\
         (New-Object Reflection.AssemblyName '{marker}'), 'Run') | Out-Null"
    );
    let mut child = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .spawn()
        .expect("start powershell.exe");
    *probe_pid.lock().expect("pid poisoned") = Some(child.id());
    let status = child.wait().expect("wait for powershell.exe");
    assert!(status.success(), "powershell.exe failed: {status}");
    thread::sleep(Duration::from_secs(2));
    trace.stop().expect("stop the ETW test session");

    let observed = observed.lock().expect("observed poisoned");
    assert!(
        observed
            .dynamic_assemblies
            .iter()
            .any(|name| name.starts_with(&marker)),
        "the dynamic assembly was not delivered; dynamic loads seen: {:?}",
        observed.dynamic_assemblies
    );
    assert_eq!(
        observed.event_ids,
        BTreeSet::from([ASSEMBLY_LOAD]),
        "the keyword mask or the event-id filter let other events through"
    );
}
