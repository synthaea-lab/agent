//! The ETW provider callbacks (Kernel-Process, Kernel-Network, Kernel-File, DNS-Client,
//! Kernel-Registry), each normalizing its records into schema events. Lab-earned notes carry over
//! each normalizing its records into schema events. Lab-earned notes carry over
//! from the old iteration: `TcpClient` emits no eid=42 (2026-08-25), PID recycling
//! prunes on `ProcessEnd`, canary events are filtered from emission.

use std::sync::{Arc, atomic::Ordering};

use ferrisetw::{
    EventRecord, GUID,
    parser::{Parser, Pointer},
    provider::Provider,
    schema_locator::SchemaLocator,
};
use schema::{
    AmsiContentEvent, AssemblyLoadEvent, ConnectEvent, DnsQueryEvent, Event, EventMeta, ExecEvent,
    FileOpenEvent, ImageLoadEvent, RegistrySetEvent, ScriptBlockEvent, SmbConnectEvent,
    UdpSendEvent, WmiActivityEvent, sensor::EventSink,
};

use crate::{
    amsi, normalize,
    sensor::{SharedState, basename, meta},
    winapi, zone_identifier,
};

const KERNEL_PROCESS_GUID: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const KERNEL_NETWORK_GUID: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";
const KERNEL_FILE_GUID: &str = "edd08927-9cc4-4e65-b970-c2560fb5c289";
/// Microsoft-Windows-DNS-Client
const DNS_CLIENT_GUID: &str = "1C95126E-7EEA-49A9-A3FE-A378B03DDB4D";
/// Microsoft-Windows-Kernel-Registry
const KERNEL_REGISTRY_GUID: &str = "70EB4F03-C1DE-4F73-A051-33D13D5413BD";
/// Microsoft-Windows-PowerShell (script-block logging)
const POWERSHELL_GUID: &str = "A0C1853B-5C40-4B15-8766-3CF1C58F985A";
/// Microsoft-Windows-WMI-Activity
const WMI_ACTIVITY_GUID: &str = "1418EF04-B0B4-4623-BF7E-D74AB47BBDAA";
/// Microsoft-Windows-DotNETRuntime (Assembly keyword, EID 154 `AssemblyLoad`)
const DOTNET_RUNTIME_GUID: &str = "e13c0d23-ccbc-4e12-931b-d9cc2eee27e4";
/// Microsoft-Antimalware-Scan-Interface (EID 1101, the scanned buffer, #282)
const AMSI_GUID: &str = "2A576B87-09A7-520E-C21A-4942F0271D67";
/// Microsoft-Windows-SMBClient (EID 30704 — TCP connection established to SMB server)
const SMB_CLIENT_GUID: &str = "988C59C5-0A1C-45B6-A555-0C62276E327D";
/// Microsoft-Windows-Bits-Client (EIDs 16403/4/5/61 — BITS jobs, #284)
const BITS_CLIENT_GUID: &str = "EF1CC15B-46C1-414E-BB95-E76B077BD51E";

/// Every provider the sensor enables, by short name — for the blind-session
/// attribution (#408), which asks the OS who else enables them.
pub(crate) const ALL_PROVIDERS: [(&str, &str); 11] = [
    ("Kernel-Process", KERNEL_PROCESS_GUID),
    ("Kernel-Network", KERNEL_NETWORK_GUID),
    ("Kernel-File", KERNEL_FILE_GUID),
    ("DNS-Client", DNS_CLIENT_GUID),
    ("Kernel-Registry", KERNEL_REGISTRY_GUID),
    ("PowerShell", POWERSHELL_GUID),
    ("WMI-Activity", WMI_ACTIVITY_GUID),
    ("DotNETRuntime", DOTNET_RUNTIME_GUID),
    ("SMBClient", SMB_CLIENT_GUID),
    ("AMSI", AMSI_GUID),
    ("Bits-Client", BITS_CLIENT_GUID),
];

/// `AssemblyFlags` bit indicating a dynamic (in-memory) assembly load.
/// File-backed assemblies are high-volume noise; only dynamic loads are forwarded.
const ASSEMBLY_FLAG_DYNAMIC: u32 = 0x2;

pub(crate) fn process_provider(sink: Arc<dyn EventSink>, state: Arc<SharedState>) -> Provider {
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        let eid = record.event_id();
        // 1=ProcessStart (new spawn → ExecEvent), 2=ProcessEnd (prune the store —
        // PID recycling), 3=ProcessDCStart (rundown of already-running processes →
        // store only, not a spawn), 5=ImageLoad (DLL/EXE mapped into a process).
        if eid != 1 && eid != 2 && eid != 3 && eid != 5 {
            return;
        }
        state.events_seen.fetch_add(1, Ordering::Relaxed);
        let Ok(schema_def) = locator.event_schema(record) else {
            return;
        };
        let parser = Parser::create(record, &schema_def);
        let pid: u32 = parser.try_parse("ProcessID").unwrap_or(0);

        if eid == 2 {
            if pid != 0 {
                state.pids.lock().unwrap().remove(pid);
            }
            return;
        }

        if eid == 5 {
            // EID 5 = ImageLoad: a DLL or EXE was mapped into the process.
            // Only emit for tracked PIDs — the store is seeded at startup and
            // populated by EID 1, so a missing PID is a kernel/driver load that
            // we intentionally ignore at userland tier.
            let Some(comm) = state.pids.lock().unwrap().get(pid).map(basename) else {
                return;
            };
            let raw_image: String = parser
                .try_parse("ImageFileName")
                .unwrap_or_else(|_| String::from("<unknown>"));
            if raw_image.is_empty() || raw_image == "<unknown>" {
                return;
            }
            let image_path = state.normalize_path(&raw_image);
            let timestamp_ns = normalize::filetime_to_ns(record.raw_timestamp());
            // EID 5 carries no parent pid; the old cache lookup here always
            // yielded 0 anyway.
            let ppid = 0;
            sink.on_event(Event::ImageLoad(ImageLoadEvent {
                meta: meta(pid, ppid, comm, timestamp_ns),
                image_path,
            }));
            return;
        }

        let ppid: u32 = parser.try_parse("ParentProcessID").unwrap_or(0);
        let raw_image: String = parser
            .try_parse("ImageName")
            .unwrap_or_else(|_| String::from("<unknown>"));
        let image_path = state.normalize_path(&raw_image);
        let timestamp_ns = normalize::filetime_to_ns(record.raw_timestamp());

        // Never store "<unknown>": a cache hit on it would suppress live lookups.
        if image_path != "<unknown>" {
            state.pids.lock().unwrap().insert(pid, image_path.clone());
        }
        if eid == 3 {
            return; // rundown: store populated, nothing else to do
        }

        // Lineage at exec time (schema parent fields): the parent is usually alive
        // and already in the store.
        let parent_image_path = state.pids.lock().unwrap().get(ppid).map(str::to_owned);
        let parent_comm = parent_image_path.as_deref().map(basename);

        // F-1: the REAL command line from the target's PEB, unbounded (F-4);
        // fall back to the image path only when the read fails — never a
        // placeholder pretending to be arguments.
        let cmdline = winapi::read_process_cmdline(pid).unwrap_or_else(|| image_path.clone());

        let comm = basename(&image_path);
        sink.on_event(Event::Exec(ExecEvent {
            meta: meta(pid, ppid, comm, timestamp_ns),
            image_path,
            cmdline,
            argv: vec![], // Windows has a flat command line; consumers fall back
            env_security: Vec::new(), // no exec-environment capture on Windows yet (#363 is Linux-only)
            parent_comm,
            parent_image_path,
            sha256: None, // filled by the agent's enrichment stage
            signature: None,
        }));
    };
    Provider::by_guid(KERNEL_PROCESS_GUID)
        .add_callback(callback)
        .build()
}

pub(crate) fn network_provider(sink: Arc<dyn EventSink>, state: Arc<SharedState>) -> Provider {
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        let eid = record.event_id();

        // EID 14 = UDPSend (IPv4): dest addr + port + payload size.
        // Handled early and returned: UDP is stateless so no dedup filter applies,
        // and the field set differs from TCP (no sport needed for emit).
        if eid == 14 {
            state.events_seen.fetch_add(1, Ordering::Relaxed);
            let Ok(schema_def) = locator.event_schema(record) else {
                return;
            };
            let parser = Parser::create(record, &schema_def);
            let pid: u32 = parser.try_parse("PID").unwrap_or(0);
            let raw: u32 = parser.try_parse("daddr").unwrap_or(0);
            if raw == 0 {
                return;
            }
            let daddr = std::net::IpAddr::V4(raw.to_ne_bytes().into());
            let dport = parser.try_parse::<u16>("dport").unwrap_or(0).swap_bytes();
            let size: u32 = parser.try_parse("size").unwrap_or(0);
            let timestamp_ns = normalize::filetime_to_ns(record.raw_timestamp());
            let Some(comm) = state.comm_for(pid) else {
                return;
            };
            sink.on_event(Event::UdpSend(UdpSendEvent {
                meta: meta(pid, 0, comm, timestamp_ns),
                daddr,
                dport,
                size,
            }));
            return;
        }

        // v4: 42=TcpIpConnect, 12=TcpIpSend (TcpClient emits no 42 — lab
        // 2026-08-25). v6 counterparts (F-7): 58=connect, 26=send. Recv excluded:
        // would double-count on the receiver side.
        let is_v6 = eid == 58 || eid == 26;
        if eid != 42 && eid != 12 && !is_v6 {
            return;
        }
        state.events_seen.fetch_add(1, Ordering::Relaxed);
        let Ok(schema_def) = locator.event_schema(record) else {
            return;
        };
        let parser = Parser::create(record, &schema_def);
        let pid: u32 = parser.try_parse("PID").unwrap_or(0);
        let dport = parser.try_parse::<u16>("dport").unwrap_or(0).swap_bytes();
        let sport = parser.try_parse::<u16>("sport").unwrap_or(0).swap_bytes();
        let timestamp_ns = normalize::filetime_to_ns(record.raw_timestamp());

        let daddr: std::net::IpAddr = if is_v6 {
            let raw: Vec<u8> = parser.try_parse("daddr").unwrap_or_default();
            let Ok(bytes) = <[u8; 16]>::try_from(raw) else {
                return;
            };
            std::net::IpAddr::V6(bytes.into())
        } else {
            let raw: u32 = parser.try_parse("daddr").unwrap_or(0);
            if raw == 0 {
                return;
            }
            // ETW stores the v4 address in memory order — to_ne_bytes preserves it.
            std::net::IpAddr::V4(raw.to_ne_bytes().into())
        };

        // F-7: one logical connection = one event — flow-keyed (sport included) so
        // parallel connections stay distinct and chatty flows never re-emit.
        if state
            .dedup
            .lock()
            .unwrap()
            .is_duplicate(pid, sport, daddr, dport, timestamp_ns)
        {
            return;
        }

        let Some(comm) = state.comm_for(pid) else {
            return;
        };
        sink.on_event(Event::Connect(ConnectEvent {
            meta: meta(pid, 0, comm, timestamp_ns),
            daddr,
            dport,
        }));
    };
    Provider::by_guid(KERNEL_NETWORK_GUID)
        .add_callback(callback)
        .build()
}

pub(crate) fn file_provider(sink: Arc<dyn EventSink>, state: Arc<SharedState>) -> Provider {
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        let eid = record.event_id();
        // 12=NameCreate; 30=CreateNewFile (F-6 partial — delete/rename semantics
        // need schema variants and land with #82/#39).
        if eid != 12 && eid != 30 {
            return;
        }
        state.events_seen.fetch_add(1, Ordering::Relaxed);
        let Ok(schema_def) = locator.event_schema(record) else {
            return;
        };
        let parser = Parser::create(record, &schema_def);
        // PID from the ETW header — the event fires in the caller's thread context.
        let pid = record.process_id();
        let timestamp_ns = normalize::filetime_to_ns(record.raw_timestamp());

        // Tracked PIDs only: discards pure kernel ops and untracked churn (the
        // volume filter the old sensor validated in the lab).
        let Some(comm) = state.pids.lock().unwrap().get(pid).map(basename) else {
            return;
        };

        let flags = if eid == 30 {
            0o101 // CreateNewFile: create+write by definition
        } else {
            // NameCreate: disposition in the high byte of CreateOptions.
            let create_options: u32 = parser.try_parse("CreateOptions").unwrap_or(0x0100_0000);
            normalize::disposition_to_flags((create_options >> 24) & 0xFF)
        };
        if flags == 0 {
            return; // read-only open — of no interest for detection
        }

        let raw_path: String = parser.try_parse("FileName").unwrap_or_default();
        if raw_path.is_empty() {
            return;
        }
        let path = state.normalize_path(&raw_path);
        // The liveness canary proves the trace is alive; it is not telemetry.
        if path.ends_with(&state.canary_path) {
            return;
        }
        // #365: a create/write on `host:Zone.Identifier` is the mark-of-the-web
        // being written. The stream is read back off this thread (#439).
        let meta = meta(pid, 0, comm, timestamp_ns);
        if let Some(host) = zone_identifier::stream_host_path(&path) {
            state.marks.offer(zone_identifier::MarkWrite {
                stream_path: path.clone(),
                host: host.to_string(),
                meta: meta.clone(),
            });
        }
        sink.on_event(Event::FileOpen(FileOpenEvent { meta, path, flags }));
    };
    Provider::by_guid(KERNEL_FILE_GUID)
        .add_callback(callback)
        .build()
}

/// DNS resolution events (EID 3008 — `QueryCompleted`).
///
/// Joins the querying process to the resolved domain and answer — the key link
/// for domain IOC matching and beacon-frequency detection. EID 3006
/// (`QueryStarted`) is intentionally skipped: without the answer it is noise; a
/// successful resolution always produces a 3008.
///
/// # Field notes (lab-validated on Windows Server 2022, 2026-09-07)
///
/// - `QueryName` : the FQDN as the application supplied it (no trailing dot).
/// - `QueryType` : u16 record type (1=A, 28=AAAA, 5=CNAME, 15=MX, ...).
/// - `QueryResults` : semicolon-separated answer, e.g. `"type:1 172.67.143.127;"`.
///   Empty string on NXDOMAIN / cache-only negative answer.
/// - `QueryStatus` : Win32 error code (0=success, 9003=NXDOMAIN, 9501=SERVFAIL).
/// - PID comes from the ETW record header (`record.process_id()`), not a payload
///   field — DNS-Client fires in the calling thread's context, same as file events.
pub(crate) fn dns_provider(sink: Arc<dyn EventSink>, state: Arc<SharedState>) -> Provider {
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        // EID 3008 = QueryCompleted — has both the query name and the answer.
        // EID 3006 = QueryStarted — no answer yet, emitting it would be noise.
        if record.event_id() != 3008 {
            return;
        }
        state.events_seen.fetch_add(1, Ordering::Relaxed);
        let Ok(schema_def) = locator.event_schema(record) else {
            return;
        };
        let parser = Parser::create(record, &schema_def);

        let pid = record.process_id();
        let query: String = parser.try_parse("QueryName").unwrap_or_default();
        if query.is_empty() {
            return; // malformed record — no name, no value for detection
        }
        let qtype: u16 = parser.try_parse("QueryType").unwrap_or(0);
        let result_raw: String = parser.try_parse("QueryResults").unwrap_or_default();
        let status: u32 = parser.try_parse("QueryStatus").unwrap_or(0);
        let timestamp_ns = normalize::filetime_to_ns(record.raw_timestamp());

        let comm = state.comm_for(pid).unwrap_or_default();

        sink.on_event(Event::DnsQuery(DnsQueryEvent {
            meta: meta(pid, 0, comm, timestamp_ns),
            query,
            qtype: u32::from(qtype),
            result: if result_raw.is_empty() {
                None
            } else {
                Some(result_raw)
            },
            status,
        }));
    };

    Provider::by_guid(DNS_CLIENT_GUID)
        .add_callback(callback)
        .build()
}

/// Decodes a `REG_SZ` / `REG_EXPAND_SZ` value: UTF-16 LE bytes → String.
/// Returns `None` for empty input, odd-length buffers, or invalid UTF-16.
fn decode_reg_string(bytes: Vec<u8>) -> Option<String> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let s = String::from_utf16_lossy(&units);
    let trimmed = s.trim_end_matches('\0');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Registry write events (EID 4 — `RegSetValueKey`).
///
/// Covers persistence writes to Run keys, IFEO, Services, and Winlogon (T1547,
/// T1546, T1543). Only write operations are captured; reads (EID 2 `RegOpenKey`)
/// are high-volume noise with negligible detection value at userland tier.
///
/// # Field notes (Windows Server 2022, 2026-09-07)
///
/// `KeyName` in EID 4 contains the full NT path of the key being written, e.g.
/// `\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`. The sensor
/// normalizes this to the Win32 hive prefix (`HKLM\...`, `HKU\...`).
///
/// `Data` is a raw binary blob. For `DataType` 1 (`REG_SZ`) and 2 (`REG_EXPAND_SZ`)
/// the sensor decodes it as UTF-16 LE; other types (DWORD, BINARY, `MULTI_SZ`) are
/// left as `None` — raw bytes have no safe string representation for rules.
pub(crate) fn registry_provider(sink: Arc<dyn EventSink>, state: Arc<SharedState>) -> Provider {
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        // EID 4 = RegSetValueKey — the only operation that writes persistence.
        if record.event_id() != 4 {
            return;
        }
        state.events_seen.fetch_add(1, Ordering::Relaxed);
        let Ok(schema_def) = locator.event_schema(record) else {
            return;
        };
        let parser = Parser::create(record, &schema_def);

        let raw_key: String = parser.try_parse("KeyName").unwrap_or_default();
        if raw_key.is_empty() {
            // Opaque handle — kernel did not resolve the name (rare on Server 2022).
            return;
        }
        let key = normalize::normalize_registry_key(&raw_key);
        let value_name: String = parser.try_parse("ValueName").unwrap_or_default();
        let data_type: u32 = parser.try_parse("DataType").unwrap_or(0);
        let data_bytes: Vec<u8> = parser.try_parse("Data").unwrap_or_default();

        // Decode string types; leave binary/DWORD as None.
        let data = if data_type == 1 || data_type == 2 {
            decode_reg_string(data_bytes)
        } else {
            None
        };

        let pid = record.process_id();
        let timestamp_ns = normalize::filetime_to_ns(record.raw_timestamp());
        let comm = state.comm_for(pid).unwrap_or_default();

        sink.on_event(Event::RegistrySet(RegistrySetEvent {
            meta: meta(pid, 0, comm, timestamp_ns),
            key,
            value_name,
            data_type,
            data,
        }));
    };

    Provider::by_guid(KERNEL_REGISTRY_GUID)
        .add_callback(callback)
        .build()
}

/// `PowerShell` script-block events (EID 4104 — `ScriptBlockLogging`).
///
/// The provider decodes `base64 -EncodedCommand` payloads before logging, so
/// this event sees the plain-text script regardless of obfuscation. Primary
/// signal for T1059.001 (`PowerShell`) and T1027 (obfuscated files/information).
///
/// # Fragmentation
///
/// Scripts that exceed the ETW record size are split: each fragment shares the
/// same `ScriptBlockId` and carries `MessageNumber` / `MessageTotal`. Every
/// fragment is emitted as a separate `ScriptBlockEvent`; the correlator can
/// reassemble them by `script_block_id` + `message_number`.
///
/// # Field notes (Windows Server 2022, 2026-09-07)
///
/// - `ScriptBlockId` : GUID string identifying this script block.
/// - `ScriptBlockText` : decoded script fragment (may be the full script).
/// - `Path` : source file path when loaded from disk; empty for interactive use.
/// - `MessageNumber` : 1-based fragment index.
/// - `MessageTotal` : total fragment count for this `ScriptBlockId`.
pub(crate) fn powershell_provider(sink: Arc<dyn EventSink>, state: Arc<SharedState>) -> Provider {
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        // EID 4104 = ScriptBlockLogging — the only EID that carries script text.
        if record.event_id() != 4104 {
            return;
        }
        state.events_seen.fetch_add(1, Ordering::Relaxed);
        let Ok(schema_def) = locator.event_schema(record) else {
            return;
        };
        let parser = Parser::create(record, &schema_def);

        let text: String = parser.try_parse("ScriptBlockText").unwrap_or_default();
        if text.is_empty() {
            return; // malformed or empty block — no detection value
        }
        let script_block_id: String = parser.try_parse("ScriptBlockId").unwrap_or_default();
        let path_raw: String = parser.try_parse("Path").unwrap_or_default();
        let path = if path_raw.is_empty() {
            None
        } else {
            Some(path_raw)
        };
        let message_number: u32 = parser.try_parse("MessageNumber").unwrap_or(1);
        let message_total: u32 = parser.try_parse("MessageTotal").unwrap_or(1);

        let pid = record.process_id();
        let timestamp_ns = normalize::filetime_to_ns(record.raw_timestamp());
        let comm = state.comm_for(pid).unwrap_or_default();

        sink.on_event(Event::ScriptBlock(ScriptBlockEvent {
            meta: meta(pid, 0, comm, timestamp_ns),
            script_block_id,
            path,
            text,
            message_number,
            message_total,
        }));
    };

    Provider::by_guid(POWERSHELL_GUID)
        .add_callback(callback)
        .build()
}

/// AMSI scans (EID 1101): the buffer a runtime hands to AMSI before running
/// it, i.e. the de-obfuscated script (#282). Volume is gated by
/// [`amsi::AmsiGate`] (dedup on AMSI's own SHA-256, per-process budget).
///
/// # Field notes (manifest, Windows 11 24H2, 2026-10-01)
///
/// `session` (Pointer), `scanStatus` (u8), `scanResult` (u32), `appname`,
/// `contentname` (strings), `contentsize`, `originalsize` (u32), `content`
/// (Binary, `contentsize` bytes), `hash` (Binary, 32), `contentFiltered`
/// (bool); v1 adds `hashoriginalcontent`. The record's pid is the scanning
/// process: AMSI runs in-process.
pub(crate) fn amsi_provider(sink: Arc<dyn EventSink>, state: Arc<SharedState>) -> Provider {
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        if record.event_id() != 1101 {
            return;
        }
        state.events_seen.fetch_add(1, Ordering::Relaxed);
        let Ok(schema_def) = locator.event_schema(record) else {
            return;
        };
        let parser = Parser::create(record, &schema_def);
        let pid = record.process_id();
        let timestamp_ns = normalize::filetime_to_ns(record.raw_timestamp());
        let hash: Vec<u8> = parser.try_parse("hash").unwrap_or_default();
        let content_hash = amsi::hex(&hash);
        // The gate runs before any parsing or token lookup: a refused rescan
        // costs one map probe on the consumer thread (#408).
        if let Err(refusal) = state
            .amsi
            .lock()
            .unwrap()
            .admit(pid, &content_hash, timestamp_ns)
        {
            tracing::trace!(pid, ?refusal, "AMSI scan not reported");
            return;
        }

        let content: Vec<u8> = parser.try_parse("content").unwrap_or_default();
        let filtered: bool = parser.try_parse("contentFiltered").unwrap_or(false);
        let (text, text_truncated) = match amsi::decode_text(&content, filtered) {
            Some((text, cut)) => (Some(text), cut),
            None => (None, false),
        };
        // `session` is a Pointer: 4 or 8 bytes depending on the scanning
        // process's bitness, which ferrisetw's `Pointer` handles.
        let session = parser
            .try_parse::<Pointer>("session")
            .map_or(0, |p| u64::try_from(*p).unwrap_or(0));
        let content_name: String = parser.try_parse("contentname").unwrap_or_default();
        let comm = state.comm_for(pid).unwrap_or_default();

        sink.on_event(Event::AmsiContent(AmsiContentEvent {
            meta: meta(pid, 0, comm, timestamp_ns),
            session,
            app_name: parser.try_parse("appname").unwrap_or_default(),
            content_name: (!content_name.is_empty()).then_some(content_name),
            content_size: parser.try_parse("contentsize").unwrap_or(0),
            original_size: parser.try_parse("originalsize").unwrap_or(0),
            text,
            text_truncated,
            content_hash,
            scan_result: parser.try_parse("scanResult").unwrap_or(0),
        }));
    };

    Provider::by_guid(AMSI_GUID).add_callback(callback).build()
}

/// WMI activity events (EID 23 — `ExecQuery`, EID 24 — `ExecMethod`).
///
/// EID 23 captures WQL queries (reconnaissance, event subscriptions).
/// EID 24 captures method invocations — `Win32_Process.Create` is the classic
/// T1047 lateral-movement / execution primitive used by `wmic /node: process
/// call create`.
///
/// # Field notes (Windows Server 2022, 2026-09-07)
///
/// EID 23: `NamespaceName` (String), `Query` (WQL String), `ResultCode` (u32).
/// EID 24: `NamespaceName` (String), `ObjectPath` (String, class name),
/// `MethodName` (String). Both: PID from the record header.
pub(crate) fn wmi_provider(sink: Arc<dyn EventSink>, state: Arc<SharedState>) -> Provider {
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        let eid = record.event_id();
        // 23 = ExecQuery, 24 = ExecMethod — the two high-value WMI operations.
        if eid != 23 && eid != 24 {
            return;
        }
        state.events_seen.fetch_add(1, Ordering::Relaxed);
        let Ok(schema_def) = locator.event_schema(record) else {
            return;
        };
        let parser = Parser::create(record, &schema_def);

        let namespace: String = parser.try_parse("NamespaceName").unwrap_or_default();
        let pid = record.process_id();
        let timestamp_ns = normalize::filetime_to_ns(record.raw_timestamp());
        let comm = state.comm_for(pid).unwrap_or_default();

        let (query, method) = if eid == 23 {
            let q: String = parser.try_parse("Query").unwrap_or_default();
            (if q.is_empty() { None } else { Some(q) }, None)
        } else {
            // EID 24: ObjectPath + MethodName → "ClassName.MethodName"
            let class: String = parser.try_parse("ObjectPath").unwrap_or_default();
            let meth: String = parser.try_parse("MethodName").unwrap_or_default();
            let combined = format!("{class}.{meth}");
            (
                None,
                if combined == "." {
                    None
                } else {
                    Some(combined)
                },
            )
        };

        if query.is_none() && method.is_none() {
            return; // nothing actionable
        }

        sink.on_event(Event::WmiActivity(WmiActivityEvent {
            meta: meta(pid, 0, comm, timestamp_ns),
            namespace,
            query,
            method,
        }));
    };

    Provider::by_guid(WMI_ACTIVITY_GUID)
        .add_callback(callback)
        .build()
}

/// In-memory .NET assembly loads (EID 154 — `AssemblyLoad`) from
/// `Microsoft-Windows-DotNETRuntime`.
///
/// Only dynamic (in-memory) assemblies are forwarded (`flags & 0x2 != 0`).
/// File-backed loads are high-volume noise (every .NET app triggers dozens on
/// startup) with almost no detection value at this tier. Dynamic loads are rare
/// in legitimate software and are the hallmark of execute-assembly / fileless
/// .NET injection (T1620, T1055).
///
/// # Field notes (Windows Server 2022, 2026-09-07)
///
/// EID 154: `AssemblyID` (u64, opaque), `AssemblyFlags` (u32, 0x2 = dynamic),
/// `FullyQualifiedAssemblyName` (String, e.g.
/// `MyPayload, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null`).
/// PID comes from the record header.
pub(crate) fn dotnet_provider(sink: Arc<dyn EventSink>, state: Arc<SharedState>) -> Provider {
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        // EID 154 = AssemblyLoad — the only EID that carries assembly identity.
        if record.event_id() != 154 {
            return;
        }
        let Ok(schema_def) = locator.event_schema(record) else {
            return;
        };
        let parser = Parser::create(record, &schema_def);

        let flags: u32 = parser.try_parse("AssemblyFlags").unwrap_or(0);
        // Drop file-backed assemblies — only in-memory loads have detection value.
        if flags & ASSEMBLY_FLAG_DYNAMIC == 0 {
            return;
        }

        state.events_seen.fetch_add(1, Ordering::Relaxed);

        let assembly_name: String = parser
            .try_parse("FullyQualifiedAssemblyName")
            .unwrap_or_default();
        if assembly_name.is_empty() {
            return;
        }

        let pid = record.process_id();
        let timestamp_ns = normalize::filetime_to_ns(record.raw_timestamp());
        let comm = state.comm_for(pid).unwrap_or_default();

        sink.on_event(Event::AssemblyLoad(AssemblyLoadEvent {
            meta: meta(pid, 0, comm, timestamp_ns),
            assembly_name,
            flags,
        }));
    };

    Provider::by_guid(DOTNET_RUNTIME_GUID)
        .add_callback(callback)
        .build()
}

/// SMB client connections to remote servers (EID 30704) from
/// `Microsoft-Windows-SMBClient`.
///
/// EID 30704 fires when the SMB redirector successfully establishes a TCP
/// connection to a remote server. Primary signal for lateral movement via SMB
/// (T1021.002 — Remote Services: SMB/Windows Admin Shares).
///
/// EID 30702 (failed connections) is not emitted — only successful connections
/// have detection value at this tier.
///
/// # Field notes (Windows Server 2022, 2026-09-08)
///
/// EID 30704: `ServerName` (length-prefixed `UnicodeString`). Verified against
/// `(Get-WinEvent -ListProvider Microsoft-Windows-SMBClient).Events`.
pub(crate) fn smb_provider(sink: Arc<dyn EventSink>, state: Arc<SharedState>) -> Provider {
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        // EID 30704 = TCP connection established to remote SMB server.
        if record.event_id() != 30704 {
            return;
        }
        let Ok(schema_def) = locator.event_schema(record) else {
            return;
        };
        let parser = Parser::create(record, &schema_def);

        let server_name: String = parser.try_parse("ServerName").unwrap_or_default();
        if server_name.is_empty() {
            return;
        }

        state.events_seen.fetch_add(1, Ordering::Relaxed);

        let pid = record.process_id();
        let timestamp_ns = normalize::filetime_to_ns(record.raw_timestamp());
        let comm = state.comm_for(pid).unwrap_or_default();

        sink.on_event(Event::SmbConnect(SmbConnectEvent {
            meta: meta(pid, 0, comm, timestamp_ns),
            server_name,
        }));
    };

    Provider::by_guid(SMB_CLIENT_GUID)
        .add_callback(callback)
        .build()
}

/// BITS jobs (#284, T1197) from `Microsoft-Windows-Bits-Client`: 16403 (file
/// added), 4 (completed), 5 (cancelled), 61 (transfer error), each turned into
/// `BitsJobEvent`s by [`crate::bits::BitsJobs`], which also drops Microsoft
/// update files (see [`crate::bits::MICROSOFT_UPDATE_HOSTS`]). The record
/// header's pid is the BITS service's; the client comes from the record's
/// `processId` (16403, 5) or, for the service's own records, from the job's
/// file-added records. Field layout per EID in the [`crate::bits`] module docs.
///
/// Enabled with no keyword or level mask: the provider writes a handful of
/// records per job and the callback drops every id but these four before
/// parsing, which keeps it the cheapest provider on the shared session
/// (#408 counts every provider there).
pub(crate) fn bits_provider(sink: Arc<dyn EventSink>, state: Arc<SharedState>) -> Provider {
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        let eid = record.event_id();
        if !matches!(eid, 4 | 5 | 61 | 16403) {
            return;
        }
        state.events_seen.fetch_add(1, Ordering::Relaxed);
        let Ok(schema_def) = locator.event_schema(record) else {
            return;
        };
        let parser = Parser::create(record, &schema_def);
        // 61 names its job `Id`; the job-level records, `jobId`.
        let Ok(job_guid) = parser.try_parse::<GUID>(if eid == 61 { "Id" } else { "jobId" }) else {
            return;
        };
        let job_id = format_guid(&job_guid);
        let timestamp_ns = normalize::filetime_to_ns(record.raw_timestamp());
        let bytes_transferred: Option<u64> = parser.try_parse("bytesTransferred").ok();
        let events = match eid {
            16403 => bits_file_added(&parser, &state, job_id, timestamp_ns)
                .into_iter()
                .collect(),
            4 => state
                .bits
                .lock()
                .unwrap()
                .completed(&job_id, timestamp_ns, bytes_transferred),
            5 => match client_meta(&parser, &state, timestamp_ns) {
                Some(canceller) => state.bits.lock().unwrap().cancelled(&job_id, &canceller),
                None => {
                    state.bits.lock().unwrap().record_missing_client();
                    Vec::new()
                }
            },
            _ => {
                let hresult: u32 = parser.try_parse("hr").unwrap_or(0);
                let url: Option<String> = parser.try_parse("url").ok();
                state
                    .bits
                    .lock()
                    .unwrap()
                    .transfer_error(
                        &job_id,
                        url.as_deref(),
                        timestamp_ns,
                        bytes_transferred,
                        hresult,
                    )
                    .into_iter()
                    .collect()
            }
        };
        // The lock is released: the sink may take its own.
        for event in events {
            sink.on_event(Event::BitsJob(event));
        }
    };

    Provider::by_guid(BITS_CLIENT_GUID)
        .add_callback(callback)
        .build()
}

/// EID 16403 through the job table, with its drops logged at debug and
/// counted in the table.
fn bits_file_added(
    parser: &Parser<'_, '_>,
    state: &SharedState,
    job_id: String,
    timestamp_ns: u64,
) -> Option<schema::BitsJobEvent> {
    let Some(client) = client_meta(parser, state, timestamp_ns) else {
        let mut jobs = state.bits.lock().unwrap();
        jobs.record_missing_client();
        tracing::debug!(
            missing_client = jobs.missing_client(),
            "BITS file-added record without a client pid dropped"
        );
        return None;
    };
    let job_title: String = parser.try_parse("jobTitle").unwrap_or_default();
    let url: String = parser.try_parse("RemoteName").unwrap_or_default();
    let local_name: String = parser.try_parse("LocalName").unwrap_or_default();
    let local_path = state.normalize_path(&crate::bits::local_path_for_join(&local_name));
    let mut jobs = state.bits.lock().unwrap();
    let (filtered, evicted) = (jobs.filtered(), jobs.evicted());
    let event = jobs.file_added(client, job_id, job_title, url, local_path);
    if jobs.filtered() > filtered {
        tracing::debug!(
            filtered = jobs.filtered(),
            "BITS file from a Microsoft update host dropped"
        );
    }
    if jobs.evicted() > evicted {
        tracing::debug!(
            evicted = jobs.evicted(),
            "BITS job table full, oldest job or file forgotten"
        );
    }
    event
}

/// The client a record names in `processId`; `None` when it names none, which
/// the caller drops and counts rather than forwarding pid 0 with no name. A
/// client that already exited (a fire-and-forget `Start-BitsTransfer`) keeps
/// its pid with an empty name.
fn client_meta(
    parser: &Parser<'_, '_>,
    state: &SharedState,
    timestamp_ns: u64,
) -> Option<EventMeta> {
    let pid: u32 = parser.try_parse("processId").ok().filter(|&pid| pid != 0)?;
    let comm = state.comm_for(pid).unwrap_or_default();
    Some(meta(pid, 0, comm, timestamp_ns))
}

/// `{c40080ab-6fe4-418a-8ba6-c271c5298f18}`: the braced, lowercase form the
/// BITS event log writes, so a job id greps the same in both.
fn format_guid(guid: &GUID) -> String {
    let d = guid.data4;
    format!(
        "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        guid.data1, guid.data2, guid.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
    )
}
