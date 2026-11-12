//! The ETW provider callbacks, each normalizing its records into schema events.
//! Lab notes: `TcpClient` emits no EID 42 (2026-08-25), PID recycling prunes on
//! `ProcessEnd`, canary events are filtered from emission.

use std::sync::{Arc, atomic::Ordering};

use ferrisetw::{
    EventRecord, GUID,
    parser::{Parser, Pointer},
    provider::Provider,
    schema_locator::SchemaLocator,
};
use schema::{
    AmsiContentEvent, ConnectEvent, Event, EventMeta, FileOpenEvent, ImageLoadEvent,
    ProcessAccessEvent, RemoteThreadEvent, UdpSendEvent, sensor::EventSink,
};

use crate::{
    amsi,
    cross_process::{self, ThreadOrigin},
    kernel_process::{self, ExecContext, KernelProcessEvent, ProcessStart, UNKNOWN_IMAGE},
    normalize, payload,
    sensor::{SharedState, find_lsass},
    silo,
    sync::LockExt,
    winapi, zone_identifier,
};

const KERNEL_PROCESS_GUID: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const KERNEL_NETWORK_GUID: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";
const KERNEL_FILE_GUID: &str = "edd08927-9cc4-4e65-b970-c2560fb5c289";
/// Kernel-File manifest keyword bits for the event IDs handled below.
const FILE_KEYWORD_CREATE: u64 = 0x80;
const FILE_KEYWORD_DELETE_PATH: u64 = 0x400;
const FILE_KEYWORD_CREATE_NEW_FILE: u64 = 0x1000;
/// EID 12 Create, EID 26 `DeletePath`, and EID 30 `CreateNewFile` only.
/// `FILE_EVENT_KEYWORDS` is the single source of truth for dispatched IDs.
const FILE_KEYWORDS: u64 =
    FILE_KEYWORD_CREATE | FILE_KEYWORD_DELETE_PATH | FILE_KEYWORD_CREATE_NEW_FILE;
const FILE_EVENT_KEYWORDS: [(u16, u64); 3] = [
    (12, FILE_KEYWORD_CREATE),
    (26, FILE_KEYWORD_DELETE_PATH),
    (30, FILE_KEYWORD_CREATE_NEW_FILE),
];

fn file_event_keyword(event_id: u16) -> Option<u64> {
    FILE_EVENT_KEYWORDS
        .iter()
        .find_map(|(id, keyword)| (*id == event_id).then_some(*keyword))
}

/// Microsoft-Windows-DNS-Client
const DNS_CLIENT_GUID: &str = "1C95126E-7EEA-49A9-A3FE-A378B03DDB4D";
/// Microsoft-Windows-Kernel-Registry
const KERNEL_REGISTRY_GUID: &str = "70EB4F03-C1DE-4F73-A051-33D13D5413BD";
/// Kernel-Registry EID 5, `SetValueKey`, and its manifest keyword. Checked against a real
/// session by `tests/kernel_registry_set_value.rs` (`#[ignore]`, elevated).
const REGISTRY_SET_VALUE_KEY_EVENT: u16 = 5;
const REGISTRY_KEYWORD_SET_VALUE_KEY: u64 = 0x100;
/// Microsoft-Windows-PowerShell (script-block logging)
const POWERSHELL_GUID: &str = "A0C1853B-5C40-4B15-8766-3CF1C58F985A";
/// Microsoft-Windows-WMI-Activity
const WMI_ACTIVITY_GUID: &str = "1418EF04-B0B4-4623-BF7E-D74AB47BBDAA";
/// Microsoft-Windows-DotNETRuntime (EID 154 `AssemblyLoad`), enabled with no keyword mask
const DOTNET_RUNTIME_GUID: &str = "e13c0d23-ccbc-4e12-931b-d9cc2eee27e4";
/// Microsoft-Antimalware-Scan-Interface (EID 1101, the scanned buffer)
const AMSI_GUID: &str = "2A576B87-09A7-520E-C21A-4942F0271D67";
/// Microsoft-Windows-LDAP-Client (EID 30, the search request)
const LDAP_CLIENT_GUID: &str = "099614a5-5dd7-4788-8bc9-e29f43db28fc";
/// Microsoft-Windows-NTLM (EIDs 4020-4023/4026/4027, NTLM usage)
const NTLM_GUID: &str = "ac43300d-5fcc-4800-8e99-1bd3f85f0320";
/// Microsoft-Windows-SMBClient (EID 30704 — TCP connection established to SMB server)
const SMB_CLIENT_GUID: &str = "988C59C5-0A1C-45B6-A555-0C62276E327D";
/// Microsoft-Windows-Bits-Client (EIDs 16403/4/5/61, BITS jobs)
const BITS_CLIENT_GUID: &str = "EF1CC15B-46C1-414E-BB95-E76B077BD51E";
/// Microsoft-Windows-Kernel-Audit-API-Calls (EID 5 `PsOpenProcess`). The manifest
/// declares no keywords, so every id arrives and the callback keeps 5.
const KERNEL_AUDIT_API_GUID: &str = "E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23";
/// Kernel-Audit-API-Calls `PsOpenProcess`: `TargetProcessId`, `DesiredAccess`,
/// `ReturnCode`; the caller is the record header's pid.
const AUDIT_OPEN_PROCESS: u16 = 5;

/// Every provider the sensor enables, by short name — for the blind-session
/// attribution (#408), which asks the OS who else enables them.
pub(crate) const ALL_PROVIDERS: [(&str, &str); 14] = [
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
    ("LDAP-Client", LDAP_CLIENT_GUID),
    ("NTLM", NTLM_GUID),
    ("Kernel-Audit-API-Calls", KERNEL_AUDIT_API_GUID),
];

/// Kernel-Process keywords the sensor reads: `WINEVENT_KEYWORD_PROCESS` (0x10,
/// EIDs 1/2), `WINEVENT_KEYWORD_THREAD` (0x20, EID 3 for remote threads),
/// `WINEVENT_KEYWORD_IMAGE` (0x40, EID 5) and `WINEVENT_KEYWORD_JOB_SILO` (0x4000,
/// the server silo EIDs 23-26). Left unset, ferrisetw enables every keyword. The
/// thread stops (EID 4) THREAD brings along are dropped on their id before any
/// parsing.
const KERNEL_PROCESS_KEYWORDS: u64 = 0x10 | 0x20 | 0x40 | 0x4000;

pub(crate) fn process_provider(sink: Arc<dyn EventSink>, state: Arc<SharedState>) -> Provider {
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        let Some(event) = KernelProcessEvent::from_id(record.event_id()) else {
            return;
        };
        state.events_seen.fetch_add(1, Ordering::Relaxed);
        let Ok(schema_def) = locator.event_schema(record) else {
            return;
        };
        let parser = Parser::create(record, &schema_def);
        let pid: u32 = parser.try_parse("ProcessID").unwrap_or(0);
        match event {
            KernelProcessEvent::ProcessStart => {
                on_process_start(record, &parser, pid, &state, sink.as_ref());
            }
            KernelProcessEvent::ProcessEnd => on_process_end(pid, &state),
            KernelProcessEvent::ThreadStart => {
                forward_remote_thread(record, &parser, pid, &state, sink.as_ref());
            }
            KernelProcessEvent::ImageLoad => {
                on_image_load(record, &parser, pid, &state, sink.as_ref());
            }
            KernelProcessEvent::SiloChange => on_silo_change(&parser, &state),
        }
    };
    Provider::by_guid(KERNEL_PROCESS_GUID)
        .any(KERNEL_PROCESS_KEYWORDS)
        .add_callback(callback)
        .build()
}

/// Kernel-Process 1 (`ProcessStart`): records the process in the pid store and forwards it
/// as an [`ExecEvent`](schema::ExecEvent).
fn on_process_start(
    record: &EventRecord,
    parser: &Parser<'_, '_>,
    pid: u32,
    state: &SharedState,
    sink: &dyn EventSink,
) {
    let raw_image: String = parser
        .try_parse("ImageName")
        .unwrap_or_else(|_| String::from(UNKNOWN_IMAGE));
    let process = ProcessStart {
        pid,
        ppid: parser.try_parse("ParentProcessID").unwrap_or(0),
        image_path: state.normalize_path(&raw_image),
        timestamp_ns: normalize::filetime_to_ns(record.raw_timestamp()),
        generation: kernel_process::sequence_number(parser.try_parse("ProcessSequenceNumber").ok()),
        parent_generation: kernel_process::sequence_number(
            parser.try_parse("ParentProcessSequenceNumber").ok(),
        ),
    };
    // https://github.com/synthaea-lab/agent/issues/41: the initial thread of this process is not an injection.
    state
        .threads
        .lock_or_recover()
        .process_started(pid, process.timestamp_ns);
    if cross_process::is_lsass_image(&process.image_path, &state.system_root) {
        take_lsass_slot(parser, pid, process.ppid, &process.image_path, state);
    }
    let parent_image_path = remember_process(&process, state);
    // Read the PEB command line and the image identity (#688) before `meta`: both race the
    // process (a short-lived one exits, a dropper renames itself), `meta` does not.
    let cmdline = winapi::read_process_cmdline(pid);
    let image_file_id = image_file_id(&process.image_path);
    let meta = state.meta(
        pid,
        process.ppid,
        normalize::basename(&process.image_path),
        process.timestamp_ns,
    );
    let context = ExecContext {
        meta,
        parent_image_path,
        cmdline,
        image_file_id,
    };
    sink.on_event(Event::Exec(process.exec_event(context)));
}

/// Puts a started process in the pid store, with the server silo it runs in, and returns
/// its parent's image path (the schema's lineage at exec time: the parent is usually alive
/// and already in the store).
fn remember_process(process: &ProcessStart, state: &SharedState) -> Option<String> {
    // Read while the process most likely still runs (one already gone is in its parent's
    // silo), and before taking the lock: it is a system call.
    let own_silo = winapi::read_server_silo_id(process.pid);
    let mut pids = state.pids.lock_or_recover();
    let silo = silo::exec_silo(own_silo, pids.silo(process.ppid));
    // The silo is kept even without an image, or the process's events would read as the host's.
    match process.cacheable_image() {
        Some(image_path) => {
            pids.insert(process.pid, image_path.to_owned(), process.generation, silo);
        }
        None => pids.insert_without_image(process.pid, process.generation, silo),
    }
    pids.get(process.ppid).map(str::to_owned)
}

/// Which file the image was started from, taken as early as possible: the T1204.002 gate
/// compares it with the file enrichment verifies later, and a dropper can swap the file at
/// its path in between. The open shares delete so it cannot block a rename. Not for a
/// network or device path (see `image_identity_is_capturable`).
fn image_file_id(image_path: &str) -> Option<String> {
    crate::image_identity_is_capturable(image_path)
        .then(|| winapi::image_file_id(std::path::Path::new(image_path)))
        .flatten()
}

/// Kernel-Process 2 (`ProcessEnd`): prunes the pid store, so a recycled pid is not taken
/// for the process that ended.
fn on_process_end(pid: u32, state: &SharedState) {
    if pid == 0 {
        return;
    }
    state.pids.lock_or_recover().remove(pid);
    state.threads.lock_or_recover().process_ended(pid);
    // LSASS does not end short of a crash (and reboot): look it up again rather than leave
    // the slot empty. A copy's end changes nothing.
    state.lsass.process_ended(pid, || find_lsass(state));
}

/// Kernel-Process 5 (`ImageLoad`): forwarded for tracked pids only. The store is seeded at
/// startup and filled by `ProcessStart`, so a missing pid is a kernel or driver load,
/// ignored at the userland tier.
fn on_image_load(
    record: &EventRecord,
    parser: &Parser<'_, '_>,
    pid: u32,
    state: &SharedState,
    sink: &dyn EventSink,
) {
    let Some(comm) = state
        .pids
        .lock_or_recover()
        .get(pid)
        .map(normalize::basename)
    else {
        return;
    };
    let Some(raw_image) = kernel_process::loaded_image(parser.try_parse("ImageFileName").ok())
    else {
        return;
    };
    let image_path = state.normalize_path(&raw_image);
    let timestamp_ns = normalize::filetime_to_ns(record.raw_timestamp());
    // EID 5 carries no parent pid.
    let ppid = 0;
    sink.on_event(Event::ImageLoad(ImageLoadEvent {
        meta: state.meta(pid, ppid, comm, timestamp_ns),
        image_path,
    }));
}

/// Kernel-Process 23-26: a server silo is created or torn down, so whichever container its
/// id named is stale (<https://github.com/synthaea-lab/agent/issues/39>).
fn on_silo_change(parser: &Parser<'_, '_>, state: &SharedState) {
    if let Ok(silo) = parser.try_parse::<u32>("Job ID") {
        state.silos.lock_or_recover().forget(silo);
    }
}

/// <https://github.com/synthaea-lab/agent/issues/41>: a `ProcessStart` of LSASS's image takes the tracked-LSASS slot only when the
/// process is the system LSASS (session 0, started by wininit) and the slot is empty
/// (#1150 review: a copy started by hand must not take it, nor end it).
fn take_lsass_slot(
    parser: &Parser<'_, '_>,
    pid: u32,
    ppid: u32,
    image_path: &str,
    state: &SharedState,
) {
    let session_id = parser.try_parse::<u32>("SessionID").ok();
    let parent_image_path = full_image_path(ppid, state);
    let claim = cross_process::LsassClaim {
        image_path,
        session_id,
        parent_image_path: parent_image_path.as_deref(),
    };
    if state.lsass.process_started(pid, &claim, &state.system_root) {
        tracing::info!(pid, "LSASS started: opens of it are watched");
    } else if state.lsass.pid() != pid {
        tracing::warn!(
            pid,
            ppid,
            session_id,
            tracked = state.lsass.pid(),
            "a process started from LSASS's image is not the system LSASS: not tracked"
        );
    }
}

/// Kernel-Process 3 (`ThreadStart`): forwards a thread started in another user process
/// as a [`RemoteThreadEvent`] (<https://github.com/synthaea-lab/agent/issues/41>, the native Sysmon 8). `owner` is the record's
/// `ProcessID`, the process the thread belongs to; the creator is the header pid.
/// [`cross_process::ThreadOrigins`] drops the own-process, kernel and initial threads;
/// what is left is deduplicated per (creator, owner, start-address bucket) and budgeted
/// per creator, a thread into LSASS excepted from the budget
/// ([`cross_process::admit_remote_thread`]).
///
/// # Field notes (manifest, Windows 11 build 26300, 2026-11-05)
///
/// v0/v1: `ProcessID`, `ThreadID` (u32), `StackBase`, `StackLimit`, `UserStackBase`,
/// `UserStackLimit`, `StartAddr`, `Win32StartAddr`, `TebBase` (pointers); v1 adds
/// `SubProcessTag`.
fn forward_remote_thread(
    record: &EventRecord,
    parser: &Parser<'_, '_>,
    owner: u32,
    state: &SharedState,
    sink: &dyn EventSink,
) {
    let creator = record.process_id();
    let timestamp_ns = normalize::filetime_to_ns(record.raw_timestamp());
    let origin = state
        .threads
        .lock_or_recover()
        .classify(creator, owner, timestamp_ns, || {
            state.pids.lock_or_recover().contains(owner)
                || winapi::process_create_time_ns(owner).is_some_and(|created| {
                    cross_process::created_before_window(created, timestamp_ns)
                })
        });
    if origin != ThreadOrigin::Remote {
        return;
    }
    let pointer = |name: &str| {
        parser
            .try_parse::<Pointer>(name)
            .map_or(0, |p| u64::try_from(*p).unwrap_or(0))
    };
    let start_address =
        cross_process::start_address(pointer("Win32StartAddr"), pointer("StartAddr"));
    let key = cross_process::remote_thread_key(creator, owner, start_address);
    // Lock order: dedup, then budget; neither is taken elsewhere with the other.
    let admitted = cross_process::admit_remote_thread(
        &mut state.remote_threads.lock_or_recover(),
        &mut state.remote_thread_budget.lock_or_recover(),
        &key,
        creator,
        state.lsass.is(owner),
        timestamp_ns,
    );
    if !admitted {
        return;
    }
    let target_image_path = state.pids.lock_or_recover().get(owner).map(str::to_owned);
    let comm = state.comm_for(creator).unwrap_or_default();
    sink.on_event(Event::RemoteThread(RemoteThreadEvent {
        meta: state.meta(creator, 0, comm, timestamp_ns),
        target_pid: owner,
        target_image_path,
        thread_id: parser.try_parse("ThreadID").unwrap_or(0),
        start_address,
    }));
}

/// The full image path of `pid` (an LSASS reader, or LSASS's parent): the pid store's when
/// it holds a path, else a live lookup. The startup seed stores only file names, and a bare
/// name is exactly what a renamed dumper controls, so it is never returned as a path.
fn full_image_path(pid: u32, state: &SharedState) -> Option<String> {
    let cached = state.pids.lock_or_recover().get(pid).map(str::to_owned);
    cached
        .filter(|path| path.contains('\\'))
        .or_else(|| winapi::resolve_pid_live(pid).map(|path| state.normalize_path(&path)))
}

/// Opens of LSASS that can reach its memory (the native Sysmon 10, T1003.001), from
/// Microsoft-Windows-Kernel-Audit-API-Calls EID 5 (`PsOpenProcess`). Every other id, and
/// every open of another process, is dropped first: the target is the filter (see
/// `cross_process` for the rates). An identical open (caller, mask, status) is reported
/// once per minute.
///
/// # Field notes (manifest, Windows 11 build 26300, 2026-11-05)
///
/// EID 5 v0: `TargetProcessId`, `DesiredAccess`, `ReturnCode` (u32). The caller is the
/// record header's pid. No keyword is declared, so the provider is
/// enabled whole and ids 1-8 all reach the callback.
pub(crate) fn audit_api_provider(sink: Arc<dyn EventSink>, state: Arc<SharedState>) -> Provider {
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        if record.event_id() != AUDIT_OPEN_PROCESS {
            return;
        }
        state.events_seen.fetch_add(1, Ordering::Relaxed);
        let lsass = state.lsass.pid();
        if lsass == 0 {
            return;
        }
        let Ok(schema_def) = locator.event_schema(record) else {
            return;
        };
        let parser = Parser::create(record, &schema_def);
        if parser.try_parse::<u32>("TargetProcessId").ok() != Some(lsass) {
            return;
        }
        let caller = record.process_id();
        let desired_access: u32 = parser.try_parse("DesiredAccess").unwrap_or(0);
        if !cross_process::lsass_open_is_reported(caller, lsass, desired_access) {
            return;
        }
        let status: u32 = parser.try_parse("ReturnCode").unwrap_or(0);
        let timestamp_ns = normalize::filetime_to_ns(record.raw_timestamp());
        let key = format!("{caller}:{desired_access:x}:{status:x}");
        if !state
            .lsass_opens
            .lock_or_recover()
            .first(&key, timestamp_ns)
        {
            return;
        }
        let comm = state.comm_for(caller).unwrap_or_default();
        let caller_image_path = full_image_path(caller, &state);
        sink.on_event(Event::ProcessAccess(ProcessAccessEvent {
            meta: state.meta(caller, 0, comm, timestamp_ns),
            caller_image_path,
            target_pid: lsass,
            // The tracked LSASS is only ever a process whose image is this path.
            target_image_path: Some(cross_process::lsass_image(&state.system_root)),
            desired_access,
            status,
        }));
    };

    Provider::by_guid(KERNEL_AUDIT_API_GUID)
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
                meta: state.meta(pid, 0, comm, timestamp_ns),
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
            .lock_or_recover()
            .is_duplicate(pid, sport, daddr, dport, timestamp_ns)
        {
            return;
        }

        let Some(comm) = state.comm_for(pid) else {
            return;
        };
        sink.on_event(Event::Connect(ConnectEvent {
            meta: state.meta(pid, 0, comm, timestamp_ns),
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
        // 12=Create; 30=CreateNewFile; 26=DeletePath, for mark-of-the-web
        // removal only.
        if file_event_keyword(eid).is_none() {
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
        let Some(comm) = state
            .pids
            .lock_or_recover()
            .get(pid)
            .map(normalize::basename)
        else {
            return;
        };
        if eid == 26 {
            forward_mark_removal(&parser, &state, sink.as_ref(), || {
                state.meta(pid, 0, comm, timestamp_ns)
            });
            return;
        }

        let flags = if eid == 30 {
            0o101 // CreateNewFile: create+write by definition
        } else {
            // Create: disposition in the high byte of CreateOptions.
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
        // A create/write on `host:Zone.Identifier` is the mark-of-the-web being
        // written. The stream is read back off this thread.
        let meta = state.meta(pid, 0, comm, timestamp_ns);
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
        .any(FILE_KEYWORDS)
        .add_callback(callback)
        .build()
}

/// Kernel-File 26 (`DeletePath`, `FilePath` field): forwards the deletion of a
/// `:Zone.Identifier` stream (the mark-of-the-web removed, T1553.005) as a
/// `FileDelete` of the stream path. Every other delete is dropped: the minifilter
/// reports deletes.
///
/// The stream check runs on the raw NT path first, so path normalization and the
/// token lookup behind `meta` only run for the rare matching delete, never for the
/// host's whole delete volume on the ETW thread.
///
/// Not distinguished: a disposition call that *clears* delete-on-close. The event
/// does not carry the flag's value.
fn forward_mark_removal(
    parser: &Parser<'_, '_>,
    state: &SharedState,
    sink: &dyn EventSink,
    meta: impl FnOnce() -> EventMeta,
) {
    let raw_path: String = parser.try_parse("FilePath").unwrap_or_default();
    if let Some(removal) =
        zone_identifier::mark_removal(&raw_path, |raw| state.normalize_path(raw), meta)
    {
        sink.on_event(Event::FileDelete(removal));
    }
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
        if let Some(event) = payload::dns_query(&parser, header_meta(record, &state)) {
            sink.on_event(Event::DnsQuery(event));
        }
    };

    Provider::by_guid(DNS_CLIENT_GUID)
        .add_callback(callback)
        .build()
}

/// Registry value writes (EID 5 `SetValueKey`, keyword `SetValueKey`).
///
/// Covers persistence writes to Run keys, IFEO, Services, and Winlogon (T1547,
/// T1546, T1543). Only value writes are enabled: reads (EID 2 `OpenKey`, 4
/// `QueryKey`, 7 `QueryValueKey`) are high-volume noise at userland tier.
///
/// # Field notes (manifest, Windows 11 26300, 2026-11-12)
///
/// EID 5: `KeyName` (the key's NT path, `\REGISTRY\MACHINE\...`, rewritten to
/// `HKLM\...`/`HKU\...`), `ValueName`, `Type` (u32), `DataSize` (u32),
/// `CapturedDataSize` (u16), `CapturedData` (Binary, `CapturedDataSize` bytes).
/// EID 4 is `QueryKey`: until 2026-11-12 the sensor read it as the write
/// (<https://github.com/synthaea-lab/agent/issues/91>), so every key read came out
/// as a `RegistrySet` with no value and no write was seen.
pub(crate) fn registry_provider(sink: Arc<dyn EventSink>, state: Arc<SharedState>) -> Provider {
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        if record.event_id() != REGISTRY_SET_VALUE_KEY_EVENT {
            return;
        }
        state.events_seen.fetch_add(1, Ordering::Relaxed);
        let Ok(schema_def) = locator.event_schema(record) else {
            return;
        };
        let parser = Parser::create(record, &schema_def);
        if let Some(event) = payload::registry_set(&parser, header_meta(record, &state)) {
            sink.on_event(Event::RegistrySet(event));
        }
    };

    Provider::by_guid(KERNEL_REGISTRY_GUID)
        .any(REGISTRY_KEYWORD_SET_VALUE_KEY)
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
        if let Some(event) = payload::script_block(&parser, header_meta(record, &state)) {
            sink.on_event(Event::ScriptBlock(event));
        }
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
            .lock_or_recover()
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
            meta: state.meta(pid, 0, comm, timestamp_ns),
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

/// LDAP searches (EID 30): the directory-reconnaissance fingerprint (#364).
/// Budgeted per process ([`SharedState::ldap`]) but not deduplicated: the
/// burst rule needs the real count of distinct searches.
///
/// # Field notes (manifest + lab, Windows 11 24H2, 2026-10-02)
///
/// `ScopeOfSearch` (u32: 0 base, 1 one level, 2 subtree), `SearchFilter`,
/// `DistinguishedName` (the base), `AttributeList` (`;`-separated),
/// `ProcessId`. Logged when the request is sent: a search to a listener that
/// never answers shows up, a failed connect does not.
pub(crate) fn ldap_provider(sink: Arc<dyn EventSink>, state: Arc<SharedState>) -> Provider {
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        if record.event_id() != 30 {
            return;
        }
        state.events_seen.fetch_add(1, Ordering::Relaxed);
        let Ok(schema_def) = locator.event_schema(record) else {
            return;
        };
        let parser = Parser::create(record, &schema_def);
        let pid = payload::ldap_pid(&parser, record.process_id());
        let timestamp_ns = normalize::filetime_to_ns(record.raw_timestamp());
        if !state.ldap.lock_or_recover().spend(pid, timestamp_ns) {
            return;
        }
        let comm = state.comm_for(pid).unwrap_or_default();
        let meta = state.meta(pid, 0, comm, timestamp_ns);
        sink.on_event(Event::LdapSearch(payload::ldap_search(&parser, meta)));
    };

    Provider::by_guid(LDAP_CLIENT_GUID)
        .add_callback(callback)
        .build()
}

/// NTLM usage (#364): 4020/4021/4026/4027 = this host authenticated out,
/// 4022/4023 = a client authenticated in. Emitted by default on Windows 11
/// 24H2 (lab, 2026-10-02, no audit setting). Deduplicated per (direction,
/// account, target, remote address, version) for a minute: no per-process
/// budget, most of these come from pid 4.
///
/// # Field notes (manifest + lab)
///
/// Outgoing: `ProcessName`, `ProcessPID` (hex string, `0x4`), `Username`,
/// `DomainName`, `TargetService` (`cifs/127.0.0.1`), `TargetMachine`,
/// `TargetIP`, `NtlmVersion` (`NTLMv2`). Incoming adds `ClientIP` and
/// `Status` (`0xc000006d`); "no value" is spelled `Null`/`(NULL)`/`-`. For
/// SMB the process is the kernel (`SYSTEM`, pid 4).
pub(crate) fn ntlm_provider(sink: Arc<dyn EventSink>, state: Arc<SharedState>) -> Provider {
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        let Some(direction) = payload::ntlm_direction(record.event_id()) else {
            return;
        };
        state.events_seen.fetch_add(1, Ordering::Relaxed);
        let Ok(schema_def) = locator.event_schema(record) else {
            return;
        };
        let parser = Parser::create(record, &schema_def);
        let auth = payload::ntlm_auth(direction, &parser);
        let timestamp_ns = normalize::filetime_to_ns(record.raw_timestamp());
        // Deduplicated before the process lookup, so a burst of identical
        // authentications costs one token read, not one per record.
        let key = auth.dedup_key(record.event_id());
        if !state.ntlm.lock_or_recover().first(&key, timestamp_ns) {
            return;
        }
        // Only `NTLMv2` was ever observed; the weak-version rule matches the other
        // spellings loosely. Log any version that is not `NTLMv2` (once per dedup key) so
        // the first real sample of `NTLMv1`/`LM` shows how the provider writes it.
        if !auth.ntlm_version.trim().eq_ignore_ascii_case("NTLMv2") {
            tracing::debug!(version = %auth.ntlm_version, "NTLM version other than NTLMv2");
        }
        let pid = payload::ntlm_pid(&parser, record.process_id());
        let comm = state
            .comm_for(pid)
            .unwrap_or_else(|| payload::ntlm_process_name(&parser));
        let meta = state.meta(pid, 0, comm, timestamp_ns);
        sink.on_event(Event::NtlmAuth(auth.into_event(meta)));
    };

    Provider::by_guid(NTLM_GUID).add_callback(callback).build()
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
        let Some(operation) = payload::WmiOperation::from_id(record.event_id()) else {
            return;
        };
        state.events_seen.fetch_add(1, Ordering::Relaxed);
        let Ok(schema_def) = locator.event_schema(record) else {
            return;
        };
        let parser = Parser::create(record, &schema_def);
        if let Some(event) = payload::wmi_activity(operation, &parser, header_meta(record, &state))
        {
            sink.on_event(Event::WmiActivity(event));
        }
    };

    Provider::by_guid(WMI_ACTIVITY_GUID)
        .add_callback(callback)
        .build()
}

/// In-memory .NET assembly loads (EID 154 — `AssemblyLoad`) from
/// `Microsoft-Windows-DotNETRuntime`.
///
/// Only dynamic (in-memory) assemblies are forwarded (`flags & 0x2 != 0`):
/// file-backed loads are high-volume noise, dynamic loads are rare in legitimate
/// software and mark execute-assembly and fileless .NET injection (T1620, T1055).
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
        if let Some(event) = payload::assembly_load(&parser, header_meta(record, &state)) {
            state.events_seen.fetch_add(1, Ordering::Relaxed);
            sink.on_event(Event::AssemblyLoad(event));
        }
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
        if let Some(event) = payload::smb_connect(&parser, header_meta(record, &state)) {
            state.events_seen.fetch_add(1, Ordering::Relaxed);
            sink.on_event(Event::SmbConnect(event));
        }
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
                .lock_or_recover()
                .completed(&job_id, timestamp_ns, bytes_transferred),
            5 => match client_meta(&parser, &state, timestamp_ns) {
                Some(canceller) => state.bits.lock_or_recover().cancelled(&job_id, &canceller),
                None => {
                    state.bits.lock_or_recover().record_missing_client();
                    Vec::new()
                }
            },
            _ => {
                let hresult: u32 = parser.try_parse("hr").unwrap_or(0);
                let url: Option<String> = parser.try_parse("url").ok();
                state
                    .bits
                    .lock_or_recover()
                    .transfer_error(
                        &job_id,
                        &crate::bits::TransferFailure {
                            url: url.as_deref(),
                            timestamp_ns,
                            bytes_transferred,
                            hresult,
                        },
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
        let mut jobs = state.bits.lock_or_recover();
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
    let mut jobs = state.bits.lock_or_recover();
    let (filtered, evicted) = (jobs.filtered(), jobs.evicted());
    let event = jobs.file_added(
        client,
        crate::bits::AddedFile {
            job_id,
            job_title,
            url,
            local_path,
        },
    );
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

/// The meta of a record about the process in its header: the providers that fire in the
/// calling thread's context (DNS, registry, `PowerShell`, WMI, .NET, SMB).
fn header_meta(record: &EventRecord, state: &SharedState) -> EventMeta {
    let pid = record.process_id();
    let comm = state.comm_for(pid).unwrap_or_default();
    state.meta(
        pid,
        0,
        comm,
        normalize::filetime_to_ns(record.raw_timestamp()),
    )
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
    Some(state.meta(pid, 0, comm, timestamp_ns))
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

#[cfg(test)]
mod process_keyword_tests {
    use super::*;

    /// Guards the constant; whether the provider really keeps ids 3 and 4 out under this
    /// mask is checked against a real session by `tests/kernel_process_keyword_mask.rs`
    /// (`#[ignore]`, elevated; run as part of the lab's elevated Windows validation).
    #[test]
    fn kernel_process_reads_process_thread_image_and_silo_events() {
        const PROCESS: u64 = 0x10;
        const THREAD: u64 = 0x20;
        const IMAGE: u64 = 0x40;
        const JOB_SILO: u64 = 0x4000;
        assert_eq!(KERNEL_PROCESS_KEYWORDS, PROCESS | THREAD | IMAGE | JOB_SILO);
    }
}

#[cfg(test)]
mod file_keyword_tests {
    use super::*;

    /// Guards the table's own arithmetic and that no dispatched id loses its keyword;
    /// it compares the table with literals it also contains, so it cannot tell whether
    /// the manifest really maps these ids to these keywords. That is checked against a
    /// real session by `tests/kernel_file_keyword_mask.rs` (`#[ignore]`, elevated; run
    /// as part of the lab's elevated Windows validation).
    #[test]
    fn every_dispatched_file_event_is_enabled_by_its_keyword() {
        for (event_id, keyword) in FILE_EVENT_KEYWORDS {
            assert_ne!(
                keyword & FILE_KEYWORDS,
                0,
                "Kernel-File EID {event_id} has no enabled keyword"
            );
            assert!(file_event_keyword(event_id).is_some());
        }
        assert_eq!(FILE_KEYWORDS, 0x80 | 0x400 | 0x1000);
        assert_eq!(file_event_keyword(10), None, "NameCreate is not handled");
    }
}
