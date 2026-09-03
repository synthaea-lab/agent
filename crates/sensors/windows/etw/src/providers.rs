//! The three ETW provider callbacks (Kernel-Process, Kernel-Network, Kernel-File),
//! each normalizing its records into schema events. Lab-earned notes carry over
//! from the old iteration: `TcpClient` emits no eid=42 (2026-08-25), PID recycling
//! prunes on `ProcessEnd`, canary events are filtered from emission.

use std::sync::{Arc, atomic::Ordering};

use ferrisetw::{EventRecord, parser::Parser, provider::Provider, schema_locator::SchemaLocator};
use schema::{ConnectEvent, Event, ExecEvent, FileOpenEvent, sensor::EventSink};

use crate::sensor::{SharedState, basename, meta};
use crate::{normalize, winapi};

const KERNEL_PROCESS_GUID: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const KERNEL_NETWORK_GUID: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";
const KERNEL_FILE_GUID: &str = "edd08927-9cc4-4e65-b970-c2560fb5c289";

pub(crate) fn process_provider(sink: Arc<dyn EventSink>, state: Arc<SharedState>) -> Provider {
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        let eid = record.event_id();
        // 1=ProcessStart (new spawn → ExecEvent), 2=ProcessEnd (prune the store —
        // PID recycling), 3=ProcessDCStart (rundown of already-running processes →
        // store only, not a spawn).
        if eid != 1 && eid != 2 && eid != 3 {
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
                state.pids.lock().unwrap().remove(&pid);
            }
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
        let parent_image_path = state.pids.lock().unwrap().get(&ppid).cloned();
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
        let Some(comm) = ({
            let pids = state.pids.lock().unwrap();
            pids.get(&pid).map(|p| basename(p))
        }) else {
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
        sink.on_event(Event::FileOpen(FileOpenEvent {
            meta: meta(pid, 0, comm, timestamp_ns),
            path,
            flags,
        }));
    };
    Provider::by_guid(KERNEL_FILE_GUID)
        .add_callback(callback)
        .build()
}
