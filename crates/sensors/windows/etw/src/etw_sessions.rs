//! Which ETW sessions enable our providers, from the OS itself (#408). Read
//! only when our session went blind: a foreign real-time session nobody
//! consumes stalls real-time delivery for every consumer on the host (lab,
//! 2026-10-01), so naming it is what the operator needs. Best-effort: any API
//! failure yields fewer entries, never an error.

use windows_sys::{
    Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_SUCCESS},
        System::Diagnostics::Etw::{
            EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, EnumerateTraceGuidsEx,
            QueryAllTracesW, TRACE_ENABLE_INFO, TRACE_GUID_INFO, TRACE_PROVIDER_INSTANCE_INFO,
            TraceGuidQueryInfo,
        },
    },
    core::GUID,
};

use crate::normalize::SessionStats;

/// Room after each `EVENT_TRACE_PROPERTIES` for the logger and log-file names
/// (`MAX_PATH`-ish UTF-16 each, generous).
const NAME_BYTES: usize = 1024 * 2;
/// `QueryAllTracesW` accepts at most 64 sessions on current Windows.
pub(crate) const MAX_SESSIONS: usize = 64;

/// "22fb2cd6-0e7b-..." → GUID; `None` on a malformed constant.
fn parse_guid(text: &str) -> Option<GUID> {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    (hex.len() == 32)
        .then(|| u128::from_str_radix(&hex, 16).ok())
        .flatten()
        .map(GUID::from_u128)
}

/// Every session enabling each of `providers` (name, GUID text), as
/// (provider name, logger id, level, match-any keyword).
pub(crate) fn provider_enablements(
    providers: &[(&'static str, &str)],
) -> Vec<(&'static str, u16, u8, u64)> {
    let mut out = Vec::new();
    for &(name, guid_text) in providers {
        let Some(guid) = parse_guid(guid_text) else {
            continue;
        };
        // u64 backing: TRACE_ENABLE_INFO holds u64 fields.
        let mut buf: Vec<u64> = vec![0; 512];
        let mut needed = 0u32;
        let mut status;
        loop {
            let size = u32::try_from(buf.len() * 8).unwrap_or(u32::MAX);
            // SAFETY: the in-buffer is one GUID we own; the out-buffer is a
            // live allocation of `size` bytes; `needed` is a valid u32 out-param.
            status = unsafe {
                EnumerateTraceGuidsEx(
                    TraceGuidQueryInfo,
                    std::ptr::from_ref(&guid).cast(),
                    u32::try_from(size_of::<GUID>()).unwrap_or(16),
                    buf.as_mut_ptr().cast(),
                    size,
                    &raw mut needed,
                )
            };
            if status == ERROR_INSUFFICIENT_BUFFER && (needed as usize) > buf.len() * 8 {
                buf = vec![0; (needed as usize).div_ceil(8)];
                continue;
            }
            break;
        }
        if status != ERROR_SUCCESS {
            continue; // not registered / no session: nothing to report
        }
        let bytes = buf.len() * 8;
        let base = buf.as_ptr().cast::<u8>();
        let read_at = |offset: usize, len: usize| offset + len <= bytes;
        if !read_at(0, size_of::<TRACE_GUID_INFO>()) {
            continue;
        }
        // SAFETY: bounds checked just above; read_unaligned tolerates any
        // alignment the OS chose for the packed records.
        let info = unsafe { base.cast::<TRACE_GUID_INFO>().read_unaligned() };
        let mut offset = size_of::<TRACE_GUID_INFO>();
        for _ in 0..info.InstanceCount {
            if !read_at(offset, size_of::<TRACE_PROVIDER_INSTANCE_INFO>()) {
                break;
            }
            // SAFETY: bounds checked just above.
            let instance = unsafe {
                base.add(offset)
                    .cast::<TRACE_PROVIDER_INSTANCE_INFO>()
                    .read_unaligned()
            };
            let mut enable_at = offset + size_of::<TRACE_PROVIDER_INSTANCE_INFO>();
            for _ in 0..instance.EnableCount {
                if !read_at(enable_at, size_of::<TRACE_ENABLE_INFO>()) {
                    break;
                }
                // SAFETY: bounds checked just above.
                let enable = unsafe {
                    base.add(enable_at)
                        .cast::<TRACE_ENABLE_INFO>()
                        .read_unaligned()
                };
                // Each process registering the provider is an instance listing
                // the same sessions: keep one entry per (provider, session).
                let entry = (name, enable.LoggerId, enable.Level, enable.MatchAnyKeyword);
                if !out.contains(&entry) {
                    out.push(entry);
                }
                enable_at += size_of::<TRACE_ENABLE_INFO>();
            }
            if instance.NextOffset == 0 {
                break;
            }
            offset += instance.NextOffset as usize;
        }
    }
    out
}

/// Every running session returned by `QueryAllTracesW` and whether the fixed
/// API buffer may have hidden additional sessions.
pub(crate) struct RunningSessions {
    pub(crate) entries: Vec<(u16, SessionStats)>,
    pub(crate) possibly_truncated: bool,
}

/// Enumerates running sessions. `ERROR_MORE_DATA` still returns the entries
/// that fit, but the caller must treat the list as incomplete.
pub(crate) fn running_sessions() -> Result<RunningSessions, u32> {
    let stride = size_of::<EVENT_TRACE_PROPERTIES>() + 2 * NAME_BYTES;
    // u64 backing keeps each EVENT_TRACE_PROPERTIES 8-aligned (stride is a
    // multiple of 8: the struct is, and NAME_BYTES is).
    let mut buf: Vec<u64> = vec![0; MAX_SESSIONS * stride / 8];
    let base = buf.as_mut_ptr().cast::<u8>();
    let mut ptrs: Vec<*mut EVENT_TRACE_PROPERTIES> = Vec::with_capacity(MAX_SESSIONS);
    for i in 0..MAX_SESSIONS {
        // SAFETY: i * stride + stride <= buf's byte length by construction.
        let p = unsafe { base.add(i * stride) }.cast::<EVENT_TRACE_PROPERTIES>();
        // SAFETY: p is 8-aligned, in bounds, and zero-initialised memory we own.
        unsafe {
            (*p).Wnode.BufferSize = u32::try_from(stride).unwrap_or(u32::MAX);
            (*p).LoggerNameOffset = u32::try_from(size_of::<EVENT_TRACE_PROPERTIES>()).unwrap_or(0);
            (*p).LogFileNameOffset =
                u32::try_from(size_of::<EVENT_TRACE_PROPERTIES>() + NAME_BYTES).unwrap_or(0);
        }
        ptrs.push(p);
    }
    let mut count = 0u32;
    // SAFETY: `ptrs` holds MAX_SESSIONS valid, sized property blocks living in `buf`.
    let status = unsafe {
        QueryAllTracesW(
            ptrs.as_mut_ptr(),
            u32::try_from(MAX_SESSIONS).unwrap_or(64),
            &raw mut count,
        )
    };
    if status != ERROR_SUCCESS && status != ERROR_MORE_DATA {
        return Err(status);
    }
    let mut out = Vec::new();
    for &p in ptrs.iter().take(count as usize) {
        // SAFETY: the OS filled the first `count` blocks; the name sits at
        // LoggerNameOffset inside the block's NAME_BYTES, NUL-terminated (the
        // scan is bounded by NAME_BYTES anyway).
        let (props, name) = unsafe {
            let props = &*p;
            let name_ptr = p
                .cast::<u8>()
                .add(props.LoggerNameOffset as usize)
                .cast::<u16>();
            let units = std::slice::from_raw_parts(name_ptr, NAME_BYTES / 2);
            let len = units.iter().position(|&u| u == 0).unwrap_or(units.len());
            (props, String::from_utf16_lossy(&units[..len]))
        };
        // SAFETY: HistoricalContext is the union member QueryAllTraces fills
        // with the session handle; its low 16 bits are the logger id.
        let logger_id = unsafe { props.Wnode.Anonymous1.HistoricalContext } as u16;
        out.push((
            logger_id,
            SessionStats {
                name,
                real_time: props.LogFileMode & EVENT_TRACE_REAL_TIME_MODE != 0,
                buffers_written: props.BuffersWritten,
                events_lost: props.EventsLost,
                real_time_buffers_lost: props.RealTimeBuffersLost,
                log_buffers_lost: props.LogBuffersLost,
            },
        ));
    }
    Ok(RunningSessions {
        entries: out,
        possibly_truncated: status == ERROR_MORE_DATA || count as usize >= MAX_SESSIONS,
    })
}
