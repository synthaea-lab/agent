//! The polling transport's read of a channel: `EvtQuery` + `EvtNext` + `EvtRender`, each
//! event rendered to its XML as UTF-16 (#1126).
//!
//! The poll loop used to run `wevtutil qe` and decode its stdout. With stdout redirected,
//! `wevtutil` writes in the system ANSI code page, so a character that code page cannot hold
//! (a Cyrillic or CJK account name on a Windows-1252 host) was already `?` before this crate
//! saw a byte, and two accounts whose names differ only there became the same string. Reading
//! the channel through the API gets the same XML the `Subscribe` transport renders, in UTF-16,
//! with nothing to guess and no process spawned per poll.

use windows_sys::Win32::{
    Foundation::{ERROR_NO_MORE_ITEMS, GetLastError},
    System::EventLog::{
        EVT_HANDLE, EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryForwardDirection,
        EvtQueryReverseDirection,
    },
};

use crate::subscribe::render_event_xml;

/// How long one `EvtNext` may wait for the service. A local channel query answers in
/// milliseconds; a call that hangs this long fails the poll tick, which the loop retries, rather
/// than freezing the target's thread for good.
const NEXT_TIMEOUT_MS: u32 = 30_000;

/// Event handles fetched per `EvtNext` call.
const BATCH: u32 = 64;

/// Which end of the channel a query starts from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Direction {
    /// Oldest first.
    Forward,
    /// Newest first.
    Reverse,
}

/// Closes an `EVT_HANDLE` when dropped.
struct Handle(EVT_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a non-null handle returned by `EvtQuery` or `EvtNext`, owned by
        // this guard alone and closed nowhere else.
        unsafe {
            EvtClose(self.0);
        }
    }
}

/// The XML of every event in `channel` matching `xpath`, in `direction` order, at most `limit`
/// of them (`None`: all).
///
/// A query that matches nothing is `Ok` and empty. A query that is refused (Security without
/// admin rights), names no channel, or is not valid `XPath` is an error, so a blinded channel
/// never looks like a quiet one (#388). An event that matches but cannot be rendered is left
/// out, like an unparseable block: the `Subscribe` transport does the same.
///
/// # Errors
/// Why `EvtQuery` or `EvtNext` failed, with its Win32 error code.
pub(crate) fn query_events(
    channel: &str,
    xpath: &str,
    direction: Direction,
    limit: Option<usize>,
) -> Result<Vec<String>, String> {
    let channel_wide: Vec<u16> = channel.encode_utf16().chain(std::iter::once(0)).collect();
    let query_wide: Vec<u16> = xpath.encode_utf16().chain(std::iter::once(0)).collect();
    let flags = EvtQueryChannelPath
        | match direction {
            Direction::Forward => EvtQueryForwardDirection,
            Direction::Reverse => EvtQueryReverseDirection,
        };
    // SAFETY: both strings are NUL-terminated UTF-16 buffers that live on this frame for the
    // whole call; session 0 is the local host.
    let results = unsafe { EvtQuery(0, channel_wide.as_ptr(), query_wide.as_ptr(), flags) };
    if results == 0 {
        // SAFETY: no precondition; read right after the call that failed.
        let error = unsafe { GetLastError() };
        return Err(format!(
            "EvtQuery on {channel} failed with Win32 error {error}"
        ));
    }
    let results = Handle(results);

    let limit = limit.unwrap_or(usize::MAX);
    let mut blocks = Vec::new();
    while blocks.len() < limit {
        let mut raw = [0isize; BATCH as usize];
        let want = u32::try_from(limit - blocks.len()).map_or(BATCH, |left| left.min(BATCH));
        let mut returned: u32 = 0;
        // SAFETY: `raw` holds `BATCH` writable handle slots and `want <= BATCH` is passed as its
        // size; `returned` is a live local. `results` is an open result set.
        let ok = unsafe {
            EvtNext(
                results.0,
                want,
                raw.as_mut_ptr(),
                NEXT_TIMEOUT_MS,
                0,
                &mut returned,
            )
        };
        if ok == 0 {
            // SAFETY: no precondition; read right after the call that failed.
            let error = unsafe { GetLastError() };
            if error == ERROR_NO_MORE_ITEMS {
                break;
            }
            return Err(format!(
                "EvtNext on {channel} failed with Win32 error {error}"
            ));
        }
        let fetched = returned.min(want) as usize;
        // Every handle `EvtNext` returned is owned from here on, so each is closed even if an
        // earlier one fails to render.
        let events: Vec<Handle> = raw[..fetched].iter().map(|&h| Handle(h)).collect();
        for event in &events {
            // SAFETY: `event.0` is an event handle from the `EvtNext` call above, open until its
            // guard drops at the end of this iteration of the outer loop.
            match unsafe { render_event_xml(event.0) } {
                Some(xml) => blocks.push(xml),
                None => tracing::debug!(channel, "EvtRender failed, event skipped"),
            }
        }
        if fetched == 0 {
            break;
        }
    }
    Ok(blocks)
}
