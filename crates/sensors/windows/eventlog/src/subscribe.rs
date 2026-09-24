//! Push-based transport for the Event Log sensor via `EvtSubscribe` (issue
//! #322). The default remains `Polling` (`sensor.rs`), see `EventLogTransport`
//! for the switch; this module is the alternative that removes the 2s poll
//! cadence, the `wevtutil` subprocess spawn per tick, and the "did we miss a
//! rotation" edge case — the OS delivers each matching event directly to a
//! callback the moment it lands in the channel.
//!
//! ## Shape
//!
//! One `EvtSubscribe` call per enabled [`PollTarget`], each with:
//! - the target's `channel` + `id_filter` wrapped into the `*[System[...]]`
//!   `XPath` the polling code already builds
//! - a per-target callback that renders the event to XML with `EvtRender`,
//!   hands the XML to the same `target.parse_block` used by the polling code,
//!   increments the same counter, and dispatches to the same sink — so
//!   normalization, counters, and downstream consumers are identical between
//!   the two transports (only the delivery mechanism differs)
//!
//! The callback runs on a Windows thread-pool thread the caller does not
//! control, so the shared state must be `Send + Sync` — which the sensor's
//! `Arc<dyn EventSink>` / `Arc<EventLogCounters>` / `Arc<AtomicBool>` already
//! are.
//!
//! ## Lifetime
//!
//! [`subscribe`] returns a [`SubscriptionHandle`] that owns both the
//! `EVT_HANDLE` and the `Box<CallbackContext>` the OS holds a raw pointer to.
//! Dropping the handle closes the subscription (`EvtClose`) **before**
//! reclaiming the boxed context, in that order — otherwise the OS could
//! deliver one last callback into freed memory. See the `Drop` impl for the
//! ordering commentary.
//!
//! ## No `EvtRender` rewrite of the parser layer
//!
//! `EvtRender` with `EvtRenderEventXml` returns the exact same UTF-16 XML shape
//! `wevtutil qe /f:xml` produces (both wrap the underlying Event Log reader
//! API). So `xml::parse_service_install_block` and its siblings are reused
//! verbatim — the substring-based parsing that felt fragile under polling is
//! the same substring-based parsing that works under push, unchanged.

#![cfg(windows)]

use std::{
    ffi::c_void,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use schema::sensor::EventSink;
use windows_sys::Win32::{
    Foundation::{ERROR_SUCCESS, GetLastError},
    System::EventLog::{
        EVT_HANDLE, EVT_SUBSCRIBE_NOTIFY_ACTION, EvtClose, EvtRender, EvtRenderEventXml,
        EvtSubscribe, EvtSubscribeActionDeliver, EvtSubscribeToFutureEvents,
    },
};

use crate::sensor::{EventLogCounters, PollTarget};

/// State shared between one subscription's `EvtSubscribe` call and the
/// callback thread the OS invokes for every event it delivers. Passed to the
/// OS as an opaque `*const c_void` and reconstructed inside the callback.
///
/// The struct is deliberately `Send + Sync` by construction: every field is
/// either `'static` or an `Arc`, matching the same shared-state pattern the
/// ETW sensor's provider callbacks use.
struct CallbackContext {
    target: &'static PollTarget,
    sink: Arc<dyn EventSink>,
    counters: Arc<EventLogCounters>,
    stop: Arc<AtomicBool>,
}

/// The C-ABI callback invoked by the OS for every matching event on the
/// channel. Returns `ERROR_SUCCESS` (0) to keep the subscription alive; any
/// non-zero return code terminates the subscription — which we never want
/// here, since a single malformed event should not stop the whole channel
/// (matches the polling code's "unparseable block advances the cursor" stance).
///
/// # Safety
///
/// - `user_context` is the `*const c_void` we handed to `EvtSubscribe` (a
///   `Box::into_raw(Box<CallbackContext>)`), still valid because we drop the
///   handle before reclaiming the box.
/// - `event_handle` is only valid for the duration of this call; we render
///   it and drop the reference before returning.
/// - The OS invokes this from an internal thread-pool worker — the callback
///   MUST be `Send`. Every captured value is `Arc` (or `'static`), so it is.
unsafe extern "system" fn subscribe_callback(
    action: EVT_SUBSCRIBE_NOTIFY_ACTION,
    user_context: *const c_void,
    event_handle: EVT_HANDLE,
) -> u32 {
    // The API delivers two action codes: `Deliver` for a real event and
    // `Error` for a subscription-level problem (channel gone, permissions
    // lost). We only normalize on `Deliver`; an `Error` is logged and the
    // subscription is left running — Windows will resume delivery on its own
    // once the transient condition clears, and we would rather see silence in
    // the metrics than crash the whole sensor on one hiccup.
    if action != EvtSubscribeActionDeliver {
        tracing::warn!(
            action = action,
            "EvtSubscribe callback received a non-Deliver action — subscription kept open, event skipped"
        );
        return ERROR_SUCCESS;
    }

    // SAFETY: `user_context` is the raw pointer we produced from
    // `Box::into_raw` in `subscribe` below; the box is kept alive by the
    // `SubscriptionHandle` this callback's subscription is tied to.
    let ctx = unsafe { &*(user_context as *const CallbackContext) };

    // Shutdown fast-path: once `stop` is signaled, the sensor's `run` loop
    // will drop the `SubscriptionHandle` shortly (`EvtClose`), but between
    // "stop was set" and "handle was dropped" the OS may still deliver a few
    // more events. Discarding them here keeps the sink from receiving events
    // for a sensor the caller has already asked to wind down.
    if ctx.stop.load(Ordering::SeqCst) {
        return ERROR_SUCCESS;
    }

    // SAFETY: `event_handle` is the OS-provided handle valid for the
    // duration of this callback. `render_event_xml` uses it only within its
    // own call and does not retain it.
    let Some(xml) = (unsafe { render_event_xml(event_handle) }) else {
        // Render failure: not much we can do besides log and skip — the
        // event handle is only valid within this call, so we cannot retry
        // later.
        tracing::warn!(
            target = ctx.target.label,
            "EvtRender failed — event dropped"
        );
        return ERROR_SUCCESS;
    };

    // `record_id` only drives the polling transport's `EventRecordID` cursor;
    // a push subscription has no cursor to advance, so it is ignored here.
    if let Some((_record_id, Some(event))) = (ctx.target.parse_block)(&xml) {
        // Same counter-then-sink order as the polling loop, so the two
        // transports produce identical metric traces given identical input.
        (ctx.target.counter)(&ctx.counters).fetch_add(1, Ordering::Relaxed);
        ctx.sink.on_event(event);
    }

    ERROR_SUCCESS
}

/// Renders one event handle to its `EvtRenderEventXml` string. Uses the
/// standard two-call `EvtRender` pattern: the first call probes the required
/// buffer size (returns `FALSE` with `GetLastError() == ERROR_INSUFFICIENT_BUFFER`,
/// and writes the needed size into `used`), the second call performs the
/// actual render into a properly sized buffer.
///
/// Returns `None` on any failure — the caller treats it the same as a
/// parser-level unparseable block (skip, keep subscription).
///
/// # Safety
///
/// `event_handle` must be a valid `EVT_HANDLE` for the duration of the call
/// (guaranteed by the OS within the callback scope).
unsafe fn render_event_xml(event_handle: EVT_HANDLE) -> Option<String> {
    let mut used: u32 = 0;
    let mut property_count: u32 = 0;

    // Probe: intentional zero-sized buffer to make the API report the needed
    // size. Return value ignored — this call is expected to fail with
    // `ERROR_INSUFFICIENT_BUFFER`; what we care about is the `used` output.
    // SAFETY: `event_handle` is a valid OS handle for this call. All buffer
    // pointers are either null (`buffer`, deliberately, since we probe) or
    // point to stack locals whose lifetimes cover the call.
    unsafe {
        EvtRender(
            0,
            event_handle,
            EvtRenderEventXml,
            0,
            std::ptr::null_mut(),
            &mut used,
            &mut property_count,
        );
    }
    if used == 0 {
        return None;
    }

    // `used` is in BYTES (per API contract), the buffer content is UTF-16 —
    // so allocate `used / 2` `u16` slots. Rounding up to be safe on an odd
    // byte count (should not happen for a NUL-terminated UTF-16 string, but
    // cheap defensive move).
    let word_count = (used as usize).div_ceil(2);
    let mut buffer: Vec<u16> = vec![0; word_count];

    // SAFETY: `event_handle` is a valid OS handle for this call. `buffer`
    // is sized to `word_count` `u16`s (i.e. at least `used` bytes as reported
    // by the probe call), and the buffer plus the two out-pointers all live
    // in this stack frame for the duration of the call.
    let ok = unsafe {
        EvtRender(
            0,
            event_handle,
            EvtRenderEventXml,
            used,
            buffer.as_mut_ptr().cast::<c_void>(),
            &mut used,
            &mut property_count,
        )
    };
    if ok == 0 {
        return None;
    }

    // Trim at the first NUL (the API returns a NUL-terminated string).
    let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    Some(String::from_utf16_lossy(&buffer[..len]))
}

/// Owns a live `EvtSubscribe` subscription and the boxed callback context the
/// OS holds a raw pointer to. Dropping this handle tears both down in the
/// correct order (subscription first, then the boxed context — see `Drop`).
pub(crate) struct SubscriptionHandle {
    handle: EVT_HANDLE,
    /// Raw pointer to the leaked `Box<CallbackContext>`. Reclaimed in `Drop`.
    ctx: *mut CallbackContext,
}

// SAFETY: `SubscriptionHandle` owns an `EVT_HANDLE` (an opaque OS handle, safe
// to close from any thread) and a `Box<CallbackContext>` whose fields are all
// `Send + Sync`. The raw pointer to the box is only ever dereferenced by the
// OS-owned callback thread and by our own `Drop`, never concurrently, so
// declaring the wrapper `Send + Sync` is sound. This is the same pattern the
// ETW sensor's provider handles use.
unsafe impl Send for SubscriptionHandle {}
// SAFETY: same reasoning as the `Send` impl above — every owned field is
// itself `Sync`, and the raw pointer is never dereferenced concurrently.
unsafe impl Sync for SubscriptionHandle {}

impl Drop for SubscriptionHandle {
    fn drop(&mut self) {
        // ORDER MATTERS: close the subscription BEFORE reclaiming the box.
        // `EvtClose` is synchronous — it waits for any in-flight callback to
        // finish before returning. Reclaiming the box first would let a
        // running callback dereference freed memory in that window.
        // SAFETY: `self.handle` was returned by `EvtSubscribe` in the
        // `subscribe` fn below and has not been closed anywhere else; this
        // `Drop` runs at most once per handle.
        unsafe {
            EvtClose(self.handle);
        }
        // SAFETY: `self.ctx` was produced by `Box::into_raw` in `subscribe`
        // below, and no callback can be running after `EvtClose` returns.
        drop(unsafe { Box::from_raw(self.ctx) });
    }
}

/// Registers one `EvtSubscribe` subscription for `target`. Returns `None`
/// when `EvtSubscribe` refuses to register (channel disabled by policy, no
/// permission on the channel, invalid `XPath`) — the caller logs and continues
/// without that target, same failure mode as an `enable_audit` call that
/// fails: one channel is degraded, the rest of the sensor keeps running.
///
/// The returned [`SubscriptionHandle`] must be kept alive for the duration
/// the caller wants the subscription active; dropping it closes the
/// subscription.
pub(crate) fn subscribe(
    target: &'static PollTarget,
    sink: Arc<dyn EventSink>,
    counters: Arc<EventLogCounters>,
    stop: Arc<AtomicBool>,
) -> Option<SubscriptionHandle> {
    // Wrap the target's `id_filter` in the same `*[System[...]]` XPath shape
    // the polling code builds — one place to maintain the query syntax.
    let query = format!("*[System[({})]]", target.id_filter);

    // Windows API takes UTF-16 NUL-terminated strings.
    let channel_wide: Vec<u16> = target
        .channel
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let query_wide: Vec<u16> = query.encode_utf16().chain(std::iter::once(0)).collect();

    // Leak the context into a raw pointer for the API to hold onto. We
    // reclaim it in `SubscriptionHandle::Drop` after `EvtClose` returns.
    let ctx_box = Box::new(CallbackContext {
        target,
        sink,
        counters,
        stop,
    });
    let ctx_raw: *mut CallbackContext = Box::into_raw(ctx_box);

    // SAFETY: all pointers point to memory we own for the call; `channel_wide`
    // and `query_wide` outlive the call because we own them on this stack
    // frame until it returns (and `EvtSubscribe` copies the strings on its
    // side). `ctx_raw` outlives the subscription because the returned handle
    // holds it until Drop.
    let handle = unsafe {
        EvtSubscribe(
            0,                    // no session (local host)
            std::ptr::null_mut(), // no signal event — deliver via callback
            channel_wide.as_ptr(),
            query_wide.as_ptr(),
            0, // no bookmark: start from "future events"
            ctx_raw.cast::<c_void>(),
            Some(subscribe_callback),
            EvtSubscribeToFutureEvents,
        )
    };

    if handle == 0 {
        // Retrieve the failure reason and log it; then reclaim the context we
        // leaked, since no callback will ever fire to consume it.
        // SAFETY: `GetLastError` is thread-local and has no
        // preconditions.
        let last_error = unsafe { GetLastError() };
        tracing::warn!(
            target = target.label,
            error = last_error,
            "EvtSubscribe failed to register — channel skipped, other targets keep running"
        );
        // SAFETY: `ctx_raw` was produced by `Box::into_raw` a few lines
        // above and never handed to any other owner (`EvtSubscribe` did not
        // accept it).
        drop(unsafe { Box::from_raw(ctx_raw) });
        return None;
    }

    Some(SubscriptionHandle {
        handle,
        ctx: ctx_raw,
    })
}
