//! The macOS `Sensor` implementation: owns the `EndpointSecurity` client
//! (through the C shim), converts flattened messages to raw records, and
//! pushes normalized events into the sink.
//!
//! Threading: `es_new_client` spins up its own dispatch threads that invoke
//! the handler; `run` itself just creates the client, subscribes, and parks
//! until [`MacosSensor::stop`] (or a stop handle) fires. The client is created
//! and destroyed on the `run` thread — a libEndpointSecurity requirement.

use std::{
    ffi::c_void,
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};

use schema::sensor::{Capabilities, EventSink, Sensor, SensorError};

use crate::{ffi, normalize::normalize};

/// Errors surfaced by [`MacosSensor::run`]. The `es_new_client` failures each
/// carry the operator action that fixes them — an ES client that cannot start
/// has exactly three fixable causes, and "error 3" helps nobody.
#[derive(Debug, thiserror::Error)]
pub enum MacosSensorError {
    #[error(
        "EndpointSecurity refused the client: this binary is not entitled \
         (com.apple.developer.endpoint-security.client). Sign it with the ES \
         entitlement — see docs/sensors/macos.md for the dev-signing path."
    )]
    NotEntitled,
    #[error(
        "EndpointSecurity refused the client: not permitted. Grant the binary \
         Full Disk Access (System Settings → Privacy & Security) — TCC gates \
         ES clients behind it."
    )]
    NotPermitted,
    #[error("EndpointSecurity refused the client: not privileged. Run the agent as root.")]
    NotPrivileged,
    #[error("EndpointSecurity refused the client (es_new_client_result_t = {0})")]
    ClientCreation(i32),
    #[error("es_subscribe failed (es_return_t = {0})")]
    Subscribe(i32),
}

/// Pairs the flag with a condvar so `run` parks instead of polling, and
/// `stop` wakes it immediately.
struct StopSignal {
    stopped: Mutex<bool>,
    condvar: Condvar,
}

/// Cloneable handle that stops a running [`MacosSensor`] from another thread
/// (Ctrl-C handler, watchdog).
#[derive(Clone)]
pub struct StopHandle {
    signal: Arc<StopSignal>,
}

impl StopHandle {
    pub fn stop(&self) {
        // A poisoned lock means a waiter panicked mid-wait; stopping must
        // still work, so take the guard either way.
        let mut stopped = self
            .signal
            .stopped
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *stopped = true;
        self.signal.condvar.notify_all();
    }
}

/// Context handed to the C callback for the client's lifetime.
struct CallbackCtx {
    sink: Box<dyn EventSink>,
}

/// Trampoline invoked by the shim on an `EndpointSecurity` dispatch thread.
/// Panics must not unwind into C (that aborts the agent), so the whole body is
/// caught — a detection-side bug costs the one event, loudly, not the sensor.
unsafe extern "C" fn on_event(ctx: *mut c_void, event: *const ffi::SynEsEvent) {
    let result = std::panic::catch_unwind(|| {
        // SAFETY: `ctx` is the `Box<CallbackCtx>` leaked in `run`, alive until
        // after `syn_es_client_destroy` returns (which synchronizes with
        // in-flight handlers); `event` is valid for this callback per the shim
        // contract.
        let ctx = unsafe { &*ctx.cast_const().cast::<CallbackCtx>() };
        // SAFETY: `event` and every string it references are valid until this
        // callback returns; `to_raw` copies them out.
        let raw = unsafe { (*event).to_raw() };
        if let Some(raw) = raw
            && let Some(normalized) = normalize(&raw)
        {
            ctx.sink.on_event(normalized);
        }
    });
    if result.is_err() {
        tracing::error!("event handler panicked; one event dropped");
    }
}

/// The `EndpointSecurity` sensor (issue #32): process exec with code-signing
/// state, file open/create/rename/unlink, writable shared mmaps, and BTM
/// launch-item persistence — normalized into `schema` events.
pub struct MacosSensor {
    signal: Arc<StopSignal>,
}

impl MacosSensor {
    #[must_use]
    pub fn new() -> Self {
        MacosSensor {
            signal: Arc::new(StopSignal {
                stopped: Mutex::new(false),
                condvar: Condvar::new(),
            }),
        }
    }

    /// Handle for stopping the sensor from another thread (Ctrl-C, watchdog).
    #[must_use]
    pub fn stop_handle(&self) -> StopHandle {
        StopHandle {
            signal: Arc::clone(&self.signal),
        }
    }
}

impl Default for MacosSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl Sensor for MacosSensor {
    fn name(&self) -> &str {
        "macos-endpoint-security"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            exec_events: true,
            file_events: true,
            // Network visibility is sensor-macos-network-extension (#33); ES
            // itself carries none (unix-socket events aside).
            connect_events: false,
            // Login/session events arrive with the ES widening (#96).
            auth_events: false,
            user_attribution: true,
            parent_lineage: true,
        }
    }

    fn run(&mut self, sink: Box<dyn EventSink>) -> Result<(), SensorError> {
        // Reset so the sensor is re-runnable after a stop.
        *self
            .signal
            .stopped
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = false;

        let ctx = Box::into_raw(Box::new(CallbackCtx { sink }));
        let mut client: *mut ffi::SynEsClient = std::ptr::null_mut();
        // SAFETY: `on_event` matches the callback ABI; `ctx` outlives the
        // client (freed below, after destroy).
        let result = unsafe { ffi::syn_es_client_new(on_event, ctx.cast::<c_void>(), &mut client) };
        if result != 0 {
            // SAFETY: on failure the shim never stored `ctx`; reclaim it.
            drop(unsafe { Box::from_raw(ctx) });
            return Err(Box::new(match result {
                3 => MacosSensorError::NotEntitled,
                4 => MacosSensorError::NotPermitted,
                5 => MacosSensorError::NotPrivileged,
                other => MacosSensorError::ClientCreation(other),
            }));
        }

        // Best-effort: the agent's own file writes (spool, alerts) must not
        // feed back into the pipeline. Failure is loud but not fatal — the
        // sensor still observes everything else correctly.
        // SAFETY: `client` is the live client created above.
        if unsafe { ffi::syn_es_mute_self(client) } != 0 {
            tracing::warn!("es_mute_process(self) failed; expect self-generated file events");
        }

        let groups =
            ffi::SYN_ES_GROUP_EXEC | ffi::SYN_ES_GROUP_FILE | ffi::SYN_ES_GROUP_PERSISTENCE;
        // SAFETY: `client` is the live client created above.
        let sub = unsafe { ffi::syn_es_subscribe(client, groups) };
        if sub != 0 {
            // SAFETY: created above on this same thread, not yet destroyed.
            unsafe { ffi::syn_es_client_destroy(client) };
            // SAFETY: destroy synchronized with in-flight handlers; `ctx` is
            // no longer referenced.
            drop(unsafe { Box::from_raw(ctx) });
            return Err(Box::new(MacosSensorError::Subscribe(sub)));
        }

        tracing::info!(
            sensor = self.name(),
            "EndpointSecurity client subscribed (exec + file + persistence)"
        );

        // Park until stop. wait_timeout (not plain wait) so a missed notify
        // can only ever delay shutdown by one tick, never hang it.
        let mut stopped = self
            .signal
            .stopped
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !*stopped {
            let (guard, _timeout) = self
                .signal
                .condvar
                .wait_timeout(stopped, Duration::from_millis(500))
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            stopped = guard;
        }
        drop(stopped);

        // SAFETY: same thread that created the client (libEndpointSecurity
        // requires it); destroy blocks until in-flight handlers return.
        unsafe { ffi::syn_es_client_destroy(client) };
        // SAFETY: no handler can reference `ctx` after destroy returned.
        drop(unsafe { Box::from_raw(ctx) });
        Ok(())
    }

    fn stop(&mut self) {
        StopHandle {
            signal: Arc::clone(&self.signal),
        }
        .stop();
    }
}
