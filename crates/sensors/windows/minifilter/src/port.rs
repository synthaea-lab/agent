//! The connected port handle (Windows only).

use std::{
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};

use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
    Storage::InstallableFileSystems::{
        FILTER_MESSAGE_HEADER, FilterConnectCommunicationPort, FilterGetMessage,
    },
    System::{
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
        Threading::{CreateEventW, ResetEvent, WaitForSingleObject},
    },
};

use crate::{CONTEXT_LEN, ConnectError, PORT_NAME, connect_context, wire};

/// `HRESULT_FROM_WIN32(ERROR_IO_PENDING)`: the read was queued and completes later.
const HRESULT_IO_PENDING: i32 = 0x8007_03E5_u32.cast_signed();

/// How long one wait lasts before the stop flag is checked again.
const STOP_CHECK_MS: u32 = 250;

/// Size of the `FILTER_MESSAGE_HEADER` `FilterGetMessage` puts before the payload.
const HEADER_SIZE: usize = std::mem::size_of::<FILTER_MESSAGE_HEADER>();

/// A receive buffer for one message, header included, 8-byte aligned as
/// `FILTER_MESSAGE_HEADER` (a `ULONGLONG` field) requires.
pub struct ReceiveBuffer {
    words: Vec<u64>,
}

impl ReceiveBuffer {
    /// A buffer large enough for the largest message the driver sends.
    #[must_use]
    pub fn new() -> Self {
        let bytes = HEADER_SIZE + wire::MAX_MESSAGE_LEN;
        Self {
            words: vec![0; bytes.div_ceil(8)],
        }
    }

    fn byte_len(&self) -> usize {
        self.words.len() * 8
    }

    /// The payload of the last message received, `len` bytes after the header.
    fn payload(&self, len: usize) -> &[u8] {
        // SAFETY: `words` is `byte_len()` initialised bytes and reading them as `u8` is always
        // valid; the range is clamped to the allocation below.
        let all = unsafe {
            std::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.byte_len())
        };
        let end = (HEADER_SIZE + len).min(all.len());
        &all[HEADER_SIZE.min(end)..end]
    }
}

impl Default for ReceiveBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Why receiving stopped. Every variant means the connection is unusable: drop the
/// `DriverPort` and reconnect (the driver was unloaded, or the port was closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReceiveError {
    /// `FilterGetMessage` failed to start the read.
    #[error("FilterGetMessage failed: HRESULT 0x{0:08X}")]
    Start(u32),
    /// The read completed with an error (typically the driver going away).
    #[error("the pending read failed: Win32 error {0}")]
    Complete(u32),
    /// Waiting on the read's event failed.
    #[error("waiting for a driver message failed: Win32 error {0}")]
    Wait(u32),
}

/// A connection to `SynthaeaFilter`'s port. The driver keeps the single
/// connection slot for as long as this lives; dropping it disconnects.
#[derive(Debug)]
pub struct DriverPort {
    handle: HANDLE,
    /// Manual-reset event the overlapped reads complete on.
    event: HANDLE,
}

// SAFETY: the handle is a kernel object handle owned by this value alone;
// Windows handles may be used and closed from any thread.
unsafe impl Send for DriverPort {}

impl DriverPort {
    /// Connects to `\SynthaeaPort` with the protocol's connection context.
    ///
    /// # Errors
    ///
    /// [`ConnectError`] with the reason the driver or Windows gave: the driver
    /// isn't loaded, the caller isn't the agent, the slot is taken, or the
    /// protocol version doesn't match.
    pub fn connect() -> Result<Self, ConnectError> {
        let name: Vec<u16> = PORT_NAME.encode_utf16().chain(std::iter::once(0)).collect();
        let context = connect_context();
        let mut handle: HANDLE = ptr::null_mut();
        // SAFETY: `name` is NUL-terminated and outlives the call; `context` is
        // CONTEXT_LEN readable bytes, the size passed alongside it; `handle` is
        // a valid out pointer; no security attributes (the default applies).
        let hr = unsafe {
            FilterConnectCommunicationPort(
                name.as_ptr(),
                0,
                context.as_ptr().cast(),
                CONTEXT_LEN,
                ptr::null(),
                &raw mut handle,
            )
        };
        if hr < 0 {
            return Err(ConnectError::from_hresult(hr));
        }
        // SAFETY: no security attributes, manual reset, initially non-signalled, unnamed.
        let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if event.is_null() {
            // SAFETY: no precondition; read before anything else can overwrite it.
            let error = unsafe { GetLastError() };
            // SAFETY: `handle` came from the successful connect above and is closed once.
            unsafe { CloseHandle(handle) };
            return Err(ConnectError::Other(error));
        }
        Ok(Self { handle, event })
    }

    /// Waits for the next message and returns its payload (the `FILTER_MESSAGE_HEADER`
    /// stripped), or `Ok(None)` once `stop` is set: the pending read is then cancelled and
    /// awaited, so no read is ever left writing into `buffer` after this returns.
    ///
    /// The kernel side never waits on this (ADR-0012 guardrail 6): a slow reader only fills
    /// the driver's bounded queue, which drops and counts.
    ///
    /// # Errors
    ///
    /// [`ReceiveError`] when the connection is no longer usable.
    pub fn receive<'b>(
        &self,
        buffer: &'b mut ReceiveBuffer,
        stop: &AtomicBool,
    ) -> Result<Option<&'b [u8]>, ReceiveError> {
        // SAFETY: an all-zero OVERLAPPED is its documented initial state.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.hEvent = self.event;
        // SAFETY: `self.event` is a live event handle owned by this value.
        unsafe { ResetEvent(self.event) };
        let size = u32::try_from(buffer.byte_len()).unwrap_or(u32::MAX);
        // SAFETY: the buffer is `size` writable bytes, 8-byte aligned for the header;
        // `overlapped` outlives the read: every path below waits for its completion (or its
        // cancellation) before returning, so the kernel never writes after `buffer` or
        // `overlapped` is released.
        let hr = unsafe {
            FilterGetMessage(
                self.handle,
                buffer.words.as_mut_ptr().cast::<FILTER_MESSAGE_HEADER>(),
                size,
                &raw mut overlapped,
            )
        };
        if hr < 0 && hr != HRESULT_IO_PENDING {
            return Err(ReceiveError::Start(hr.cast_unsigned()));
        }
        loop {
            // SAFETY: `self.event` is live.
            match unsafe { WaitForSingleObject(self.event, STOP_CHECK_MS) } {
                WAIT_OBJECT_0 => break,
                WAIT_TIMEOUT if stop.load(Ordering::Relaxed) => {
                    self.cancel_and_wait(&overlapped);
                    return Ok(None);
                }
                WAIT_TIMEOUT => {}
                _ => {
                    // SAFETY: no precondition; read before the cancel can overwrite it.
                    let error = unsafe { GetLastError() };
                    self.cancel_and_wait(&overlapped);
                    return Err(ReceiveError::Wait(error));
                }
            }
        }
        let mut transferred = 0u32;
        // SAFETY: the event is signalled, so the read has completed; no wait is needed.
        let ok = unsafe {
            GetOverlappedResult(self.handle, &raw const overlapped, &raw mut transferred, 0)
        };
        if ok == 0 {
            // SAFETY: no precondition.
            return Err(ReceiveError::Complete(unsafe { GetLastError() }));
        }
        let total = usize::try_from(transferred).unwrap_or(usize::MAX);
        Ok(Some(buffer.payload(total.saturating_sub(HEADER_SIZE))))
    }

    /// Cancels the one read in flight on this handle and waits for it to finish, cancelled or
    /// completed, so neither `overlapped` nor the buffer can be released while the kernel
    /// still writes to them.
    fn cancel_and_wait(&self, overlapped: &OVERLAPPED) {
        let mut ignored = 0u32;
        // SAFETY: `overlapped` is the read issued on `self.handle`; waiting (`bWait` = 1) on
        // its completion is what makes returning afterwards safe.
        unsafe {
            CancelIoEx(self.handle, overlapped);
            GetOverlappedResult(self.handle, overlapped, &raw mut ignored, 1);
        }
    }
}

impl Drop for DriverPort {
    fn drop(&mut self) {
        // SAFETY: both handles came from a successful connect, are owned by this value and
        // are closed exactly once, here. No read is pending: `receive` never returns with one.
        unsafe {
            CloseHandle(self.handle);
            CloseHandle(self.event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_test_process_is_never_let_in() {
        // A test runner is neither the agent nor, on CI, next to a loaded
        // driver: without the driver the port doesn't exist (NotLoaded); on
        // the lab VM with it loaded, the identity check refuses us
        // (AccessDenied). Either way, never a connection.
        let err = DriverPort::connect().expect_err("a test process must not connect");
        assert!(
            matches!(err, ConnectError::NotLoaded | ConnectError::AccessDenied),
            "{err:?}"
        );
    }
}
