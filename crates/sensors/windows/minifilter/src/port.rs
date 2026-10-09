//! The connected port handle (Windows only).

use std::ptr;

use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    Storage::InstallableFileSystems::FilterConnectCommunicationPort,
};

use crate::{CONTEXT_LEN, ConnectError, PORT_NAME, connect_context};

/// A connection to `SynthaeaFilter`'s port. The driver keeps the single
/// connection slot for as long as this lives; dropping it disconnects.
#[derive(Debug)]
pub struct DriverPort {
    handle: HANDLE,
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
        Ok(Self { handle })
    }
}

impl Drop for DriverPort {
    fn drop(&mut self) {
        // SAFETY: `handle` came from a successful connect, is owned by this
        // value, and is closed exactly once, here.
        unsafe {
            CloseHandle(self.handle);
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
