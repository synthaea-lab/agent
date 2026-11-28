//! What the detection pipeline must know about the OS it was built for, in one place.
//!
//! These are facts about the platform's sensor and account model, not behaviour: the code
//! that uses them is the same on every OS.

/// The ML correlation model family of this platform.
#[cfg(target_os = "linux")]
pub(crate) const MODEL_FAMILY: &str = "correlation-iforest-linux";
/// The ML correlation model family of this platform.
#[cfg(target_os = "windows")]
pub(crate) const MODEL_FAMILY: &str = "correlation-iforest-windows";
/// The ML correlation model family of this platform.
#[cfg(target_os = "macos")]
pub(crate) const MODEL_FAMILY: &str = "correlation-iforest-macos";

/// Whether a signature verdict on an exec event means the certificate chain was verified.
/// Only the Windows sensor verifies it; `codesign` and the Endpoint Security flags call
/// ad-hoc signatures valid too.
pub(crate) const SIGNATURE_CHAIN_VERIFIED: bool = cfg!(windows);

/// Whether the platform's sensor records the image's identity at exec time. Only the
/// Windows ETW sensor does (#688).
pub(crate) const EXEC_IDENTITY_CAPTURED: bool = cfg!(windows);

/// Whether events carry a uid a file read can be checked against.
pub(crate) const USERS_HAVE_UID: bool = cfg!(unix);

/// The uid the agent runs as, where the platform has one.
pub(crate) fn own_uid() -> Option<u32> {
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` takes no arguments, touches no memory and cannot fail.
        Some(unsafe { libc::geteuid() })
    }
    #[cfg(not(unix))]
    {
        None
    }
}
