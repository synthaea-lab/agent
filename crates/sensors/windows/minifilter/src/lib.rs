//! # sensor-windows-minifilter
//!
//! User-mode side of the `SynthaeaFilter` minifilter's communication port
//! (#136, ADR-0012). The agent connects to `\SynthaeaPort` with a fixed
//! connection context; the driver accepts exactly one client, and only one
//! running as the agent (`NT SERVICE\SynthaEDR` in its token, guardrail 5).
//!
//! Milestone 2b: connecting only. The driver sends nothing yet (the event
//! channel is milestone 2c), so there is no receive loop here.
//!
//! The protocol constants mirror `driver/minifilter/SynthaeaFilter.c`: a
//! change on one side is a change on the other. This crate sits next to
//! `driver/` and depends on no workspace crate (ADR-0012 guardrail 8; it will
//! depend on `schema` once it decodes events).

/// Name of the driver's communication port.
pub const PORT_NAME: &str = r"\SynthaeaPort";

/// First field of the connection context: `SYNT` in little-endian byte order.
pub const CONNECT_MAGIC: u32 = 0x544E_5953;

/// Second field of the connection context. The driver refuses any other value.
pub const PROTOCOL_VERSION: u32 = 1;

/// The service SID the driver requires in the connecting process's token:
/// `NT SERVICE\SynthaEDR`, the watchdog service that spawns the agent
/// (`sc showsid SynthaEDR`). Present only when the service is installed with
/// `sidtype unrestricted`, which `watchdog install` does.
pub const AGENT_SERVICE_SID: &str = "S-1-5-80-3000362003-865703788-3960528645-4228801270-24284304";

/// Size of the connection context, as `FilterConnectCommunicationPort` takes it.
const CONTEXT_LEN: u16 = 8;

/// The connection context: `{ magic, version }` as two little-endian `u32`s,
/// i.e. the driver's `SYNTHAEA_CONNECT_CONTEXT`.
#[must_use]
pub fn connect_context() -> [u8; CONTEXT_LEN as usize] {
    let mut context = [0u8; CONTEXT_LEN as usize];
    context[..4].copy_from_slice(&CONNECT_MAGIC.to_le_bytes());
    context[4..].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    context
}

/// Why connecting to the driver's port failed. Each variant is one HRESULT
/// the lab checks pin (`crates/sensors/windows/driver/test/port-check.ps1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConnectError {
    /// No `\SynthaeaPort`: the driver isn't loaded.
    #[error("SynthaeaFilter is not loaded (no \\SynthaeaPort)")]
    NotLoaded,
    /// Refused by the port's security descriptor (not SYSTEM/Administrators)
    /// or by the driver's identity check (not the agent).
    #[error("access denied: not elevated, or not running as the agent (NT SERVICE\\SynthaEDR)")]
    AccessDenied,
    /// The driver's single connection is already taken.
    #[error("another client already holds the driver's single connection")]
    AlreadyConnected,
    /// The driver rejected the connection context: a protocol mismatch.
    #[error("the driver refused the connection context (protocol version mismatch?)")]
    Refused,
    /// Any other failure, with its HRESULT.
    #[error("FilterConnectCommunicationPort failed: HRESULT 0x{0:08X}")]
    Other(u32),
}

impl ConnectError {
    /// Maps a failed `FilterConnectCommunicationPort` HRESULT.
    #[must_use]
    pub fn from_hresult(hr: i32) -> Self {
        // HRESULT_FROM_WIN32 values; the cast only reinterprets the bits.
        #[allow(clippy::cast_sign_loss)]
        match hr as u32 {
            0x8007_0002 | 0x8007_0003 => Self::NotLoaded, // file / path not found
            0x8007_0005 => Self::AccessDenied,
            0x8007_04D6 => Self::AlreadyConnected, // ERROR_CONNECTION_COUNT_LIMIT
            0x8007_0057 => Self::Refused,          // STATUS_INVALID_PARAMETER
            other => Self::Other(other),
        }
    }
}

#[cfg(windows)]
mod port;
#[cfg(windows)]
pub use port::DriverPort;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_connection_context_spells_synt_then_version_one() {
        assert_eq!(connect_context(), *b"SYNT\x01\x00\x00\x00");
    }

    #[test]
    fn each_pinned_hresult_maps_to_its_own_error() {
        #[allow(clippy::cast_possible_wrap)]
        let hr = |v: u32| v as i32;
        assert_eq!(
            ConnectError::from_hresult(hr(0x8007_0002)),
            ConnectError::NotLoaded
        );
        assert_eq!(
            ConnectError::from_hresult(hr(0x8007_0005)),
            ConnectError::AccessDenied
        );
        assert_eq!(
            ConnectError::from_hresult(hr(0x8007_04D6)),
            ConnectError::AlreadyConnected
        );
        assert_eq!(
            ConnectError::from_hresult(hr(0x8007_0057)),
            ConnectError::Refused
        );
        assert_eq!(
            ConnectError::from_hresult(hr(0x8000_4005)),
            ConnectError::Other(0x8000_4005)
        );
    }
}
