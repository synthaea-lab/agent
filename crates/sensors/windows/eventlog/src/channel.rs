//! Whether an event log channel is enabled (#786).
//!
//! A disabled channel is silent: `wevtutil qe` on it exits 0 with no events (lab,
//! Windows 11 25H2, `Microsoft-Windows-TaskScheduler/Operational`), so the poll
//! loop treats it as a quiet, healthy channel, its liveness counter moves, and
//! nothing says the target can never see an event. `EvtSubscribe` registers on it
//! just as happily. The sensor therefore reads the channel's own `Enabled` setting
//! once at start-up and warns about a target whose channel is off.
//!
//! Read-only: enabling a channel is the operator's call (see the `AppLocker`
//! target's `enable_audit` comment in `sensor.rs`).

#![cfg(windows)]

use windows_sys::Win32::System::EventLog::{
    EVT_HANDLE, EVT_VARIANT, EvtChannelConfigEnabled, EvtClose, EvtGetChannelConfigProperty,
    EvtOpenChannelConfig, EvtVarTypeBoolean,
};

/// `Some(true)` / `Some(false)` from the channel's configuration; `None` when it
/// cannot be read (no such channel, access denied, unexpected property type), in
/// which case the caller says nothing rather than guess.
pub(crate) fn is_enabled(channel: &str) -> Option<bool> {
    let wide: Vec<u16> = channel.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `wide` is a null-terminated UTF-16 string that outlives the call; a
    // null session handle means the local computer.
    let config: EVT_HANDLE = unsafe { EvtOpenChannelConfig(0, wide.as_ptr(), 0) };
    if config == 0 {
        return None;
    }
    // SAFETY: `EVT_VARIANT` is plain old data (a union of integers and pointers
    // plus two `u32`s), for which all-zero bytes are a valid value.
    let mut value: EVT_VARIANT = unsafe { core::mem::zeroed() };
    let mut used = 0_u32;
    // SAFETY: `config` was returned non-null above; `value` is a writable
    // `EVT_VARIANT` whose size is passed with it, which is all a boolean property
    // needs; `used` is a live `u32`.
    let ok = unsafe {
        EvtGetChannelConfigProperty(
            config,
            EvtChannelConfigEnabled,
            0,
            size_of::<EVT_VARIANT>() as u32,
            &mut value,
            &mut used,
        )
    };
    // SAFETY: `config` was opened above and is closed exactly once, here.
    unsafe { EvtClose(config) };
    if ok == 0 || value.Type != EvtVarTypeBoolean as u32 {
        return None;
    }
    // SAFETY: the type tag checked just above says `BooleanVal` is the live field.
    Some(unsafe { value.Anonymous.BooleanVal } != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_log_is_enabled() {
        assert_eq!(is_enabled("System"), Some(true));
    }

    #[test]
    fn an_unknown_channel_is_unknown_not_disabled() {
        assert_eq!(is_enabled("Synthaea-No-Such-Channel/Operational"), None);
    }

    /// Lab check, not a CI assertion: whether Task Scheduler history is on is the
    /// host's configuration. On a default Windows 11 25H2 client it reads
    /// `Some(false)` (#786).
    #[test]
    #[ignore = "depends on the host's Task Scheduler history setting"]
    fn task_scheduler_operational_state_on_this_host() {
        eprintln!(
            "TaskScheduler/Operational enabled: {:?}",
            is_enabled("Microsoft-Windows-TaskScheduler/Operational")
        );
    }
}
