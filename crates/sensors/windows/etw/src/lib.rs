//! # sensor-windows
//!
//! Windows user-mode sensor built on one ETW real-time session over the
//! kernel and user-mode providers in `providers`. Identity (the real command
//! line from the PEB, user SID and integrity level, container) is attached and
//! NT paths are normalized to one DOS form before an event leaves the crate.
//! Compiles to a stub off Windows. See `docs/sensors/windows/etw.md` and
//! `docs/sensors/windows/etw-enrichment.md`.

#[cfg(any(windows, test))]
mod amsi;
pub mod bits;
#[cfg(any(windows, test))]
mod budget;
#[cfg(any(windows, test))]
mod cross_process;
#[cfg(windows)]
mod etw_sessions;
#[cfg(windows)]
mod hcs;
#[cfg(any(windows, test))]
mod kernel_process;
#[cfg(any(windows, test))]
mod long_path;
pub mod normalize;
#[cfg(any(windows, test))]
mod path_normalizer;
#[cfg(any(windows, test))]
mod payload;
#[cfg(any(windows, test))]
mod pid_cache;
#[cfg(windows)]
mod providers;

#[cfg(windows)]
mod sensor;
#[cfg(any(windows, test))]
mod silo;
#[cfg(any(windows, test))]
mod sync;
#[cfg(windows)]
mod winapi;
pub mod zone_identifier;
#[cfg(windows)]
pub use sensor::{EtwNames, WindowsSensor};
#[cfg(windows)]
pub use winapi::image_file_id;

/// The text form of a file identity, `"{volume serial:016x}:{file id:032x}"` (#688): what
/// `schema::ExecEvent::image_file_id` carries and what the agent's enrichment compares with
/// `enrich::path_identity` (the same format, written twice because sensor crates depend on
/// `schema` only; the agent's Windows test pins the two together). `file_id` is the 16 bytes
/// of `FILE_ID_128`, read as a little-endian integer.
#[must_use]
pub fn identity_token(volume_serial: u64, file_id: [u8; 16]) -> String {
    format!("{volume_serial:016x}:{:032x}", u128::from_le_bytes(file_id))
}

/// Whether the image identity is worth capturing on the callback thread (#688): only an
/// image at `X:\...`. A UNC (`\\server\share`), `\\?\` or `\Device\...` path would make the
/// open a network round trip on the thread that delivers every kernel-process event, and a
/// dead SMB server would stall process telemetry host-wide. No identity is recorded for
/// those, so the T1204.002 gate fails closed (the alert is raised, not silenced). A mapped
/// network drive letter cannot be told from a local one by its text and is not excluded.
#[cfg(any(windows, test))]
#[must_use]
pub(crate) fn image_identity_is_capturable(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\'
}

#[cfg(test)]
mod identity_capture_tests {
    use super::image_identity_is_capturable;

    #[test]
    fn only_a_drive_letter_path_is_captured() {
        assert!(image_identity_is_capturable(r"C:\Users\u\Downloads\a.exe"));
        assert!(image_identity_is_capturable(r"d:\tools\a.exe"));
    }

    #[test]
    fn network_and_device_paths_are_not_captured() {
        for path in [
            r"\\server\share\a.exe",
            r"\\?\UNC\server\share\a.exe",
            r"\\?\C:\a.exe",
            r"\Device\Mup\server\share\a.exe",
            r"\Device\LanmanRedirector\server\share\a.exe",
            "<unknown>",
            "",
            "C:",
            "C:a.exe",
            "/usr/bin/a",
        ] {
            assert!(!image_identity_is_capturable(path), "{path}");
        }
    }
}

#[cfg(test)]
mod identity_token_tests {
    use super::identity_token;

    #[test]
    fn the_token_is_volume_then_little_endian_file_id_in_fixed_width_hex() {
        let mut id = [0u8; 16];
        id[0] = 0xef;
        id[1] = 0xbe;
        id[4] = 0x03;
        assert_eq!(
            identity_token(0xa1b2_c3d4, id),
            "00000000a1b2c3d4:0000000000000000000000030000beef"
        );
        assert_eq!(identity_token(0, [0; 16]), format!("{:016x}:{:032x}", 0, 0));
    }
}
