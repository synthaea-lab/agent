//! # sensor-windows
//!
//! Windows user-mode sensor built on ETW (Kernel-Process, Kernel-Network,
//! Kernel-File), migrated from the old iteration with the coverage-audit findings
//! fixed at the source:
//!
//! - **F-1**: the command line is the REAL command line, read from the target's PEB
//!   (`NtQueryInformationProcess` + `ReadProcessMemory`), never the image path.
//! - **F-2**: the session name is randomized per start, but under a fixed
//!   `wtrace-` prefix — every session matching it is enumerated and stopped at
//!   startup (issue #408 — catches every orphan left by any number of consecutive
//!   unclean shutdowns, not just the most recent). That prefix is itself a
//!   fingerprint: an attacker can enumerate our session exactly the way we do
//!   (`logman query -ets | findstr wtrace-`), so the session is still stoppable.
//!   The guarantee is that stopping it is *loud*, not that it's impossible: the
//!   silence watchdog turns a stopped trace into a sensor error instead of quiet
//!   blindness.
//! - **F-3**: every event carries the process's user SID and integrity level
//!   (`User::Windows`), resolved from the process token.
//! - **F-4**: unbounded strings via the new schema — multi-KB encoded command lines
//!   survive intact.
//! - **F-5**: NT device paths normalize through a real `QueryDosDeviceW` volume map,
//!   not a hardcoded `C:`, then 8.3 short components expand to their long names
//!   (#489) so one file has one path.
//! - **F-6** (partial): `CreateNewFile` (EID 30) joins `NameCreate` (EID 12), and
//!   `DeletePath` (EID 26) is kept for one case, a `:Zone.Identifier` stream
//!   deletion (#442); full delete/rename semantics land with the ransomware pack
//!   (#82) / driver (#39).
//! - **F-7**: IPv6 connects (EID 58/26) are first-class, and a short dedup window
//!   prevents Connect+Send double-counting.
//!
//! The provider expansion (registry, DNS, image load, AMSI, WMI — audit P2–P8) is
//! #21; each provider arrives as its own module. Compiles to a stub off Windows.
//!
//! Download provenance (#365): a Kernel-File write to a `:Zone.Identifier`
//! stream (mark-of-the-web) is read back and reported as
//! `schema::FileQuarantineEvent`, the macOS quarantine-xattr sibling — see
//! [`zone_identifier`].
//! Deleting that stream (the mark removed, T1553.005) is reported as a
//! `schema::FileDeleteEvent` of the stream path (#442).
//!
//! BITS jobs (#284): `Microsoft-Windows-Bits-Client` records, reported as
//! `schema::BitsJobEvent` with the job's client process as the actor (BITS
//! does the network I/O from its own service), Microsoft update jobs dropped
//! — see [`bits`].

#[cfg(any(windows, test))]
mod amsi;
pub mod bits;
#[cfg(any(windows, test))]
mod budget;
#[cfg(windows)]
mod etw_sessions;
#[cfg(any(windows, test))]
mod long_path;
pub mod normalize;
#[cfg(any(windows, test))]
mod pid_cache;
#[cfg(windows)]
mod providers;

#[cfg(windows)]
mod sensor;
#[cfg(windows)]
mod winapi;
pub mod zone_identifier;
#[cfg(windows)]
pub use sensor::WindowsSensor;
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
