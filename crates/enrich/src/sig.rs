//! Per-platform code-signature verification.
//!
//! - **Windows**: Authenticode via `WinVerifyTrust` (manual FFI against wintrust.dll
//!   — the API surface is one function and two structs, stable since XP; a manual
//!   binding avoids pulling the whole windows-sys surface into a detection-tier
//!   crate). Revocation checks run offline-only: the event path must never wait on
//!   the network. **Known limitation** (discovered on CI: notepad.exe reads
//!   Unsigned): this checks EMBEDDED signatures only — most System32 binaries are
//!   catalog-signed, which needs the CryptCATAdmin lookup chain; tracked with the
//!   Windows telemetry expansion (#21, P7). Until then a Windows "Unsigned" verdict
//!   means "no embedded signature", and rules must not treat it as tampering.
//! - **macOS**: `codesign --verify` as a subprocess — Apple's supported CLI for
//!   exactly this check; distinguishing "not signed at all" from "signed but
//!   invalid" uses `codesign --display`.
//! - **Linux**: no standard userland code-signing scheme (IMA is a kernel/policy
//!   concern) — always [`Signature::Unsupported`].

use std::path::Path;

use schema::Signature;

#[cfg(target_os = "linux")]
pub(crate) fn verify(_path: &Path) -> Signature {
    Signature::Unsupported
}

#[cfg(target_os = "macos")]
pub(crate) fn verify(path: &Path) -> Signature {
    use std::process::Command;
    // --verify: exit 0 = signed and valid.
    let verify = Command::new("codesign").arg("--verify").arg(path).output();
    match verify {
        Ok(out) if out.status.success() => Signature::Valid,
        Ok(_) => {
            // Failed verification: separate "unsigned" from "signed but broken".
            let display = Command::new("codesign").arg("--display").arg(path).output();
            match display {
                Ok(out) if out.status.success() => Signature::Invalid,
                Ok(_) => Signature::Unsigned,
                Err(_) => Signature::Unsupported,
            }
        }
        Err(_) => Signature::Unsupported,
    }
}

#[cfg(windows)]
pub(crate) fn verify(path: &Path) -> Signature {
    use std::os::windows::ffi::OsStrExt as _;
    windows_impl::verify_wide(
        &path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>(),
    )
}

#[cfg(windows)]
mod windows_impl {
    use schema::Signature;

    #[repr(C)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    /// WINTRUST_ACTION_GENERIC_VERIFY_V2 {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}.
    const ACTION_GENERIC_VERIFY_V2: Guid = Guid {
        data1: 0x00AA_C56B,
        data2: 0xCD44,
        data3: 0x11D0,
        data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
    };

    #[repr(C)]
    struct WintrustFileInfo {
        cb_struct: u32,
        file_path: *const u16,
        h_file: *mut core::ffi::c_void,
        known_subject: *const Guid,
    }

    #[repr(C)]
    struct WintrustData {
        cb_struct: u32,
        policy_callback_data: *mut core::ffi::c_void,
        sip_client_data: *mut core::ffi::c_void,
        ui_choice: u32,
        revocation_checks: u32,
        union_choice: u32,
        file: *mut WintrustFileInfo,
        state_action: u32,
        state_data: *mut core::ffi::c_void,
        url_reference: *mut u16,
        prov_flags: u32,
        ui_context: u32,
        signature_settings: *mut core::ffi::c_void,
    }

    const WTD_UI_NONE: u32 = 2;
    const WTD_REVOKE_NONE: u32 = 0;
    const WTD_CHOICE_FILE: u32 = 1;
    const WTD_STATEACTION_VERIFY: u32 = 1;
    const WTD_STATEACTION_CLOSE: u32 = 2;
    /// Offline-only: never fetch revocation data on the event path.
    const WTD_CACHE_ONLY_URL_RETRIEVAL: u32 = 0x1000;
    const TRUST_E_NOSIGNATURE: i32 = 0x800B_0100u32 as i32;
    /// No SIP recognizes the file type (plain data files, extensionless scripts).
    const TRUST_E_PROVIDER_UNKNOWN: i32 = 0x800B_0001u32 as i32;
    const TRUST_E_SUBJECT_FORM_UNKNOWN: i32 = 0x800B_0003u32 as i32;

    #[link(name = "wintrust")]
    unsafe extern "system" {
        fn WinVerifyTrust(hwnd: isize, action_id: *const Guid, data: *mut core::ffi::c_void)
        -> i32;
    }

    pub(super) fn verify_wide(path_utf16: &[u16]) -> Signature {
        let mut file_info = WintrustFileInfo {
            cb_struct: size_of::<WintrustFileInfo>() as u32,
            file_path: path_utf16.as_ptr(),
            h_file: core::ptr::null_mut(),
            known_subject: core::ptr::null(),
        };
        let mut data = WintrustData {
            cb_struct: size_of::<WintrustData>() as u32,
            policy_callback_data: core::ptr::null_mut(),
            sip_client_data: core::ptr::null_mut(),
            ui_choice: WTD_UI_NONE,
            revocation_checks: WTD_REVOKE_NONE,
            union_choice: WTD_CHOICE_FILE,
            file: &mut file_info,
            state_action: WTD_STATEACTION_VERIFY,
            state_data: core::ptr::null_mut(),
            url_reference: core::ptr::null_mut(),
            prov_flags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            ui_context: 0,
            signature_settings: core::ptr::null_mut(),
        };
        let status = unsafe {
            WinVerifyTrust(
                0,
                &ACTION_GENERIC_VERIFY_V2,
                (&mut data as *mut WintrustData).cast(),
            )
        };
        // Release verifier state regardless of the verdict.
        data.state_action = WTD_STATEACTION_CLOSE;
        unsafe {
            WinVerifyTrust(
                0,
                &ACTION_GENERIC_VERIFY_V2,
                (&mut data as *mut WintrustData).cast(),
            );
        }
        match status {
            0 => Signature::Valid,
            TRUST_E_NOSIGNATURE => Signature::Unsigned,
            // Not a signable file type — a verdict of Invalid would brand every
            // text/data file as tampered.
            TRUST_E_PROVIDER_UNKNOWN | TRUST_E_SUBJECT_FORM_UNKNOWN => Signature::Unsupported,
            _ => Signature::Invalid,
        }
    }
}
