//! Per-platform code-signature verification.
//!
//! - **Windows**: Authenticode via `WinVerifyTrust` (manual FFI against wintrust.dll
//!   — a manual binding avoids pulling the whole windows-sys surface into a
//!   detection-tier crate). Revocation checks run offline-only: the event path must
//!   never wait on the network. Two verification modes are tried, in order:
//!   1. **Embedded** signature check (`WTD_CHOICE_FILE`) — one function, two structs,
//!      stable since XP.
//!   2. If (1) reports [`Signature::Unsigned`] specifically: a **catalog-membership**
//!      check (`WTD_CHOICE_CATALOG`, fed by the `CryptCATAdmin*` lookup chain) —
//!      most System32 binaries are catalog-signed, not embedded-signed (discovered on
//!      CI: notepad.exe read `Unsigned` under mode 1 alone). This is the P7 gap
//!      flagged in issue #21's closing comment; see
//!      `docs/adr/0007-windows-catalog-signed-binary-verification.md`. Every failure
//!      path in the catalog chain (context acquisition, hashing, no catalog match,
//!      catalog-info lookup) falls back to `Unsigned` — the same conservative
//!      default as before this existed, never `Valid`/`Invalid` on a tooling hiccup.
//!      Not attempted when mode 1 reports `Unsupported` or `Invalid`: those verdicts
//!      are not "maybe signed a different way", so a catalog lookup would not change
//!      them.
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
    let path_utf16: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let embedded = windows_impl::verify_wide(&path_utf16);
    if embedded != Signature::Unsigned {
        return embedded;
    }
    // No embedded signature: most System32 binaries are catalog-signed instead
    // (#21, P7) — check the catalog chain before concluding Unsigned.
    windows_impl::catalog_verify(path, &path_utf16)
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

    /// `WINTRUST_ACTION_GENERIC_VERIFY_V2` {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}.
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

    /// The catalog-mode counterpart to [`WintrustFileInfo`] — `WINTRUST_CATALOG_INFO`.
    /// Fed to [`WintrustData`] instead of a `WintrustFileInfo` when
    /// `union_choice == WTD_CHOICE_CATALOG`.
    #[repr(C)]
    struct WintrustCatalogInfo {
        cb_struct: u32,
        catalog_version: u32,
        catalog_file_path: *const u16,
        member_tag: *const u16,
        member_file_path: *const u16,
        member_file: *mut core::ffi::c_void,
        calculated_hash: *mut u8,
        calculated_hash_len: u32,
        catalog_context: *const core::ffi::c_void,
        cat_admin: *mut core::ffi::c_void,
    }

    /// `MAX_PATH`, used by [`CatalogInfo`]'s fixed-size buffer per the documented
    /// `CATALOG_INFO` layout.
    const MAX_PATH: usize = 260;

    /// `CATALOG_INFO` — filled in by `CryptCATCatalogInfoFromContext`.
    #[repr(C)]
    struct CatalogInfo {
        cb_struct: u32,
        catalog_file: [u16; MAX_PATH],
    }

    #[repr(C)]
    struct WintrustData {
        cb_struct: u32,
        policy_callback_data: *mut core::ffi::c_void,
        sip_client_data: *mut core::ffi::c_void,
        ui_choice: u32,
        revocation_checks: u32,
        union_choice: u32,
        /// Either a `*mut WintrustFileInfo` (`WTD_CHOICE_FILE`) or a
        /// `*mut WintrustCatalogInfo` (`WTD_CHOICE_CATALOG`) — a real union in the
        /// C header; a untyped pointer here with the caller casting at each call
        /// site, since both call sites already live in this module.
        file: *mut core::ffi::c_void,
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
    const WTD_CHOICE_CATALOG: u32 = 2;
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

        // Catalog-membership lookup chain (all in wintrust.dll, mscat.h; all
        // require Windows 8 / Server 2012 or later, which is below this
        // workspace's floor).
        fn CryptCATAdminAcquireContext2(
            cat_admin: *mut *mut core::ffi::c_void,
            subsystem: *const Guid,
            hash_algorithm: *const u16,
            strong_hash_policy: *const core::ffi::c_void,
            flags: u32,
        ) -> i32;

        fn CryptCATAdminCalcHashFromFileHandle2(
            cat_admin: *mut core::ffi::c_void,
            file: *mut core::ffi::c_void,
            hash_len: *mut u32,
            hash: *mut u8,
            flags: u32,
        ) -> i32;

        fn CryptCATAdminEnumCatalogFromHash(
            cat_admin: *mut core::ffi::c_void,
            hash: *mut u8,
            hash_len: u32,
            flags: u32,
            prev_cat_info: *mut *mut core::ffi::c_void,
        ) -> *mut core::ffi::c_void;

        fn CryptCATCatalogInfoFromContext(
            cat_info: *mut core::ffi::c_void,
            catalog_info: *mut CatalogInfo,
            flags: u32,
        ) -> i32;

        fn CryptCATAdminReleaseCatalogContext(
            cat_admin: *mut core::ffi::c_void,
            cat_info: *mut core::ffi::c_void,
            flags: u32,
        ) -> i32;

        fn CryptCATAdminReleaseContext(cat_admin: *mut core::ffi::c_void, flags: u32) -> i32;
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
            file: (&mut file_info as *mut WintrustFileInfo).cast(),
            state_action: WTD_STATEACTION_VERIFY,
            state_data: core::ptr::null_mut(),
            url_reference: core::ptr::null_mut(),
            prov_flags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            ui_context: 0,
            signature_settings: core::ptr::null_mut(),
        };
        // SAFETY: `data` and `file_info` are fully initialized above and outlive
        // the call; the struct layout matches the manual WINTRUST_DATA binding.
        let status = unsafe {
            WinVerifyTrust(
                0,
                &ACTION_GENERIC_VERIFY_V2,
                (&mut data as *mut WintrustData).cast(),
            )
        };
        // Release verifier state regardless of the verdict.
        data.state_action = WTD_STATEACTION_CLOSE;
        // SAFETY: same live `data` as the verify call, now asking the provider to
        // release the state it allocated.
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

    /// Catalog-membership fallback: only called when [`verify_wide`] already
    /// reported [`Signature::Unsigned`]. Every early return is `Unsigned` too —
    /// a tooling failure here must never read as `Valid` or `Invalid`.
    pub(super) fn catalog_verify(path: &std::path::Path, path_utf16: &[u16]) -> Signature {
        use std::os::windows::io::AsRawHandle as _;

        // Only a real, readable file can be hashed for a catalog lookup.
        let Ok(file) = std::fs::File::open(path) else {
            return Signature::Unsigned;
        };
        let h_file = file.as_raw_handle();

        let mut cat_admin: *mut core::ffi::c_void = core::ptr::null_mut();
        // Null-terminated wide "SHA256" — the modern algorithm; this whole API
        // requires Windows 8+ regardless, so there is no legacy-SHA1 case to
        // support here.
        let hash_algorithm: Vec<u16> = "SHA256\0".encode_utf16().collect();
        // SAFETY: `cat_admin` is an out-param the callee fully initializes on
        // success; `hash_algorithm` is a valid null-terminated wide string that
        // outlives this call.
        let acquired = unsafe {
            CryptCATAdminAcquireContext2(
                &mut cat_admin,
                core::ptr::null(),
                hash_algorithm.as_ptr(),
                core::ptr::null(),
                0,
            )
        };
        if acquired == 0 || cat_admin.is_null() {
            return Signature::Unsigned;
        }

        // Two-call pattern: first learn the required hash buffer size (null
        // `hash` pointer), then fill it.
        let mut hash_len: u32 = 0;
        // SAFETY: `cat_admin` was just acquired above; a null `hash` with
        // `hash_len` pointing at a live `u32` is the documented size-query mode.
        unsafe {
            CryptCATAdminCalcHashFromFileHandle2(
                cat_admin,
                h_file,
                &mut hash_len,
                core::ptr::null_mut(),
                0,
            );
        }
        if hash_len == 0 {
            // SAFETY: releasing a context acquired above; nothing uses it after.
            unsafe { CryptCATAdminReleaseContext(cat_admin, 0) };
            return Signature::Unsigned;
        }
        let mut hash = vec![0u8; hash_len as usize];
        // SAFETY: `hash` is sized exactly to the length reported by the call
        // above and outlives this call.
        let hashed = unsafe {
            CryptCATAdminCalcHashFromFileHandle2(
                cat_admin,
                h_file,
                &mut hash_len,
                hash.as_mut_ptr(),
                0,
            )
        };
        if hashed == 0 {
            // SAFETY: releasing a context acquired above; nothing uses it after.
            unsafe { CryptCATAdminReleaseContext(cat_admin, 0) };
            return Signature::Unsigned;
        }

        // SAFETY: `cat_admin` and `hash` are both live and valid for this call.
        let cat_info = unsafe {
            CryptCATAdminEnumCatalogFromHash(
                cat_admin,
                hash.as_mut_ptr(),
                hash_len,
                0,
                core::ptr::null_mut(),
            )
        };
        if cat_info.is_null() {
            // Not a member of any installed catalog — genuinely unsigned, not a
            // tooling failure.
            // SAFETY: releasing a context acquired above; nothing uses it after.
            unsafe { CryptCATAdminReleaseContext(cat_admin, 0) };
            return Signature::Unsigned;
        }

        let mut catalog_info = CatalogInfo {
            cb_struct: size_of::<CatalogInfo>() as u32,
            catalog_file: [0u16; MAX_PATH],
        };
        // SAFETY: `cat_info` was just returned non-null above; `catalog_info` is
        // fully sized with `cb_struct` set per the documented contract.
        let got_catalog_path =
            unsafe { CryptCATCatalogInfoFromContext(cat_info, &mut catalog_info, 0) };

        let verdict = if got_catalog_path == 0 {
            Signature::Unsigned
        } else {
            // The member tag WinVerifyTrust expects in catalog mode is the file
            // hash rendered as an uppercase hex string, wide-encoded.
            let mut tag = String::with_capacity(hash.len() * 2 + 1);
            for byte in &hash {
                use std::fmt::Write as _;
                let _ = write!(tag, "{byte:02X}");
            }
            let tag_utf16: Vec<u16> = tag.encode_utf16().chain(std::iter::once(0)).collect();

            let mut catalog_file_info = WintrustCatalogInfo {
                cb_struct: size_of::<WintrustCatalogInfo>() as u32,
                catalog_version: 0,
                catalog_file_path: catalog_info.catalog_file.as_ptr(),
                member_tag: tag_utf16.as_ptr(),
                member_file_path: path_utf16.as_ptr(),
                member_file: h_file,
                calculated_hash: hash.as_mut_ptr(),
                calculated_hash_len: hash_len,
                catalog_context: core::ptr::null(),
                cat_admin,
            };
            let mut data = WintrustData {
                cb_struct: size_of::<WintrustData>() as u32,
                policy_callback_data: core::ptr::null_mut(),
                sip_client_data: core::ptr::null_mut(),
                ui_choice: WTD_UI_NONE,
                revocation_checks: WTD_REVOKE_NONE,
                union_choice: WTD_CHOICE_CATALOG,
                file: (&mut catalog_file_info as *mut WintrustCatalogInfo).cast(),
                state_action: WTD_STATEACTION_VERIFY,
                state_data: core::ptr::null_mut(),
                url_reference: core::ptr::null_mut(),
                prov_flags: WTD_CACHE_ONLY_URL_RETRIEVAL,
                ui_context: 0,
                signature_settings: core::ptr::null_mut(),
            };
            // SAFETY: `data` and `catalog_file_info` are fully initialized above
            // and outlive the call; `file` (the still-open handle backing
            // `h_file`) is not dropped until this function returns; the struct
            // layout matches the manual WINTRUST_DATA/WINTRUST_CATALOG_INFO
            // bindings in catalog mode (`union_choice = WTD_CHOICE_CATALOG`).
            let status = unsafe {
                WinVerifyTrust(
                    0,
                    &ACTION_GENERIC_VERIFY_V2,
                    (&mut data as *mut WintrustData).cast(),
                )
            };
            data.state_action = WTD_STATEACTION_CLOSE;
            // SAFETY: same live `data` as the verify call, now asking the
            // provider to release the state it allocated.
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
                TRUST_E_PROVIDER_UNKNOWN | TRUST_E_SUBJECT_FORM_UNKNOWN => Signature::Unsupported,
                _ => Signature::Invalid,
            }
        };

        // SAFETY: `cat_info` and `cat_admin` were acquired above and are each
        // released exactly once here, in the documented catalog-then-admin
        // order; `file` (backing `h_file`, used by the WinVerifyTrust call
        // above) is still alive at this point and is dropped by the caller's
        // scope after this function returns.
        unsafe {
            CryptCATAdminReleaseCatalogContext(cat_admin, cat_info, 0);
            CryptCATAdminReleaseContext(cat_admin, 0);
        }
        verdict
    }
}
