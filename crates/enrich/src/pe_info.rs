//! PE version-resource metadata: `OriginalFilename`, `CompanyName`,
//! `FileDescription`, `ProductName` (issue #983) — the `SigmaHQ` `process_creation`
//! catalogue's primary renamed-binary signal (`cmd.exe` copied to `svchost.exe`
//! still carries `OriginalFilename: Cmd.Exe` in its resource).
//!
//! **Windows only.** PE version resources are a Windows/PE concept with no
//! Mach-O or ELF equivalent — [`read`] is always [`PeInfo::default`] (all
//! `None`) on every other platform, same posture as [`crate::sig::verify`]'s
//! `Signature::Unsupported`.
//!
//! Read via the classic Version API (`version.dll`: `GetFileVersionInfoSizeW` /
//! `GetFileVersionInfoW` / `VerQueryValueW`), hand-bound rather than pulling in
//! `windows-sys` for three functions — same posture as `sig.rs`.
//!
//! **Unlike `sig::verify`, this reads by path, not by the caller's already-open
//! handle**: the Version API has no handle-based entry point (`GetFileVersionInfoExW`'s
//! `dwFlags` only controls locale fallback, not the data source — every variant
//! of this API takes a path and reopens the file itself). This narrows the
//! TOCTOU guarantee #688 established for the hash and signature: a file swapped
//! between this module's internal open and the caller's own open (whose identity
//! is what the cache is keyed on) could, in principle, have this one field
//! describe the replacement rather than the file the cache entry is for. The
//! blast radius is bounded to these four cosmetic strings — never the hash or
//! signature verdict, which still come from the caller's handle — and the
//! window is one more open/close pair a few instructions after the first, not
//! an attacker-controlled delay. Flagged here rather than silently accepted;
//! closing it fully would mean parsing the PE resource directory ourselves off
//! the open handle instead of calling into `version.dll`, left as a follow-up
//! if this field's integrity ever needs the same bar as the hash.

use std::path::Path;

/// What this module could read from one image's PE version resource. Every
/// field is independently `None`: a resource can carry some of the four
/// strings and not others (translation present, one string entry missing), and
/// `None` here must never be read as "unsigned" or any other value judgment —
/// only "not present or not read."
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeInfo {
    pub original_file_name: Option<String>,
    pub company_name: Option<String>,
    pub file_description: Option<String>,
    pub product_name: Option<String>,
}

impl PeInfo {
    /// `true` when every field is `None` — the common case (no version
    /// resource, not a PE, or over budget), checked by the caller to skip a
    /// cache write's clone when there is nothing to remember.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.original_file_name.is_none()
            && self.company_name.is_none()
            && self.file_description.is_none()
            && self.product_name.is_none()
    }
}

#[cfg(not(windows))]
pub(crate) fn read(_path: &Path) -> PeInfo {
    PeInfo::default()
}

#[cfg(windows)]
pub(crate) fn read(path: &Path) -> PeInfo {
    use std::os::windows::ffi::OsStrExt as _;
    let path_utf16: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    windows_impl::read_wide(&path_utf16)
}

#[cfg(windows)]
mod windows_impl {
    use super::PeInfo;

    #[link(name = "version")]
    unsafe extern "system" {
        fn GetFileVersionInfoSizeW(filename: *const u16, handle: *mut u32) -> u32;
        fn GetFileVersionInfoW(
            filename: *const u16,
            handle: u32,
            len: u32,
            data: *mut core::ffi::c_void,
        ) -> i32;
        fn VerQueryValueW(
            block: *const core::ffi::c_void,
            sub_block: *const u16,
            buffer: *mut *mut core::ffi::c_void,
            len: *mut u32,
        ) -> i32;
    }

    /// `VS_FIXEDFILEINFO`'s `\VarFileInfo\Translation` entry: one `(language,
    /// codepage)` pair per localization the resource carries. Almost every
    /// real-world binary has exactly one; this reads only the first, which is
    /// what every other Sigma-targeting EDR does too (a rule matching on the
    /// second localization of a dual-language binary is not a case this field
    /// exists to cover).
    fn translation(block: *const core::ffi::c_void) -> Option<(u16, u16)> {
        let sub_block: Vec<u16> = "\\VarFileInfo\\Translation\0".encode_utf16().collect();
        let mut ptr: *mut core::ffi::c_void = core::ptr::null_mut();
        let mut len: u32 = 0;
        // SAFETY: `block` is the buffer `GetFileVersionInfoW` just filled, live for
        // the duration of this call; `sub_block` is a valid null-terminated wide
        // string; `ptr`/`len` are out-params `VerQueryValueW` writes into a buffer
        // owned by `block`, never freed by the caller.
        let ok = unsafe { VerQueryValueW(block, sub_block.as_ptr(), &mut ptr, &mut len) };
        if ok == 0 || ptr.is_null() || len < 4 {
            return None;
        }
        // SAFETY: `ptr` was just reported valid for `len` bytes by the call above;
        // a `(u16, u16)` pair is within that range since `len >= 4`.
        let pair = unsafe { ptr.cast::<[u16; 2]>().read_unaligned() };
        Some((pair[0], pair[1]))
    }

    /// Reads one `StringFileInfo` entry (`OriginalFilename`, `CompanyName`, ...)
    /// for the given `(language, codepage)`. `None` when the resource has no
    /// such entry — normal, not an error (see [`PeInfo`]'s doc).
    fn string_value(
        block: *const core::ffi::c_void,
        lang: u16,
        codepage: u16,
        name: &str,
    ) -> Option<String> {
        let sub_block: Vec<u16> = format!("\\StringFileInfo\\{lang:04x}{codepage:04x}\\{name}\0")
            .encode_utf16()
            .collect();
        let mut ptr: *mut core::ffi::c_void = core::ptr::null_mut();
        let mut len: u32 = 0;
        // SAFETY: as in `translation` — `block` outlives this call, `sub_block` is
        // a valid wide C string, and the out-params point at this call's own
        // locals.
        let ok = unsafe { VerQueryValueW(block, sub_block.as_ptr(), &mut ptr, &mut len) };
        if ok == 0 || ptr.is_null() || len == 0 {
            return None;
        }
        // `len` is a `u16` count *including* a trailing NUL for a `VerQueryValueW`
        // string value (documented behavior) — trimmed below rather than relied
        // on, since a malformed resource could omit it.
        // SAFETY: `ptr` was just reported valid for `len` `u16` units.
        let slice = unsafe { std::slice::from_raw_parts(ptr.cast::<u16>(), len as usize) };
        let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
        if end == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&slice[..end]))
    }

    pub(super) fn read_wide(path_utf16: &[u16]) -> PeInfo {
        let mut handle: u32 = 0;
        // SAFETY: `path_utf16` is a valid null-terminated wide string for the
        // duration of this call; `handle` is an out-param this API always writes
        // (and this binding, like Microsoft's own current docs, ignores: it is
        // vestigial since Windows 95).
        let size = unsafe { GetFileVersionInfoSizeW(path_utf16.as_ptr(), &mut handle) };
        if size == 0 {
            // No version resource at all — most dropped/compiled-on-the-fly
            // payloads, scripts-as-exe, and plenty of legitimate tools.
            return PeInfo::default();
        }
        let mut buffer = vec![0u8; size as usize];
        // SAFETY: `buffer` is sized exactly to `size`, which the call above just
        // reported as the required size for this same path.
        let got = unsafe {
            GetFileVersionInfoW(
                path_utf16.as_ptr(),
                0,
                size,
                buffer.as_mut_ptr().cast::<core::ffi::c_void>(),
            )
        };
        if got == 0 {
            return PeInfo::default();
        }
        let block = buffer.as_ptr().cast::<core::ffi::c_void>();
        // Most binaries declare exactly one translation; a handful (notably some
        // localized system files) declare none despite having string data under
        // the generic "neutral" `0409 04B0` (US English, Unicode) key — the
        // fallback every version-resource reader in the wild uses.
        let (lang, codepage) = translation(block).unwrap_or((0x0409, 0x04B0));
        PeInfo {
            original_file_name: string_value(block, lang, codepage, "OriginalFilename"),
            company_name: string_value(block, lang, codepage, "CompanyName"),
            file_description: string_value(block, lang, codepage, "FileDescription"),
            product_name: string_value(block, lang, codepage, "ProductName"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_reads_as_empty() {
        let info = read(Path::new("/nonexistent/pe-info-test"));
        assert!(info.is_empty());
    }

    #[test]
    fn non_pe_file_reads_as_empty() {
        let p = std::env::temp_dir().join(format!("pe-info-test-{}", std::process::id()));
        std::fs::write(&p, b"just some bytes, not a PE").unwrap();
        let info = read(&p);
        assert!(info.is_empty());
        std::fs::remove_file(&p).ok();
    }

    /// Real platform coverage in CI, mirroring `lib.rs`'s
    /// `platform_signature_of_system_binary`: a known system binary's
    /// `OriginalFilename` must round-trip. `cmd.exe` is the exact example issue
    /// #983 and this module's own doc comment use, but the exact string is build-
    /// and locale-dependent — caught on a real (French-localized) Windows host in
    /// this PR's own CI run, where System32's `cmd.exe` reads `Cmd.Exe.MUI`, not
    /// `Cmd.Exe` (`FileDescription` comes back as `Interpréteur de commandes
    /// Windows`, confirming this is the real resource, not a misread). The
    /// prefix check below is deliberately loose for that reason; a rule shipped
    /// against the real catalogue would need the same tolerance, which is itself
    /// a finding worth carrying into any follow-up that ships actual
    /// `OriginalFileName` content rules.
    #[cfg(windows)]
    #[test]
    fn cmd_exe_original_file_name_starts_with_cmd_dot_exe() {
        let path = Path::new(r"C:\Windows\System32\cmd.exe");
        if !path.exists() {
            eprintln!("skipping: {} not present on this host", path.display());
            return;
        }
        let info = read(path);
        let name = info
            .original_file_name
            .as_deref()
            .unwrap_or_else(|| panic!("expected an OriginalFilename: {info:?}"));
        assert!(
            name.to_lowercase().starts_with("cmd.exe"),
            "expected an OriginalFilename starting with `cmd.exe`, got {name:?} ({info:?})"
        );
        assert_eq!(
            info.company_name.as_deref(),
            Some("Microsoft Corporation"),
            "{info:?}"
        );
        assert!(info.product_name.is_some());
    }

    #[cfg(not(windows))]
    #[test]
    fn always_empty_off_windows() {
        // Even a real, existing file reads as empty: the platform has no PE
        // version-resource concept to read, not a failed read of one.
        let info = read(Path::new(file!()));
        assert!(info.is_empty());
    }
}
