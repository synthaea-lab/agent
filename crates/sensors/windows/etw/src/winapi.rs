//! Win32/NT API access for enrichment of ETW events: real command lines (F-1),
//! token identity (F-3), the volume map (F-5), and process-table seeding. Every
//! function here is best-effort — a failure degrades one field, never the event.

use std::collections::HashMap;

use schema::User;
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
    Security::{
        Authorization::ConvertSidToStringSidW, GetTokenInformation, TOKEN_MANDATORY_LABEL,
        TOKEN_QUERY, TOKEN_USER, TokenIntegrityLevel, TokenUser,
    },
    Storage::FileSystem::QueryDosDeviceW,
    System::{
        Diagnostics::{
            Debug::ReadProcessMemory,
            ToolHelp::{
                CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
                TH32CS_SNAPPROCESS,
            },
        },
        Threading::{
            OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_VM_READ, QueryFullProcessImageNameW,
        },
    },
};

// ── F-1: real command line from the target's PEB ─────────────────────────────

#[repr(C)]
struct ProcessBasicInformation {
    exit_status: isize,
    peb_base_address: *mut core::ffi::c_void,
    affinity_mask: usize,
    base_priority: isize,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

// NtQueryInformationProcess is the documented-enough route to the PEB address;
// a manual ntdll binding keeps the surface to one function (same stance as the
// WinVerifyTrust binding in `enrich`).
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationProcess(
        process: HANDLE,
        class: u32,
        info: *mut core::ffi::c_void,
        info_len: u32,
        return_len: *mut u32,
    ) -> i32;
}

/// Reads the target's real command line from its PEB
/// (`PEB → ProcessParameters → CommandLine`). This is what fixes F-1: the encoded
/// `PowerShell` payload, the `LOLBin` arguments — everything the ETW `ProcessStart` event
/// does not carry. `None` on any failure (protected process, already exited, WOW64
/// mismatch) — the caller falls back to the image path, never fabricates.
pub(crate) fn read_process_cmdline(pid: u32) -> Option<String> {
    // SAFETY: OpenProcess returns either null (checked) or a handle we own and
    // close on every path; read_cmdline_from_handle only receives the live handle.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pid);
        if handle.is_null() {
            return None;
        }
        let result = read_cmdline_from_handle(handle);
        CloseHandle(handle);
        result
    }
}

/// PEB (x64): `ProcessParameters` pointer offset.
const PEB_PROCESS_PARAMETERS: usize = 0x20;
/// `RTL_USER_PROCESS_PARAMETERS` (x64): `CommandLine` `UNICODE_STRING` offset
/// (`Length: u16`, `MaximumLength: u16`, pad, `Buffer: *mut u16` at +0x8).
const PARAMS_CMDLINE_LENGTH: usize = 0x70;
const PARAMS_CMDLINE_BUFFER: usize = 0x78;

/// Reads one plain-old-data value out of the target's address space.
///
/// # Safety
///
/// `T` must be valid for any bit pattern (used here with `usize` and `u16`);
/// `addr` is only ever passed to the kernel as a remote address, never
/// dereferenced locally.
unsafe fn read_remote<T: Copy>(handle: HANDLE, addr: usize) -> Option<T> {
    // SAFETY: the destination is a local zeroed T and the length is exactly
    // size_of::<T>(); the return code is checked.
    unsafe {
        let mut value: T = core::mem::zeroed();
        if ReadProcessMemory(
            handle,
            addr as *const _,
            (&mut value as *mut T).cast(),
            size_of::<T>(),
            core::ptr::null_mut(),
        ) == 0
        {
            return None;
        }
        Some(value)
    }
}

/// The PEB walk: `PEB → ProcessParameters → CommandLine{Length, Buffer}`.
unsafe fn read_cmdline_from_handle(handle: HANDLE) -> Option<String> {
    // SAFETY: NtQueryInformationProcess writes into a local zeroed struct of the
    // exact size passed; remote pointers flow only through read_remote.
    unsafe {
        let mut pbi: ProcessBasicInformation = core::mem::zeroed();
        let mut ret_len = 0u32;
        // 0 = ProcessBasicInformation
        if NtQueryInformationProcess(
            handle,
            0,
            (&mut pbi as *mut ProcessBasicInformation).cast(),
            size_of::<ProcessBasicInformation>() as u32,
            &mut ret_len,
        ) != 0
            || pbi.peb_base_address.is_null()
        {
            return None;
        }
        let peb = pbi.peb_base_address as usize;

        let params: usize = read_remote(handle, peb + PEB_PROCESS_PARAMETERS)?;
        if params == 0 {
            return None;
        }
        let len_bytes: u16 = read_remote(handle, params + PARAMS_CMDLINE_LENGTH)?;
        if len_bytes == 0 {
            return None;
        }
        let buf_ptr: usize = read_remote(handle, params + PARAMS_CMDLINE_BUFFER)?;
        if buf_ptr == 0 {
            return None;
        }

        // F-4 by construction: read the full length, no 256-byte cap. Bound only by
        // the UNICODE_STRING's own u16 length (64KB), which is the OS's bound.
        let n_u16 = (len_bytes as usize) / 2;
        let mut wide = vec![0u16; n_u16];
        // SAFETY: the destination buffer holds exactly len_bytes bytes.
        if ReadProcessMemory(
            handle,
            buf_ptr as *const _,
            wide.as_mut_ptr().cast(),
            len_bytes as usize,
            core::ptr::null_mut(),
        ) == 0
        {
            return None;
        }
        Some(String::from_utf16_lossy(&wide))
    }
}

// ── F-3: token identity (SID + integrity level) ──────────────────────────────

/// Resolves the user the process runs as. `User::Unknown` on failure — the
/// capabilities flag stays honest either way.
pub(crate) fn read_process_user(pid: u32) -> User {
    // SAFETY: process and token handles are null-checked and closed on every
    // path; token_sid_string/token_integrity_rid only see live handles.
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            // Exited or protected target: attribution honestly failed. Never fall
            // back to our own token — the agent runs as SYSTEM, and stamping SYSTEM
            // onto exactly the processes we could not open would corrupt identity
            // where it matters most (review finding on #100).
            return User::Unknown;
        }
        let mut token: HANDLE = core::ptr::null_mut();
        if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
            CloseHandle(process);
            return User::Unknown;
        }

        let sid = token_sid_string(token);
        let integrity_level = token_integrity_rid(token);

        CloseHandle(token);
        CloseHandle(process);
        match sid {
            Some(sid) => User::Windows {
                sid,
                integrity_level,
            },
            None => User::Unknown,
        }
    }
}

unsafe fn token_sid_string(token: HANDLE) -> Option<String> {
    // SAFETY: the buffer is sized by the first GetTokenInformation call and the
    // TOKEN_USER cast reads within it; the SID string is measured to its NUL and
    // freed with LocalFree exactly once.
    unsafe {
        let mut needed = 0u32;
        GetTokenInformation(token, TokenUser, core::ptr::null_mut(), 0, &mut needed);
        if needed == 0 {
            return None;
        }
        let mut buf = vec![0u8; needed as usize];
        if GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        ) == 0
        {
            return None;
        }
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut wide: *mut u16 = core::ptr::null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut wide) == 0 || wide.is_null() {
            return None;
        }
        let mut len = 0usize;
        while *wide.add(len) != 0 {
            len += 1;
        }
        let s = String::from_utf16_lossy(core::slice::from_raw_parts(wide, len));
        windows_sys::Win32::Foundation::LocalFree(wide.cast());
        Some(s)
    }
}

unsafe fn token_integrity_rid(token: HANDLE) -> Option<u32> {
    // SAFETY: the buffer is sized by the first GetTokenInformation call; the SID
    // sub-authority read is bounded by the SID's own count byte (checked > 0).
    unsafe {
        let mut needed = 0u32;
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            core::ptr::null_mut(),
            0,
            &mut needed,
        );
        if needed == 0 {
            return None;
        }
        let mut buf = vec![0u8; needed as usize];
        if GetTokenInformation(
            token,
            TokenIntegrityLevel,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        ) == 0
        {
            return None;
        }
        let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        // The integrity RID is the SID's last sub-authority.
        let sid = label.Label.Sid as *const u8;
        let count = *sid.add(1);
        if count == 0 {
            return None;
        }
        let sub_auths = sid.add(8) as *const u32;
        Some(*sub_auths.add((count - 1) as usize))
    }
}

// ── F-5: real volume map via QueryDosDeviceW ─────────────────────────────────

/// Builds the `\Device\HarddiskVolumeN` → `X:` map from the live drive table.
/// Consumed by [`crate::normalize::normalize_nt_path`]; refreshed by the sensor on
/// normalization misses (a newly mounted VHDX appears without restart).
pub(crate) fn build_volume_map() -> HashMap<String, String> {
    let mut map = HashMap::new();
    for letter in b'A'..=b'Z' {
        let drive: [u16; 3] = [letter as u16, b':' as u16, 0];
        let mut target = [0u16; 512];
        // SAFETY: both buffers are valid for the lengths passed (drive is
        // NUL-terminated, target is 512 wide chars as declared).
        let n = unsafe { QueryDosDeviceW(drive.as_ptr(), target.as_mut_ptr(), 512) };
        if n == 0 {
            continue;
        }
        let end = target.iter().position(|&c| c == 0).unwrap_or(0);
        if end == 0 {
            continue;
        }
        map.insert(
            String::from_utf16_lossy(&target[..end]),
            format!("{}:", letter as char),
        );
    }
    map
}

// ── Process-table seeding + live lookup (carried over from the old sensor) ───

/// Fills the pid→image table with every process running at call time (before the
/// trace starts), so network events from already-running processes resolve — and
/// the rules' parent-side exclusions apply to pre-existing parents.
pub(crate) fn snapshot_processes() -> Vec<(u32, String)> {
    let mut out = Vec::new();
    // SAFETY: the snapshot handle is checked against INVALID_HANDLE_VALUE and
    // closed; PROCESSENTRY32W is zeroed with dwSize set before the first call,
    // and szExeFile reads are bounded by its NUL (or full length).
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            tracing::warn!("toolhelp snapshot failed — seeding skipped");
            return out;
        }
        let mut entry: PROCESSENTRY32W = core::mem::zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut entry) != 0 {
            loop {
                let end = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                out.push((
                    entry.th32ProcessID,
                    String::from_utf16_lossy(&entry.szExeFile[..end]),
                ));
                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    out
}

/// Live pid → image name via Win32 — the fallback for the ETW race where a
/// `ConnectEvent` arrives before the `ExecEvent` populated the store.
/// `PROCESS_QUERY_LIMITED_INFORMATION` needs no admin privileges.
pub(crate) fn resolve_pid_live(pid: u32) -> Option<String> {
    // SAFETY: the handle is null-checked and closed on every path; the buffer
    // length in/out contract of QueryFullProcessImageNameW is respected.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
        CloseHandle(handle);
        if ok == 0 {
            return None;
        }
        let path = String::from_utf16_lossy(&buf[..len as usize]);
        Some(path)
    }
}
