//! The Host Compute Service client behind container attribution (#371): the
//! containers the service runs, and the processes in each.
//!
//! `computecore.dll` is loaded on first use, from System32 only, and first use
//! only happens once a process was seen in a server silo. Linking it would make
//! the agent fail to start on a build without it, and a host that never runs a
//! container never needs it. When the DLL or the service is missing, every call
//! answers an error and the silo keeps its provisional id.

use std::{ffi::c_void, sync::OnceLock};

use windows_sys::{
    Win32::{
        Foundation::{GENERIC_ALL, LocalFree},
        System::LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW},
    },
    core::{HRESULT, PCWSTR, PWSTR},
};

use crate::silo::{self, ContainerSource};

/// Per call: the service answers in milliseconds, and a resolver pass that
/// waits on a hung service only delays attribution, never an event.
const TIMEOUT_MS: u32 = 5_000;
/// Every compute system; containers are filtered from the answer.
const ALL_SYSTEMS_QUERY: &str = "{}";
const PROCESS_LIST_QUERY: &str = r#"{"PropertyTypes":["ProcessList"]}"#;

type HcsOperation = *mut c_void;
type HcsSystem = *mut c_void;
type CreateOperation = unsafe extern "system" fn(*const c_void, *const c_void) -> HcsOperation;
type CloseOperation = unsafe extern "system" fn(HcsOperation);
type EnumerateComputeSystems = unsafe extern "system" fn(PCWSTR, HcsOperation) -> HRESULT;
type OpenComputeSystem = unsafe extern "system" fn(PCWSTR, u32, *mut HcsSystem) -> HRESULT;
type CloseComputeSystem = unsafe extern "system" fn(HcsSystem);
type GetComputeSystemProperties =
    unsafe extern "system" fn(HcsSystem, HcsOperation, PCWSTR) -> HRESULT;
type WaitForOperationResult = unsafe extern "system" fn(HcsOperation, u32, *mut PWSTR) -> HRESULT;

struct Api {
    create_operation: CreateOperation,
    close_operation: CloseOperation,
    enumerate: EnumerateComputeSystems,
    open_system: OpenComputeSystem,
    close_system: CloseComputeSystem,
    properties: GetComputeSystemProperties,
    wait: WaitForOperationResult,
}

/// The Host Compute Service, loaded on first use.
#[derive(Default)]
pub(crate) struct Hcs {
    api: OnceLock<Option<Api>>,
}

impl Hcs {
    fn api(&self) -> Result<&Api, String> {
        self.api
            .get_or_init(load)
            .as_ref()
            .ok_or_else(|| "computecore.dll unavailable".to_string())
    }
}

impl ContainerSource for Hcs {
    fn container_ids(&self) -> Result<Vec<String>, String> {
        let api = self.api()?;
        let query = wide(ALL_SYSTEMS_QUERY);
        // SAFETY: `query` is NUL-terminated and outlives the call, which
        // `run_operation` waits for.
        let json = unsafe { run_operation(api, |op| (api.enumerate)(query.as_ptr(), op)) }?;
        Ok(silo::parse_container_ids(&json))
    }

    fn processes(&self, container_id: &str) -> Result<Vec<(u32, String)>, String> {
        let api = self.api()?;
        let id = wide(container_id);
        let query = wide(PROCESS_LIST_QUERY);
        // SAFETY: `id` and `query` are NUL-terminated and outlive both calls;
        // the system handle is closed on every path after a successful open.
        unsafe {
            let mut system: HcsSystem = core::ptr::null_mut();
            let hr = (api.open_system)(id.as_ptr(), GENERIC_ALL, &mut system);
            if hr < 0 || system.is_null() {
                return Err(format!("HcsOpenComputeSystem: {}", hresult(hr)));
            }
            let json = run_operation(api, |op| (api.properties)(system, op, query.as_ptr()));
            (api.close_system)(system);
            Ok(silo::parse_process_list(&json?))
        }
    }
}

fn load() -> Option<Api> {
    let name = wide("computecore.dll");
    // SAFETY: `name` is NUL-terminated; the module is never freed, so the
    // function pointers stay valid for the life of the process. Each pointer is
    // transmuted to the signature computecore.h declares for that name.
    unsafe {
        let module = LoadLibraryExW(
            name.as_ptr(),
            core::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        );
        if module.is_null() {
            tracing::debug!("computecore.dll not found: no container lookup");
            return None;
        }
        macro_rules! symbol {
            ($name:literal, $ty:ty) => {
                core::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(GetProcAddress(
                    module,
                    concat!($name, "\0").as_ptr(),
                )?)
            };
        }
        Some(Api {
            create_operation: symbol!("HcsCreateOperation", CreateOperation),
            close_operation: symbol!("HcsCloseOperation", CloseOperation),
            enumerate: symbol!("HcsEnumerateComputeSystems", EnumerateComputeSystems),
            open_system: symbol!("HcsOpenComputeSystem", OpenComputeSystem),
            close_system: symbol!("HcsCloseComputeSystem", CloseComputeSystem),
            properties: symbol!("HcsGetComputeSystemProperties", GetComputeSystemProperties),
            wait: symbol!("HcsWaitForOperationResult", WaitForOperationResult),
        })
    }
}

/// Starts one asynchronous HCS call on a fresh operation and waits for its
/// result document.
///
/// # Safety
///
/// `start` must only pass the operation to an HCS function together with
/// arguments that stay valid until this function returns.
unsafe fn run_operation(
    api: &Api,
    start: impl FnOnce(HcsOperation) -> HRESULT,
) -> Result<String, String> {
    // SAFETY: the operation is null-checked and closed on every path; the
    // result document is owned by us once returned and freed with LocalFree,
    // as computecore.h requires.
    unsafe {
        let op = (api.create_operation)(core::ptr::null(), core::ptr::null());
        if op.is_null() {
            return Err("HcsCreateOperation failed".to_string());
        }
        let hr = start(op);
        if hr < 0 {
            (api.close_operation)(op);
            return Err(hresult(hr));
        }
        let mut document: PWSTR = core::ptr::null_mut();
        let hr = (api.wait)(op, TIMEOUT_MS, &mut document);
        let text = if document.is_null() {
            String::new()
        } else {
            let text = from_wide_nul(document);
            LocalFree(document.cast());
            text
        };
        (api.close_operation)(op);
        if hr < 0 {
            return Err(format!("{}: {text}", hresult(hr)));
        }
        Ok(text)
    }
}

/// # Safety
///
/// `ptr` points to a NUL-terminated UTF-16 string.
unsafe fn from_wide_nul(ptr: *const u16) -> String {
    // SAFETY: the caller guarantees a terminator, so every read up to it is
    // inside the string.
    unsafe {
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(core::slice::from_raw_parts(ptr, len))
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn hresult(hr: HRESULT) -> String {
    format!("HRESULT 0x{:08X}", hr.cast_unsigned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whatever the host (no Containers feature, no running service): the
    /// lookup answers, it does not crash or hang past its timeout.
    #[test]
    fn listing_containers_answers_on_any_host() {
        let _ = Hcs::default().container_ids();
    }
}
