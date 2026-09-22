//! FFI mirror of `shim/es_shim.h` — the only place the C shim's layout is
//! spelled in Rust, kept field-for-field identical to the header (both sides
//! are plain C layout; the shim exists so no `es_message_t` internals ever
//! appear here).

use std::ffi::{c_char, c_void};

use crate::raw::{BtmItemType, RawEsEvent, RawMeta};

/// Mirrors `SYN_ES_MAX_ARGV`.
pub(crate) const SYN_ES_MAX_ARGV: usize = 128;

// Mirrors `enum syn_es_kind`.
pub(crate) const SYN_ES_KIND_EXEC: i32 = 1;
pub(crate) const SYN_ES_KIND_OPEN: i32 = 2;
pub(crate) const SYN_ES_KIND_CREATE: i32 = 3;
pub(crate) const SYN_ES_KIND_RENAME: i32 = 4;
pub(crate) const SYN_ES_KIND_UNLINK: i32 = 5;
pub(crate) const SYN_ES_KIND_MMAP_WRITE_SHARED: i32 = 6;
pub(crate) const SYN_ES_KIND_BTM_LAUNCH_ITEM_ADD: i32 = 7;
pub(crate) const SYN_ES_KIND_SSH_LOGIN: i32 = 8;
pub(crate) const SYN_ES_KIND_LOGIN: i32 = 9;
pub(crate) const SYN_ES_KIND_LW_LOGIN: i32 = 10;
pub(crate) const SYN_ES_KIND_QUARANTINE: i32 = 11;
pub(crate) const SYN_ES_KIND_MOUNT: i32 = 12;
pub(crate) const SYN_ES_KIND_UNMOUNT: i32 = 13;
pub(crate) const SYN_ES_KIND_SIGNAL_ES_CLIENT: i32 = 14;
pub(crate) const SYN_ES_KIND_XPC_CONNECT: i32 = 15;

// Mirrors the `SYN_ES_GROUP_*` bitflags.
pub(crate) const SYN_ES_GROUP_EXEC: u32 = 0x1;
pub(crate) const SYN_ES_GROUP_FILE: u32 = 0x2;
pub(crate) const SYN_ES_GROUP_PERSISTENCE: u32 = 0x4;
pub(crate) const SYN_ES_GROUP_SESSIONS: u32 = 0x8;
pub(crate) const SYN_ES_GROUP_PROVENANCE: u32 = 0x10;
pub(crate) const SYN_ES_GROUP_MOUNT: u32 = 0x20;
pub(crate) const SYN_ES_GROUP_TAMPER: u32 = 0x40;
pub(crate) const SYN_ES_GROUP_XPC: u32 = 0x80;

/// Mirrors `syn_es_str`: borrowed, length-delimited, `data` null when absent.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct SynEsStr {
    pub data: *const c_char,
    pub len: usize,
}

impl SynEsStr {
    /// Copies the borrowed bytes out (lossy on invalid UTF-8 — ES paths are
    /// bytes, and a path with broken UTF-8 must still surface rather than
    /// drop the event). `None` when the field is absent.
    ///
    /// # Safety
    ///
    /// `data`, when non-null, must point to `len` readable bytes — guaranteed
    /// by the shim for the duration of the callback.
    unsafe fn to_option_string(self) -> Option<String> {
        if self.data.is_null() {
            return None;
        }
        // SAFETY: non-null `data` with `len` readable bytes per the contract
        // above; the slice is copied before the callback returns.
        let bytes = unsafe { std::slice::from_raw_parts(self.data.cast::<u8>(), self.len) };
        Some(String::from_utf8_lossy(bytes).into_owned())
    }

    /// Like [`SynEsStr::to_option_string`], defaulting absence to `""`.
    ///
    /// # Safety
    ///
    /// Same contract as [`SynEsStr::to_option_string`].
    unsafe fn to_string_lossy(self) -> String {
        // SAFETY: forwarded contract.
        unsafe { self.to_option_string() }.unwrap_or_default()
    }

    /// Raw-bytes copy for fields that are not text (the `kMDItemWhereFroms`
    /// binary plist). `None` when absent.
    ///
    /// # Safety
    ///
    /// Same contract as [`SynEsStr::to_option_string`].
    unsafe fn to_option_bytes(self) -> Option<Vec<u8>> {
        if self.data.is_null() {
            return None;
        }
        // SAFETY: non-null `data` with `len` readable bytes per the contract.
        Some(unsafe { std::slice::from_raw_parts(self.data.cast::<u8>(), self.len) }.to_vec())
    }
}

/// Mirrors `syn_es_meta`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct SynEsMeta {
    pub pid: i32,
    pub ppid: i32,
    pub uid: u32,
    pub gid: u32,
    pub wall_time_ns: u64,
    pub process_path: SynEsStr,
}

/// Mirrors `syn_es_event` (flat struct — see the header for why no union).
#[repr(C)]
pub(crate) struct SynEsEvent {
    pub kind: i32,
    pub meta: SynEsMeta,

    pub exec_image_path: SynEsStr,
    pub exec_argc: u32,
    pub exec_argc_total: u32,
    pub exec_argv: [SynEsStr; SYN_ES_MAX_ARGV],
    pub exec_signing_id: SynEsStr,
    pub exec_team_id: SynEsStr,
    pub exec_cs_flags: u32,
    pub exec_is_platform_binary: u8,
    pub exec_parent_path: SynEsStr,

    pub file_path: SynEsStr,
    pub open_fflag: i32,
    pub rename_old_path: SynEsStr,

    pub btm_item_type: u32,
    pub btm_legacy: u8,
    pub btm_item_uid: u32,
    pub btm_app_url: SynEsStr,
    pub btm_executable_path: SynEsStr,

    pub auth_success: u8,
    pub auth_username: SynEsStr,
    pub auth_source_address: SynEsStr,

    pub quarantine_raw: SynEsStr,
    pub wherefroms_raw: SynEsStr,

    pub mount_source: SynEsStr,
    pub mount_fs_type: SynEsStr,
    pub mount_readonly: u8,

    pub signal_number: i32,
    pub signal_target_pid: i32,

    pub xpc_service_name: SynEsStr,
    pub xpc_domain_type: u32,
}

impl SynEsEvent {
    /// Converts the borrowed C record into an owned [`RawEsEvent`], copying
    /// every string. `None` for an unknown `kind` (a shim newer than this
    /// crate — skip, never crash the pipeline).
    ///
    /// # Safety
    ///
    /// Every `SynEsStr` in `self` must satisfy the borrow contract of
    /// [`SynEsStr::to_option_string`] — guaranteed by the shim within the
    /// callback.
    pub(crate) unsafe fn to_raw(&self) -> Option<RawEsEvent> {
        // SAFETY: all string accesses below inherit this function's contract.
        unsafe {
            let meta = RawMeta {
                pid: self.meta.pid.max(0).cast_unsigned(),
                ppid: self.meta.ppid.max(0).cast_unsigned(),
                uid: self.meta.uid,
                gid: self.meta.gid,
                wall_time_ns: self.meta.wall_time_ns,
                process_path: self.meta.process_path.to_string_lossy(),
            };
            match self.kind {
                SYN_ES_KIND_EXEC => {
                    let argc = (self.exec_argc as usize).min(SYN_ES_MAX_ARGV);
                    let argv = self.exec_argv[..argc]
                        .iter()
                        .map(|s| s.to_string_lossy())
                        .collect();
                    Some(RawEsEvent::Exec {
                        meta,
                        image_path: self.exec_image_path.to_string_lossy(),
                        argv,
                        argv_truncated: self.exec_argc_total > self.exec_argc,
                        signing_id: self
                            .exec_signing_id
                            .to_option_string()
                            .filter(|s| !s.is_empty()),
                        team_id: self
                            .exec_team_id
                            .to_option_string()
                            .filter(|s| !s.is_empty()),
                        cs_flags: self.exec_cs_flags,
                        is_platform_binary: self.exec_is_platform_binary != 0,
                        parent_path: self
                            .exec_parent_path
                            .to_option_string()
                            .filter(|s| !s.is_empty()),
                    })
                }
                SYN_ES_KIND_OPEN => Some(RawEsEvent::Open {
                    meta,
                    path: self.file_path.to_string_lossy(),
                    fflag: self.open_fflag,
                }),
                SYN_ES_KIND_CREATE => Some(RawEsEvent::Create {
                    meta,
                    path: self.file_path.to_string_lossy(),
                }),
                SYN_ES_KIND_RENAME => Some(RawEsEvent::Rename {
                    meta,
                    old_path: self.rename_old_path.to_string_lossy(),
                    new_path: self.file_path.to_string_lossy(),
                }),
                SYN_ES_KIND_UNLINK => Some(RawEsEvent::Unlink {
                    meta,
                    path: self.file_path.to_string_lossy(),
                }),
                SYN_ES_KIND_MMAP_WRITE_SHARED => Some(RawEsEvent::MmapWriteShared {
                    meta,
                    path: self.file_path.to_string_lossy(),
                }),
                SYN_ES_KIND_SSH_LOGIN => Some(RawEsEvent::SshLogin {
                    meta,
                    success: self.auth_success != 0,
                    username: self.auth_username.to_string_lossy(),
                    source_address: self
                        .auth_source_address
                        .to_option_string()
                        .filter(|s| !s.is_empty()),
                }),
                SYN_ES_KIND_LOGIN => Some(RawEsEvent::LoginLogin {
                    meta,
                    success: self.auth_success != 0,
                    username: self.auth_username.to_string_lossy(),
                }),
                SYN_ES_KIND_LW_LOGIN => Some(RawEsEvent::LwSessionLogin {
                    meta,
                    username: self.auth_username.to_string_lossy(),
                }),
                SYN_ES_KIND_QUARANTINE => Some(RawEsEvent::QuarantineSet {
                    meta,
                    path: self.file_path.to_string_lossy(),
                    quarantine: self
                        .quarantine_raw
                        .to_option_string()
                        .filter(|s| !s.is_empty()),
                    wherefroms_plist: self.wherefroms_raw.to_option_bytes(),
                }),
                SYN_ES_KIND_MOUNT | SYN_ES_KIND_UNMOUNT => Some(RawEsEvent::Mount {
                    meta,
                    mount_point: self.file_path.to_string_lossy(),
                    source: self
                        .mount_source
                        .to_option_string()
                        .filter(|s| !s.is_empty()),
                    fs_type: self
                        .mount_fs_type
                        .to_option_string()
                        .filter(|s| !s.is_empty()),
                    readonly: self.mount_readonly != 0,
                    mounted: self.kind == SYN_ES_KIND_MOUNT,
                }),
                SYN_ES_KIND_SIGNAL_ES_CLIENT => Some(RawEsEvent::SignalToEsClient {
                    meta,
                    signal: self.signal_number.max(0).cast_unsigned(),
                    target_pid: self.signal_target_pid.max(0).cast_unsigned(),
                    target_path: self.file_path.to_option_string().filter(|s| !s.is_empty()),
                }),
                SYN_ES_KIND_XPC_CONNECT => Some(RawEsEvent::XpcConnect {
                    meta,
                    service_name: self.xpc_service_name.to_string_lossy(),
                    domain_type: self.xpc_domain_type,
                }),
                SYN_ES_KIND_BTM_LAUNCH_ITEM_ADD => Some(RawEsEvent::BtmLaunchItemAdd {
                    meta,
                    item_type: BtmItemType::from_raw(self.btm_item_type),
                    legacy: self.btm_legacy != 0,
                    item_uid: self.btm_item_uid,
                    item_url: self.file_path.to_string_lossy(),
                    app_url: self
                        .btm_app_url
                        .to_option_string()
                        .filter(|s| !s.is_empty()),
                    executable_path: self
                        .btm_executable_path
                        .to_option_string()
                        .filter(|s| !s.is_empty()),
                }),
                _ => None,
            }
        }
    }
}

/// Opaque `syn_es_client`.
#[repr(C)]
pub(crate) struct SynEsClient {
    _opaque: [u8; 0],
}

pub(crate) type SynEsEventCb = unsafe extern "C" fn(ctx: *mut c_void, event: *const SynEsEvent);

unsafe extern "C" {
    pub(crate) fn syn_es_client_new(
        cb: SynEsEventCb,
        ctx: *mut c_void,
        out_client: *mut *mut SynEsClient,
    ) -> i32;
    pub(crate) fn syn_es_subscribe(client: *mut SynEsClient, groups: u32) -> i32;
    pub(crate) fn syn_es_mute_self(client: *mut SynEsClient) -> i32;
    pub(crate) fn syn_es_client_destroy(client: *mut SynEsClient);
}
