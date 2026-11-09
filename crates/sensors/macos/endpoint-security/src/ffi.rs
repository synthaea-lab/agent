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

    /// Like [`SynEsStr::to_option_string`], treating an empty string as
    /// absent (the shim reports some optional fields as `""`).
    ///
    /// # Safety
    ///
    /// Same contract as [`SynEsStr::to_option_string`].
    unsafe fn to_non_empty_string(self) -> Option<String> {
        // SAFETY: forwarded contract.
        unsafe { self.to_option_string() }.filter(|s| !s.is_empty())
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
    /// callback. Each per-kind conversion below relies on the same contract
    /// for the fields of its kind only.
    pub(crate) unsafe fn to_raw(&self) -> Option<RawEsEvent> {
        // SAFETY: `meta.process_path` is borrowed per this function's contract.
        let meta = unsafe { self.raw_meta() };
        // SAFETY: each arm calls one per-kind conversion, which reads only
        // fields covered by this function's contract.
        let raw = unsafe {
            match self.kind {
                SYN_ES_KIND_EXEC => self.exec_to_raw(meta),
                SYN_ES_KIND_OPEN => self.open_to_raw(meta),
                SYN_ES_KIND_CREATE => self.create_to_raw(meta),
                SYN_ES_KIND_RENAME => self.rename_to_raw(meta),
                SYN_ES_KIND_UNLINK => self.unlink_to_raw(meta),
                SYN_ES_KIND_MMAP_WRITE_SHARED => self.mmap_write_shared_to_raw(meta),
                SYN_ES_KIND_SSH_LOGIN => self.ssh_login_to_raw(meta),
                SYN_ES_KIND_LOGIN => self.login_to_raw(meta),
                SYN_ES_KIND_LW_LOGIN => self.lw_login_to_raw(meta),
                SYN_ES_KIND_QUARANTINE => self.quarantine_to_raw(meta),
                SYN_ES_KIND_MOUNT | SYN_ES_KIND_UNMOUNT => self.mount_to_raw(meta),
                SYN_ES_KIND_SIGNAL_ES_CLIENT => self.signal_to_raw(meta),
                SYN_ES_KIND_XPC_CONNECT => self.xpc_connect_to_raw(meta),
                SYN_ES_KIND_BTM_LAUNCH_ITEM_ADD => self.btm_launch_item_add_to_raw(meta),
                _ => return None,
            }
        };
        Some(raw)
    }

    /// # Safety
    ///
    /// `meta.process_path` must satisfy the [`SynEsStr`] borrow contract.
    unsafe fn raw_meta(&self) -> RawMeta {
        RawMeta {
            pid: self.meta.pid.max(0).cast_unsigned(),
            ppid: self.meta.ppid.max(0).cast_unsigned(),
            uid: self.meta.uid,
            gid: self.meta.gid,
            wall_time_ns: self.meta.wall_time_ns,
            // SAFETY: forwarded contract.
            process_path: unsafe { self.meta.process_path.to_string_lossy() },
        }
    }

    /// # Safety
    ///
    /// The first `min(exec_argc, SYN_ES_MAX_ARGV)` entries of `exec_argv` and
    /// the other `exec_*` strings must satisfy the [`SynEsStr`] borrow contract.
    unsafe fn exec_to_raw(&self, meta: RawMeta) -> RawEsEvent {
        let argc = (self.exec_argc as usize).min(SYN_ES_MAX_ARGV);
        // SAFETY: forwarded contract; the shim fills exactly `exec_argc`
        // entries and `argc` never exceeds the array.
        unsafe {
            RawEsEvent::Exec {
                meta,
                image_path: self.exec_image_path.to_string_lossy(),
                argv: self.exec_argv[..argc]
                    .iter()
                    .map(|s| s.to_string_lossy())
                    .collect(),
                argv_truncated: self.exec_argc_total > self.exec_argc,
                signing_id: self.exec_signing_id.to_non_empty_string(),
                team_id: self.exec_team_id.to_non_empty_string(),
                cs_flags: self.exec_cs_flags,
                is_platform_binary: self.exec_is_platform_binary != 0,
                parent_path: self.exec_parent_path.to_non_empty_string(),
            }
        }
    }

    /// # Safety
    ///
    /// `file_path` must satisfy the [`SynEsStr`] borrow contract.
    unsafe fn open_to_raw(&self, meta: RawMeta) -> RawEsEvent {
        // SAFETY: forwarded contract.
        let path = unsafe { self.file_path.to_string_lossy() };
        RawEsEvent::Open {
            meta,
            path,
            fflag: self.open_fflag,
        }
    }

    /// # Safety
    ///
    /// `file_path` must satisfy the [`SynEsStr`] borrow contract.
    unsafe fn create_to_raw(&self, meta: RawMeta) -> RawEsEvent {
        // SAFETY: forwarded contract.
        let path = unsafe { self.file_path.to_string_lossy() };
        RawEsEvent::Create { meta, path }
    }

    /// # Safety
    ///
    /// `rename_old_path` and `file_path` must satisfy the [`SynEsStr`] borrow
    /// contract.
    unsafe fn rename_to_raw(&self, meta: RawMeta) -> RawEsEvent {
        // SAFETY: forwarded contract.
        let (old_path, new_path) = unsafe {
            (
                self.rename_old_path.to_string_lossy(),
                self.file_path.to_string_lossy(),
            )
        };
        RawEsEvent::Rename {
            meta,
            old_path,
            new_path,
        }
    }

    /// # Safety
    ///
    /// `file_path` must satisfy the [`SynEsStr`] borrow contract.
    unsafe fn unlink_to_raw(&self, meta: RawMeta) -> RawEsEvent {
        // SAFETY: forwarded contract.
        let path = unsafe { self.file_path.to_string_lossy() };
        RawEsEvent::Unlink { meta, path }
    }

    /// # Safety
    ///
    /// `file_path` must satisfy the [`SynEsStr`] borrow contract.
    unsafe fn mmap_write_shared_to_raw(&self, meta: RawMeta) -> RawEsEvent {
        // SAFETY: forwarded contract.
        let path = unsafe { self.file_path.to_string_lossy() };
        RawEsEvent::MmapWriteShared { meta, path }
    }

    /// # Safety
    ///
    /// `auth_username` and `auth_source_address` must satisfy the
    /// [`SynEsStr`] borrow contract.
    unsafe fn ssh_login_to_raw(&self, meta: RawMeta) -> RawEsEvent {
        // SAFETY: forwarded contract.
        let (username, source_address) = unsafe {
            (
                self.auth_username.to_string_lossy(),
                self.auth_source_address.to_non_empty_string(),
            )
        };
        RawEsEvent::SshLogin {
            meta,
            success: self.auth_success != 0,
            username,
            source_address,
        }
    }

    /// # Safety
    ///
    /// `auth_username` must satisfy the [`SynEsStr`] borrow contract.
    unsafe fn login_to_raw(&self, meta: RawMeta) -> RawEsEvent {
        // SAFETY: forwarded contract.
        let username = unsafe { self.auth_username.to_string_lossy() };
        RawEsEvent::LoginLogin {
            meta,
            success: self.auth_success != 0,
            username,
        }
    }

    /// # Safety
    ///
    /// `auth_username` must satisfy the [`SynEsStr`] borrow contract.
    unsafe fn lw_login_to_raw(&self, meta: RawMeta) -> RawEsEvent {
        // SAFETY: forwarded contract.
        let username = unsafe { self.auth_username.to_string_lossy() };
        RawEsEvent::LwSessionLogin { meta, username }
    }

    /// # Safety
    ///
    /// `file_path`, `quarantine_raw` and `wherefroms_raw` must satisfy the
    /// [`SynEsStr`] borrow contract.
    unsafe fn quarantine_to_raw(&self, meta: RawMeta) -> RawEsEvent {
        // SAFETY: forwarded contract.
        unsafe {
            RawEsEvent::QuarantineSet {
                meta,
                path: self.file_path.to_string_lossy(),
                quarantine: self.quarantine_raw.to_non_empty_string(),
                wherefroms_plist: self.wherefroms_raw.to_option_bytes(),
            }
        }
    }

    /// # Safety
    ///
    /// `file_path`, `mount_source` and `mount_fs_type` must satisfy the
    /// [`SynEsStr`] borrow contract.
    unsafe fn mount_to_raw(&self, meta: RawMeta) -> RawEsEvent {
        // SAFETY: forwarded contract.
        unsafe {
            RawEsEvent::Mount {
                meta,
                mount_point: self.file_path.to_string_lossy(),
                source: self.mount_source.to_non_empty_string(),
                fs_type: self.mount_fs_type.to_non_empty_string(),
                readonly: self.mount_readonly != 0,
                mounted: self.kind == SYN_ES_KIND_MOUNT,
            }
        }
    }

    /// # Safety
    ///
    /// `file_path` must satisfy the [`SynEsStr`] borrow contract.
    unsafe fn signal_to_raw(&self, meta: RawMeta) -> RawEsEvent {
        // SAFETY: forwarded contract.
        let target_path = unsafe { self.file_path.to_non_empty_string() };
        RawEsEvent::SignalToEsClient {
            meta,
            signal: self.signal_number.max(0).cast_unsigned(),
            target_pid: self.signal_target_pid.max(0).cast_unsigned(),
            target_path,
        }
    }

    /// # Safety
    ///
    /// `xpc_service_name` must satisfy the [`SynEsStr`] borrow contract.
    unsafe fn xpc_connect_to_raw(&self, meta: RawMeta) -> RawEsEvent {
        // SAFETY: forwarded contract.
        let service_name = unsafe { self.xpc_service_name.to_string_lossy() };
        RawEsEvent::XpcConnect {
            meta,
            service_name,
            domain_type: self.xpc_domain_type,
        }
    }

    /// # Safety
    ///
    /// `file_path`, `btm_app_url` and `btm_executable_path` must satisfy the
    /// [`SynEsStr`] borrow contract.
    unsafe fn btm_launch_item_add_to_raw(&self, meta: RawMeta) -> RawEsEvent {
        // SAFETY: forwarded contract.
        unsafe {
            RawEsEvent::BtmLaunchItemAdd {
                meta,
                item_type: BtmItemType::from_raw(self.btm_item_type),
                legacy: self.btm_legacy != 0,
                item_uid: self.btm_item_uid,
                item_url: self.file_path.to_string_lossy(),
                app_url: self.btm_app_url.to_non_empty_string(),
                executable_path: self.btm_executable_path.to_non_empty_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    const ABSENT: SynEsStr = SynEsStr {
        data: std::ptr::null(),
        len: 0,
    };

    fn bytes(b: &'static [u8]) -> SynEsStr {
        SynEsStr {
            data: b.as_ptr().cast::<c_char>(),
            len: b.len(),
        }
    }

    fn s(text: &'static str) -> SynEsStr {
        bytes(text.as_bytes())
    }

    /// A record of `kind` with the shared meta set and every other field
    /// absent or zero, the way the shim leaves fields another kind owns.
    fn event(kind: i32) -> SynEsEvent {
        SynEsEvent {
            kind,
            meta: SynEsMeta {
                pid: 4242,
                ppid: 1,
                uid: 501,
                gid: 20,
                wall_time_ns: 1_700_000_000_000_000_000,
                process_path: s("/usr/bin/curl"),
            },
            exec_image_path: ABSENT,
            exec_argc: 0,
            exec_argc_total: 0,
            exec_argv: [ABSENT; SYN_ES_MAX_ARGV],
            exec_signing_id: ABSENT,
            exec_team_id: ABSENT,
            exec_cs_flags: 0,
            exec_is_platform_binary: 0,
            exec_parent_path: ABSENT,
            file_path: ABSENT,
            open_fflag: 0,
            rename_old_path: ABSENT,
            btm_item_type: 0,
            btm_legacy: 0,
            btm_item_uid: 0,
            btm_app_url: ABSENT,
            btm_executable_path: ABSENT,
            auth_success: 0,
            auth_username: ABSENT,
            auth_source_address: ABSENT,
            quarantine_raw: ABSENT,
            wherefroms_raw: ABSENT,
            mount_source: ABSENT,
            mount_fs_type: ABSENT,
            mount_readonly: 0,
            signal_number: 0,
            signal_target_pid: 0,
            xpc_service_name: ABSENT,
            xpc_domain_type: 0,
        }
    }

    fn meta() -> RawMeta {
        RawMeta {
            pid: 4242,
            ppid: 1,
            uid: 501,
            gid: 20,
            wall_time_ns: 1_700_000_000_000_000_000,
            process_path: "/usr/bin/curl".to_string(),
        }
    }

    fn convert(event: &SynEsEvent) -> Option<RawEsEvent> {
        // SAFETY: every string in a test record is null or a `'static` slice
        // of exactly `len` bytes.
        unsafe { event.to_raw() }
    }

    #[test]
    fn unknown_kind_is_skipped() {
        assert_eq!(convert(&event(0)), None);
        assert_eq!(convert(&event(99)), None);
    }

    #[test]
    fn meta_clamps_negative_pids_to_zero() {
        let mut ev = event(SYN_ES_KIND_UNLINK);
        ev.meta.pid = -1;
        ev.meta.ppid = -7;
        ev.meta.process_path = ABSENT;
        ev.file_path = s("/tmp/x");
        let Some(RawEsEvent::Unlink { meta, .. }) = convert(&ev) else {
            panic!("expected Unlink");
        };
        assert_eq!((meta.pid, meta.ppid), (0, 0));
        assert_eq!(meta.process_path, "");
    }

    #[test]
    fn invalid_utf8_paths_are_copied_lossily() {
        let mut ev = event(SYN_ES_KIND_CREATE);
        ev.file_path = bytes(b"/tmp/\xffbad");
        assert_eq!(
            convert(&ev),
            Some(RawEsEvent::Create {
                meta: meta(),
                path: "/tmp/\u{fffd}bad".to_string(),
            })
        );
    }

    #[test]
    fn exec_copies_argv_signing_and_lineage() {
        let mut ev = event(SYN_ES_KIND_EXEC);
        ev.exec_image_path = s("/bin/ls");
        ev.exec_argc = 2;
        ev.exec_argc_total = 2;
        ev.exec_argv[0] = s("ls");
        ev.exec_argv[1] = s("-la");
        // Past `exec_argc`: never read.
        ev.exec_argv[2] = s("stale");
        ev.exec_signing_id = s("com.apple.ls");
        ev.exec_team_id = s("");
        ev.exec_cs_flags = 0x1;
        ev.exec_is_platform_binary = 1;
        ev.exec_parent_path = s("/bin/zsh");
        assert_eq!(
            convert(&ev),
            Some(RawEsEvent::Exec {
                meta: meta(),
                image_path: "/bin/ls".to_string(),
                argv: vec!["ls".to_string(), "-la".to_string()],
                argv_truncated: false,
                signing_id: Some("com.apple.ls".to_string()),
                team_id: None,
                cs_flags: 0x1,
                is_platform_binary: true,
                parent_path: Some("/bin/zsh".to_string()),
            })
        );
    }

    #[test]
    fn exec_caps_argc_at_the_array_and_flags_dropped_entries() {
        let mut ev = event(SYN_ES_KIND_EXEC);
        ev.exec_argc = u32::MAX;
        ev.exec_argc_total = u32::MAX;
        ev.exec_argv = [s("a"); SYN_ES_MAX_ARGV];
        let Some(RawEsEvent::Exec {
            argv,
            argv_truncated,
            image_path,
            signing_id,
            parent_path,
            ..
        }) = convert(&ev)
        else {
            panic!("expected Exec");
        };
        assert_eq!(argv.len(), SYN_ES_MAX_ARGV);
        assert!(!argv_truncated, "total == argc: the shim dropped nothing");
        assert_eq!(image_path, "");
        assert_eq!((signing_id, parent_path), (None, None));

        ev.exec_argc = 1;
        ev.exec_argc_total = 3;
        let Some(RawEsEvent::Exec {
            argv,
            argv_truncated,
            ..
        }) = convert(&ev)
        else {
            panic!("expected Exec");
        };
        assert_eq!(argv, vec!["a".to_string()]);
        assert!(argv_truncated);
    }

    #[test]
    fn file_kinds_carry_their_paths() {
        let mut ev = event(SYN_ES_KIND_OPEN);
        ev.file_path = s("/etc/hosts");
        ev.open_fflag = 0x3;
        assert_eq!(
            convert(&ev),
            Some(RawEsEvent::Open {
                meta: meta(),
                path: "/etc/hosts".to_string(),
                fflag: 0x3,
            })
        );

        ev.kind = SYN_ES_KIND_UNLINK;
        assert_eq!(
            convert(&ev),
            Some(RawEsEvent::Unlink {
                meta: meta(),
                path: "/etc/hosts".to_string(),
            })
        );

        ev.kind = SYN_ES_KIND_MMAP_WRITE_SHARED;
        assert_eq!(
            convert(&ev),
            Some(RawEsEvent::MmapWriteShared {
                meta: meta(),
                path: "/etc/hosts".to_string(),
            })
        );

        ev.kind = SYN_ES_KIND_RENAME;
        ev.rename_old_path = s("/tmp/a");
        assert_eq!(
            convert(&ev),
            Some(RawEsEvent::Rename {
                meta: meta(),
                old_path: "/tmp/a".to_string(),
                new_path: "/etc/hosts".to_string(),
            })
        );
    }

    #[test]
    fn session_kinds_carry_user_and_outcome() {
        let mut ev = event(SYN_ES_KIND_SSH_LOGIN);
        ev.auth_success = 1;
        ev.auth_username = s("alice");
        ev.auth_source_address = s("192.0.2.7");
        assert_eq!(
            convert(&ev),
            Some(RawEsEvent::SshLogin {
                meta: meta(),
                success: true,
                username: "alice".to_string(),
                source_address: Some("192.0.2.7".to_string()),
            })
        );

        ev.auth_source_address = s("");
        let Some(RawEsEvent::SshLogin { source_address, .. }) = convert(&ev) else {
            panic!("expected SshLogin");
        };
        assert_eq!(source_address, None);

        ev.kind = SYN_ES_KIND_LOGIN;
        ev.auth_success = 0;
        assert_eq!(
            convert(&ev),
            Some(RawEsEvent::LoginLogin {
                meta: meta(),
                success: false,
                username: "alice".to_string(),
            })
        );

        ev.kind = SYN_ES_KIND_LW_LOGIN;
        assert_eq!(
            convert(&ev),
            Some(RawEsEvent::LwSessionLogin {
                meta: meta(),
                username: "alice".to_string(),
            })
        );
    }

    #[test]
    fn quarantine_copies_the_string_and_raw_plist_bytes() {
        let mut ev = event(SYN_ES_KIND_QUARANTINE);
        ev.file_path = s("/Users/a/Downloads/x.dmg");
        ev.quarantine_raw = s("0083;6553f100;Safari;");
        ev.wherefroms_raw = bytes(b"bplist00\x00\xff");
        assert_eq!(
            convert(&ev),
            Some(RawEsEvent::QuarantineSet {
                meta: meta(),
                path: "/Users/a/Downloads/x.dmg".to_string(),
                quarantine: Some("0083;6553f100;Safari;".to_string()),
                wherefroms_plist: Some(b"bplist00\x00\xff".to_vec()),
            })
        );

        ev.quarantine_raw = s("");
        ev.wherefroms_raw = ABSENT;
        let Some(RawEsEvent::QuarantineSet {
            quarantine,
            wherefroms_plist,
            ..
        }) = convert(&ev)
        else {
            panic!("expected QuarantineSet");
        };
        assert_eq!((quarantine, wherefroms_plist), (None, None));
    }

    #[test]
    fn mount_and_unmount_share_a_record_with_direction() {
        let mut ev = event(SYN_ES_KIND_MOUNT);
        ev.file_path = s("/Volumes/X");
        ev.mount_source = s("/dev/disk4s1");
        ev.mount_fs_type = s("");
        ev.mount_readonly = 1;
        assert_eq!(
            convert(&ev),
            Some(RawEsEvent::Mount {
                meta: meta(),
                mount_point: "/Volumes/X".to_string(),
                source: Some("/dev/disk4s1".to_string()),
                fs_type: None,
                readonly: true,
                mounted: true,
            })
        );

        ev.kind = SYN_ES_KIND_UNMOUNT;
        let Some(RawEsEvent::Mount { mounted, .. }) = convert(&ev) else {
            panic!("expected Mount");
        };
        assert!(!mounted);
    }

    #[test]
    fn signal_clamps_negative_values_and_drops_an_empty_target() {
        let mut ev = event(SYN_ES_KIND_SIGNAL_ES_CLIENT);
        ev.signal_number = 9;
        ev.signal_target_pid = 77;
        ev.file_path = s("/usr/local/bin/agent");
        assert_eq!(
            convert(&ev),
            Some(RawEsEvent::SignalToEsClient {
                meta: meta(),
                signal: 9,
                target_pid: 77,
                target_path: Some("/usr/local/bin/agent".to_string()),
            })
        );

        ev.signal_number = -1;
        ev.signal_target_pid = -1;
        ev.file_path = s("");
        assert_eq!(
            convert(&ev),
            Some(RawEsEvent::SignalToEsClient {
                meta: meta(),
                signal: 0,
                target_pid: 0,
                target_path: None,
            })
        );
    }

    #[test]
    fn xpc_connect_carries_service_and_domain() {
        let mut ev = event(SYN_ES_KIND_XPC_CONNECT);
        ev.xpc_service_name = s("com.apple.securityd");
        ev.xpc_domain_type = 3;
        assert_eq!(
            convert(&ev),
            Some(RawEsEvent::XpcConnect {
                meta: meta(),
                service_name: "com.apple.securityd".to_string(),
                domain_type: 3,
            })
        );
    }

    #[test]
    fn btm_launch_item_decodes_type_and_optional_urls() {
        let mut ev = event(SYN_ES_KIND_BTM_LAUNCH_ITEM_ADD);
        ev.btm_item_type = 4;
        ev.btm_legacy = 1;
        ev.btm_item_uid = 501;
        ev.file_path = s("file:///Library/LaunchDaemons/x.plist");
        ev.btm_app_url = s("");
        ev.btm_executable_path = s("/usr/local/bin/x");
        assert_eq!(
            convert(&ev),
            Some(RawEsEvent::BtmLaunchItemAdd {
                meta: meta(),
                item_type: BtmItemType::Daemon,
                legacy: true,
                item_uid: 501,
                item_url: "file:///Library/LaunchDaemons/x.plist".to_string(),
                app_url: None,
                executable_path: Some("/usr/local/bin/x".to_string()),
            })
        );

        ev.btm_item_type = 42;
        ev.btm_app_url = s("file:///Applications/X.app");
        ev.btm_executable_path = ABSENT;
        let Some(RawEsEvent::BtmLaunchItemAdd {
            item_type,
            app_url,
            executable_path,
            ..
        }) = convert(&ev)
        else {
            panic!("expected BtmLaunchItemAdd");
        };
        assert_eq!(item_type, BtmItemType::Other(42));
        assert_eq!(app_url.as_deref(), Some("file:///Applications/X.app"));
        assert_eq!(executable_path, None);
    }
}
