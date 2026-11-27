//! File records: opens, writes, renames, metadata changes and mounts.

use super::meta;
use super::process::exe_path_for_pid;
use schema::{
    ContainerContext, Event, FileChmodEvent, FileChownEvent, FileDeleteEvent, FileOpenEvent,
    FileRemovexattrEvent, FileRenameEvent, FileSetxattrEvent, FileWriteEvent, MountEvent,
};
use sensor_linux_wire as wire;

/// The bits a Linux `open(2)` flag word can carry. Every `O_*` flag of the kernel's
/// `VALID_OPEN_FLAGS` sits below `0x0080_0000` (the highest, `__O_TMPFILE`, is `0x0040_0000` in
/// asm-generic `fcntl.h`, which `x86_64` and `aarch64` use). `open` and `openat` ignore any other bit
/// without an error, and the probe records the argument as passed, so a process could set the
/// synthetic `schema::FLAG_*` bits that other sources use to mark a persistence or tamper fact on
/// a `FileOpenEvent`, and raise those alerts at will: measured from uid 1000, `0x4000_0000` raised
/// T1543.002 and `0x1000_0000` T1543.003 (#1129).
pub(super) const OPEN_FLAGS_MASK: u32 = 0x007F_FFFF;

// Every synthetic flag is outside the mask, so no open can carry one. A new `FLAG_*` must be
// added here too.
const _: () = {
    let synthetic = [
        schema::FLAG_PERSISTENCE_ARTIFACT,
        schema::FLAG_PERSISTENCE_TASK_ARTIFACT,
        schema::FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN,
        schema::FLAG_PERSISTENCE_ACCOUNT_ARTIFACT,
        schema::FLAG_PERSISTENCE_SYSTEMD_ARTIFACT,
        schema::FLAG_PERSISTENCE_BTM_ARTIFACT,
        schema::FLAG_APPLICATION_BLOCKED,
        schema::FLAG_PERSISTENCE_TASK_UPDATE_ARTIFACT,
    ];
    let mut i = 0;
    while i < synthetic.len() {
        assert!(
            synthetic[i] & OPEN_FLAGS_MASK == 0,
            "a synthetic FLAG_* bit is inside the open(2) flag mask"
        );
        i += 1;
    }
};

/// Maps a `wire::FileOpenEvent` to `Event::FileOpen`. The path is the raw argument (not resolved), and `flags`
/// is masked with `OPEN_FLAGS_MASK` so a process cannot forge the synthetic `schema::FLAG_*` bits (#1129).
/// `boot_epoch_offset_ns` converts the boot-relative timestamp to wall-clock; `container` is caller-resolved.
#[must_use]
pub fn file_open(
    event: &wire::FileOpenEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let raw = &event.path[..(event.path_len as usize).min(wire::MAX_PATH_LEN)];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    Event::FileOpen(FileOpenEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        path: String::from_utf8_lossy(&raw[..end]).into_owned(),
        flags: event.flags & OPEN_FLAGS_MASK,
    })
}

/// Maps a `wire::FileWriteEvent` to `Event::FileWrite`. `bytes_requested` is the `count` passed to
/// `write(2)`, not the bytes actually written. `boot_epoch_offset_ns` and `container` as in [`file_open`].
#[must_use]
pub fn file_write(
    event: &wire::FileWriteEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    Event::FileWrite(FileWriteEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        fd: event.fd,
        bytes_requested: event.bytes_requested,
    })
}

/// Maps a `wire::FileDeleteEvent` to `Event::FileDelete`. The path is the raw NUL-terminated argument, not resolved.
/// `boot_epoch_offset_ns` and `container` as in [`file_open`].
#[must_use]
pub fn file_delete(
    event: &wire::FileDeleteEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let raw = &event.path[..(event.path_len as usize).min(wire::MAX_PATH_LEN)];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    Event::FileDelete(FileDeleteEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        path: String::from_utf8_lossy(&raw[..end]).into_owned(),
    })
}

/// Maps a `wire::FileRenameEvent` to `Event::FileRename`. Both paths are made absolute against the caller's
/// dirfd or cwd (#515) and `executable_path` is read from `/proc`, so this is not pure. `boot_epoch_offset_ns`
/// and `container` as in [`file_open`].
#[must_use]
pub fn file_rename(
    event: &wire::FileRenameEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let old_raw = &event.old_path[..(event.old_path_len as usize).min(wire::MAX_PATH_LEN)];
    let old_end = old_raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(old_raw.len());
    let new_raw = &event.new_path[..(event.new_path_len as usize).min(wire::MAX_PATH_LEN)];
    let new_end = new_raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(new_raw.len());
    let pid = event.meta.pid;
    Event::FileRename(FileRenameEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        old_path: resolve_dirfd_path(pid, event.old_dfd, &old_raw[..old_end]),
        new_path: resolve_dirfd_path(pid, event.new_dfd, &new_raw[..new_end]),
        executable_path: exe_path_for_pid(pid),
    })
}

/// `AT_FDCWD`: "relative to the current directory", what `rename(2)` implies and what
/// a `renameat` caller passes for the same.
pub(super) const AT_FDCWD: i32 = -100;

/// Turns a rename path the caller wrote relative to a directory fd into an absolute
/// one (#515), so path-prefix rules (`RANSOMWARE_EXCLUDED_PATH_PREFIXES`) can see it.
/// An absolute path is returned as it is (the kernel ignores the fd for those).
///
/// The directory comes from `/proc/<pid>/cwd` for `AT_FDCWD` and `/proc/<pid>/fd/<n>`
/// otherwise, read at *normalize* time. That races the process: a short-lived `mv`
/// that has already exited cannot be resolved, and neither can a directory fd that
/// was closed or whose directory was deleted. In every such case the raw relative
/// path is returned unchanged, which is exactly what the sensor reported before and
/// never a guessed directory: a wrong absolute path would be worse than a relative
/// one, because a prefix exclusion would then act on a place the rename never touched.
pub(super) fn resolve_dirfd_path(pid: u32, dfd: i32, raw: &[u8]) -> String {
    let path = String::from_utf8_lossy(raw).into_owned();
    if path.is_empty() || path.starts_with('/') {
        return path;
    }
    let link = if dfd == AT_FDCWD {
        format!("/proc/{pid}/cwd")
    } else if dfd >= 0 {
        format!("/proc/{pid}/fd/{dfd}")
    } else {
        return path;
    };
    match std::fs::read_link(link) {
        Ok(base) => join_resolved(&base, &path).unwrap_or(path),
        Err(_) => path,
    }
}

/// `base` joined with the relative `path`, or `None` when `base` is not a usable
/// directory: not absolute (a pipe or socket fd reads as `pipe:[123]`), or a directory
/// that has since been deleted (the kernel appends ` (deleted)`).
pub(super) fn join_resolved(base: &std::path::Path, path: &str) -> Option<String> {
    let base = base.to_str()?;
    if !base.starts_with('/') || base.ends_with(" (deleted)") {
        return None;
    }
    Some(if base.ends_with('/') {
        format!("{base}{path}")
    } else {
        format!("{base}/{path}")
    })
}

/// Maps a `wire::FileChmodEvent` to `Event::FileChmod`. The path is the raw NUL-terminated argument, not resolved. `mode` is passed through unmasked.
/// `boot_epoch_offset_ns` and `container` as in [`file_open`].
#[must_use]
pub fn file_chmod(
    event: &wire::FileChmodEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let raw = &event.path[..(event.path_len as usize).min(wire::MAX_PATH_LEN)];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    Event::FileChmod(FileChmodEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        path: String::from_utf8_lossy(&raw[..end]).into_owned(),
        mode: event.mode,
    })
}

/// 100 ns intervals between 1601-01-01 (the `FILETIME` epoch) and 1970-01-01.
pub(super) const FILETIME_UNIX_EPOCH: i64 = 116_444_736_000_000_000;

/// A requested Unix time as the raw `FILETIME` units `schema::FileSetTimeEvent` carries, so
/// one rule serves both OSes (#1036). Saturates instead of wrapping, and never returns the
/// 0/-1/-2 values the rule reads as "unchanged": a time before 1601 becomes 1, one past the
/// `i64` range `i64::MAX`.
pub(super) fn unix_to_filetime(sec: i64, nsec: i64) -> i64 {
    sec.saturating_mul(10_000_000)
        .saturating_add(nsec.clamp(0, 999_999_999) / 100)
        .saturating_add(FILETIME_UNIX_EPOCH)
        .max(1)
}

/// Joins the dentry names the probe copied (file first, root last) into a path. An incomplete
/// chain gets a `/...` prefix rather than passing for an absolute path.
pub(super) fn set_time_path(event: &wire::FileSetTimeEvent) -> String {
    let depth = usize::from(event.depth).min(wire::SET_TIME_COMPONENTS);
    let mut path = String::new();
    if event.flags & wire::SET_TIME_TRUNCATED != 0 {
        path.push_str("/...");
    }
    for slot in event.components[..depth].iter().rev() {
        let end = slot.iter().position(|&b| b == 0).unwrap_or(slot.len());
        if end == 0 {
            continue;
        }
        path.push('/');
        path.push_str(&String::from_utf8_lossy(&slot[..end]));
    }
    if path.is_empty() { "/".into() } else { path }
}

/// `inode_setattr` explicit timestamp request → the platform-neutral `FileSetTimeEvent`
/// (#1036). Only the fields the caller chose (`flags`) are `Some`.
#[must_use]
pub fn file_set_time(
    event: &wire::FileSetTimeEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    Event::FileSetTime(schema::FileSetTimeEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        path: set_time_path(event),
        creation_time: None,
        last_access_time: (event.flags & wire::SET_TIME_ATIME != 0)
            .then(|| unix_to_filetime(event.atime_sec, event.atime_nsec)),
        last_write_time: (event.flags & wire::SET_TIME_MTIME != 0)
            .then(|| unix_to_filetime(event.mtime_sec, event.mtime_nsec)),
        change_time: None,
    })
}

/// Maps a `wire::FileChownEvent` to `Event::FileChown`. The path is the raw NUL-terminated argument, not resolved. `uid`/`gid` of `u32::MAX` mean "unchanged" and are passed through.
/// `boot_epoch_offset_ns` and `container` as in [`file_open`].
#[must_use]
pub fn file_chown(
    event: &wire::FileChownEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let raw = &event.path[..(event.path_len as usize).min(wire::MAX_PATH_LEN)];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    Event::FileChown(FileChownEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        path: String::from_utf8_lossy(&raw[..end]).into_owned(),
        uid: event.uid,
        gid: event.gid,
    })
}

/// Maps a `wire::FileSetxattrEvent` to `Event::FileSetxattr`: the target path and the attribute name,
/// both truncated to their buffer sizes. `boot_epoch_offset_ns` and `container` as in [`file_open`].
#[must_use]
pub fn file_setxattr(
    event: &wire::FileSetxattrEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let path_raw = &event.path[..(event.path_len as usize).min(wire::MAX_PATH_LEN)];
    let path_end = path_raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(path_raw.len());
    let name_raw = &event.name[..(event.name_len as usize).min(wire::MAX_XATTR_NAME_LEN)];
    let name_end = name_raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_raw.len());
    Event::FileSetxattr(FileSetxattrEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        path: String::from_utf8_lossy(&path_raw[..path_end]).into_owned(),
        name: String::from_utf8_lossy(&name_raw[..name_end]).into_owned(),
    })
}

/// Maps a `wire::FileRemovexattrEvent` to `Event::FileRemovexattr`: the target path and the attribute name,
/// both truncated to their buffer sizes. `boot_epoch_offset_ns` and `container` as in [`file_open`].
#[must_use]
pub fn file_removexattr(
    event: &wire::FileRemovexattrEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let path_raw = &event.path[..(event.path_len as usize).min(wire::MAX_PATH_LEN)];
    let path_end = path_raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(path_raw.len());
    let name_raw = &event.name[..(event.name_len as usize).min(wire::MAX_XATTR_NAME_LEN)];
    let name_end = name_raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_raw.len());
    Event::FileRemovexattr(FileRemovexattrEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        path: String::from_utf8_lossy(&path_raw[..path_end]).into_owned(),
        name: String::from_utf8_lossy(&name_raw[..name_end]).into_owned(),
    })
}

/// Maps a `wire::MountEvent` to `Event::Mount`. `source` and `fs_type` are `None` when the probe captured none
/// (length 0). `boot_epoch_offset_ns` and `container` as in [`file_open`].
#[must_use]
pub fn mount(
    event: &wire::MountEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let mp_raw = &event.mount_point[..(event.mount_point_len as usize).min(wire::MAX_PATH_LEN)];
    let mp_end = mp_raw.iter().position(|&b| b == 0).unwrap_or(mp_raw.len());
    let source = (event.source_len > 0).then(|| {
        let raw = &event.source[..(event.source_len as usize).min(wire::MAX_PATH_LEN)];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        String::from_utf8_lossy(&raw[..end]).into_owned()
    });
    let fs_type = (event.fs_type_len > 0).then(|| {
        let raw = &event.fs_type[..(event.fs_type_len as usize).min(wire::MAX_FS_TYPE_LEN)];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        String::from_utf8_lossy(&raw[..end]).into_owned()
    });
    Event::Mount(MountEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        mount_point: String::from_utf8_lossy(&mp_raw[..mp_end]).into_owned(),
        source,
        fs_type,
        readonly: event.readonly,
        mounted: event.mounted,
    })
}
