//! File activity: opens, writes, renames, metadata, mounts.

use super::*;

// Standard POSIX open(2) flag values, stable across the Linux architectures this
// project supports (x86_64, aarch64). Defined here rather than via `libc`:
// `FileOpenEvent::flags` is platform-native and these are the Linux values; a
// `libc` dependency would drag platform quirks (no `O_ACCMODE` on Windows) into
// the boundary crate that must compile everywhere.
/// `open(2)` access-mode mask (`flags & O_ACCMODE` is one of `O_RDONLY`=0,
/// [`O_WRONLY`], [`O_RDWR`] — a 2-bit field, not independent bits).
pub const O_ACCMODE: u32 = 0o3;
/// `open(2)` write-only access mode.
pub const O_WRONLY: u32 = 0o1;
/// `open(2)` read-write access mode.
pub const O_RDWR: u32 = 0o2;
/// `open(2)` create-if-absent flag.
pub const O_CREAT: u32 = 0o100;
/// `open(2)` truncate-to-zero flag.
pub const O_TRUNC: u32 = 0o1000;

/// Write intent on [`FileOpenEvent::flags`]: a write access mode, creation
/// (`O_CREAT` — creating a file is write intent even with `O_RDONLY`), or
/// truncation (`O_TRUNC`).
///
/// `O_TRUNC` counts whatever the access mode: Linux adds `MAY_WRITE` for it in
/// `build_open_flags`, and `open(path, O_RDONLY | O_TRUNC)` empties a regular file
/// the caller may write (verified on Debian 12, kernel 6.1.0-17: a 12-byte file
/// became 0 bytes, #233). Without it, a process could wipe a file through an open
/// no write-side rule saw as a write.
///
/// The ONE definition of this predicate. It used to exist five times (rules,
/// correlator, `crates/ml`, and two Python mirrors) with two different
/// semantics — an access-mode comparison vs. a bitmask-any — which classified
/// `flags = 0o3` differently, so the rule engine and the correlator could
/// disagree about the same event. The access-mode comparison is canonical
/// because it is what the kernel does: the access mode is a 2-bit *field*
/// (`O_ACCMODE`), not independent bits, and the `0o3` combination is invalid —
/// `open(2)` refuses it with `EINVAL`, so no write can result and counting it
/// would let crafted always-failing opens inflate behavioral write counts.
/// The Python mirror (`synthaea_ml.features.posix.has_write_intent`) must match
/// this exactly — parity-tested against shared fixtures.
///
/// Lives in `schema` deliberately: a pure helper on a field this crate
/// defines, additive to the semi-frozen surface (no serialization impact),
/// and the only crate every consumer of `flags` may depend on.
#[must_use]
pub fn has_write_intent(flags: u32) -> bool {
    let access_mode = flags & O_ACCMODE;
    access_mode == O_WRONLY || access_mode == O_RDWR || (flags & (O_CREAT | O_TRUNC)) != 0
}

/// File open/create.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOpenEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Path of the opened file, as the sensor reports it.
    pub path: String,
    /// Platform-native open/access flags (Linux `open(2)` flags, Windows create
    /// dispositions). Rules match primarily on `path`; flag interpretation is
    /// per-platform and documented by each sensor.
    ///
    /// The synthetic `FLAG_*` bits (see `SYNTHETIC_FLAGS`) are set only by userspace sensors
    /// that build the event themselves. On Linux the probe's raw `open(2)` flags are masked
    /// with `OPEN_FLAGS_MASK` (`sensor-linux`'s `normalize`) before they get here, because the kernel ignores unknown
    /// bits and any local user could otherwise forge a synthetic bit (#1129).
    pub flags: u32,
}

/// File write (issue #262).
///
/// ## ⚠️ Critical Limitation: No Path Included
///
/// This event carries **no path** — only `(pid, fd, bytes_requested)`. `write(2)` and
/// `pwrite64(2)` operate on file descriptors, not paths, and the Linux sensor resolves
/// no fd→path mapping (neither kernel-side `bpf_d_path`/LSM hooks nor userspace
/// `/proc/<pid>/fd/<n>` lookup — see `sensor-linux-wire::FileWriteEvent`'s version
/// history for rationale).
///
/// **This is a volume/frequency signal** for burst-write detection (ransomware, mass
/// tampering, log destruction), not a per-write path trail. To correlate a write with
/// a file path, detection rules must join to a recent [`FileOpenEvent`] on
/// `(meta.pid, fd)`.
///
/// ## Detection Correlation Pattern
///
/// ```rust,ignore
/// // Pseudo-code example: correlate FileOpen → FileWrite
/// match event {
///     Event::FileOpen(open) => {
///         // Store (pid, fd) → path mapping
///         state.track_fd(open.meta.pid, open.fd, open.path.clone());
///     }
///     Event::FileWrite(write) => {
///         // Look up path from prior FileOpen
///         if let Some(path) = state.get_path(write.meta.pid, write.fd) {
///             // Now you can detect: "wrote 1MB to /etc/passwd"
///             check_suspicious_write(path, write.bytes_requested);
///         }
///     }
///     Event::FileClose(_) => {
///         // Clean up fd tracking to bound memory
///     }
/// }
/// ```
///
/// See `docs/detection/file-activity-patterns.md` for full worked examples including
/// ransomware burst-write + mass-rename correlation.
///
/// ## Performance Notes
///
/// `write(2)` is one of the hottest syscalls in the system. Current implementation:
/// - Captures **every** write syscall (no size filtering)
/// - Expected rate: 10-1000+ events/sec under normal load, 10K+/sec under heavy I/O
/// - No built-in sampling or backpressure (Phase 1 implementation)
///
/// Future work (issue #262 Phase 2):
/// - Add min-size filter (e.g., skip writes < 4KB)
/// - Consider sampling under sustained high-volume
/// - Add `writev(2)`, `pwrite64(2)`, `pwritev(2)` coverage (currently only `write(2)`)
///
/// ## Syscall Coverage
///
/// Phase 1 (current): `write(2)` only
/// Phase 2 (deferred): `writev`, `pwrite64`, `pwritev`, `pwritev2`
///
/// Rationale for deferral: `write(2)` covers the common case; vectored/positioned
/// writes are used by databases and async I/O but add complexity (multiple fd/offset
/// pairs per syscall). Added once the Phase 1 signal proves useful and performance
/// characteristics are understood.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileWriteEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// The file descriptor written to, in the writing process's own fd table —
    /// meaningful only paired with `meta.pid`, and reused across the process's
    /// lifetime like any fd.
    pub fd: u32,
    /// The caller's requested byte count (`write(2)`'s `count` argument), read at
    /// syscall entry — not the syscall's return value, so a short write or a
    /// failed call still reports the requested size.
    pub bytes_requested: u64,
}

/// File delete (issue #262): `unlink(2)`/`unlinkat(2)` on Linux, ES `UNLINK`
/// on macOS. On Windows, only the deletion of a `:Zone.Identifier` stream, the
/// mark-of-the-web removed (#442); `path` is then the stream path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDeleteEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Path of the deleted file.
    pub path: String,
}

/// File rename (issue #262): `rename(2)`/`renameat(2)`/`renameat2(2)`. The classic
/// ransomware signal (`invoice.pdf` → `invoice.pdf.locked`) lives entirely in
/// `new_path`'s suffix relative to `old_path`'s.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRenameEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Path before the rename.
    pub old_path: String,
    /// Path after the rename.
    pub new_path: String,
    /// The renaming process's own executable path (#459 part 1) — `None`
    /// when the sensor couldn't resolve it (see [`SCHEMA_VERSION`]'s v31
    /// changelog entry for the per-platform reasoning). Lets an
    /// evidence-gated exclusion tell a real in-place-edit tool
    /// (`/usr/bin/sed`) from an encryptor claiming `comm=sed` apart, instead
    /// of trusting `comm` alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_path: Option<String>,
}

/// Explicit `FileBasicInformation` timestamp request observed by the Windows minifilter.
/// Values are raw signed 100-ns Windows FILETIME units requested by the caller; `None` means
/// that field was unchanged. Windows' own -1 (don't change) and -2 (don't change, don't update
/// on next write either) sentinels still survive as `Some(-1)`/`Some(-2)`, not `None` — the
/// field being set at all is what `None` tracks, distinct from the caller asking it stay as-is;
/// `rules::evaluate_file_set_time` is what filters those two sentinel values out of the ones
/// that count as a real requested time. This reports a successful request, not proof of
/// malicious intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSetTimeEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Normalized path captured by the minifilter before the operation.
    pub path: String,
    /// Requested creation time in raw signed 100-ns FILETIME units; `None` means unchanged.
    pub creation_time: Option<i64>,
    /// Requested last-access time in raw signed 100-ns FILETIME units; `None` means unchanged.
    pub last_access_time: Option<i64>,
    /// Requested last-write time in raw signed 100-ns FILETIME units; `None` means unchanged.
    pub last_write_time: Option<i64>,
    /// Requested change time in raw signed 100-ns FILETIME units; `None` means unchanged.
    pub change_time: Option<i64>,
}

/// Successful open of a mounted logical volume through the Windows minifilter.
/// `desired_access` is the caller's requested `ACCESS_MASK`, not the rights granted or later used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawVolumeOpenEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Kernel device name captured from the attached volume (for example `\\Device\\HarddiskVolume3`).
    pub volume: String,
    /// Raw Windows `ACCESS_MASK` requested by the caller.
    pub desired_access: u32,
}

/// File permission change (issue #262 Phase 2): `chmod(2)`/`fchmodat(2)`. `fchmod(2)`
/// (fd-only, no path) is deferred — see `sensor-linux-wire::FileChmodEvent`'s doc.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileChmodEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Path whose mode changed.
    pub path: String,
    /// Requested mode bits (permission bits plus setuid/setgid/sticky). A `chmod
    /// +s` (mode & 0o4000/0o2000) on a world-writable or unexpected binary is a
    /// classic privilege-escalation signal (T1222.002).
    pub mode: u32,
}

/// File ownership change (issue #262 Phase 2): `chown(2)`/`lchown(2)`/
/// `fchownat(2)`. `fchown(2)` (fd-only, no path) is deferred — see
/// `sensor-linux-wire::FileChownEvent`'s doc.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileChownEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Path whose owner changed.
    pub path: String,
    /// New owner uid, or `u32::MAX` (`(uid_t)-1`) meaning "leave unchanged" per
    /// `chown(2)`'s own semantics — passed through as-is, not specially interpreted.
    pub uid: u32,
    /// New owner gid, same "leave unchanged" sentinel as `uid`.
    pub gid: u32,
}

/// Extended attribute set (issue #262 Phase 3): `setxattr(2)`. `lsetxattr(2)`/
/// `fsetxattr(2)` (symlink/fd-only variants) are deferred — same posture as
/// `chmod`/`chown`'s fd-only siblings. `name` only, not the attribute's `value` —
/// see `sensor-linux-wire::FileSetxattrEvent`'s doc. `name == "security.capability"`
/// is the Linux file-capability grant `setcap` writes — functionally the
/// extended-attribute equivalent of `chmod +s` (T1222.002).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSetxattrEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Path whose extended attribute was set.
    pub path: String,
    /// Name of the extended attribute.
    pub name: String,
}

/// Extended attribute removal (issue #262 Phase 3): `removexattr(2)`. Same
/// deferred symlink/fd-variant posture as [`FileSetxattrEvent`]. Removing
/// `security.selinux` or `security.capability` from a binary is an anti-forensics/
/// evasion signal in its own right, independent of what `setxattr` ever wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRemovexattrEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Path whose extended attribute was removed.
    pub path: String,
    /// Name of the extended attribute.
    pub name: String,
}

/// Download provenance — a file was marked as downloaded from the network.
/// Emitted by `sensor-macos` (#96) when the `com.apple.quarantine` extended
/// attribute is set (`SETEXTATTR`, with the quarantine string and the
/// `kMDItemWhereFroms` origin URLs read back at event time), and by
/// `sensor-windows` (#365) when a `Zone.Identifier` stream — the
/// mark-of-the-web — is written (`HostUrl`/`ReferrerUrl` read back; `agent`
/// is the writing process, Windows records no downloader name).
///
/// This is the network→file link: a later exec of `path` joins this event to
/// answer "where did that binary come from" (cross-platform note in
/// `docs/sensors/sources.md`).
///
/// `agent`/`origin_url`/`referrer_url` are `None` when the writing application
/// did not (or had not yet) recorded them — the quarantine mark alone is still
/// the signal that the file arrived from outside.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileQuarantineEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// The quarantined file.
    pub path: String,
    /// Application that downloaded it, from the quarantine string's agent
    /// field (e.g. `Safari`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// Download URL from `kMDItemWhereFroms`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_url: Option<String>,
    /// Referrer URL from `kMDItemWhereFroms`, when recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referrer_url: Option<String>,
}

/// A filesystem was mounted or unmounted. Emitted by `sensor-macos` (#96);
/// deliberately platform-neutral — Linux mount telemetry can reuse it.
///
/// Detection value: staging via disk images (`hdiutil attach` of a downloaded
/// DMG is the classic macOS malware delivery step), USB mass storage, and
/// unmounts destroying evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Where the filesystem is (or was) mounted.
    pub mount_point: String,
    /// What was mounted (device node, image path, network source), when the
    /// platform reports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Filesystem type (`hfs`, `apfs`, `smbfs`, ...), when reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs_type: Option<String>,
    /// True for a read-only mount.
    pub readonly: bool,
    /// True for a mount, false for an unmount.
    pub mounted: bool,
}

#[cfg(test)]
mod write_intent_tests {
    use super::has_write_intent;

    #[test]
    fn write_access_modes_are_write_intent() {
        assert!(has_write_intent(super::O_WRONLY));
        assert!(has_write_intent(super::O_RDWR));
        assert!(has_write_intent(
            super::O_WRONLY | 0o2000 /* O_APPEND */
        ));
    }

    #[test]
    fn creat_is_write_intent_even_with_rdonly() {
        // Creating a file mutates the filesystem regardless of the access mode.
        assert!(has_write_intent(super::O_CREAT));
    }

    #[test]
    fn trunc_is_write_intent_even_with_rdonly() {
        // `open(O_RDONLY | O_TRUNC)` empties the file on Linux (#233).
        assert!(has_write_intent(super::O_TRUNC));
        assert!(has_write_intent(
            super::O_TRUNC | 0o2000000 /* O_CLOEXEC */
        ));
        assert!(
            has_write_intent(0o3 | super::O_TRUNC),
            "truncation still counts"
        );
    }

    #[test]
    fn rdonly_is_not_write_intent() {
        assert!(!has_write_intent(0));
        assert!(!has_write_intent(
            0o2000 /* O_APPEND alone — no write mode */
        ));
    }

    #[test]
    fn invalid_accmode_combo_is_not_write_intent() {
        // The divergence that motivated unifying the five copies: 0o3 sets both
        // access-mode bits, which open(2) refuses with EINVAL — no write can
        // result, so the bitmask-any copies that counted it were wrong. Pinned
        // so the semantics never fork again.
        assert!(!has_write_intent(0o3));
        assert!(
            has_write_intent(0o3 | super::O_CREAT),
            "creation still counts"
        );
    }
}
