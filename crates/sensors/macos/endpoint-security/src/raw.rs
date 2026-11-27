//! Owned Rust mirror of the shim's flattened `EndpointSecurity` records.
//!
//! Cross-platform on purpose (no `cfg`): the macOS-only FFI layer converts the
//! borrowed C structs into these owned values, and [`crate::normalize`] maps
//! them into `schema` events — so the whole normalization path is unit-testable
//! on any development host, the same split `sensor-windows` uses between its
//! ETW plumbing and `normalize`.

/// Identity of the acting process, common to every raw event.
///
/// The shim fills it from the message's process (`es_process_t`). Two events name another
/// process: for `Exec` it is the post-exec target, for `BtmLaunchItemAdd` the instigator when BTM
/// identified one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawMeta {
    /// Process id, from the audit token.
    pub pid: u32,
    /// Parent process id, from `es_process_t.ppid`.
    pub ppid: u32,
    /// Effective uid from the audit token.
    pub uid: u32,
    /// Effective gid from the audit token.
    pub gid: u32,
    /// Wall-clock time of the message, ns since the UNIX epoch (already
    /// normalized by the shim from the message's `timespec`).
    pub wall_time_ns: u64,
    /// Executable path of the acting process.
    pub process_path: String,
}

/// Background Task Management item classification, as reported by
/// `es_btm_item_type_t` — kept as the raw value plus a decoded view so an SDK
/// addition degrades to `Other` instead of being dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtmItemType {
    /// Raw value 0, `ES_BTM_ITEM_TYPE_USER_ITEM`.
    UserItem,
    /// Raw value 1, `ES_BTM_ITEM_TYPE_APP`.
    App,
    /// Raw value 2, `ES_BTM_ITEM_TYPE_LOGIN_ITEM`.
    LoginItem,
    /// Raw value 3, `ES_BTM_ITEM_TYPE_AGENT`: a launch agent.
    Agent,
    /// Raw value 4, `ES_BTM_ITEM_TYPE_DAEMON`: a launch daemon.
    Daemon,
    /// A value this build does not know, kept as the SDK sent it.
    Other(u32),
}

impl BtmItemType {
    /// Raw values per `es_btm_item_type_t` (`ESTypes.h`, stable since macOS 13).
    #[must_use]
    pub fn from_raw(raw: u32) -> Self {
        match raw {
            0 => BtmItemType::UserItem,
            1 => BtmItemType::App,
            2 => BtmItemType::LoginItem,
            3 => BtmItemType::Agent,
            4 => BtmItemType::Daemon,
            other => BtmItemType::Other(other),
        }
    }
}

/// One `EndpointSecurity` message, flattened and owned. Mirrors
/// `shim/es_shim.h`'s `syn_es_event` — one variant per `syn_es_kind`.
///
/// Every `meta` is the acting process (see [`RawMeta`] for the two exceptions). Strings are
/// copied out of the shim lossily, so invalid UTF-8 in a path becomes U+FFFD instead of dropping
/// the event. An optional string is `None` when the shim sent it absent or empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawEsEvent {
    /// `ES_EVENT_TYPE_NOTIFY_EXEC` — `meta` describes the post-exec process.
    Exec {
        /// The post-exec process.
        meta: RawMeta,
        /// Path of the new executable image.
        image_path: String,
        /// Arguments, at most `SYN_ES_MAX_ARGV` (128) entries.
        argv: Vec<String>,
        /// True when the shim's argv cap (`SYN_ES_MAX_ARGV`) dropped entries.
        argv_truncated: bool,
        /// Code-signing identifier (`None` when unsigned).
        signing_id: Option<String>,
        /// Team identifier (`None` for unsigned, ad-hoc, and platform binaries).
        team_id: Option<String>,
        /// Kernel codesigning flags (`CS_VALID` & co.) at exec time.
        cs_flags: u32,
        /// Whether the binary is an Apple platform binary (`es_process_t.is_platform_binary`).
        is_platform_binary: bool,
        /// Pre-exec image of the exec-ing process — the conventional
        /// parent-lineage view (for fork+exec, the parent's image the child
        /// still carried when it called `execve`).
        parent_path: Option<String>,
    },
    /// `ES_EVENT_TYPE_NOTIFY_OPEN`.
    Open {
        /// The process opening the file.
        meta: RawMeta,
        /// The file opened.
        path: String,
        /// Kernel `fflag` (`FREAD`/`FWRITE` bits — NOT `open(2)` `O_*` values;
        /// `normalize` translates).
        fflag: i32,
    },
    /// `ES_EVENT_TYPE_NOTIFY_CREATE`.
    Create {
        /// The process creating the file.
        meta: RawMeta,
        /// The file created: the existing file when the create targets one, else the new
        /// directory joined to the file name.
        path: String,
    },
    /// `ES_EVENT_TYPE_NOTIFY_RENAME`.
    Rename {
        /// The process renaming.
        meta: RawMeta,
        /// Source path.
        old_path: String,
        /// Destination: the existing file it replaces, else the target directory joined to the
        /// new name.
        new_path: String,
    },
    /// `ES_EVENT_TYPE_NOTIFY_UNLINK`.
    Unlink {
        /// The process deleting the file.
        meta: RawMeta,
        /// The file removed.
        path: String,
    },
    /// `ES_EVENT_TYPE_NOTIFY_MMAP`, already filtered by the shim to writable
    /// `MAP_SHARED` mappings (the only mmap case that mutates the file).
    MmapWriteShared {
        /// The process mapping the file.
        meta: RawMeta,
        /// The file mapped.
        path: String,
    },
    /// `ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN` (macOS 13+, #96).
    SshLogin {
        /// The process `EndpointSecurity` attributes the login message to.
        meta: RawMeta,
        /// Whether authentication succeeded.
        success: bool,
        /// Account the login named.
        username: String,
        /// Source address as sshd reports it (IPv4/IPv6 literal or hostname).
        source_address: Option<String>,
    },
    /// `ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN` — `login(1)`, local console
    /// (macOS 13+, #96).
    LoginLogin {
        /// The process `EndpointSecurity` attributes the login message to.
        meta: RawMeta,
        /// Whether authentication succeeded.
        success: bool,
        /// Account the login named.
        username: String,
    },
    /// `ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN` — a loginwindow graphical
    /// session login; only completed logins are reported (macOS 13+, #96).
    LwSessionLogin {
        /// The process `EndpointSecurity` attributes the login message to.
        meta: RawMeta,
        /// Account that logged in.
        username: String,
    },
    /// `ES_EVENT_TYPE_NOTIFY_SETEXTATTR` filtered by the shim to
    /// `com.apple.quarantine` (#96): download provenance. Both values are
    /// read back from the file at event time and `None` when that read raced
    /// the writer.
    QuarantineSet {
        /// The process that set the attribute.
        meta: RawMeta,
        /// The file that received the quarantine mark.
        path: String,
        /// The raw quarantine string (`flags;timestamp;agent;uuid`).
        quarantine: Option<String>,
        /// `kMDItemWhereFroms` raw bytes (a binary plist of URL strings).
        wherefroms_plist: Option<Vec<u8>>,
    },
    /// `ES_EVENT_TYPE_NOTIFY_MOUNT` / `NOTIFY_UNMOUNT` (#96).
    Mount {
        /// The process mounting or unmounting.
        meta: RawMeta,
        /// Where the volume is mounted (`f_mntonname`).
        mount_point: String,
        /// The mounted device or share (`f_mntfromname`).
        source: Option<String>,
        /// Filesystem type name (`f_fstypename`, for example `apfs`).
        fs_type: Option<String>,
        /// Whether the volume is mounted read-only (`MNT_RDONLY`).
        readonly: bool,
        /// True for a mount, false for an unmount.
        mounted: bool,
    },
    /// `ES_EVENT_TYPE_NOTIFY_SIGNAL`, filtered by the shim to targets that
    /// are `EndpointSecurity` clients — the tamper-relevant subset (#96).
    /// `meta` is the sender.
    SignalToEsClient {
        /// The sender.
        meta: RawMeta,
        /// Signal number, `0` if the kernel reported a negative one.
        signal: u32,
        /// Pid of the targeted client, `0` if the kernel reported a negative one.
        target_pid: u32,
        /// Executable of the targeted client.
        target_path: Option<String>,
    },
    /// `ES_EVENT_TYPE_NOTIFY_XPC_CONNECT` (macOS 14+, #96).
    XpcConnect {
        /// The connecting process.
        meta: RawMeta,
        /// Name of the XPC service connected to.
        service_name: String,
        /// Raw `es_xpc_domain_type_t`.
        domain_type: u32,
    },
    /// `ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD` (macOS 13+) — Background
    /// Task Management registered a launch item. `meta` is the instigating
    /// process when BTM identified one, otherwise the BTM subsystem itself.
    BtmLaunchItemAdd {
        /// The instigator, or the BTM subsystem when none was identified.
        meta: RawMeta,
        /// What kind of item BTM registered. Not read by normalization today.
        item_type: BtmItemType,
        /// True for a legacy plist (dropped in `~/Library/LaunchAgents` & co.
        /// rather than registered via `SMAppService`).
        legacy: bool,
        /// User the item is registered for (may be nobody, `u32::MAX - 1`).
        item_uid: u32,
        /// URL of the launch item itself (plist or app).
        item_url: String,
        /// App the item is attributed to, when any.
        app_url: Option<String>,
        /// Executable path from the launchd plist, when BTM resolves one —
        /// the actual persistence payload.
        executable_path: Option<String>,
    },
}
