//! Owned Rust mirror of the shim's flattened `EndpointSecurity` records.
//!
//! Cross-platform on purpose (no `cfg`): the macOS-only FFI layer converts the
//! borrowed C structs into these owned values, and [`crate::normalize`] maps
//! them into `schema` events — so the whole normalization path is unit-testable
//! on any development host, the same split `sensor-windows` uses between its
//! ETW plumbing and `normalize`.

/// Identity of the acting process, common to every raw event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawMeta {
    pub pid: u32,
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
    UserItem,
    App,
    LoginItem,
    Agent,
    Daemon,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawEsEvent {
    /// `ES_EVENT_TYPE_NOTIFY_EXEC` — `meta` describes the post-exec process.
    Exec {
        meta: RawMeta,
        image_path: String,
        argv: Vec<String>,
        /// True when the shim's argv cap (`SYN_ES_MAX_ARGV`) dropped entries.
        argv_truncated: bool,
        /// Code-signing identifier, empty-able (`None` when unsigned).
        signing_id: Option<String>,
        /// Team identifier (`None` for unsigned, ad-hoc, and platform binaries).
        team_id: Option<String>,
        /// Kernel codesigning flags (`CS_VALID` & co.) at exec time.
        cs_flags: u32,
        is_platform_binary: bool,
        /// Pre-exec image of the exec-ing process — the conventional
        /// parent-lineage view (for fork+exec, the parent's image the child
        /// still carried when it called `execve`).
        parent_path: Option<String>,
    },
    /// `ES_EVENT_TYPE_NOTIFY_OPEN`.
    Open {
        meta: RawMeta,
        path: String,
        /// Kernel `fflag` (`FREAD`/`FWRITE` bits — NOT `open(2)` `O_*` values;
        /// `normalize` translates).
        fflag: i32,
    },
    /// `ES_EVENT_TYPE_NOTIFY_CREATE`.
    Create { meta: RawMeta, path: String },
    /// `ES_EVENT_TYPE_NOTIFY_RENAME`.
    Rename {
        meta: RawMeta,
        old_path: String,
        new_path: String,
    },
    /// `ES_EVENT_TYPE_NOTIFY_UNLINK`.
    Unlink { meta: RawMeta, path: String },
    /// `ES_EVENT_TYPE_NOTIFY_MMAP`, already filtered by the shim to writable
    /// `MAP_SHARED` mappings (the only mmap case that mutates the file).
    MmapWriteShared { meta: RawMeta, path: String },
    /// `ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD` (macOS 13+) — Background
    /// Task Management registered a launch item. `meta` is the instigating
    /// process when BTM identified one, otherwise the BTM subsystem itself.
    BtmLaunchItemAdd {
        meta: RawMeta,
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
