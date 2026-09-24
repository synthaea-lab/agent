//! Normalization of raw `EndpointSecurity` records ([`crate::raw`]) into
//! `schema` events — pure and cross-platform, so the mapping is unit-tested on
//! any host (same split as `sensor-windows`' `normalize`).
//!
//! ## Flag semantics
//!
//! `schema::FileOpenEvent::flags` is platform-native by contract; this sensor
//! deliberately emits **POSIX `O_*` values** (macOS shares them with Linux for
//! the bits `schema` defines), so `schema::has_write_intent` and every
//! path+write rule work unchanged. The kernel's `fflag` (`FREAD`/`FWRITE`) is
//! translated in [`open_fflag_to_flags`], never passed through raw.
//!
//! ## Signature at the source
//!
//! Unlike Windows (where enrichment computes Authenticode verdicts after the
//! fact), `EndpointSecurity` hands the kernel's code-signing state to the
//! sensor for free on every exec, so [`normalize`] fills
//! `ExecEvent::signature` directly. This is the kernel's *dynamic validity*
//! view (`CS_VALID`), not a full chain evaluation — good enough for "unsigned
//! or invalidated binary ran", and enrichment may still refine it later.

use schema::{
    AuthEvent, AuthKind, AuthOutcome, Event, EventMeta, ExecEvent, FileDeleteEvent, FileOpenEvent,
    FileQuarantineEvent, FileRenameEvent, MountEvent, SignalEvent, Signature, User,
    XpcConnectEvent,
};

use crate::raw::{RawEsEvent, RawMeta};

/// Kernel `fflag` read bit (`FREAD`, `sys/fcntl.h`).
const FFLAG_READ: i32 = 0x1;
/// Kernel `fflag` write bit (`FWRITE`).
const FFLAG_WRITE: i32 = 0x2;

/// Kernel codesigning flag: signature is dynamically valid (`CS_VALID`,
/// `sys/codesign.h`).
const CS_VALID: u32 = 0x0000_0001;

/// Translates the kernel's open `fflag` (`FREAD`/`FWRITE` bits) into the
/// POSIX access-mode values `schema` defines (see module doc).
#[must_use]
pub(crate) fn open_fflag_to_flags(fflag: i32) -> u32 {
    let read = fflag & FFLAG_READ != 0;
    let write = fflag & FFLAG_WRITE != 0;
    match (read, write) {
        (_, false) => 0, // O_RDONLY
        (false, true) => schema::O_WRONLY,
        (true, true) => schema::O_RDWR,
    }
}

/// Maps the kernel's codesigning flags to the schema verdict (see module doc
/// for why the sensor fills this rather than enrichment).
#[must_use]
pub(crate) fn signature_from_cs_flags(cs_flags: u32) -> Signature {
    if cs_flags == 0 {
        Signature::Unsigned
    } else if cs_flags & CS_VALID != 0 {
        Signature::Valid
    } else {
        // Signed at some point but no longer dynamically valid — e.g. the
        // kernel invalidated the signature after in-memory tampering.
        Signature::Invalid
    }
}

/// Short process name: the image path's basename (macOS has no separate
/// kernel `comm` worth preferring — the BSD `p_comm` is 16-byte-truncated).
fn basename(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

fn event_meta(meta: &RawMeta) -> EventMeta {
    EventMeta {
        pid: meta.pid,
        ppid: meta.ppid,
        user: User::Unix {
            uid: meta.uid,
            gid: meta.gid,
        },
        timestamp_ns: meta.wall_time_ns,
        comm: basename(&meta.process_path),
        container: None,
    }
}

/// Agent field of the quarantine string — `flags;timestamp;agent;uuid`
/// (the format is undocumented but stable since 10.5; pinned by tests).
pub(crate) fn quarantine_agent(quarantine: &str) -> Option<String> {
    let agent = quarantine.split(';').nth(2)?.trim();
    if agent.is_empty() {
        return None;
    }
    Some(agent.to_string())
}

/// Extracts `(origin_url, referrer_url)` from `kMDItemWhereFroms` — a binary
/// plist holding an array of URL strings, download URL first, referrer (when
/// recorded) second. Unparseable bytes yield `(None, None)`: provenance is
/// best-effort enrichment, never a reason to drop the quarantine event.
pub(crate) fn wherefroms_urls(bytes: &[u8]) -> (Option<String>, Option<String>) {
    let Ok(plist::Value::Array(values)) = plist::Value::from_reader(std::io::Cursor::new(bytes))
    else {
        return (None, None);
    };
    let mut strings = values.into_iter().filter_map(|v| match v {
        plist::Value::String(s) if !s.is_empty() => Some(s),
        _ => None,
    });
    (strings.next(), strings.next())
}

/// Maps one raw ES record to its schema event.
///
/// Total today (every [`RawEsEvent`] variant produces an event) but kept
/// `Option` so a future variant can be consumed for sensor-internal state
/// without a schema counterpart.
#[must_use]
pub fn normalize(raw: &RawEsEvent) -> Option<Event> {
    match raw {
        RawEsEvent::Exec {
            meta,
            image_path,
            argv,
            argv_truncated: _,
            signing_id: _,
            team_id: _,
            cs_flags,
            is_platform_binary: _,
            parent_path,
        } => Some(Event::Exec(ExecEvent {
            meta: event_meta(meta),
            image_path: image_path.clone(),
            // Display/Sigma-friendly form, same choice as the Linux userspace
            // sensor; ML consumers use ExecEvent::ml_cmdline (NUL-joined argv).
            cmdline: argv.join(" "),
            argv: argv.clone(),
            parent_comm: parent_path.as_deref().map(basename),
            parent_image_path: parent_path.clone(),
            sha256: None,
            signature: Some(signature_from_cs_flags(*cs_flags)),
            env_security: Vec::new(),
        })),
        RawEsEvent::Open { meta, path, fflag } => Some(Event::FileOpen(FileOpenEvent {
            meta: event_meta(meta),
            path: path.clone(),
            flags: open_fflag_to_flags(*fflag),
        })),
        RawEsEvent::Create { meta, path } => Some(Event::FileOpen(FileOpenEvent {
            meta: event_meta(meta),
            path: path.clone(),
            // Creation is write intent by definition — same shape the kernel's
            // own open(2) would report for O_CREAT|O_WRONLY.
            flags: schema::O_CREAT | schema::O_WRONLY,
        })),
        RawEsEvent::Rename {
            meta,
            old_path,
            new_path,
        } => Some(Event::FileRename(FileRenameEvent {
            meta: event_meta(meta),
            old_path: old_path.clone(),
            new_path: new_path.clone(),
        })),
        RawEsEvent::Unlink { meta, path } => Some(Event::FileDelete(FileDeleteEvent {
            meta: event_meta(meta),
            path: path.clone(),
        })),
        RawEsEvent::MmapWriteShared { meta, path } => Some(Event::FileOpen(FileOpenEvent {
            meta: event_meta(meta),
            path: path.clone(),
            // A writable shared mapping mutates the file exactly like opening
            // it read-write — report it as that (the shim already dropped
            // read-only/private mappings).
            flags: schema::O_RDWR,
        })),
        RawEsEvent::SshLogin {
            meta,
            success,
            username,
            source_address,
        } => Some(Event::Auth(AuthEvent {
            meta: event_meta(meta),
            outcome: if *success {
                AuthOutcome::Success
            } else {
                AuthOutcome::Failure
            },
            kind: if *success {
                AuthKind::Logon
            } else {
                AuthKind::LogonFailure
            },
            target_user: username.clone(),
            target_user_sid: None,
            // sshd may report a hostname here; only a literal address is an
            // IpAddr — a non-parsing value is dropped, not fabricated.
            source_address: source_address.as_deref().and_then(|s| s.parse().ok()),
            status_code: None,
        })),
        RawEsEvent::LoginLogin {
            meta,
            success,
            username,
        } => Some(Event::Auth(AuthEvent {
            meta: event_meta(meta),
            outcome: if *success {
                AuthOutcome::Success
            } else {
                AuthOutcome::Failure
            },
            kind: if *success {
                AuthKind::Logon
            } else {
                AuthKind::LogonFailure
            },
            target_user: username.clone(),
            target_user_sid: None,
            // Local console login — no source address, which is itself
            // meaningful (see AuthEvent::source_address's doc).
            source_address: None,
            status_code: None,
        })),
        RawEsEvent::LwSessionLogin { meta, username } => Some(Event::Auth(AuthEvent {
            meta: event_meta(meta),
            outcome: AuthOutcome::Success,
            kind: AuthKind::Logon,
            target_user: username.clone(),
            target_user_sid: None,
            source_address: None,
            status_code: None,
        })),
        RawEsEvent::QuarantineSet {
            meta,
            path,
            quarantine,
            wherefroms_plist,
        } => {
            let (origin_url, referrer_url) = wherefroms_plist
                .as_deref()
                .map_or((None, None), wherefroms_urls);
            Some(Event::FileQuarantine(FileQuarantineEvent {
                meta: event_meta(meta),
                path: path.clone(),
                agent: quarantine.as_deref().and_then(quarantine_agent),
                origin_url,
                referrer_url,
            }))
        }
        RawEsEvent::Mount {
            meta,
            mount_point,
            source,
            fs_type,
            readonly,
            mounted,
        } => Some(Event::Mount(MountEvent {
            meta: event_meta(meta),
            mount_point: mount_point.clone(),
            source: source.clone(),
            fs_type: fs_type.clone(),
            readonly: *readonly,
            mounted: *mounted,
        })),
        RawEsEvent::SignalToEsClient {
            meta,
            signal,
            target_pid,
            target_path,
        } => Some(Event::Signal(SignalEvent {
            meta: event_meta(meta),
            signal: *signal,
            target_pid: *target_pid,
            target_image_path: target_path.clone(),
        })),
        RawEsEvent::XpcConnect {
            meta,
            service_name,
            domain_type,
        } => Some(Event::XpcConnect(XpcConnectEvent {
            meta: event_meta(meta),
            service_name: service_name.clone(),
            domain_type: *domain_type,
        })),
        RawEsEvent::BtmLaunchItemAdd {
            meta,
            item_type: _,
            legacy: _,
            item_uid: _,
            item_url,
            app_url: _,
            executable_path,
        } => Some(Event::FileOpen(FileOpenEvent {
            meta: event_meta(meta),
            // The persistence payload when BTM resolved one (the executable
            // the launchd plist points at), else the item URL — the artifact
            // an analyst removes.
            path: executable_path.clone().unwrap_or_else(|| item_url.clone()),
            flags: schema::FLAG_PERSISTENCE_BTM_ARTIFACT,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::BtmItemType;

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

    #[test]
    fn open_fflag_translates_to_posix_access_modes() {
        assert_eq!(open_fflag_to_flags(FFLAG_READ), 0);
        assert_eq!(open_fflag_to_flags(FFLAG_WRITE), schema::O_WRONLY);
        assert_eq!(
            open_fflag_to_flags(FFLAG_READ | FFLAG_WRITE),
            schema::O_RDWR
        );
        // Whatever else fflag carries (O_NONBLOCK etc. shifted in), only the
        // access mode is translated.
        assert_eq!(open_fflag_to_flags(FFLAG_WRITE | 0x40), schema::O_WRONLY);
    }

    #[test]
    fn open_write_modes_carry_write_intent_for_rules() {
        // The property the flag translation exists for: schema's ONE write
        // predicate must see macOS opens exactly like Linux ones.
        assert!(schema::has_write_intent(open_fflag_to_flags(FFLAG_WRITE)));
        assert!(schema::has_write_intent(open_fflag_to_flags(
            FFLAG_READ | FFLAG_WRITE
        )));
        assert!(!schema::has_write_intent(open_fflag_to_flags(FFLAG_READ)));
    }

    #[test]
    fn cs_flags_map_to_signature_verdicts() {
        assert_eq!(signature_from_cs_flags(0), Signature::Unsigned);
        assert_eq!(signature_from_cs_flags(CS_VALID), Signature::Valid);
        // CS_VALID plus other bits (hardened runtime etc.) is still valid.
        assert_eq!(
            signature_from_cs_flags(CS_VALID | 0x1_0000),
            Signature::Valid
        );
        // Signed but invalidated: flags present, CS_VALID cleared.
        assert_eq!(signature_from_cs_flags(0x0000_0200), Signature::Invalid);
    }

    #[test]
    fn exec_normalizes_lineage_cmdline_and_signature() {
        let raw = RawEsEvent::Exec {
            meta: RawMeta {
                process_path: "/bin/zsh".to_string(),
                ..meta()
            },
            image_path: "/bin/zsh".to_string(),
            argv: vec!["zsh".to_string(), "-c".to_string(), "id".to_string()],
            argv_truncated: false,
            signing_id: Some("com.apple.zsh".to_string()),
            team_id: None,
            cs_flags: CS_VALID,
            is_platform_binary: true,
            parent_path: Some(
                "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal".to_string(),
            ),
        };
        let Some(Event::Exec(exec)) = normalize(&raw) else {
            panic!("exec must normalize to Event::Exec");
        };
        assert_eq!(exec.meta.comm, "zsh");
        assert_eq!(exec.meta.user, User::Unix { uid: 501, gid: 20 });
        assert_eq!(exec.cmdline, "zsh -c id");
        assert_eq!(exec.argv.len(), 3);
        assert_eq!(exec.parent_comm.as_deref(), Some("Terminal"));
        assert_eq!(exec.signature, Some(Signature::Valid));
        // ML canonical form stays NUL-joined regardless of the display cmdline.
        assert_eq!(exec.ml_cmdline(), "zsh\0-c\0id\0");
    }

    #[test]
    fn create_reports_creation_write_intent() {
        let raw = RawEsEvent::Create {
            meta: meta(),
            path: "/Users/mal/Library/LaunchAgents/com.evil.plist".to_string(),
        };
        let Some(Event::FileOpen(open)) = normalize(&raw) else {
            panic!("create must normalize to Event::FileOpen");
        };
        assert_eq!(open.flags, schema::O_CREAT | schema::O_WRONLY);
        assert!(schema::has_write_intent(open.flags));
    }

    #[test]
    fn shared_writable_mmap_reports_as_readwrite_open() {
        let raw = RawEsEvent::MmapWriteShared {
            meta: meta(),
            path: "/tmp/target".to_string(),
        };
        let Some(Event::FileOpen(open)) = normalize(&raw) else {
            panic!("mmap must normalize to Event::FileOpen");
        };
        assert_eq!(open.flags, schema::O_RDWR);
    }

    #[test]
    fn rename_and_unlink_map_to_their_file_events() {
        let rename = RawEsEvent::Rename {
            meta: meta(),
            old_path: "/Users/mal/invoice.pdf".to_string(),
            new_path: "/Users/mal/invoice.pdf.locked".to_string(),
        };
        assert!(matches!(
            normalize(&rename),
            Some(Event::FileRename(e)) if e.new_path.ends_with(".locked")
        ));

        let unlink = RawEsEvent::Unlink {
            meta: meta(),
            path: "/var/log/system.log".to_string(),
        };
        assert!(matches!(
            normalize(&unlink),
            Some(Event::FileDelete(e)) if e.path == "/var/log/system.log"
        ));
    }

    #[test]
    fn btm_launch_item_carries_persistence_flag_and_payload_path() {
        let raw = RawEsEvent::BtmLaunchItemAdd {
            meta: meta(),
            item_type: BtmItemType::Agent,
            legacy: true,
            item_uid: 501,
            item_url: "file:///Users/mal/Library/LaunchAgents/com.evil.plist".to_string(),
            app_url: None,
            executable_path: Some("/Users/mal/.hidden/payload".to_string()),
        };
        let Some(Event::FileOpen(open)) = normalize(&raw) else {
            panic!("BTM add must normalize to Event::FileOpen");
        };
        assert_eq!(open.flags, schema::FLAG_PERSISTENCE_BTM_ARTIFACT);
        assert_eq!(open.path, "/Users/mal/.hidden/payload");
    }

    #[test]
    fn ssh_login_maps_to_logon_with_source_address() {
        let raw = RawEsEvent::SshLogin {
            meta: meta(),
            success: true,
            username: "alice".to_string(),
            source_address: Some("10.0.0.5".to_string()),
        };
        let Some(Event::Auth(auth)) = normalize(&raw) else {
            panic!("must map to Event::Auth");
        };
        assert_eq!(auth.outcome, schema::AuthOutcome::Success);
        assert_eq!(auth.kind, schema::AuthKind::Logon);
        assert_eq!(auth.target_user, "alice");
        assert_eq!(auth.source_address, Some("10.0.0.5".parse().unwrap()));
    }

    #[test]
    fn failed_ssh_login_maps_to_logon_failure() {
        let raw = RawEsEvent::SshLogin {
            meta: meta(),
            success: false,
            username: "root".to_string(),
            // sshd can report a hostname — not an IpAddr, dropped not faked.
            source_address: Some("attacker.example".to_string()),
        };
        let Some(Event::Auth(auth)) = normalize(&raw) else {
            panic!("must map to Event::Auth");
        };
        assert_eq!(auth.outcome, schema::AuthOutcome::Failure);
        assert_eq!(auth.kind, schema::AuthKind::LogonFailure);
        assert_eq!(auth.source_address, None);
    }

    #[test]
    fn quarantine_carries_agent_and_origin_urls() {
        // Real kMDItemWhereFroms shape: a binary plist array of URL strings,
        // download URL first, referrer second — built with the same parser
        // family that reads it, so the bytes are genuine bplist00.
        let mut wherefroms = Vec::new();
        plist::Value::Array(vec![
            plist::Value::String("https://example.test/payload.zip".into()),
            plist::Value::String("https://example.test/downloads".into()),
        ])
        .to_writer_binary(&mut wherefroms)
        .expect("bplist serializes");

        let raw = RawEsEvent::QuarantineSet {
            meta: meta(),
            path: "/Users/mal/Downloads/payload.zip".to_string(),
            quarantine: Some("0083;68d1a2c4;Safari;720E0F04-2A44-4B4C".to_string()),
            wherefroms_plist: Some(wherefroms),
        };
        let Some(Event::FileQuarantine(q)) = normalize(&raw) else {
            panic!("must map to Event::FileQuarantine");
        };
        assert_eq!(q.agent.as_deref(), Some("Safari"));
        assert_eq!(
            q.origin_url.as_deref(),
            Some("https://example.test/payload.zip")
        );
        assert_eq!(
            q.referrer_url.as_deref(),
            Some("https://example.test/downloads")
        );
    }

    #[test]
    fn quarantine_without_readable_values_still_reports_the_mark() {
        // The xattr read raced the writer: the mark alone is still the
        // "arrived from outside" signal.
        let raw = RawEsEvent::QuarantineSet {
            meta: meta(),
            path: "/Users/mal/Downloads/payload.zip".to_string(),
            quarantine: None,
            wherefroms_plist: Some(b"not a plist".to_vec()),
        };
        let Some(Event::FileQuarantine(q)) = normalize(&raw) else {
            panic!("must map to Event::FileQuarantine");
        };
        assert_eq!(q.agent, None);
        assert_eq!(q.origin_url, None);
        assert_eq!(q.referrer_url, None);
    }

    #[test]
    fn mount_and_unmount_map_with_direction() {
        let mount = RawEsEvent::Mount {
            meta: meta(),
            mount_point: "/Volumes/Installer".to_string(),
            source: Some("/dev/disk4s1".to_string()),
            fs_type: Some("hfs".to_string()),
            readonly: true,
            mounted: true,
        };
        assert!(matches!(
            normalize(&mount),
            Some(Event::Mount(m)) if m.mounted && m.readonly && m.fs_type.as_deref() == Some("hfs")
        ));
        let unmount = RawEsEvent::Mount {
            meta: meta(),
            mount_point: "/Volumes/Installer".to_string(),
            source: None,
            fs_type: None,
            readonly: false,
            mounted: false,
        };
        assert!(matches!(
            normalize(&unmount),
            Some(Event::Mount(m)) if !m.mounted
        ));
    }

    #[test]
    fn signal_to_es_client_maps_with_sender_meta() {
        let raw = RawEsEvent::SignalToEsClient {
            meta: meta(), // the sender
            signal: 9,
            target_pid: 400,
            target_path: Some("/usr/local/bin/synthaea-agent".to_string()),
        };
        let Some(Event::Signal(sig)) = normalize(&raw) else {
            panic!("must map to Event::Signal");
        };
        assert_eq!(sig.signal, 9);
        assert_eq!(sig.target_pid, 400);
        assert_eq!(sig.meta.comm, "curl", "meta must stay the sender");
    }

    #[test]
    fn xpc_connect_maps_service_name() {
        let raw = RawEsEvent::XpcConnect {
            meta: meta(),
            service_name: "com.apple.tccd".to_string(),
            domain_type: 1,
        };
        assert!(matches!(
            normalize(&raw),
            Some(Event::XpcConnect(x)) if x.service_name == "com.apple.tccd"
        ));
    }

    #[test]
    fn quarantine_agent_field_parsing_is_pinned() {
        assert_eq!(
            quarantine_agent("0083;68d1a2c4;Safari;720E0F04").as_deref(),
            Some("Safari")
        );
        assert_eq!(quarantine_agent("0083;68d1a2c4"), None);
        assert_eq!(quarantine_agent("0083;68d1a2c4;;uuid"), None);
    }

    #[test]
    fn btm_launch_item_falls_back_to_item_url_without_payload() {
        let raw = RawEsEvent::BtmLaunchItemAdd {
            meta: meta(),
            item_type: BtmItemType::LoginItem,
            legacy: false,
            item_uid: 501,
            item_url: "file:///Applications/Evil.app".to_string(),
            app_url: Some("file:///Applications/Evil.app".to_string()),
            executable_path: None,
        };
        let Some(Event::FileOpen(open)) = normalize(&raw) else {
            panic!("BTM add must normalize to Event::FileOpen");
        };
        assert_eq!(open.path, "file:///Applications/Evil.app");
    }
}
