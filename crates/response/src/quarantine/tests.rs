#[cfg(any(test, not(unix)))]
use super::copy::move_to_quarantine;
#[cfg(unix)]
use super::permissions::quarantine_dir_needs_chmod;
#[cfg(unix)]
use super::snapshot::SnapshotLock;
#[cfg(unix)]
use super::snapshot::copy_prefix_hashed;
#[cfg(unix)]
use super::snapshot::is_written_after_hash;
#[cfg(unix)]
use super::snapshot::may_take_snapshot;
#[cfg(unix)]
use super::snapshot::quarantine_snapshot;
#[cfg(unix)]
use super::snapshot::sweep_stale_snapshots;
#[cfg(unix)]
use super::snapshot::try_lock_exclusive;
#[cfg(unix)]
use super::source::can_fall_back_to_copy;
#[cfg(unix)]
use super::source::copy_open_file_no_clobber;
use super::{
    copy::{copy_no_clobber, copy_no_clobber_with, move_file_no_clobber},
    origin::{decode_origin_record, origin_sidecar_path},
    permissions::secure_payload,
    *,
};
#[cfg(unix)]
use super::{
    copy::{sha256_file, sha256_reader},
    origin::encode_origin_record,
    permissions::secure_quarantine_dir,
    source::Source,
};

fn temp_dir(name: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "response-quarantine-test-{name}-{}-{unique}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn policy_disabled_leaves_the_file_in_place() {
    let dir = temp_dir("observe-only");
    let payload = dir.join("payload.bin");
    std::fs::write(&payload, b"not actually malware").unwrap();
    let policy = ResponsePolicy {
        kill_enabled: false,
        quarantine_enabled: false,
        isolate_enabled: false,
    };

    let outcome = quarantine_file(&payload, &dir.join("quarantine"), &policy);

    assert_eq!(
        outcome,
        QuarantineOutcome::ObserveOnly {
            path: payload.clone()
        }
    );
    assert!(payload.exists(), "observe-only must not touch the file");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_quarantined_file_moves_read_only_and_can_be_restored() {
    let dir = temp_dir("roundtrip");
    let payload = dir.join("payload.bin");
    std::fs::write(&payload, b"not actually malware").unwrap();
    let quarantine_dir = dir.join("quarantine");
    let policy = ResponsePolicy {
        kill_enabled: false,
        quarantine_enabled: true,
        isolate_enabled: false,
    };

    let outcome = quarantine_file(&payload, &quarantine_dir, &policy);
    let (quarantined_at, sha256_hex) = match outcome {
        QuarantineOutcome::Quarantined {
            quarantined_at,
            sha256_hex,
            ref original,
        } => {
            assert_eq!(original, &payload);
            (quarantined_at, sha256_hex)
        }
        other => panic!("expected Quarantined, got {other:?}"),
    };

    assert!(
        !payload.exists(),
        "the original path must be empty after quarantine"
    );
    assert!(quarantined_at.exists());
    assert!(
        std::fs::metadata(&quarantined_at)
            .unwrap()
            .permissions()
            .readonly(),
        "a quarantined file must be read-only"
    );

    let restored = unquarantine(&quarantine_dir, &sha256_hex).unwrap();
    assert_eq!(restored, payload);
    assert!(
        payload.exists(),
        "unquarantine must restore the original file"
    );
    assert_eq!(std::fs::read(&payload).unwrap(), b"not actually malware");
    assert!(
        !quarantine_dir.join(format!("{sha256_hex}.origin")).exists(),
        "the sidecar must be removed after a successful restore"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn duplicate_digests_are_quarantined_and_restored_individually() {
    let dir = temp_dir("duplicate-digest");
    let first = dir.join("first");
    let second = dir.join("second");
    std::fs::write(&first, b"same bytes").unwrap();
    std::fs::write(&second, b"same bytes").unwrap();
    let quarantine_dir = dir.join("quarantine");
    let policy = ResponsePolicy {
        kill_enabled: false,
        quarantine_enabled: true,
        isolate_enabled: false,
    };

    let first_result = quarantine_file(&first, &quarantine_dir, &policy);
    let QuarantineOutcome::Quarantined {
        sha256_hex,
        quarantined_at: first_stored,
        ..
    } = first_result
    else {
        panic!("first payload must be quarantined");
    };
    let second_result = quarantine_file(&second, &quarantine_dir, &policy);
    let QuarantineOutcome::Quarantined {
        sha256_hex: second_digest,
        quarantined_at: second_stored,
        ..
    } = second_result
    else {
        panic!("duplicate payload must also be quarantined");
    };
    assert_eq!(sha256_hex, second_digest);
    assert_ne!(first_stored, second_stored);
    assert!(!first.exists());
    assert!(!second.exists());
    assert_eq!(
        decode_origin_record(
            &std::fs::read(origin_sidecar_path(&quarantine_dir, &sha256_hex)).unwrap()
        )
        .unwrap()
        .original,
        first
    );
    assert_eq!(
        decode_origin_record(
            &std::fs::read(quarantine_dir.join(format!("{sha256_hex}.1.origin"))).unwrap()
        )
        .unwrap()
        .original,
        second
    );
    assert_eq!(list_quarantined(&quarantine_dir).unwrap().len(), 2);
    assert!(is_still_quarantined(&quarantine_dir, &sha256_hex));
    assert_eq!(unquarantine(&quarantine_dir, &sha256_hex).unwrap(), first);
    assert!(is_still_quarantined(&quarantine_dir, &sha256_hex));
    assert_eq!(unquarantine(&quarantine_dir, &sha256_hex).unwrap(), second);
    assert!(!is_still_quarantined(&quarantine_dir, &sha256_hex));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn failed_payload_security_rolls_back_to_source() {
    let dir = temp_dir("secure-rollback");
    let source = dir.join("source");
    let stored = dir.join("stored");
    std::fs::write(&source, b"payload").unwrap();
    let error = move_and_secure(
        &source,
        &stored,
        move_to_quarantine,
        |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected",
            ))
        },
        move_file_no_clobber,
    )
    .unwrap_err();
    assert!(!error.retained_in_quarantine);
    assert_eq!(error.error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(source.exists());
    assert!(!stored.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn partial_move_failure_keeps_its_quarantine_record() {
    let dir = temp_dir("partial-move");
    let source = dir.join("source");
    let stored = dir.join("stored");
    std::fs::write(&source, b"payload").unwrap();
    std::fs::write(&stored, b"partially moved payload").unwrap();
    let error = move_and_secure(
        &source,
        &stored,
        |_, _| Err(std::io::Error::other("injected partial move failure")),
        secure_payload,
        move_file_no_clobber,
    )
    .unwrap_err();
    assert!(error.retained_in_quarantine);
    assert!(source.exists());
    assert!(stored.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn failed_rollback_retains_payload_for_inspection() {
    let dir = temp_dir("failed-rollback");
    let source = dir.join("source");
    let stored = dir.join("stored");
    std::fs::write(&source, b"payload").unwrap();
    let error = move_and_secure(
        &source,
        &stored,
        move_to_quarantine,
        |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected",
            ))
        },
        |_, _| Err(std::io::Error::other("injected rollback failure")),
    )
    .unwrap_err();
    assert!(error.retained_in_quarantine);
    assert!(error.error.to_string().contains("remain in quarantine"));
    assert!(!source.exists());
    assert_eq!(std::fs::read(&stored).unwrap(), b"payload");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn quarantine_removes_execute_and_tightens_existing_permissions() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = temp_dir("unix-modes");
    let payload = dir.join("payload");
    std::fs::write(&payload, b"executable payload").unwrap();
    std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o751)).unwrap();
    let quarantine_dir = dir.join("quarantine");
    std::fs::create_dir(&quarantine_dir).unwrap();
    std::fs::set_permissions(&quarantine_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

    let outcome = quarantine_file(
        &payload,
        &quarantine_dir,
        &ResponsePolicy {
            kill_enabled: false,
            quarantine_enabled: true,
            isolate_enabled: false,
        },
    );
    let (stored, digest) = match outcome {
        QuarantineOutcome::Quarantined {
            quarantined_at,
            sha256_hex,
            ..
        } => (quarantined_at, sha256_hex),
        other => panic!("expected quarantine, got {other:?}"),
    };
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&quarantine_dir), 0o700);
    assert_eq!(mode(&stored), 0o400);
    assert_eq!(mode(&origin_sidecar_path(&quarantine_dir, &digest)), 0o600);

    let restored = unquarantine(&quarantine_dir, &digest).unwrap();
    assert_eq!(restored, payload);
    assert_eq!(
        mode(&restored),
        0o751,
        "restore must recover the original mode"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn a_path_only_legacy_sidecar_restores_with_the_safe_mode() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = temp_dir("legacy-sidecar-restore");
    let quarantine_dir = dir.join("quarantine");
    std::fs::create_dir(&quarantine_dir).unwrap();
    let original = dir.join("restored-payload");
    let body = b"legacy quarantined bytes";
    let digest = sha256_reader(&mut &body[..]).unwrap();
    let stored = quarantine_dir.join(&digest);
    std::fs::write(&stored, body).unwrap();
    std::fs::set_permissions(&stored, std::fs::Permissions::from_mode(0o400)).unwrap();
    std::fs::write(
        origin_sidecar_path(&quarantine_dir, &digest),
        original.to_string_lossy().as_bytes(),
    )
    .unwrap();

    assert_eq!(unquarantine(&quarantine_dir, &digest).unwrap(), original);
    assert_eq!(std::fs::read(&original).unwrap(), body);
    assert_eq!(
        std::fs::metadata(&original).unwrap().permissions().mode() & 0o777,
        0o400,
        "a legacy record has no mode to restore"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn altered_sidecar_cannot_restore_special_mode_bits() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = temp_dir("altered-mode-sidecar");
    let (original, quarantine_dir, digest) =
        quarantine_one(&dir, "payload.bin", b"mode tamper payload");
    let sidecar = origin_sidecar_path(&quarantine_dir, &digest);
    // Simulate a sidecar edit that asks restore to setuid, setgid, and sticky.
    std::fs::write(&sidecar, encode_origin_record(&original, Some(0o7777))).unwrap();

    let restored = unquarantine(&quarantine_dir, &digest).unwrap();

    let mode = std::fs::metadata(restored).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o777, "only ordinary permission bits may be restored");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn quarantine_modes_are_independent_of_the_process_umask() {
    const UMASK_ENV: &str = "SYNTHAEA_QUARANTINE_TEST_UMASK";
    if let Some(mask) = std::env::var_os(UMASK_ENV) {
        use std::os::unix::fs::PermissionsExt as _;
        let mask = u32::from_str_radix(&mask.to_string_lossy(), 8).unwrap();
        // SAFETY: this runs in an isolated child test process and restores the previous mask.
        let previous = unsafe { libc::umask(mask as libc::mode_t) };
        let dir = temp_dir("umask");
        let payload = dir.join("payload");
        std::fs::write(&payload, b"umask-independent payload").unwrap();
        let quarantine_dir = dir.join("quarantine");
        let outcome = quarantine_file(
            &payload,
            &quarantine_dir,
            &ResponsePolicy {
                kill_enabled: false,
                quarantine_enabled: true,
                isolate_enabled: false,
            },
        );
        // SAFETY: restore the mask changed above before doing assertions or cleanup.
        unsafe { libc::umask(previous) };
        let QuarantineOutcome::Quarantined {
            quarantined_at,
            sha256_hex,
            ..
        } = outcome
        else {
            panic!("expected quarantine, got {outcome:?}");
        };
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&quarantine_dir), 0o700);
        assert_eq!(mode(&quarantined_at), 0o400);
        assert_eq!(
            mode(&origin_sidecar_path(&quarantine_dir, &sha256_hex)),
            0o600
        );
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }

    let executable = std::env::current_exe().unwrap();
    let test_name = std::thread::current().name().unwrap().to_owned();
    for mask in ["000", "077"] {
        let status = std::process::Command::new(&executable)
            .arg("--exact")
            .arg(&test_name)
            .env(UMASK_ENV, mask)
            .status()
            .unwrap();
        assert!(status.success(), "child test failed under umask {mask}");
    }
}

#[cfg(unix)]
#[test]
fn listing_tightens_legacy_quarantine_entries() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = temp_dir("legacy-modes");
    let quarantine_dir = dir.join("quarantine");
    std::fs::create_dir(&quarantine_dir).unwrap();
    let payload = b"legacy payload";
    let payload_path = dir.join("payload");
    std::fs::write(&payload_path, payload).unwrap();
    let digest = sha256_file(&payload_path).unwrap();
    let stored = quarantine_dir.join(&digest);
    let sidecar = origin_sidecar_path(&quarantine_dir, &digest);
    std::fs::write(&stored, payload).unwrap();
    std::fs::write(&sidecar, payload_path.to_string_lossy().as_bytes()).unwrap();
    std::fs::set_permissions(&quarantine_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&stored, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o644)).unwrap();

    let listed = list_quarantined(&quarantine_dir).unwrap();
    assert_eq!(listed.len(), 1);
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&quarantine_dir), 0o700);
    assert_eq!(mode(&stored), 0o400);
    assert_eq!(mode(&sidecar), 0o600);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_missing_file_reports_failed_not_a_panic() {
    let dir = temp_dir("missing");
    let policy = ResponsePolicy {
        kill_enabled: false,
        quarantine_enabled: true,
        isolate_enabled: false,
    };

    let outcome = quarantine_file(
        &dir.join("does-not-exist"),
        &dir.join("quarantine"),
        &policy,
    );

    assert!(matches!(outcome, QuarantineOutcome::Failed { .. }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn a_symlink_payload_is_refused_without_changing_its_target() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let dir = temp_dir("symlink-source");
    let target = dir.join("target");
    let source = dir.join("source-link");
    std::fs::write(&target, b"payload target").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
    symlink(&target, &source).unwrap();

    let outcome = quarantine_file(
        &source,
        &dir.join("quarantine"),
        &ResponsePolicy {
            kill_enabled: false,
            quarantine_enabled: true,
            isolate_enabled: false,
        },
    );
    assert!(matches!(outcome, QuarantineOutcome::Failed { .. }));
    assert!(source.is_symlink());
    assert_eq!(
        std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert!(!dir.join("quarantine").exists());

    let _ = std::fs::remove_dir_all(&dir);
}

/// #689: the name is swapped for a symlink to a victim file after the source was opened
/// and checked. The move must store the inode that was checked, leave the symlink and its
/// target alone, and the `chmod` that follows must not reach the victim.
#[cfg(target_os = "linux")]
#[test]
fn a_symlink_swapped_in_after_the_check_does_not_redirect_the_move_or_the_chmod() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let dir = temp_dir("swap-symlink");
    let source = dir.join("payload");
    let victim = dir.join("victim");
    let stored = dir.join("stored");
    std::fs::write(&source, b"the payload").unwrap();
    std::fs::write(&victim, b"someone else's file").unwrap();
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();

    let opened = Source::open(&source).unwrap();
    let digest = opened.sha256(&source).unwrap();
    // The race: between the check and the move, the name becomes a symlink.
    std::fs::remove_file(&source).unwrap();
    symlink(&victim, &source).unwrap();

    move_and_secure(
        &source,
        &stored,
        |from, to| opened.move_into_quarantine(from, to),
        secure_payload,
        move_file_no_clobber,
    )
    .unwrap_or_else(|failure| panic!("move failed: {}", failure.error));

    assert!(!std::fs::symlink_metadata(&stored).unwrap().is_symlink());
    assert_eq!(
        sha256_file(&stored).unwrap(),
        digest,
        "stored what was hashed"
    );
    assert_eq!(std::fs::read(&stored).unwrap(), b"the payload");
    assert_eq!(
        std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
        0o644,
        "the symlink's target is untouched"
    );
    assert!(
        std::fs::symlink_metadata(&source).unwrap().is_symlink(),
        "a name that is no longer ours is left alone"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// #689: the file is replaced by another one after it was hashed. What is stored is the
/// file that was hashed, so the digest it is filed under is its own.
#[cfg(target_os = "linux")]
#[test]
fn a_file_replaced_after_hashing_is_stored_under_its_own_digest() {
    let dir = temp_dir("swap-file");
    let source = dir.join("payload");
    let other = dir.join("other");
    let stored = dir.join("stored");
    std::fs::write(&source, b"hashed content").unwrap();
    std::fs::write(&other, b"replacement content").unwrap();

    let opened = Source::open(&source).unwrap();
    let digest = opened.sha256(&source).unwrap();
    std::fs::rename(&other, &source).unwrap();

    opened.move_into_quarantine(&source, &stored).unwrap();

    assert_eq!(sha256_file(&stored).unwrap(), digest);
    assert_eq!(
        std::fs::read(&source).unwrap(),
        b"replacement content",
        "the replacement is not ours to remove"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// #689: a file deleted after it was opened cannot be linked; it is copied from the
/// descriptor, which is also the path taken across filesystems.
#[cfg(unix)]
#[test]
fn a_file_unlinked_after_the_check_is_still_stored_from_its_descriptor() {
    let dir = temp_dir("unlinked-source");
    let source = dir.join("payload");
    let stored = dir.join("stored");
    std::fs::write(&source, b"still readable").unwrap();

    let opened = Source::open(&source).unwrap();
    let digest = opened.sha256(&source).unwrap();
    std::fs::remove_file(&source).unwrap();

    opened.move_into_quarantine(&source, &stored).unwrap();

    assert_eq!(sha256_file(&stored).unwrap(), digest);
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn the_copy_from_a_descriptor_ignores_a_symlink_that_took_the_name() {
    use std::os::unix::fs::symlink;

    let dir = temp_dir("copy-from-fd");
    let source = dir.join("payload");
    let victim = dir.join("victim");
    let stored = dir.join("stored");
    std::fs::write(&source, b"the payload").unwrap();
    std::fs::write(&victim, b"someone else's file").unwrap();

    let opened = Source::open(&source).unwrap();
    std::fs::remove_file(&source).unwrap();
    symlink(&victim, &source).unwrap();

    copy_open_file_no_clobber(&opened.file, &stored, u64::MAX).unwrap();

    assert_eq!(std::fs::read(&stored).unwrap(), b"the payload");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(target_os = "linux")]
#[test]
fn linking_an_open_file_never_replaces_an_existing_name() {
    let dir = temp_dir("link-no-clobber");
    let source = dir.join("payload");
    let taken = dir.join("taken");
    std::fs::write(&source, b"payload").unwrap();
    std::fs::write(&taken, b"already here").unwrap();

    let opened = Source::open(&source).unwrap();
    let error = opened.move_into_quarantine(&source, &taken).unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&taken).unwrap(), b"already here");
    assert!(source.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn only_the_cannot_link_errors_fall_back_to_a_copy() {
    for code in [
        libc::EXDEV,
        libc::ENOENT,
        libc::EMLINK,
        libc::EPERM,
        libc::EOPNOTSUPP,
    ] {
        assert!(can_fall_back_to_copy(&std::io::Error::from_raw_os_error(
            code
        )));
    }
    assert!(can_fall_back_to_copy(&std::io::Error::from(
        std::io::ErrorKind::Unsupported
    )));
    for code in [libc::ENOSPC, libc::EACCES, libc::EMFILE, libc::EIO] {
        assert!(
            !can_fall_back_to_copy(&std::io::Error::from_raw_os_error(code)),
            "errno {code}"
        );
    }
}

/// #713 review: after a copy, a name that was taken by something else must not end as
/// "quarantined" while the checked file may stay executable under another name.
#[cfg(unix)]
#[test]
fn a_copy_is_refused_when_another_file_took_the_name() {
    use std::os::unix::fs::symlink;

    let dir = temp_dir("copy-name-taken");
    let source = dir.join("payload");
    let stored = dir.join("stored");
    std::fs::write(&source, b"the payload").unwrap();
    let opened = Source::open(&source).unwrap();
    copy_open_file_no_clobber(&opened.file, &stored, u64::MAX).unwrap();
    std::fs::rename(&source, dir.join("moved-elsewhere")).unwrap();
    symlink(dir.join("moved-elsewhere"), &source).unwrap();

    let error = opened.release_name(&source, &stored, false).unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(!stored.exists(), "the copy is not kept");
    assert!(std::fs::symlink_metadata(&source).unwrap().is_symlink());
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn a_name_that_is_gone_or_taken_after_a_link_is_not_an_error() {
    let dir = temp_dir("name-gone-or-taken");
    let source = dir.join("payload");
    let stored = dir.join("stored");
    std::fs::write(&source, b"the payload").unwrap();
    let opened = Source::open(&source).unwrap();
    std::fs::write(&stored, b"stands for the stored copy").unwrap();
    std::fs::remove_file(&source).unwrap();
    // Gone: fine after a copy as after a link.
    opened.release_name(&source, &stored, false).unwrap();
    opened.release_name(&source, &stored, true).unwrap();
    // Taken by another file after a link: the shared inode is secured by the caller.
    std::fs::write(&source, b"somebody else's").unwrap();
    opened.release_name(&source, &stored, true).unwrap();
    // Taken after a copy while the checked file has no name left (the usual swap): it
    // disappears once closed, the copy is all that remains, so this is fine too.
    opened.release_name(&source, &stored, false).unwrap();
    assert_eq!(std::fs::read(&source).unwrap(), b"somebody else's");
    assert!(stored.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// #713 review: a write between the open and the store is noticed, and the store itself
/// reports it with a marker the caller turns into a snapshot, not into a refusal.
#[cfg(unix)]
#[test]
fn a_source_written_to_after_it_was_opened_is_noticed_not_refused_by_the_hash() {
    use std::io::Write as _;

    let dir = temp_dir("written-after-open");
    let source = dir.join("payload");
    let stored = dir.join("stored");
    std::fs::write(&source, b"the payload").unwrap();
    let opened = Source::open(&source).unwrap();
    opened.sha256(&source).unwrap();
    assert!(!opened.written_since_open().unwrap());
    std::fs::OpenOptions::new()
        .append(true)
        .open(&source)
        .unwrap()
        .write_all(b" and more")
        .unwrap();

    assert!(opened.written_since_open().unwrap());
    assert!(opened.sha256(&source).is_ok(), "hashing is not refused");
    let error = opened.move_into_quarantine(&source, &stored).unwrap_err();
    assert!(is_written_after_hash(&error));
    assert!(!stored.exists());
    assert!(source.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn a_source_whose_modification_time_moved_is_noticed_even_at_the_same_size() {
    let dir = temp_dir("mtime-moved");
    let source = dir.join("payload");
    std::fs::write(&source, b"the payload").unwrap();
    let opened = Source::open(&source).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&source)
        .unwrap()
        .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(3600))
        .unwrap();

    assert!(opened.written_since_open().unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

/// #713 review: the snapshot is filed under the digest of the bytes it holds, the source
/// name is removed, nothing is left behind, and the payload can be restored. What is stored
/// is the prefix the file had when it was opened, not what was appended since.
#[cfg(unix)]
#[test]
fn a_snapshot_of_a_written_source_is_stored_under_its_own_digest_and_restores() {
    use std::io::Write as _;

    let dir = temp_dir("snapshot");
    let source = dir.join("payload");
    let qdir = dir.join("quarantine");
    std::fs::write(&source, b"first").unwrap();
    secure_quarantine_dir(&qdir).unwrap();
    let opened = Source::open(&source).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&source)
        .unwrap()
        .write_all(b" and more")
        .unwrap();

    let (stored, digest) = quarantine_snapshot(&opened, &source, &qdir).unwrap();

    assert_eq!(sha256_file(&stored).unwrap(), digest);
    assert_eq!(std::fs::read(&stored).unwrap(), b"first");
    assert!(!source.exists(), "the name is removed");
    assert!(
        std::fs::read_dir(&qdir).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".incoming")),
        "no temporary file is left"
    );
    assert_eq!(unquarantine(&qdir, &digest).unwrap(), source);
    assert_eq!(std::fs::read(&source).unwrap(), b"first");
    let _ = std::fs::remove_dir_all(&dir);
}

/// #713 review (second round): the hash and the snapshot both use the length from the
/// open, so appending after it changes neither the digest nor the stored bytes, whatever
/// the writer does in between.
#[cfg(unix)]
#[test]
fn hash_and_snapshot_both_stop_at_the_length_the_file_had_when_opened() {
    use std::io::Write as _;

    let dir = temp_dir("prefix-at-open");
    let source = dir.join("payload");
    let qdir = dir.join("quarantine");
    std::fs::write(&source, b"original bytes").unwrap();
    secure_quarantine_dir(&qdir).unwrap();
    let opened = Source::open(&source).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&source)
        .unwrap()
        .write_all(&[b'x'; 4096])
        .unwrap();

    let hashed = opened.sha256(&source).unwrap();
    let (stored, digest) = quarantine_snapshot(&opened, &source, &qdir).unwrap();

    assert_eq!(hashed, sha256_reader(&mut &b"original bytes"[..]).unwrap());
    assert_eq!(digest, hashed, "both steps saw the same prefix");
    assert_eq!(std::fs::read(&stored).unwrap(), b"original bytes");
    let _ = std::fs::remove_dir_all(&dir);
}

/// #713 review (second round): the sweep runs at every quarantine, so a leftover of a
/// killed agent does not wait for a written source to be cleaned up.
#[cfg(unix)]
#[test]
fn a_leftover_snapshot_is_swept_by_an_ordinary_quarantine() {
    let dir = temp_dir("sweep-on-quarantine");
    let source = dir.join("payload");
    let qdir = dir.join("quarantine");
    secure_quarantine_dir(&qdir).unwrap();
    let stale = qdir.join(".incoming-1-0");
    std::fs::write(&stale, b"partial").unwrap();
    backdate(&stale);
    std::fs::write(&source, b"not being written").unwrap();

    try_quarantine(&source, &qdir).unwrap();

    assert!(!stale.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// #713 review: the snapshot is bounded to the length the file had when it started, so a
/// file that grew since is stored as a consistent prefix, hashed as that prefix.
#[cfg(unix)]
#[test]
fn a_snapshot_copies_at_most_the_length_it_started_with() {
    let dir = temp_dir("bounded-snapshot");
    let source = dir.join("payload");
    std::fs::write(&source, vec![9u8; 5000]).unwrap();
    let file = std::fs::File::open(&source).unwrap();

    let (stored, digest, _lock) = copy_prefix_hashed(&file, &dir, 1000).unwrap();

    let bytes = std::fs::read(&stored).unwrap();
    assert_eq!(bytes.len(), 1000, "a growing file ends the copy");
    assert_eq!(digest, sha256_file(&stored).unwrap());
    assert_eq!(digest, sha256_reader(&mut &bytes[..]).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Makes `path` look as if it had been left an hour ago.
#[cfg(unix)]
fn backdate(path: &Path) {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600))
        .unwrap();
}

/// #713 review: a partial snapshot left by a process that was killed is swept, whatever
/// its pid (1 in every container); one that is locked (in flight, of this process or of
/// another), a fresh one and everything else are kept.
#[cfg(unix)]
#[test]
fn only_abandoned_partial_snapshots_are_swept() {
    let dir = temp_dir("sweep-snapshots");
    let stale = dir.join(".incoming-1-0");
    let stale_same_pid = dir.join(format!(".incoming-{}-0", std::process::id()));
    let in_flight = dir.join(".incoming-4242-0");
    let fresh = dir.join(".incoming-4343-0");
    let stored = dir.join("0".repeat(64));
    let odd = dir.join(".incoming-notapid-0");
    for path in [&stale, &stale_same_pid, &in_flight, &fresh, &stored, &odd] {
        std::fs::write(path, b"x").unwrap();
    }
    for path in [&stale, &stale_same_pid, &in_flight, &odd] {
        backdate(path);
    }
    let lock = std::fs::File::open(&in_flight).unwrap();
    assert_eq!(try_lock_exclusive(&lock), SnapshotLock::Acquired);

    sweep_stale_snapshots(&dir);

    assert!(!stale.exists(), "abandoned, pid of another process");
    assert!(
        !stale_same_pid.exists(),
        "abandoned, pid reused (1 in a container)"
    );
    assert!(in_flight.exists(), "locked by a snapshot in flight");
    assert!(fresh.exists(), "just created, maybe not locked yet");
    assert!(stored.exists());
    assert!(odd.exists(), "a name that is not ours is not touched");
    drop(lock);
    let _ = std::fs::remove_dir_all(&dir);
}

/// #713 follow-up: where `flock` does not work, only a long silence lets a sweep take a
/// snapshot; where it works, the lock decides.
#[cfg(unix)]
#[test]
fn the_sweep_decision_depends_on_what_the_lock_can_tell() {
    use std::time::Duration;
    let secs = Duration::from_secs;
    assert!(may_take_snapshot(secs(3600), &SnapshotLock::Acquired));
    assert!(
        !may_take_snapshot(secs(5), &SnapshotLock::Acquired),
        "too fresh"
    );
    assert!(
        !may_take_snapshot(secs(7200), &SnapshotLock::Held),
        "in flight"
    );
    assert!(!may_take_snapshot(secs(60), &SnapshotLock::Unsupported));
    assert!(may_take_snapshot(secs(3600), &SnapshotLock::Unsupported));
}

/// #713 follow-up: the sweep neither blocks on a FIFO nor follows a link under a snapshot
/// name, and leaves both alone.
#[cfg(unix)]
#[test]
fn the_sweep_ignores_a_fifo_and_a_link_under_a_snapshot_name() {
    use std::os::unix::ffi::OsStrExt as _;
    let dir = temp_dir("sweep-odd-entries");
    let fifo = dir.join(".incoming-1-1");
    let c_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: `c_path` is a valid NUL-terminated path that outlives the call.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
    let target = dir.join("target");
    std::fs::write(&target, b"x").unwrap();
    backdate(&target);
    let link = dir.join(".incoming-2-2");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let swept = dir.clone();
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        sweep_stale_snapshots(&swept);
        let _ = done.send(());
    });
    finished
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the sweep must not block on a FIFO");

    assert!(fifo.exists(), "not a regular file: left alone");
    assert!(
        link.symlink_metadata().is_ok(),
        "a link is not followed or removed"
    );
    assert!(target.exists(), "what the link points at is untouched");
    let _ = std::fs::remove_dir_all(&dir);
}

/// #713 follow-up: a write between the link (or the copy) and the check that follows is
/// noticed, the stored name is undone and the source name is untouched, so that the caller
/// goes on to the snapshot.
#[cfg(unix)]
#[test]
fn a_write_during_the_link_undoes_it_and_sends_the_caller_to_the_snapshot() {
    use std::io::Write as _;
    let dir = temp_dir("write-during-link");
    let source = dir.join("payload");
    let stored = dir.join("stored");
    std::fs::write(&source, vec![1u8; 4096]).unwrap();
    let opened = Source::open(&source).unwrap();

    let error = opened
        .move_into_quarantine_with(&source, &stored, || {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&source)
                .unwrap();
            file.write_all(b"more").unwrap();
        })
        .unwrap_err();

    assert!(is_written_after_hash(&error));
    assert!(!stored.exists(), "the link or copy is removed");
    assert!(source.exists(), "the source name is not touched");
    let _ = std::fs::remove_dir_all(&dir);
}

/// #713 review: the copy used when a file cannot be linked stops at the length given, so
/// a writer that keeps appending cannot make it run without end.
#[cfg(unix)]
#[test]
fn the_copy_fallback_stops_at_the_length_at_open() {
    let dir = temp_dir("bounded-copy");
    let source = dir.join("payload");
    let stored = dir.join("stored");
    std::fs::write(&source, vec![5u8; 5000]).unwrap();
    let opened = Source::open(&source).unwrap();

    copy_open_file_no_clobber(&opened.file, &stored, 1000).unwrap();

    assert_eq!(std::fs::read(&stored).unwrap().len(), 1000);
    let _ = std::fs::remove_dir_all(&dir);
}

/// #713 review (measured by the reviewer): a writer that keeps appending must not make the
/// quarantine fail, and what is stored must match the digest it is filed under.
#[cfg(unix)]
#[test]
fn a_file_that_keeps_being_written_is_still_quarantined() {
    use std::{
        io::Write as _,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };

    let dir = temp_dir("busy-writer");
    let source = dir.join("payload");
    std::fs::write(&source, vec![7u8; 4 * 1024 * 1024]).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let (source, stop) = (source.clone(), Arc::clone(&stop));
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match std::fs::OpenOptions::new().append(true).open(&source) {
                    Ok(mut file) => {
                        let _ = file.write_all(b"x");
                    }
                    Err(_) => break,
                }
                std::thread::sleep(std::time::Duration::from_micros(200));
            }
        })
    };

    let outcome = quarantine_file(
        &source,
        &dir.join("quarantine"),
        &ResponsePolicy {
            kill_enabled: false,
            quarantine_enabled: true,
            isolate_enabled: false,
        },
    );
    stop.store(true, Ordering::Relaxed);
    writer.join().unwrap();

    let QuarantineOutcome::Quarantined {
        quarantined_at,
        sha256_hex,
        ..
    } = outcome
    else {
        panic!("a busy writer must not defeat the quarantine: {outcome:?}");
    };
    assert_eq!(sha256_file(&quarantined_at).unwrap(), sha256_hex);
    assert!(!source.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A FIFO under the file's name must be refused, not waited on.
#[cfg(unix)]
#[test]
fn a_fifo_source_is_refused_without_blocking() {
    use std::{ffi::CString, os::unix::ffi::OsStrExt as _};

    let dir = temp_dir("fifo-source");
    let fifo = dir.join("pipe");
    let name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: `name` is a valid NUL-terminated path that outlives the call.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);

    let outcome = quarantine_file(
        &fifo,
        &dir.join("quarantine"),
        &ResponsePolicy {
            kill_enabled: false,
            quarantine_enabled: true,
            isolate_enabled: false,
        },
    );

    assert!(
        matches!(outcome, QuarantineOutcome::Failed { .. }),
        "{outcome:?}"
    );
    assert!(!dir.join("quarantine").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// #689 (review note): a tampered slot returned early, so the intact copies of the same
/// digest after it could never be restored.
#[test]
fn a_tampered_slot_does_not_hide_an_intact_one_of_the_same_digest() {
    let dir = temp_dir("tampered-then-intact");
    let first = dir.join("first");
    let second = dir.join("second");
    std::fs::write(&first, b"same bytes").unwrap();
    std::fs::write(&second, b"same bytes").unwrap();
    let qdir = dir.join("quarantine");
    let policy = ResponsePolicy {
        kill_enabled: false,
        quarantine_enabled: true,
        isolate_enabled: false,
    };
    let QuarantineOutcome::Quarantined {
        sha256_hex: digest,
        quarantined_at: first_stored,
        ..
    } = quarantine_file(&first, &qdir, &policy)
    else {
        panic!("first payload must be quarantined");
    };
    assert!(matches!(
        quarantine_file(&second, &qdir, &policy),
        QuarantineOutcome::Quarantined { .. }
    ));
    let mut perms = std::fs::metadata(&first_stored).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    std::fs::set_permissions(&first_stored, perms).unwrap();
    std::fs::write(&first_stored, b"swapped by someone").unwrap();

    let restored = unquarantine(&qdir, &digest).unwrap();

    assert_eq!(restored, second);
    assert_eq!(std::fs::read(&second).unwrap(), b"same bytes");
    assert!(!first.exists(), "the tampered copy is not put back");
    // What is left is the tampered slot, still refused.
    let err = unquarantine(&qdir, &digest).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    let _ = std::fs::remove_dir_all(&dir);
}

/// #689 (review note): asking to restore from a quarantine that was never created must
/// not create it.
#[test]
fn restoring_from_a_quarantine_that_does_not_exist_creates_nothing() {
    let dir = temp_dir("restore-nothing");
    let qdir = dir.join("never-created");

    let err = unquarantine(&qdir, &"0".repeat(64)).unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    assert!(!qdir.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn a_directory_of_another_user_is_left_alone_only_when_it_is_already_private() {
    // Ours: always set to 0700, whatever it was.
    assert!(quarantine_dir_needs_chmod(true, 0o040_755).unwrap());
    assert!(quarantine_dir_needs_chmod(true, 0o040_700).unwrap());
    // Someone else's and already 0700 (root running `list`): no chmod, no refusal.
    assert!(!quarantine_dir_needs_chmod(false, 0o040_700).unwrap());
    // Someone else's and it would have to change: refused.
    for mode in [0o040_755, 0o040_750, 0o040_777, 0o040_500] {
        let err = quarantine_dir_needs_chmod(false, mode).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{mode:o}");
    }
}

/// #689 (review note): an existing directory that belongs to someone else is refused, not
/// `chmod`ed. `/usr` is root's; as root it would be this process's own, so the test only
/// runs unprivileged (it must never reach the `chmod`).
#[cfg(unix)]
#[test]
fn a_quarantine_directory_owned_by_another_user_is_refused() {
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let err = secure_quarantine_dir(Path::new("/usr")).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

fn quarantine_one(dir: &Path, name: &str, body: &[u8]) -> (PathBuf, PathBuf, String) {
    let payload = dir.join(name);
    std::fs::write(&payload, body).unwrap();
    let quarantine_dir = dir.join("quarantine");
    let policy = ResponsePolicy {
        kill_enabled: false,
        quarantine_enabled: true,
        isolate_enabled: false,
    };
    match quarantine_file(&payload, &quarantine_dir, &policy) {
        QuarantineOutcome::Quarantined { sha256_hex, .. } => (payload, quarantine_dir, sha256_hex),
        other => panic!("expected Quarantined, got {other:?}"),
    }
}

#[test]
fn listing_a_directory_that_does_not_exist_yet_is_empty() {
    let dir = temp_dir("list-missing");
    assert_eq!(
        list_quarantined(&dir.join("quarantine")).unwrap(),
        Vec::new()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_listing_names_each_payload_and_where_it_came_from_sorted_by_digest() {
    let dir = temp_dir("list");
    let (p1, qdir, d1) = quarantine_one(&dir, "one.bin", b"first payload");
    let (p2, _, d2) = quarantine_one(&dir, "two.bin", b"second payload");
    // Something that is not ours must be ignored, not treated as a payload.
    std::fs::write(qdir.join("stray.origin"), "/etc/passwd").unwrap();

    let listed = list_quarantined(&qdir).unwrap();

    let mut expected = vec![
        QuarantinedFile {
            sha256_hex: d1,
            original: p1,
        },
        QuarantinedFile {
            sha256_hex: d2,
            original: p2,
        },
    ];
    expected.sort_by(|a, b| a.sha256_hex.cmp(&b.sha256_hex));
    assert_eq!(listed, expected);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn listing_skips_one_invalid_companion_and_keeps_valid_entries() {
    let dir = temp_dir("list-invalid-sidecar");
    let (_payload, quarantine_dir, digest) =
        quarantine_one(&dir, "valid.bin", b"valid listed payload");
    std::fs::write(
        quarantine_dir.join(format!("{digest}.1")),
        b"another payload",
    )
    .unwrap();
    std::fs::write(
        quarantine_dir.join(format!("{digest}.1.origin")),
        b"\0synthaea-origin-v1\0\x01",
    )
    .unwrap();

    let listed = list_quarantined(&quarantine_dir).unwrap();

    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].sha256_hex, digest);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn restoring_never_overwrites_a_file_that_took_the_originals_place() {
    let dir = temp_dir("no-clobber");
    let (payload, qdir, digest) = quarantine_one(&dir, "payload.bin", b"malware");
    std::fs::write(&payload, b"a different, legitimate file").unwrap();

    let err = unquarantine(&qdir, &digest).unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(
        std::fs::read(&payload).unwrap(),
        b"a different, legitimate file"
    );
    assert!(
        qdir.join(&digest).exists(),
        "the quarantined copy must stay"
    );
    assert!(
        qdir.join(format!("{digest}.origin")).exists(),
        "and its sidecar"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_quarantined_file_altered_in_place_is_not_restored() {
    let dir = temp_dir("tampered");
    let (payload, qdir, digest) = quarantine_one(&dir, "payload.bin", b"malware");
    let stored = qdir.join(&digest);
    let mut perms = std::fs::metadata(&stored).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    std::fs::set_permissions(&stored, perms).unwrap();
    std::fs::write(&stored, b"swapped by someone").unwrap();

    let err = unquarantine(&qdir, &digest).unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(!payload.exists(), "nothing may be put back");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_digest_that_could_name_a_path_outside_the_directory_is_refused() {
    let dir = temp_dir("traversal");
    for bad in [
        "../../etc/passwd",
        "",
        "abc",
        &"A".repeat(64),
        &"g".repeat(64),
    ] {
        let err = unquarantine(&dir.join("quarantine"), bad).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{bad:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_copy_that_fails_midway_leaves_nothing_at_the_destination() {
    let dir = temp_dir("copy-fails");
    let from = dir.join("from.bin");
    let to = dir.join("to.bin");
    std::fs::write(&from, b"the quarantined payload").unwrap();

    let err = copy_no_clobber_with(&from, &to, |_, dst| {
        use std::io::Write as _;
        dst.write_all(b"half of it")?; // the disk fills up here
        Err(std::io::Error::other("no space left on device"))
    })
    .unwrap_err();

    assert_eq!(err.to_string(), "no space left on device");
    assert!(!to.exists(), "our own half-written file must be removed");
    assert_eq!(std::fs::read(&from).unwrap(), b"the quarantined payload");
    // And a retry is not jammed behind that debris.
    copy_no_clobber(&from, &to).unwrap();
    assert_eq!(std::fs::read(&to).unwrap(), b"the quarantined payload");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_copy_never_removes_a_file_it_did_not_create() {
    let dir = temp_dir("copy-not-ours");
    let from = dir.join("from.bin");
    let to = dir.join("to.bin");
    std::fs::write(&from, b"payload").unwrap();
    std::fs::write(&to, b"somebody else's file").unwrap();

    let err = copy_no_clobber_with(&from, &to, |_, _| {
        panic!("nothing may be written when the destination exists")
    })
    .unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&to).unwrap(), b"somebody else's file");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_completed_copy_carries_the_read_only_bit() {
    let dir = temp_dir("copy-readonly");
    let from = dir.join("from.bin");
    let to = dir.join("to.bin");
    std::fs::write(&from, b"payload").unwrap();
    let mut perms = std::fs::metadata(&from).unwrap().permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&from, perms).unwrap();

    copy_no_clobber(&from, &to).unwrap();

    assert!(std::fs::metadata(&to).unwrap().permissions().readonly());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn nothing_is_left_after_a_normal_restore() {
    let dir = temp_dir("leftover-none");
    let (_, qdir, digest) = quarantine_one(&dir, "payload.bin", b"malware");
    assert!(
        is_still_quarantined(&qdir, &digest),
        "it is quarantined before the restore"
    );
    unquarantine(&qdir, &digest).unwrap();
    assert!(!is_still_quarantined(&qdir, &digest));
    assert!(
        !is_still_quarantined(&qdir, "../../etc/passwd"),
        "a bad digest is never 'quarantined'"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A quarantine directory with legacy read-only permissions. `None` when this
/// process ignores permissions (root), where the scenario cannot be built.
#[cfg(unix)]
fn legacy_read_only_quarantine(name: &str) -> Option<(PathBuf, PathBuf, PathBuf, String)> {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = temp_dir(name);
    let (payload, qdir, digest) = quarantine_one(&dir, "payload.bin", b"malware");
    std::fs::set_permissions(&qdir, std::fs::Permissions::from_mode(0o555)).unwrap();
    if std::fs::write(qdir.join("probe"), b"x").is_ok() {
        let _ = std::fs::remove_file(qdir.join("probe"));
        return None;
    }
    Some((dir, payload, qdir, digest))
}

#[cfg(unix)]
#[test]
fn restore_tightens_legacy_read_only_directory_before_cleanup() {
    let Some((dir, payload, qdir, digest)) = legacy_read_only_quarantine("leftover") else {
        return; // root ignores directory permissions
    };

    let restored = unquarantine(&qdir, &digest);

    assert_eq!(
        restored.unwrap(),
        payload,
        "the file is back, so the restore worked"
    );
    assert_eq!(std::fs::read(&payload).unwrap(), b"malware");
    use std::os::unix::fs::PermissionsExt as _;
    assert_eq!(
        std::fs::metadata(&qdir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(
        !is_still_quarantined(&qdir, &digest),
        "successful restore must remove the payload and sidecar"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
