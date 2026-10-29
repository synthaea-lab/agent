//! SETUID-ROOT-REQUEST (T1548.001, #1041). The events carry the values the sensor reported in the
//! lab run of 2026-10-29 (`lab/captures/test-1041-20261029/`): `meta.user` is the caller's real
//! uid, `4294967295` is `setresuid`'s "unchanged".

use schema::{EventMeta, ExecEvent, IdentityChangeEvent, IdentityChangeKind, User};

use super::meta;
use schema::detection::Severity;

use crate::RuleState;

const NONE: u32 = u32::MAX;

fn exec(state: &mut RuleState, pid: u32, generation: Option<u64>, image: &str, comm: &str) {
    let event = ExecEvent {
        meta: EventMeta {
            pid,
            comm: comm.into(),
            process_generation: generation,
            ..meta()
        },
        image_path: image.into(),
        ..schema::fixtures::exec()
    };
    state.on_exec(&event);
}

fn identity(
    pid: u32,
    generation: Option<u64>,
    uid: u32,
    comm: &str,
    kind: IdentityChangeKind,
    ids: (u32, Option<u32>, Option<u32>),
) -> IdentityChangeEvent {
    IdentityChangeEvent {
        meta: EventMeta {
            pid,
            comm: comm.into(),
            process_generation: generation,
            user: User::Unix { uid, gid: uid },
            ..meta()
        },
        kind,
        real: ids.0,
        effective: ids.1,
        saved: ids.2,
    }
}

fn set_uid(pid: u32, uid: u32, comm: &str, to: u32) -> IdentityChangeEvent {
    identity(
        pid,
        Some(7),
        uid,
        comm,
        IdentityChangeKind::SetUid,
        (to, None, None),
    )
}

fn set_res_uid(pid: u32, uid: u32, comm: &str, ids: (u32, u32, u32)) -> IdentityChangeEvent {
    identity(
        pid,
        Some(7),
        uid,
        comm,
        IdentityChangeKind::SetResUid,
        (ids.0, Some(ids.1), Some(ids.2)),
    )
}

#[test]
fn an_interpreter_asking_for_uid_zero_as_a_user_alerts_once() {
    let mut state = RuleState::new();
    exec(&mut state, 4596, Some(7), "/usr/bin/python3", "python3");
    let first = state.on_identity_change(&set_uid(4596, 1001, "python3", 0));
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].technique, "T1548.001");
    assert_eq!(first[0].severity, Severity::Low);
    assert!(first[0].message.contains("/usr/bin/python3"));
    // The same process then calls setresuid(0, 0, 0): one finding for the process.
    assert!(
        state
            .on_identity_change(&set_res_uid(4596, 1001, "python3", (0, 0, 0)))
            .is_empty()
    );
}

#[test]
fn a_copy_named_sudo_outside_a_system_path_is_not_sudo() {
    // Measured: the copy of python3 placed at /tmp/sudo reports comm = sudo.
    let mut state = RuleState::new();
    exec(&mut state, 4599, Some(7), "/tmp/sudo", "sudo");
    let alerts = state.on_identity_change(&set_uid(4599, 1001, "sudo", 0));
    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].message.contains("/tmp/sudo"));
}

#[test]
fn the_measured_setuid_root_programs_stay_silent() {
    for (image, comm, call) in [
        ("/usr/bin/sudo", "sudo", set_uid(10, 1001, "sudo", 0)),
        ("/usr/bin/su", "su", set_uid(11, 1001, "su", 0)),
        (
            "/usr/bin/crontab",
            "crontab",
            set_uid(12, 1001, "crontab", 0),
        ),
        (
            "/usr/libexec/openssh/sshd-session",
            "sshd-session",
            set_res_uid(13, 1000, "sshd-session", (NONE, 0, NONE)),
        ),
        (
            "/usr/libexec/openssh/sshd-auth",
            "sshd-auth",
            set_uid(14, 74, "sshd-auth", 0),
        ),
        // sudo's own call, as recorded: setresuid(-1, 0, -1)... and setresuid(0, 0, 0)
        (
            "/usr/bin/sudo",
            "sudo",
            set_res_uid(10, 1001, "sudo", (0, 0, 0)),
        ),
    ] {
        let mut state = RuleState::new();
        exec(&mut state, call.meta.pid, Some(7), image, comm);
        assert!(state.on_identity_change(&call).is_empty(), "{image}");
    }
}

#[test]
fn root_and_privilege_drops_stay_silent() {
    let mut state = RuleState::new();
    exec(&mut state, 20, Some(7), "/usr/bin/python3", "python3");
    // Root calling setuid(0) is not a request; root dropping to 1001 asks for no uid 0.
    assert!(
        state
            .on_identity_change(&set_uid(20, 0, "python3", 0))
            .is_empty()
    );
    assert!(
        state
            .on_identity_change(&set_uid(20, 0, "python3", 1001))
            .is_empty()
    );
    // A user asking for its own id, or leaving every slot unchanged, is not a request for root.
    assert!(
        state
            .on_identity_change(&set_uid(20, 1001, "python3", 1001))
            .is_empty()
    );
    assert!(
        state
            .on_identity_change(&set_res_uid(20, 1001, "python3", (NONE, NONE, NONE)))
            .is_empty()
    );
}

#[test]
fn a_zero_in_any_setresuid_slot_is_a_request() {
    for ids in [(0, NONE, NONE), (NONE, 0, NONE), (NONE, NONE, 0)] {
        let mut state = RuleState::new();
        exec(&mut state, 21, Some(7), "/home/u/exploit", "exploit");
        let alerts = state.on_identity_change(&set_res_uid(21, 1001, "exploit", ids));
        assert_eq!(alerts.len(), 1, "{ids:?}");
    }
}

#[test]
fn a_group_or_filesystem_id_change_is_not_read() {
    let mut state = RuleState::new();
    exec(&mut state, 22, Some(7), "/home/u/exploit", "exploit");
    for kind in [
        IdentityChangeKind::SetGid,
        IdentityChangeKind::SetResGid,
        IdentityChangeKind::SetFsUid,
        IdentityChangeKind::SetFsGid,
    ] {
        let event = identity(22, Some(7), 1001, "exploit", kind, (0, Some(0), Some(0)));
        assert!(state.on_identity_change(&event).is_empty(), "{kind:?}");
    }
}

#[test]
fn an_unknown_image_is_silent() {
    // Started before the agent: no exec seen, so nothing says it is not sudo.
    let mut state = RuleState::new();
    assert!(
        state
            .on_identity_change(&set_uid(30, 1001, "exploit", 0))
            .is_empty()
    );
}

#[test]
fn a_reused_pid_is_a_new_process() {
    let mut state = RuleState::new();
    exec(&mut state, 40, Some(7), "/home/u/exploit", "exploit");
    assert_eq!(
        state
            .on_identity_change(&set_uid(40, 1001, "exploit", 0))
            .len(),
        1
    );
    // Same pid, new incarnation: a fresh exec, and a fresh alert.
    exec(&mut state, 40, Some(8), "/home/u/exploit", "exploit");
    let again = identity(
        40,
        Some(8),
        1001,
        "exploit",
        IdentityChangeKind::SetUid,
        (0, None, None),
    );
    assert_eq!(state.on_identity_change(&again).len(), 1);
    // The old incarnation's exec says nothing about a newer one whose exec was never seen:
    // a stale generation is an unknown image, so silent, not the old image's verdict.
    exec(&mut state, 41, Some(7), "/home/u/exploit", "exploit");
    let other_gen = identity(
        41,
        Some(9),
        1001,
        "exploit",
        IdentityChangeKind::SetUid,
        (0, None, None),
    );
    assert!(state.on_identity_change(&other_gen).is_empty());
}

#[test]
fn a_system_path_alone_does_not_vouch_for_a_non_setuid_name() {
    // python3 lives under /usr/bin and still alerts: the name must be a measured program too.
    let mut state = RuleState::new();
    exec(&mut state, 50, Some(7), "/usr/bin/bash", "bash");
    assert_eq!(
        state
            .on_identity_change(&set_uid(50, 1001, "bash", 0))
            .len(),
        1
    );
}
