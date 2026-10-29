//! SETUID-ROOT-REQUEST (T1548.001, #1041). The events carry the values the sensor reported in the
//! lab run of 2026-10-29 (`lab/captures/test-1041-20261029/`): `meta.user` is the caller's real
//! uid, `4294967295` is `setresuid`'s "unchanged". A request is judged once the stream clock is
//! `IDENTITY_DEFER_NS` past it, against the image the pid had at its time, so these tests build
//! the order the sensor really delivers (the identity events before the exec that explains them).

use schema::{
    EventMeta, ExecEvent, IdentityChangeEvent, IdentityChangeKind, User, detection::Severity,
};

use super::meta;
use crate::{
    Alert, RuleState,
    privesc::{IDENTITY_DEFER_NS, IDENTITY_PENDING_CAP},
};

const NONE: u32 = u32::MAX;
const SEC: u64 = 1_000_000_000;

fn exec(state: &mut RuleState, pid: u32, generation: Option<u64>, image: &str, at_s: u64) {
    let event = ExecEvent {
        meta: EventMeta {
            pid,
            comm: image.rsplit('/').next().unwrap_or("").into(),
            process_generation: generation,
            timestamp_ns: at_s * SEC,
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
    at_s: u64,
) -> IdentityChangeEvent {
    IdentityChangeEvent {
        meta: EventMeta {
            pid,
            comm: comm.into(),
            process_generation: generation,
            user: User::Unix { uid, gid: uid },
            timestamp_ns: at_s * SEC,
            ..meta()
        },
        kind,
        real: ids.0,
        effective: ids.1,
        saved: ids.2,
    }
}

fn set_uid(pid: u32, uid: u32, comm: &str, to: u32, at_s: u64) -> IdentityChangeEvent {
    identity(
        pid,
        Some(7),
        uid,
        comm,
        IdentityChangeKind::SetUid,
        (to, None, None),
        at_s,
    )
}

fn set_res_uid(
    pid: u32,
    uid: u32,
    comm: &str,
    ids: (u32, u32, u32),
    at_s: u64,
) -> IdentityChangeEvent {
    identity(
        pid,
        Some(7),
        uid,
        comm,
        IdentityChangeKind::SetResUid,
        (ids.0, Some(ids.1), Some(ids.2)),
        at_s,
    )
}

fn alerts_of(due: Vec<(IdentityChangeEvent, Alert)>) -> Vec<Alert> {
    due.into_iter().map(|(_, alert)| alert).collect()
}

/// A root identity event at `at_s`: moves the stream clock, queues nothing.
fn tick(state: &mut RuleState, at_s: u64) -> Vec<Alert> {
    let root = set_uid(1, 0, "init", 0, at_s);
    alerts_of(state.on_identity_change(&root))
}

/// What the rule says about `event` once the deferral is over.
fn call(state: &mut RuleState, event: &IdentityChangeEvent) -> Vec<Alert> {
    let at_s = event.meta.timestamp_ns / SEC;
    let mut alerts = alerts_of(state.on_identity_change(event));
    alerts.extend(tick(state, at_s + IDENTITY_DEFER_NS / SEC));
    alerts
}

#[test]
fn an_interpreter_asking_for_uid_zero_as_a_user_alerts_once() {
    let mut state = RuleState::new();
    exec(&mut state, 4596, Some(7), "/usr/bin/python3", 10);
    let first = call(&mut state, &set_uid(4596, 1001, "python3", 0, 11));
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].technique, "T1548.001");
    assert_eq!(first[0].severity, Severity::Low);
    assert!(first[0].message.contains("/usr/bin/python3"));
    // The same process then calls setresuid(0, 0, 0): one finding for the process.
    assert!(
        call(
            &mut state,
            &set_res_uid(4596, 1001, "python3", (0, 0, 0), 11)
        )
        .is_empty()
    );
}

#[test]
fn a_copy_named_sudo_outside_a_system_path_is_not_sudo() {
    // Measured: the copy of python3 placed at /tmp/sudo reports comm = sudo.
    let mut state = RuleState::new();
    exec(&mut state, 4599, Some(7), "/tmp/sudo", 10);
    let alerts = call(&mut state, &set_uid(4599, 1001, "sudo", 0, 11));
    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].message.contains("/tmp/sudo"));
}

#[test]
fn the_measured_setuid_root_programs_stay_silent() {
    for (image, comm, call_) in [
        ("/usr/bin/sudo", "sudo", set_uid(10, 1001, "sudo", 0, 11)),
        ("/usr/bin/su", "su", set_uid(11, 1001, "su", 0, 11)),
        (
            "/usr/bin/crontab",
            "crontab",
            set_uid(12, 1001, "crontab", 0, 11),
        ),
        (
            "/usr/libexec/openssh/sshd-session",
            "sshd-session",
            set_res_uid(13, 1000, "sshd-session", (NONE, 0, NONE), 11),
        ),
        (
            "/usr/libexec/openssh/sshd-auth",
            "sshd-auth",
            set_uid(14, 74, "sshd-auth", 0, 11),
        ),
        (
            "/usr/bin/sudo",
            "sudo",
            set_res_uid(10, 1001, "sudo", (0, 0, 0), 11),
        ),
    ] {
        let mut state = RuleState::new();
        exec(&mut state, call_.meta.pid, Some(7), image, 10);
        assert!(call(&mut state, &call_).is_empty(), "{image} ({comm})");
    }
}

#[test]
fn root_and_privilege_drops_stay_silent() {
    let mut state = RuleState::new();
    exec(&mut state, 20, Some(7), "/usr/bin/python3", 10);
    // Root calling setuid(0) is not a request; root dropping to 1001 asks for no uid 0.
    assert!(call(&mut state, &set_uid(20, 0, "python3", 0, 11)).is_empty());
    assert!(call(&mut state, &set_uid(20, 0, "python3", 1001, 11)).is_empty());
    // A user asking for its own id, or leaving every slot unchanged, is not a request for root.
    assert!(call(&mut state, &set_uid(20, 1001, "python3", 1001, 11)).is_empty());
    assert!(
        call(
            &mut state,
            &set_res_uid(20, 1001, "python3", (NONE, NONE, NONE), 11)
        )
        .is_empty()
    );
}

#[test]
fn a_zero_in_any_setresuid_slot_is_a_request() {
    for ids in [(0, NONE, NONE), (NONE, 0, NONE), (NONE, NONE, 0)] {
        let mut state = RuleState::new();
        exec(&mut state, 21, Some(7), "/home/u/exploit", 10);
        let alerts = call(&mut state, &set_res_uid(21, 1001, "exploit", ids, 11));
        assert_eq!(alerts.len(), 1, "{ids:?}");
    }
}

#[test]
fn a_group_or_filesystem_id_change_is_not_read() {
    let mut state = RuleState::new();
    exec(&mut state, 22, Some(7), "/home/u/exploit", 10);
    for kind in [
        IdentityChangeKind::SetGid,
        IdentityChangeKind::SetResGid,
        IdentityChangeKind::SetFsUid,
        IdentityChangeKind::SetFsGid,
    ] {
        let event = identity(
            22,
            Some(7),
            1001,
            "exploit",
            kind,
            (0, Some(0), Some(0)),
            11,
        );
        assert!(call(&mut state, &event).is_empty(), "{kind:?}");
    }
}

#[test]
fn an_unknown_image_is_silent() {
    // Started before the agent: no exec seen, so nothing says it is not sudo.
    let mut state = RuleState::new();
    assert!(call(&mut state, &set_uid(30, 1001, "exploit", 0, 11)).is_empty());
}

#[test]
fn a_reused_pid_is_a_new_process() {
    let mut state = RuleState::new();
    exec(&mut state, 40, Some(7), "/home/u/exploit", 10);
    assert_eq!(
        call(&mut state, &set_uid(40, 1001, "exploit", 0, 11)).len(),
        1
    );
    // Same pid, new incarnation: a fresh exec, and a fresh alert.
    exec(&mut state, 40, Some(8), "/home/u/exploit", 30);
    let again = identity(
        40,
        Some(8),
        1001,
        "exploit",
        IdentityChangeKind::SetUid,
        (0, None, None),
        31,
    );
    assert_eq!(call(&mut state, &again).len(), 1);
    // The old incarnation's exec says nothing about a newer one whose exec was never seen:
    // another generation is an unknown image, so silent, not the old image's verdict.
    exec(&mut state, 41, Some(7), "/home/u/exploit", 10);
    let other_gen = identity(
        41,
        Some(9),
        1001,
        "exploit",
        IdentityChangeKind::SetUid,
        (0, None, None),
        51,
    );
    assert!(call(&mut state, &other_gen).is_empty());
}

#[test]
fn a_system_path_alone_does_not_vouch_for_a_non_setuid_name() {
    // bash lives under /usr/bin and still alerts: the name must be a measured program too.
    let mut state = RuleState::new();
    exec(&mut state, 50, Some(7), "/usr/bin/bash", 10);
    assert_eq!(call(&mut state, &set_uid(50, 1001, "bash", 0, 11)).len(), 1);
}

/// A call made by `pid`, a child (`ppid`, whose incarnation is `parent_generation`) that forked
/// and never exec'd.
fn forked_child_call(
    pid: u32,
    ppid: u32,
    parent_generation: Option<u64>,
    comm: &str,
    at_s: u64,
) -> IdentityChangeEvent {
    let mut event = set_uid(pid, 1001, comm, 0, at_s);
    event.meta.ppid = ppid;
    event.meta.parent_process_generation = parent_generation;
    event
}

#[test]
fn a_forked_child_of_an_unknown_image_still_alerts() {
    // The final `setuid(0); exec /bin/sh` of a race-window exploit often runs in a forked child:
    // a new pid with no exec of its own, so it takes its parent's image.
    let mut state = RuleState::new();
    exec(&mut state, 100, Some(7), "/tmp/exploit", 10);
    let alerts = call(
        &mut state,
        &forked_child_call(101, 100, Some(7), "exploit", 11),
    );
    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].message.contains("/tmp/exploit"));
}

#[test]
fn a_forked_child_of_a_setuid_root_program_stays_silent() {
    // sshd's privilege-separated children and sudo's own forks resolve to the listed program.
    for (image, comm) in [
        ("/usr/libexec/openssh/sshd-session", "sshd-session"),
        ("/usr/bin/sudo", "sudo"),
    ] {
        let mut state = RuleState::new();
        exec(&mut state, 110, Some(7), image, 10);
        let event = forked_child_call(111, 110, Some(7), comm, 11);
        assert!(call(&mut state, &event).is_empty(), "{image}");
    }
}

#[test]
fn a_child_whose_parent_is_another_incarnation_is_unknown() {
    // The parent pid now belongs to a different process: its image says nothing about the child.
    let mut state = RuleState::new();
    exec(&mut state, 120, Some(7), "/tmp/exploit", 10);
    let event = forked_child_call(121, 120, Some(9), "exploit", 11);
    assert!(call(&mut state, &event).is_empty());
}

#[test]
fn only_one_level_of_fork_is_followed() {
    // Pins the documented limit: a grandchild forked twice without an exec has no image.
    let mut state = RuleState::new();
    exec(&mut state, 130, Some(7), "/tmp/exploit", 10);
    let grandchild = forked_child_call(132, 131, Some(8), "exploit", 11);
    assert!(call(&mut state, &grandchild).is_empty());
}

// ---- the order the sensor delivers: the identity events come before the exec that explains them

#[test]
fn a_request_judged_before_its_exec_arrives_still_gets_that_exec() {
    // Under load the exec of pid 200 reaches the rules after its own setuid(0): judged on
    // arrival it had no image and was silent. The exec has a timestamp before the request.
    let mut state = RuleState::new();
    assert!(alerts_of(state.on_identity_change(&set_uid(200, 1001, "exploit", 0, 100))).is_empty());
    exec(&mut state, 200, Some(7), "/tmp/exploit", 99);
    let alerts = tick(&mut state, 100 + IDENTITY_DEFER_NS / SEC);
    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].message.contains("/tmp/exploit"));
}

#[test]
fn a_sudo_run_from_a_shell_is_not_the_shell_when_its_exec_is_late() {
    // The shell (pid 300) forks pid 301, which execs sudo at 50 s. 301's setuid(0) reaches the
    // rules first; on arrival the pid has no image and the parent fallback said `/usr/bin/bash`.
    let mut state = RuleState::new();
    exec(&mut state, 300, Some(7), "/usr/bin/bash", 10);
    let early = forked_child_call(301, 300, Some(7), "sudo", 51);
    assert!(alerts_of(state.on_identity_change(&early)).is_empty());
    exec(&mut state, 301, Some(7), "/usr/bin/sudo", 50);
    assert!(tick(&mut state, 51 + IDENTITY_DEFER_NS / SEC).is_empty());
}

#[test]
fn a_childs_later_exec_does_not_rename_its_earlier_request() {
    // sudo (pid 400) forks pid 401, which calls setuid(0) at 2 s and execs `unix_chkpwd` at
    // 2.5 s. Judged after both, the image is the one at 2 s: its parent's `sudo`.
    let mut state = RuleState::new();
    exec(&mut state, 400, Some(7), "/usr/bin/sudo", 1);
    let request = forked_child_call(401, 400, Some(7), "sudo", 2);
    assert!(alerts_of(state.on_identity_change(&request)).is_empty());
    state.on_exec(&ExecEvent {
        meta: EventMeta {
            pid: 401,
            process_generation: Some(7),
            timestamp_ns: 2 * SEC + SEC / 2,
            ..meta()
        },
        image_path: "/usr/bin/unix_chkpwd".into(),
        ..schema::fixtures::exec()
    });
    assert!(tick(&mut state, 2 + IDENTITY_DEFER_NS / SEC).is_empty());
}

#[test]
fn a_pids_earlier_image_does_not_speak_for_a_later_request() {
    // `bash -c '... sudo ...'` keeps its pid: bash at 1 s, sudo at 3 s. A request at 3.5 s is
    // sudo's; one at 2 s is still bash's.
    let mut state = RuleState::new();
    exec(&mut state, 500, Some(7), "/usr/bin/bash", 1);
    exec(&mut state, 500, Some(7), "/usr/bin/sudo", 3);
    let late = identity(
        500,
        Some(7),
        1001,
        "sudo",
        IdentityChangeKind::SetUid,
        (0, None, None),
        4,
    );
    assert!(call(&mut state, &late).is_empty());
    let mut other = RuleState::new();
    exec(&mut other, 500, Some(7), "/usr/bin/bash", 1);
    exec(&mut other, 500, Some(7), "/usr/bin/sudo", 3);
    let early = identity(
        500,
        Some(7),
        1001,
        "bash",
        IdentityChangeKind::SetUid,
        (0, None, None),
        2,
    );
    let alerts = call(&mut other, &early);
    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].message.contains("/usr/bin/bash"));
}

#[test]
fn a_request_waits_for_the_stream_clock_and_an_exec_after_the_wait_is_not_seen() {
    let mut state = RuleState::new();
    assert!(alerts_of(state.on_identity_change(&set_uid(600, 1001, "exploit", 0, 100))).is_empty());
    // Just short of the deferral, nothing is judged, and an exec that arrives now still counts.
    assert!(tick(&mut state, 100 + IDENTITY_DEFER_NS / SEC - 1).is_empty());
    exec(&mut state, 600, Some(7), "/tmp/exploit", 99);
    assert_eq!(tick(&mut state, 100 + IDENTITY_DEFER_NS / SEC).len(), 1);

    // An exec later than the deferral is not seen: the request was judged without it.
    let mut late = RuleState::new();
    assert!(alerts_of(late.on_identity_change(&set_uid(601, 1001, "exploit", 0, 100))).is_empty());
    assert!(tick(&mut late, 100 + IDENTITY_DEFER_NS / SEC).is_empty());
    exec(&mut late, 601, Some(7), "/tmp/exploit", 99);
    assert!(tick(&mut late, 200).is_empty());
}

#[test]
fn an_exec_moves_the_clock_too() {
    // The sink drains after every exec: an exec event alone can make a request due.
    let mut state = RuleState::new();
    exec(&mut state, 700, Some(7), "/tmp/exploit", 99);
    assert!(alerts_of(state.on_identity_change(&set_uid(700, 1001, "exploit", 0, 100))).is_empty());
    exec(
        &mut state,
        701,
        Some(7),
        "/usr/bin/true",
        100 + IDENTITY_DEFER_NS / SEC,
    );
    let due = alerts_of(state.take_due_identity_alerts());
    assert_eq!(due.len(), 1);
}

#[test]
fn the_queue_is_bounded_and_drops_the_oldest() {
    let mut state = RuleState::new();
    for i in 0..=IDENTITY_PENDING_CAP as u32 {
        let pid = 10_000 + i;
        exec(&mut state, pid, Some(7), "/tmp/exploit", 99);
        state.on_identity_change(&set_uid(pid, 1001, "exploit", 0, 100));
    }
    let alerts = tick(&mut state, 100 + IDENTITY_DEFER_NS / SEC);
    assert_eq!(alerts.len(), IDENTITY_PENDING_CAP);
}

#[test]
fn each_due_alert_comes_with_its_own_event() {
    // The sink attributes an alert to the event it returns with, not to the event that moved
    // the clock.
    let mut state = RuleState::new();
    exec(&mut state, 800, Some(7), "/tmp/exploit", 99);
    state.on_identity_change(&set_uid(800, 1001, "exploit", 0, 100));
    let root = set_uid(1, 0, "init", 0, 100 + IDENTITY_DEFER_NS / SEC);
    let due = state.on_identity_change(&root);
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].0.meta.pid, 800);
}
