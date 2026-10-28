//! Host isolation (ADR-0037): block every connection in and out of the host except
//! loopback, DHCP and the agent's own path to its control plane.
//!
//! Platform-neutral, the same split as [`crate::kill`]: this module owns the plan, the
//! policy gate, the persisted intent and the decision a start-up reconciliation makes.
//! The firewall itself (WFP on Windows) is a [`HostFirewall`] the `agent` binary
//! implements per platform, so `response` gains no platform branch.
//!
//! The intent is written **before** the firewall changes, and a reconciliation at start-up
//! makes the firewall match it. So a crash between the two leaves the host converging to
//! what the operator last asked for, not to whatever half-state the crash left.

use std::{
    fs::{File, OpenOptions},
    io::{self, Write as _},
    net::{IpAddr, SocketAddr},
    path::Path,
};

use policy::ResponsePolicy;
use serde::{Deserialize, Serialize};

/// How many distinct control-plane endpoints one isolation pins. A server name resolves
/// to a handful of addresses; more than this is a misconfiguration or a resolver
/// answering with something other than the control plane.
pub const MAX_CONTROL_PLANE_ENDPOINTS: usize = 16;

/// Why an endpoint list cannot become an [`IsolationPlan`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    /// An address or port that cannot name one control-plane server.
    #[error("{endpoint} cannot be a control-plane endpoint: {reason}")]
    NotAnEndpoint {
        /// The rejected endpoint.
        endpoint: SocketAddr,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// More distinct endpoints than [`MAX_CONTROL_PLANE_ENDPOINTS`].
    #[error("{count} control-plane endpoints, more than the {max} an isolation pins")]
    TooMany {
        /// Distinct endpoints after deduplication.
        count: usize,
        /// [`MAX_CONTROL_PLANE_ENDPOINTS`].
        max: usize,
    },
}

/// What an isolation lets through besides loopback and DHCP: the control-plane endpoints
/// the agent itself may still reach, pinned when the isolation is applied (ADR-0037 §3).
///
/// Sorted and deduplicated, so two plans for the same endpoints compare equal whatever
/// order the resolver returned them in. Deserializing goes through [`IsolationPlan::new`]
/// too, so a hand-edited `isolation.json` can neither widen the allowlist nor break that
/// invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PlanOnDisk", into = "PlanOnDisk")]
pub struct IsolationPlan {
    control_plane: Vec<SocketAddr>,
}

/// The serialized shape of an [`IsolationPlan`], unvalidated.
#[derive(Serialize, Deserialize)]
struct PlanOnDisk {
    control_plane: Vec<SocketAddr>,
}

impl TryFrom<PlanOnDisk> for IsolationPlan {
    type Error = PlanError;

    fn try_from(raw: PlanOnDisk) -> Result<Self, PlanError> {
        Self::new(raw.control_plane)
    }
}

impl From<IsolationPlan> for PlanOnDisk {
    fn from(plan: IsolationPlan) -> Self {
        Self {
            control_plane: plan.control_plane,
        }
    }
}

impl IsolationPlan {
    /// Validates and pins `endpoints`. An empty list is a valid plan: an agent without a
    /// control plane can still be isolated, and lifted locally.
    ///
    /// IPv4-mapped IPv6 addresses are stored as IPv4, the form the stack matches them in.
    ///
    /// # Errors
    ///
    /// [`PlanError::NotAnEndpoint`] for port 0, an unspecified, multicast or broadcast
    /// address (each would open more than one server) or an IPv6 link-local address (its
    /// scope is not kept, so it would match on every interface); [`PlanError::TooMany`]
    /// past [`MAX_CONTROL_PLANE_ENDPOINTS`].
    pub fn new(endpoints: impl IntoIterator<Item = SocketAddr>) -> Result<Self, PlanError> {
        let mut control_plane = Vec::new();
        for endpoint in endpoints {
            let endpoint = SocketAddr::new(endpoint.ip().to_canonical(), endpoint.port());
            if let Some(reason) = not_an_endpoint(endpoint) {
                return Err(PlanError::NotAnEndpoint { endpoint, reason });
            }
            control_plane.push(endpoint);
        }
        control_plane.sort_unstable();
        control_plane.dedup();
        if control_plane.len() > MAX_CONTROL_PLANE_ENDPOINTS {
            return Err(PlanError::TooMany {
                count: control_plane.len(),
                max: MAX_CONTROL_PLANE_ENDPOINTS,
            });
        }
        Ok(Self { control_plane })
    }

    /// The pinned control-plane endpoints, sorted.
    #[must_use]
    pub fn control_plane(&self) -> &[SocketAddr] {
        &self.control_plane
    }
}

fn not_an_endpoint(endpoint: SocketAddr) -> Option<&'static str> {
    let ip = endpoint.ip();
    if endpoint.port() == 0 {
        Some("port 0 matches every port")
    } else if ip.is_unspecified() {
        Some("an unspecified address matches every host")
    } else if ip.is_multicast() {
        Some("a multicast address names a group, not a server")
    } else if matches!(ip, IpAddr::V4(v4) if v4.is_broadcast()) {
        Some("the broadcast address names every host on the link")
    } else if matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local()) {
        Some("an IPv6 link-local address needs its scope, which a plan does not keep")
    } else {
        None
    }
}

/// The platform firewall an isolation drives, implemented by the `agent` binary.
///
/// Every object it installs is the agent's own (on Windows, one WFP provider and
/// sublayer with fixed keys), so [`HostFirewall::lift`] never touches anything else on
/// the host.
pub trait HostFirewall {
    /// Installs the block and `plan`'s permits, replacing whatever isolation the agent
    /// installed before. **Atomic**: on `Err`, the firewall is as it was before the call
    /// (WFP: one transaction).
    ///
    /// # Errors
    ///
    /// The platform call failed; nothing was changed.
    fn apply(&self, plan: &IsolationPlan) -> io::Result<()>;

    /// Removes every object the agent installed. `Ok` when there was nothing to remove.
    ///
    /// # Errors
    ///
    /// The platform call failed.
    fn lift(&self) -> io::Result<()>;

    /// Whether the agent's block is installed right now.
    ///
    /// # Errors
    ///
    /// The platform state could not be read.
    fn applied(&self) -> io::Result<bool>;
}

/// What the operator last asked for, persisted beside the agent's other state so a
/// restart, of the agent or the host, converges back to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsolationIntent {
    /// `Some` while the host should be isolated, with the endpoints pinned at the time.
    pub plan: Option<IsolationPlan>,
    /// Who asked, for the audit trail (`cli isolate`, `agent isolation lift`, ...).
    pub trigger: String,
    /// When the intent last changed, in nanoseconds since the Unix epoch.
    pub changed_at_ns: u64,
}

/// Why the persisted intent could not be read.
#[derive(Debug, thiserror::Error)]
pub enum IntentError {
    /// The file exists but could not be read.
    #[error("reading the isolation intent: {0}")]
    Io(#[from] io::Error),
    /// The file is not an intent this version can read.
    #[error("the isolation intent is unreadable: {0}")]
    Corrupt(#[from] serde_json::Error),
}

/// Reads the intent at `path`. `Ok(None)` when there is none: the host was never isolated.
///
/// # Errors
///
/// [`IntentError`] when the file exists but cannot be read or parsed.
pub fn read_intent(path: &Path) -> Result<Option<IsolationIntent>, IntentError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Takes the exclusive lock every reader-writer of the intent holds until the returned
/// file drops: `cli`, the agent's IPC handler and `agent isolation lift` are separate
/// processes, so the lock is a sibling `.lock` file, not a mutex.
///
/// It is also why [`write_intent`]'s temporary file keeps one fixed name: only the lock
/// holder writes it, and a crash leaves one stale file that the next write replaces.
fn lock_intent(path: &Path) -> io::Result<File> {
    let mut lock_path = path.as_os_str().to_owned();
    lock_path.push(".lock");
    let lock = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(lock_path)?;
    lock.lock()?;
    Ok(lock)
}

/// Writes through a synced sibling temporary file and a rename, so a crash or a power loss
/// leaves either the old intent or the new one, never a torn file that [`reconcile`] could
/// not read. The caller holds [`lock_intent`].
fn write_intent(path: &Path, intent: &IsolationIntent) -> io::Result<()> {
    let bytes = serde_json::to_vec(intent).map_err(io::Error::other)?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let mut file = File::create(&tmp)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)?;
    sync_parent(path);
    Ok(())
}

/// Makes the rename itself durable. Best effort by design: Windows cannot open a directory
/// as a `File`, and NTFS journals the rename, so a power loss there still leaves the old
/// name or the new one.
fn sync_parent(path: &Path) {
    if let Some(dir) = path.parent()
        && let Ok(dir) = File::open(dir)
    {
        let _ = dir.sync_all();
    }
}

fn is_isolated(intent: Option<&IsolationIntent>) -> bool {
    intent.is_some_and(|i| i.plan.is_some())
}

/// What an isolation request did, for the `HOST-ISOLATE` audit line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsolateOutcome {
    /// The firewall now enforces `plan`.
    Isolated {
        /// The plan in force.
        plan: IsolationPlan,
    },
    /// The host was already isolated with this same plan and the block was in place. The
    /// plan was applied again all the same, which puts back a permit removed beside an
    /// intact block.
    AlreadyIsolated {
        /// The plan in force.
        plan: IsolationPlan,
    },
    /// `policy.isolate_enabled` was false; nothing was changed.
    ObserveOnly,
    /// Nothing was changed: the intent could not be read or written, or the firewall
    /// refused the plan (and the previous intent was put back).
    Failed {
        /// The cause, rendered.
        error: String,
    },
}

/// Policy-gates and applies an isolation.
///
/// The new intent is persisted first, then the firewall applied. If the firewall
/// refuses, the previous intent is put back, so a later [`reconcile`] does not retry a
/// plan the operator was told failed. A request for the plan already intended only
/// re-applies it: the intent, its trigger and its time stay those of the first request.
///
/// # Errors
///
/// Never returns `Err`: every failure is an [`IsolateOutcome::Failed`], so a caller
/// auditing every outcome has one path, as with [`crate::kill_process`].
#[must_use]
pub fn isolate_host(
    plan: IsolationPlan,
    policy: &ResponsePolicy,
    firewall: &impl HostFirewall,
    intent_path: &Path,
    trigger: &str,
    now_ns: u64,
) -> IsolateOutcome {
    if !policy.isolate_enabled {
        return IsolateOutcome::ObserveOnly;
    }
    let _lock = match lock_intent(intent_path) {
        Ok(lock) => lock,
        Err(e) => {
            return IsolateOutcome::Failed {
                error: format!("locking the isolation intent: {e}"),
            };
        }
    };
    let previous = match read_intent(intent_path) {
        Ok(previous) => previous,
        Err(e) => {
            return IsolateOutcome::Failed {
                error: e.to_string(),
            };
        }
    };
    let same_plan = previous
        .as_ref()
        .is_some_and(|p| p.plan.as_ref() == Some(&plan));
    if same_plan {
        // `applied` only sees the block, not the permits, so the plan is re-applied even
        // when the block is there; `apply` is atomic and replaces.
        let was_applied = matches!(firewall.applied(), Ok(true));
        return match firewall.apply(&plan) {
            Ok(()) if was_applied => IsolateOutcome::AlreadyIsolated { plan },
            Ok(()) => IsolateOutcome::Isolated { plan },
            Err(e) => IsolateOutcome::Failed {
                error: format!("applying the isolation: {e}"),
            },
        };
    }
    let intent = IsolationIntent {
        plan: Some(plan.clone()),
        trigger: trigger.to_string(),
        changed_at_ns: now_ns,
    };
    if let Err(e) = write_intent(intent_path, &intent) {
        return IsolateOutcome::Failed {
            error: format!("writing the isolation intent: {e}"),
        };
    }
    match firewall.apply(&plan) {
        Ok(()) => IsolateOutcome::Isolated { plan },
        Err(e) => {
            let restored = match &previous {
                Some(previous) => write_intent(intent_path, previous),
                None => std::fs::remove_file(intent_path),
            };
            let error = match restored {
                Ok(()) => format!("applying the isolation: {e}"),
                Err(r) => format!(
                    "applying the isolation: {e}; restoring the previous intent also failed: {r}"
                ),
            };
            IsolateOutcome::Failed { error }
        }
    }
}

/// What a lift request did, for the `HOST-UNISOLATE` audit line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiftOutcome {
    /// The isolation was in place, or intended, and is now gone.
    Lifted,
    /// There was no isolation to lift; nothing changed.
    NotIsolated,
    /// The intent now says "not isolated" but the firewall refused the lift, so the block
    /// may still be in place. The next [`reconcile`] retries it.
    Failed {
        /// The cause, rendered.
        error: String,
    },
}

/// Lifts the isolation. **Never policy-gated** (ADR-0037 §4): lifting is the safe
/// direction, and refusing it would turn a policy mistake into a host nobody can recover.
/// An unreadable intent does not stop it either: it is overwritten. Nor does a lock that
/// cannot be taken: the lift then runs unserialized rather than not at all.
///
/// # Errors
///
/// Never returns `Err`; see [`LiftOutcome::Failed`].
#[must_use]
pub fn lift_isolation(
    firewall: &impl HostFirewall,
    intent_path: &Path,
    trigger: &str,
    now_ns: u64,
) -> LiftOutcome {
    let _lock = lock_intent(intent_path);
    let intended = read_intent(intent_path).map_or(true, |i| is_isolated(i.as_ref()));
    let applied = firewall.applied().unwrap_or(true);
    if !intended && !applied {
        return LiftOutcome::NotIsolated;
    }
    let intent = IsolationIntent {
        plan: None,
        trigger: trigger.to_string(),
        changed_at_ns: now_ns,
    };
    let persisted = write_intent(intent_path, &intent);
    match (firewall.lift(), persisted) {
        (Ok(()), Ok(())) => LiftOutcome::Lifted,
        (Err(e), _) => LiftOutcome::Failed {
            error: format!("lifting the isolation: {e}"),
        },
        // The block is gone now, but an older intent still says "isolated", so the
        // next start-up would put it back.
        (Ok(()), Err(e)) => LiftOutcome::Failed {
            error: format!("the block is lifted but the intent could not be written: {e}"),
        },
    }
}

/// What a start-up reconciliation found and did. [`Reconciliation::Reapplied`] and
/// [`Reconciliation::RemovedLeftover`] are drift (`HOST-ISOLATION-DRIFT`): the firewall
/// did not match the intent, and a missing block on an isolated host is a tampering
/// signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reconciliation {
    /// The firewall already matched the intent.
    InSync {
        /// Whether the host is isolated.
        isolated: bool,
    },
    /// The host should be isolated and the block was missing; it is back.
    Reapplied {
        /// The plan in force.
        plan: IsolationPlan,
    },
    /// The host should not be isolated and the agent's block was still there; it is gone.
    RemovedLeftover,
    /// The intent or the firewall could not be read or changed, so the firewall was left
    /// as it was found; the caller audits it like drift (ADR-0037 §7).
    Failed {
        /// The cause, rendered.
        error: String,
    },
}

/// Makes the firewall match the persisted intent; run once when the agent starts.
///
/// An unreadable intent changes nothing: guessing either way could isolate a host nobody
/// asked to isolate, or free one that should stay contained.
///
/// Not policy-gated, on purpose: the gate is on the request ([`isolate_host`]), and an
/// isolation already persisted stays enforced if the policy is turned off afterwards. The
/// way out is a lift, which is never gated.
///
/// # Errors
///
/// Never returns `Err`; see [`Reconciliation::Failed`].
#[must_use]
pub fn reconcile(firewall: &impl HostFirewall, intent_path: &Path) -> Reconciliation {
    let _lock = match lock_intent(intent_path) {
        Ok(lock) => lock,
        Err(e) => {
            return Reconciliation::Failed {
                error: format!("locking the isolation intent: {e}"),
            };
        }
    };
    let intent = match read_intent(intent_path) {
        Ok(intent) => intent,
        Err(e) => {
            return Reconciliation::Failed {
                error: e.to_string(),
            };
        }
    };
    let applied = match firewall.applied() {
        Ok(applied) => applied,
        Err(e) => {
            return Reconciliation::Failed {
                error: format!("reading the firewall: {e}"),
            };
        }
    };
    match (intent.and_then(|i| i.plan), applied) {
        // Applied again even when the block is there: `apply` is atomic and replaces, so
        // this also restores a permit someone removed beside an intact block.
        (Some(plan), applied) => match firewall.apply(&plan) {
            Ok(()) if applied => Reconciliation::InSync { isolated: true },
            Ok(()) => Reconciliation::Reapplied { plan },
            Err(e) => Reconciliation::Failed {
                error: format!("re-applying the isolation: {e}"),
            },
        },
        (None, true) => match firewall.lift() {
            Ok(()) => Reconciliation::RemovedLeftover,
            Err(e) => Reconciliation::Failed {
                error: format!("removing a leftover isolation: {e}"),
            },
        },
        (None, false) => Reconciliation::InSync { isolated: false },
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, path::PathBuf};

    use super::*;

    fn intent_path(name: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "response-isolation-test-{name}-{}-{unique}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("isolation.json")
    }

    /// A firewall that records what is installed, and fails on demand. With `lock_probe`
    /// set to an intent path, each call also records whether that intent's lock was held.
    #[derive(Default)]
    struct FakeFirewall {
        installed: RefCell<Option<IsolationPlan>>,
        fail_apply: bool,
        fail_lift: bool,
        calls: RefCell<Vec<&'static str>>,
        lock_probe: Option<PathBuf>,
        lock_held: RefCell<Vec<bool>>,
    }

    impl FakeFirewall {
        fn holding(plan: IsolationPlan) -> Self {
            Self {
                installed: RefCell::new(Some(plan)),
                ..Self::default()
            }
        }

        fn probe_lock(&self) {
            let Some(intent) = &self.lock_probe else {
                return;
            };
            let mut lock_path = intent.as_os_str().to_owned();
            lock_path.push(".lock");
            let lock = File::open(lock_path).unwrap();
            let held = matches!(lock.try_lock(), Err(std::fs::TryLockError::WouldBlock));
            self.lock_held.borrow_mut().push(held);
        }
    }

    impl HostFirewall for FakeFirewall {
        fn apply(&self, plan: &IsolationPlan) -> io::Result<()> {
            self.calls.borrow_mut().push("apply");
            self.probe_lock();
            if self.fail_apply {
                return Err(io::Error::other("BFE refused the transaction"));
            }
            *self.installed.borrow_mut() = Some(plan.clone());
            Ok(())
        }

        fn lift(&self) -> io::Result<()> {
            self.calls.borrow_mut().push("lift");
            self.probe_lock();
            if self.fail_lift {
                return Err(io::Error::other("BFE refused the delete"));
            }
            *self.installed.borrow_mut() = None;
            Ok(())
        }

        fn applied(&self) -> io::Result<bool> {
            Ok(self.installed.borrow().is_some())
        }
    }

    fn enabled() -> ResponsePolicy {
        ResponsePolicy {
            isolate_enabled: true,
            ..ResponsePolicy::default()
        }
    }

    fn plan(endpoints: &[&str]) -> IsolationPlan {
        IsolationPlan::new(endpoints.iter().map(|e| e.parse().unwrap())).unwrap()
    }

    fn isolate(
        firewall: &FakeFirewall,
        path: &Path,
        p: &IsolationPlan,
        now_ns: u64,
    ) -> IsolateOutcome {
        isolate_host(p.clone(), &enabled(), firewall, path, "cli isolate", now_ns)
    }

    #[test]
    fn a_plan_is_sorted_deduplicated_and_maps_ipv4_in_ipv6_to_ipv4() {
        let p = plan(&["10.0.0.2:443", "[::ffff:10.0.0.1]:443", "10.0.0.2:443"]);
        let expected: Vec<SocketAddr> = vec![
            "10.0.0.1:443".parse().unwrap(),
            "10.0.0.2:443".parse().unwrap(),
        ];
        assert_eq!(p.control_plane(), expected.as_slice());
    }

    #[test]
    fn a_plan_refuses_endpoints_that_would_open_more_than_one_server() {
        for bad in [
            "0.0.0.0:443",
            "[::]:443",
            "224.0.0.1:443",
            "[ff02::1]:443",
            "255.255.255.255:443",
            "10.0.0.1:0",
            "[fe80::1%5]:443",
            "[fe80::1]:443",
        ] {
            let result = IsolationPlan::new([bad.parse::<SocketAddr>().unwrap()]);
            assert!(
                matches!(result, Err(PlanError::NotAnEndpoint { .. })),
                "{bad}: {result:?}"
            );
        }
    }

    #[test]
    fn a_plan_refuses_more_endpoints_than_the_cap_but_counts_them_after_deduplication() {
        let many = (1..=MAX_CONTROL_PLANE_ENDPOINTS + 1)
            .map(|i| SocketAddr::from(([10, 0, 0, u8::try_from(i).unwrap()], 443)));
        assert!(matches!(
            IsolationPlan::new(many),
            Err(PlanError::TooMany { .. })
        ));
        let repeated = std::iter::repeat_n(SocketAddr::from(([10, 0, 0, 1], 443)), 100);
        assert_eq!(
            IsolationPlan::new(repeated).unwrap().control_plane().len(),
            1
        );
    }

    #[test]
    fn a_plan_read_from_disk_is_validated_like_a_new_one() {
        // A hand-edited intent must not widen the allowlist, or hand `apply` an unsorted
        // list that `same_plan` would compare wrongly.
        let path = intent_path("hand-edited");
        std::fs::write(
            &path,
            br#"{"plan":{"control_plane":["0.0.0.0:0"]},"trigger":"x","changed_at_ns":1}"#,
        )
        .unwrap();
        assert!(matches!(read_intent(&path), Err(IntentError::Corrupt(_))));
        let firewall = FakeFirewall::default();
        assert!(matches!(
            reconcile(&firewall, &path),
            Reconciliation::Failed { .. }
        ));
        assert!(firewall.calls.borrow().is_empty());

        std::fs::write(
            &path,
            br#"{"plan":{"control_plane":["10.0.0.2:443","10.0.0.1:443","10.0.0.2:443"]},"trigger":"x","changed_at_ns":1}"#,
        )
        .unwrap();
        assert_eq!(
            read_intent(&path).unwrap().unwrap().plan,
            Some(plan(&["10.0.0.1:443", "10.0.0.2:443"]))
        );
    }

    #[test]
    fn a_plan_keeps_its_serialized_shape() {
        assert_eq!(
            serde_json::to_string(&plan(&["10.0.0.1:443"])).unwrap(),
            r#"{"control_plane":["10.0.0.1:443"]}"#
        );
    }

    #[test]
    fn every_firewall_change_runs_under_the_intent_lock() {
        // `cli isolate`, `cli unisolate` and a start-up reconciliation run in different
        // processes; unserialized, one can restore a "previous" intent over the other's.
        let path = intent_path("locked");
        let firewall = FakeFirewall {
            lock_probe: Some(path.clone()),
            ..FakeFirewall::default()
        };
        let _ = isolate(&firewall, &path, &plan(&["10.0.0.1:443"]), 1);
        let _ = reconcile(&firewall, &path);
        let _ = lift_isolation(&firewall, &path, "cli unisolate", 2);
        assert_eq!(*firewall.calls.borrow(), ["apply", "apply", "lift"]);
        assert_eq!(*firewall.lock_held.borrow(), [true, true, true]);
        // Released afterwards: the next request does not wait forever.
        let _ = isolate(&FakeFirewall::default(), &path, &plan(&["10.0.0.1:443"]), 3);
    }

    #[test]
    fn isolation_with_the_policy_off_changes_nothing() {
        let path = intent_path("observe-only");
        let firewall = FakeFirewall::default();
        let outcome = isolate_host(
            plan(&["10.0.0.1:443"]),
            &ResponsePolicy::default(),
            &firewall,
            &path,
            "cli isolate",
            1,
        );
        assert_eq!(outcome, IsolateOutcome::ObserveOnly);
        assert!(firewall.calls.borrow().is_empty());
        assert!(!path.exists());
    }

    #[test]
    fn isolating_persists_the_intent_and_applies_the_plan() {
        let path = intent_path("isolate");
        let firewall = FakeFirewall::default();
        let p = plan(&["10.0.0.1:443"]);
        assert_eq!(
            isolate(&firewall, &path, &p, 7),
            IsolateOutcome::Isolated { plan: p.clone() }
        );
        assert_eq!(*firewall.installed.borrow(), Some(p.clone()));
        let intent = read_intent(&path).unwrap().unwrap();
        assert_eq!(intent.plan, Some(p));
        assert_eq!(intent.trigger, "cli isolate");
        assert_eq!(intent.changed_at_ns, 7);
    }

    #[test]
    fn isolating_again_with_the_same_plan_is_already_isolated() {
        let path = intent_path("again");
        let firewall = FakeFirewall::default();
        let p = plan(&["10.0.0.1:443"]);
        let _ = isolate(&firewall, &path, &p, 1);
        assert_eq!(
            isolate(&firewall, &path, &p, 2),
            IsolateOutcome::AlreadyIsolated { plan: p }
        );
        assert_eq!(*firewall.calls.borrow(), ["apply", "apply"]);
        assert_eq!(read_intent(&path).unwrap().unwrap().changed_at_ns, 1);
    }

    #[test]
    fn isolating_again_puts_back_a_permit_removed_beside_an_intact_block() {
        // `applied` only reports the block, so "already isolated" must not skip the apply.
        let path = intent_path("permit-removed");
        let p = plan(&["10.0.0.1:443", "10.0.0.2:443"]);
        let _ = isolate(&FakeFirewall::default(), &path, &p, 1);
        let tampered = FakeFirewall::holding(plan(&["10.0.0.1:443"]));
        assert_eq!(
            isolate(&tampered, &path, &p, 2),
            IsolateOutcome::AlreadyIsolated { plan: p.clone() }
        );
        assert_eq!(*tampered.installed.borrow(), Some(p));
    }

    #[test]
    fn a_refused_isolation_puts_the_previous_intent_back() {
        // Otherwise the next start-up would apply a plan the operator was told failed.
        let path = intent_path("refused");
        let first = plan(&["10.0.0.1:443"]);
        let _ = isolate(&FakeFirewall::default(), &path, &first, 1);

        let refusing = FakeFirewall {
            fail_apply: true,
            ..FakeFirewall::default()
        };
        let outcome = isolate(&refusing, &path, &plan(&["10.0.0.9:443"]), 2);
        assert!(
            matches!(outcome, IsolateOutcome::Failed { .. }),
            "{outcome:?}"
        );
        assert_eq!(
            read_intent(&path).unwrap().unwrap().plan,
            Some(first.clone())
        );

        let never_isolated = intent_path("refused-first");
        let outcome = isolate(&refusing, &never_isolated, &first, 1);
        assert!(
            matches!(outcome, IsolateOutcome::Failed { .. }),
            "{outcome:?}"
        );
        assert!(!never_isolated.exists());
    }

    #[test]
    fn lifting_is_never_policy_gated() {
        let path = intent_path("lift");
        let firewall = FakeFirewall::default();
        let _ = isolate(&firewall, &path, &plan(&["10.0.0.1:443"]), 1);
        // `lift_isolation` takes no policy at all: there is nothing to turn off.
        assert_eq!(
            lift_isolation(&firewall, &path, "cli unisolate", 2),
            LiftOutcome::Lifted
        );
        assert!(firewall.installed.borrow().is_none());
        assert_eq!(read_intent(&path).unwrap().unwrap().plan, None);
        assert_eq!(
            lift_isolation(&firewall, &path, "cli unisolate", 3),
            LiftOutcome::NotIsolated
        );
    }

    #[test]
    fn lifting_works_over_an_unreadable_intent() {
        let path = intent_path("lift-corrupt");
        std::fs::write(&path, b"{not json").unwrap();
        let firewall = FakeFirewall::holding(plan(&[]));
        assert_eq!(
            lift_isolation(&firewall, &path, "agent isolation lift", 1),
            LiftOutcome::Lifted
        );
        assert!(firewall.installed.borrow().is_none());
        assert_eq!(read_intent(&path).unwrap().unwrap().plan, None);
    }

    #[test]
    fn a_refused_lift_is_retried_by_the_next_reconciliation() {
        let path = intent_path("lift-refused");
        let refusing = FakeFirewall {
            fail_lift: true,
            ..FakeFirewall::holding(plan(&[]))
        };
        let outcome = lift_isolation(&refusing, &path, "cli unisolate", 1);
        assert!(matches!(outcome, LiftOutcome::Failed { .. }), "{outcome:?}");

        let next_start = FakeFirewall::holding(plan(&[]));
        assert_eq!(
            reconcile(&next_start, &path),
            Reconciliation::RemovedLeftover
        );
        assert!(next_start.installed.borrow().is_none());
    }

    #[test]
    fn reconciliation_puts_a_removed_block_back_on_an_isolated_host() {
        // A block that vanished while the host should be isolated is the tampering case.
        let path = intent_path("reapply");
        let p = plan(&["10.0.0.1:443"]);
        let _ = isolate(&FakeFirewall::default(), &path, &p, 1);
        let wiped = FakeFirewall::default();
        assert_eq!(
            reconcile(&wiped, &path),
            Reconciliation::Reapplied { plan: p.clone() }
        );
        assert_eq!(*wiped.installed.borrow(), Some(p));
    }

    #[test]
    fn reconciliation_reports_in_sync_when_nothing_differs() {
        assert_eq!(
            reconcile(&FakeFirewall::default(), &intent_path("never")),
            Reconciliation::InSync { isolated: false }
        );

        let path = intent_path("in-sync");
        let firewall = FakeFirewall::default();
        let _ = isolate(&firewall, &path, &plan(&["10.0.0.1:443"]), 1);
        assert_eq!(
            reconcile(&firewall, &path),
            Reconciliation::InSync { isolated: true }
        );
    }

    #[test]
    fn reconciliation_changes_nothing_over_an_unreadable_intent() {
        let path = intent_path("reconcile-corrupt");
        std::fs::write(&path, b"{not json").unwrap();
        let firewall = FakeFirewall::holding(plan(&[]));
        assert!(matches!(
            reconcile(&firewall, &path),
            Reconciliation::Failed { .. }
        ));
        assert!(firewall.calls.borrow().is_empty());
    }
}
