//! Which IOC address and domain matches are the agent's own control-plane traffic (<https://github.com/synthaea-lab/agent/issues/47>).
//!
//! A feed that lists the control plane's address (shared hosting, a CDN it sits behind) made
//! the agent alert on its own fetch and upload, and that finding started the indicator's
//! cooldown, which then absorbed a real process reaching the same address. The IOC matcher
//! therefore skips a match when **both** hold:
//!
//! - the destination is the configured control plane (`server.control_plane_url`): the queried
//!   name is its host, or the connected address is one that host resolved to;
//! - the process is the agent: this process, or a *sibling* (a second process on the agent's
//!   own executable, `agent apply-content-manifest`) whose `Exec` the agent saw, of the same
//!   incarnation (`process_generation`) as the event, run by the agent's own uid, outside any
//!   container, and that has not exec'd another image since.
//!
//! The destination half is what keeps the skip from being a channel: the agent's binary pointed
//! at any other host (`apply-content-manifest --server https://<listed host>`, code running
//! inside the agent) still raises. Everything that cannot be established fails toward raising:
//! no control plane configured, its host not resolved yet or resolved to other addresses than
//! the ones connected to, a sibling the agent did not see start, a sensor without incarnation
//! stamps (macOS), a platform without a uid (Windows: only this process is the agent), a
//! containerized process (its image path names a file in another mount namespace).

use std::{
    net::{IpAddr, ToSocketAddrs as _},
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock, RwLock},
    time::Duration,
};

use crate::sync::{LockExt, RwLockExt};

/// Addresses of the control-plane host kept at once. A host behind a CDN resolves to a handful.
const MAX_CONTROL_PLANE_ADDRS: usize = 32;
/// How often the control-plane host is resolved again, so a rotated address is followed.
const REFRESH_INTERVAL: Duration = Duration::from_secs(60);
/// Sibling processes remembered at once; the oldest are forgotten first (a forgotten one raises).
const MAX_SIBLINGS: usize = 64;

/// Who made a skipped match, for the counters and the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum AgentOrigin {
    /// This process.
    Own,
    /// A second process on the agent's executable.
    Sibling,
}

/// The configured control plane: its host as written and the addresses it last resolved to.
struct ControlPlane {
    /// Lowercase, without a trailing dot, for comparison with a queried name.
    host: String,
    port: u16,
    /// A literal address in the URL never needs resolving.
    literal: Option<IpAddr>,
    resolved: RwLock<Vec<IpAddr>>,
}

/// One sibling incarnation the agent saw start.
#[derive(Debug, Clone, Copy)]
struct Sibling {
    generation: u64,
    exec_ns: u64,
}

/// What the IOC matcher asks before skipping a match as the agent's own traffic.
pub(crate) struct OwnTraffic {
    control_plane: OnceLock<ControlPlane>,
    /// The agent's executable, canonical; `None` where it cannot be read (no sibling then).
    own_exe: Option<PathBuf>,
    siblings: Mutex<store::BoundedMap<u32, Sibling>>,
}

impl OwnTraffic {
    pub(crate) fn new() -> Self {
        Self {
            control_plane: OnceLock::new(),
            own_exe: std::env::current_exe()
                .ok()
                .and_then(|exe| std::fs::canonicalize(exe).ok()),
            siblings: Mutex::new(store::BoundedMap::new(MAX_SIBLINGS)),
        }
    }

    /// Names the control plane the agent talks to. `false` when the URL names no host, or when
    /// one was already set (the first stays).
    pub(crate) fn set_control_plane(&self, url: &str) -> bool {
        let Some((host, port)) = host_and_port(url) else {
            return false;
        };
        let literal = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .ok()
            .map(|ip| ip.to_canonical());
        self.control_plane
            .set(ControlPlane {
                host,
                port,
                literal,
                resolved: RwLock::new(Vec::new()),
            })
            .is_ok()
    }

    /// Resolves the control-plane host again. A failure keeps the previous addresses.
    pub(crate) fn refresh(&self) {
        let Some(cp) = self.control_plane.get() else {
            return;
        };
        if cp.literal.is_some() {
            return;
        }
        match (cp.host.as_str(), cp.port).to_socket_addrs() {
            Ok(addrs) => {
                let mut fresh: Vec<IpAddr> = addrs.map(|a| a.ip().to_canonical()).collect();
                fresh.sort_unstable();
                fresh.dedup();
                fresh.truncate(MAX_CONTROL_PLANE_ADDRS);
                *cp.resolved.write_recovering() = fresh;
            }
            Err(error) => {
                tracing::debug!(%error, "ioc: the control-plane host did not resolve; keeping the last addresses");
            }
        }
    }

    /// Resolves the control-plane host now and every [`REFRESH_INTERVAL`] on its own thread.
    pub(crate) fn spawn_refresh(self: &Arc<Self>) {
        if self
            .control_plane
            .get()
            .is_none_or(|cp| cp.literal.is_some())
        {
            return;
        }
        let this = Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name("ioc-control-plane".into())
            .spawn(move || {
                loop {
                    this.refresh();
                    std::thread::sleep(REFRESH_INTERVAL);
                }
            });
        if let Err(error) = spawned {
            tracing::error!(%error, "ioc: could not start the control-plane resolver; the agent's own traffic will raise");
        }
    }

    /// Whether `name` is the control plane's host (exactly: a subdomain is not).
    pub(crate) fn is_control_plane_name(&self, name: &str) -> bool {
        self.control_plane.get().is_some_and(|cp| {
            cp.literal.is_none() && name.trim_end_matches('.').eq_ignore_ascii_case(&cp.host)
        })
    }

    /// Whether `address` is the control plane's literal address or one its host resolved to.
    pub(crate) fn is_control_plane_address(&self, address: IpAddr) -> bool {
        let address = address.to_canonical();
        self.control_plane.get().is_some_and(|cp| {
            cp.literal == Some(address) || cp.resolved.read_recovering().contains(&address)
        })
    }

    /// Remembers an `Exec` of the agent's own executable, so that process's traffic can be
    /// told apart from a later holder of the same pid. Any other exec at a remembered pid
    /// forgets it: `process_generation` is stamped at fork and survives an exec, so the image
    /// that pid now runs is no longer the agent's even though its incarnation stamp is.
    pub(crate) fn record_exec(&self, exec: &schema::ExecEvent) {
        let sibling = self.sibling_of(exec);
        let mut siblings = self.siblings.lock_recovering();
        match sibling {
            Some(sibling) => siblings.insert(exec.meta.pid, sibling),
            None => {
                siblings.remove(&exec.meta.pid);
            }
        }
    }

    /// The sibling `exec` starts, if its image is the agent's own executable on the agent's own
    /// filesystem.
    fn sibling_of(&self, exec: &schema::ExecEvent) -> Option<Sibling> {
        let (Some(own), Some(generation)) = (&self.own_exe, exec.meta.process_generation) else {
            return None;
        };
        // `image_path` is a path in the process's mount namespace, and it is canonicalized
        // here in the agent's: a container's own file at the agent's path would resolve to the
        // agent's binary. A containerized exec is never a sibling.
        if exec.meta.container.is_some() {
            return None;
        }
        // The cheap test first: only an exec whose file name is the agent's is canonicalized.
        let image = std::path::Path::new(&exec.image_path);
        if image.file_name() != own.file_name() {
            return None;
        }
        (std::fs::canonicalize(image).ok().as_ref() == Some(own)).then_some(Sibling {
            generation,
            exec_ns: exec.meta.timestamp_ns,
        })
    }

    /// Whether the process that made `meta` is the agent, judged from what was captured with the
    /// event, never from what holds the pid now.
    pub(crate) fn origin(&self, meta: &schema::EventMeta) -> Option<AgentOrigin> {
        if meta.pid == std::process::id() {
            return Some(AgentOrigin::Own);
        }
        let generation = meta.process_generation?;
        let sibling = *self.siblings.lock_recovering().get(&meta.pid)?;
        (sibling.generation == generation
            && sibling.exec_ns <= meta.timestamp_ns
            && meta.container.is_none()
            && runs_as_the_agent(&meta.user))
        .then_some(AgentOrigin::Sibling)
    }
}

/// Whether `user` is the account the agent runs as. Only Unix has a uid to compare; elsewhere no
/// sibling is the agent.
fn runs_as_the_agent(user: &schema::User) -> bool {
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` takes no arguments, touches no memory and cannot fail.
        let own = unsafe { libc::geteuid() };
        matches!(user, schema::User::Unix { uid, .. } if *uid == own)
    }
    #[cfg(not(unix))]
    {
        let _ = user;
        false
    }
}

/// The host (lowercase, brackets kept for IPv6) and port of an `https://` URL.
fn host_and_port(url: &str) -> Option<(String, u16)> {
    let rest = url.strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?;
    let (host, port) = if let Some(v6_end) = authority.find(']') {
        let host = &authority[..=v6_end];
        let port = authority[v6_end + 1..].strip_prefix(':');
        (host, port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    let port = match port {
        Some(p) => p.parse().ok()?,
        None => 443,
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec_of(path: &str, pid: u32, generation: Option<u64>, ts: u64) -> schema::ExecEvent {
        schema::ExecEvent {
            meta: schema::EventMeta {
                pid,
                process_generation: generation,
                timestamp_ns: ts,
                ..schema::fixtures::meta()
            },
            image_path: path.to_string(),
            ..schema::fixtures::exec()
        }
    }

    fn meta_of(
        pid: u32,
        generation: Option<u64>,
        ts: u64,
        user: schema::User,
    ) -> schema::EventMeta {
        schema::EventMeta {
            pid,
            process_generation: generation,
            timestamp_ns: ts,
            user,
            ..schema::fixtures::meta()
        }
    }

    #[cfg(unix)]
    fn own_user() -> schema::User {
        // SAFETY: `geteuid` takes no arguments, touches no memory and cannot fail.
        let uid = unsafe { libc::geteuid() };
        schema::User::Unix { uid, gid: 0 }
    }

    #[test]
    fn the_url_gives_its_host_and_port() {
        let cases = [
            ("https://cp.example", Some(("cp.example", 443))),
            (
                "https://CP.Example.:8443/api?x#y",
                Some(("cp.example", 8443)),
            ),
            ("https://user@cp.example/", Some(("cp.example", 443))),
            ("https://[2001:db8::1]:9443/", Some(("[2001:db8::1]", 9443))),
            ("https://203.0.113.9", Some(("203.0.113.9", 443))),
            ("http://cp.example", None),
            ("https://", None),
            ("https://cp.example:notaport", None),
        ];
        for (url, want) in cases {
            let got = host_and_port(url);
            assert_eq!(got.as_ref().map(|(h, p)| (h.as_str(), *p)), want, "{url}");
        }
    }

    #[test]
    fn only_the_control_plane_host_is_its_name_not_a_subdomain_nor_another_host() {
        let own = OwnTraffic::new();
        assert!(
            !own.is_control_plane_name("cp.example"),
            "nothing configured"
        );
        assert!(own.set_control_plane("https://cp.example:8443/"));
        assert!(own.is_control_plane_name("CP.example."));
        assert!(!own.is_control_plane_name("x.cp.example"));
        assert!(!own.is_control_plane_name("evil.example"));
        assert!(
            !own.set_control_plane("https://other.example"),
            "the first stays"
        );
    }

    #[test]
    fn a_literal_control_plane_address_matches_itself_and_no_name() {
        let own = OwnTraffic::new();
        assert!(own.set_control_plane("https://[2001:db8::1]/"));
        assert!(own.is_control_plane_address("2001:db8::1".parse().unwrap()));
        assert!(!own.is_control_plane_address("2001:db8::2".parse().unwrap()));
        assert!(!own.is_control_plane_name("[2001:db8::1]"));

        let v4 = OwnTraffic::new();
        assert!(v4.set_control_plane("https://203.0.113.9"));
        assert!(
            v4.is_control_plane_address("::ffff:203.0.113.9".parse().unwrap()),
            "a mapped address is the same destination"
        );
    }

    #[test]
    fn a_resolved_control_plane_matches_its_addresses_and_none_before_resolving() {
        let own = OwnTraffic::new();
        assert!(own.set_control_plane("https://localhost"));
        let loopback = "127.0.0.1".parse().unwrap();
        assert!(!own.is_control_plane_address(loopback), "not resolved yet");
        own.refresh();
        let resolved = own.is_control_plane_address(loopback)
            || own.is_control_plane_address("::1".parse().unwrap());
        assert!(resolved, "localhost resolves to a loopback address");
        assert!(!own.is_control_plane_address("203.0.113.9".parse().unwrap()));
    }

    #[test]
    fn this_process_is_the_agent() {
        let own = OwnTraffic::new();
        let meta = meta_of(std::process::id(), None, 1, schema::User::Unknown);
        assert_eq!(own.origin(&meta), Some(AgentOrigin::Own));
    }

    #[cfg(unix)]
    #[test]
    fn a_sibling_on_the_agents_executable_is_the_agent_for_its_own_incarnation_only() {
        let own = OwnTraffic::new();
        let exe = std::env::current_exe().unwrap();
        own.record_exec(&exec_of(exe.to_str().unwrap(), 4242, Some(7), 1_000));
        assert_eq!(
            own.origin(&meta_of(4242, Some(7), 2_000, own_user())),
            Some(AgentOrigin::Sibling)
        );
        assert_eq!(
            own.origin(&meta_of(4242, Some(8), 2_000, own_user())),
            None,
            "a recycled pid is another incarnation"
        );
        assert_eq!(
            own.origin(&meta_of(4242, None, 2_000, own_user())),
            None,
            "without a stamp the pid cannot be told from a recycled one"
        );
        assert_eq!(
            own.origin(&meta_of(4242, Some(7), 500, own_user())),
            None,
            "traffic before the exec was not the agent's"
        );
        let other_uid = match own_user() {
            schema::User::Unix { uid, .. } => uid.wrapping_add(1),
            _ => unreachable!(),
        };
        assert_eq!(
            own.origin(&meta_of(
                4242,
                Some(7),
                2_000,
                schema::User::Unix {
                    uid: other_uid,
                    gid: 0
                }
            )),
            None,
            "another user running the agent's binary is not the agent"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_sibling_that_execs_another_binary_is_no_longer_the_agent() {
        let own = OwnTraffic::new();
        let exe = std::env::current_exe().unwrap();
        own.record_exec(&exec_of(exe.to_str().unwrap(), 4646, Some(3), 1_000));
        assert_eq!(
            own.origin(&meta_of(4646, Some(3), 1_500, own_user())),
            Some(AgentOrigin::Sibling)
        );
        // Same pid, same fork-time stamp: only the image changed.
        own.record_exec(&exec_of("/usr/bin/curl", 4646, Some(3), 2_000));
        assert_eq!(
            own.origin(&meta_of(4646, Some(3), 3_000, own_user())),
            None,
            "the image that pid runs now is not the agent's"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_exec_of_the_agents_path_inside_a_container_is_not_the_agent() {
        let own = OwnTraffic::new();
        let exe = std::env::current_exe().unwrap();
        let mut exec = exec_of(exe.to_str().unwrap(), 4747, Some(5), 1_000);
        exec.meta.container = Some(schema::ContainerContext {
            id: "c0ffee".into(),
            image: None,
            name: None,
        });
        own.record_exec(&exec);
        assert!(own.siblings.lock().unwrap().is_empty());
        assert_eq!(own.origin(&meta_of(4747, Some(5), 2_000, own_user())), None);
    }

    #[test]
    fn an_exec_of_another_binary_or_one_never_seen_is_not_the_agent() {
        let own = OwnTraffic::new();
        own.record_exec(&exec_of("/usr/bin/curl", 4343, Some(1), 1_000));
        let user = schema::User::Unknown;
        assert_eq!(
            own.origin(&meta_of(4343, Some(1), 2_000, user.clone())),
            None
        );
        assert_eq!(own.origin(&meta_of(4444, Some(1), 2_000, user)), None);
    }

    #[test]
    fn an_exec_named_like_the_agent_elsewhere_is_not_the_agent() {
        let own = OwnTraffic::new();
        let name = std::env::current_exe().unwrap();
        let name = name.file_name().unwrap().to_str().unwrap();
        let dir =
            std::env::temp_dir().join(format!("own-traffic-lookalike-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join(name);
        std::fs::write(&fake, b"not the agent").unwrap();
        own.record_exec(&exec_of(fake.to_str().unwrap(), 4545, Some(1), 1_000));
        assert!(own.siblings.lock().unwrap().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn locks_poisoned_by_a_panicking_thread_are_recovered() {
        let own = OwnTraffic::new();
        assert!(own.set_control_plane("https://127.0.0.1:8443"));
        let cp = own.control_plane.get().unwrap();
        std::thread::scope(|s| {
            let _ = s
                .spawn(|| {
                    let _resolved = cp.resolved.write().unwrap();
                    let _siblings = own.siblings.lock().unwrap();
                    panic!("poison the own-traffic locks while holding them");
                })
                .join();
        });
        assert!(cp.resolved.is_poisoned() && own.siblings.is_poisoned());
        assert!(own.is_control_plane_address("127.0.0.1".parse().unwrap()));
        assert!(!own.is_control_plane_address("198.51.100.7".parse().unwrap()));
        own.record_exec(&schema::fixtures::exec());
        assert!(!own.siblings.is_poisoned());
    }
}
