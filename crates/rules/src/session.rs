//! Rules over interactive-session lifecycle events (#285): T1563.002, Remote
//! Service Session Hijacking: RDP.
//!
//! A disconnected Windows session stays alive on the host, and anyone able to
//! attach a client to it gets the session as it was left, its owner's token
//! included, without that owner's credentials (`tscon <id>` as SYSTEM, or
//! reconnecting through another RDP connection). What the session's history
//! shows is the client changing between the disconnect (24) and the reconnect
//! (25) of the same session.
//!
//! Known benign shape, hence Medium: the owner roaming, who disconnects at the
//! office and reconnects from home or over a VPN, or walks from the console
//! to an RDP client. Not seen: a hijack from the same client the owner last
//! used (an attacker on the same jump host).

use std::net::IpAddr;

use schema::{SessionEvent, SessionState, detection::Severity};
use store::BoundedMap;

use crate::Alert;

/// Live sessions on one host number in the tens even on a busy RDS server;
/// the cap only stops a hostile flood of disconnect events growing memory.
const DISCONNECTED_SESSIONS_CAP: usize = 1_024;

/// Where a session's client was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Client {
    Console,
    Remote(IpAddr),
}

impl Client {
    /// `None` when the event names no client, or one that is not an address.
    fn of(event: &SessionEvent) -> Option<Self> {
        if event.console {
            Some(Self::Console)
        } else {
            event.source_address.map(Self::Remote)
        }
    }
}

impl std::fmt::Display for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Console => f.write_str("the console"),
            Self::Remote(address) => address.fmt(f),
        }
    }
}

struct Disconnected {
    client: Client,
    timestamp_ns: u64,
}

/// Session id → the client it was disconnected from, until it is reconnected,
/// logged off, or its id is reused by a new logon.
pub(crate) struct SessionHijack {
    disconnected: BoundedMap<u32, Disconnected>,
}

impl SessionHijack {
    pub(crate) fn new() -> Self {
        Self {
            disconnected: BoundedMap::new(DISCONNECTED_SESSIONS_CAP),
        }
    }

    /// Records a disconnect; on a reconnect from another client than the one
    /// the session was disconnected from, alerts. A client that cannot be
    /// read is not evidence either way, and never alerts. A disconnect without
    /// one records nothing. A reconnect always consumes the stored disconnect
    /// before reading its client, because the session is attached again
    /// whoever it was attached to.
    pub(crate) fn on_session(&mut self, event: &SessionEvent) -> Option<Alert> {
        let id = event.session_id?;
        match event.state {
            SessionState::Disconnect => {
                let client = Client::of(event)?;
                self.disconnected.insert(
                    id,
                    Disconnected {
                        client,
                        timestamp_ns: event.meta.timestamp_ns,
                    },
                );
                None
            }
            SessionState::Reconnect => {
                let before = self.disconnected.remove(&id)?;
                let now = Client::of(event)?;
                (before.client != now).then(|| hijack_alert(event, id, &before, now))
            }
            SessionState::Logon | SessionState::Logoff => {
                self.disconnected.remove(&id);
                None
            }
            SessionState::Connect => None,
        }
    }
}

fn hijack_alert(event: &SessionEvent, id: u32, before: &Disconnected, now: Client) -> Alert {
    let away_s = event.meta.timestamp_ns.saturating_sub(before.timestamp_ns) / 1_000_000_000;
    Alert {
        technique: "T1563.002",
        severity: Severity::Medium,
        message: format!(
            "session {id} (user={}) disconnected from {} and reconnected from {now} {away_s}s later — \
             RDP session hijack shape, or its owner moving between clients",
            event.target_user, before.client,
        ),
    }
}
