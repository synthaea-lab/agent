//! The transport layer: OS-native listener, per-connection stream, and
//! peer-credentials read.
//!
//! One file, one place for all the `#[cfg(target_family = "…")]` — the
//! server and client never see anything OS-specific, they talk in terms
//! of the opaque [`Listener`] / [`Stream`] types this module exports.
//!
//! ## Layout per OS
//!
//! - **Windows** — a named pipe, path `\\.\pipe\synthaea-agent` by
//!   convention (the actual name comes from `config.ipc.endpoint`).
//!   Peer credentials are read via `GetNamedPipeClientProcessId` +
//!   `OpenProcessToken` + `GetTokenInformation(TokenElevation)` —
//!   deliberately elevation, not group membership: the auth check is
//!   "was this process launched elevated?", which is what an operator
//!   running `cli` as Administrator will pass.
//! - **Unix (Linux, macOS)** — an `AF_UNIX` stream socket at the
//!   filesystem path from `config.ipc.endpoint` (`/var/run/synthaea/
//!   agent.sock` by default). Peer credentials come from
//!   `SO_PEERCRED` (or `LOCAL_PEERCRED` on macOS) — tokio's
//!   [`tokio::net::UnixStream::peer_cred`] wraps the syscall.
//!
//! ## Authorization policy (v1)
//!
//! [`PeerCreds::check_authorized`] returns `Ok(())` iff the peer is
//! "privileged": `uid == 0` on Unix, `TokenIsElevated == true` on
//! Windows. Any other peer is rejected. This is stricter than what
//! ADR-0010 mandates for the eventual UI (which will need a
//! per-capability check via `policy`), and deliberately: v1 has no
//! mutating commands, so read-only-for-root is a safe starting point.
//! Widening this to "any local user" is a policy change, not a code
//! change — the current shape stays.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Peer identity read off an already-accepted connection. What the two
/// platforms populate is not the same, so `Option` fields on either
/// side reflect "this identity is not exposed on this OS". The
/// [`Self::check_authorized`] check consumes only the fields it needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCreds {
    /// The peer process's PID, on both OSes. Not authenticated — treat
    /// as informational (for logging, correlation) rather than
    /// authoritative.
    pub pid: u32,
    /// The peer process's effective UID. Unix only; `None` on Windows.
    pub uid: Option<u32>,
    /// Whether the peer's process token is elevated. Windows only;
    /// `None` on Unix.
    pub is_elevated: Option<bool>,
}

impl PeerCreds {
    /// The v1 authorization gate: root on Unix OR elevated on Windows.
    ///
    /// # Errors
    ///
    /// Returns `Err` with a human-readable reason string when the peer
    /// does not satisfy the policy. The reason is safe to log — it
    /// carries the identity that failed, not internal state.
    pub fn check_authorized(&self) -> Result<(), String> {
        match (self.uid, self.is_elevated) {
            // Unix side: uid=0 (root) authorized.
            (Some(0), _) => Ok(()),
            (Some(uid), _) => Err(format!("caller uid {uid} is not root (uid=0)")),
            // Windows side: TokenIsElevated true.
            (None, Some(true)) => Ok(()),
            (None, Some(false)) => Err(format!(
                "caller pid {} is not running elevated (Administrators)",
                self.pid
            )),
            // Neither field populated — should never happen for an
            // accepted connection; treat as unauthorized to fail closed.
            (None, None) => Err(format!(
                "caller pid {} exposes no peer credentials to authorize against",
                self.pid
            )),
        }
    }
}

// ── Windows ──────────────────────────────────────────────────────────────

#[cfg(windows)]
mod platform {
    use super::*;
    use tokio::net::windows::named_pipe::{
        ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
    };

    /// A named-pipe listener. Not a socket — Windows named pipes are
    /// their own IPC primitive, but tokio wraps them behind
    /// `NamedPipeServer` with the same read/write semantics as a
    /// stream socket.
    ///
    /// Tokio's model for named pipes is: each "listener" is one
    /// pipe-instance that becomes the accepted connection once a
    /// client connects; we then create the NEXT pipe instance for the
    /// next client. That's the "one-instance-per-accept" pattern the
    /// code below implements.
    pub struct Listener {
        endpoint: String,
        // The next instance waiting to be handed to a client.
        // Rebound after each accept in `accept()`.
        current: NamedPipeServer,
    }

    impl Listener {
        /// Bind a named-pipe listener at `endpoint`.
        ///
        /// # Errors
        ///
        /// Underlying `io::Error` from `ServerOptions::create` — most
        /// often "access denied" (needs Admin on Windows to reserve a
        /// well-known pipe name) or "instances already exist".
        pub async fn bind(endpoint: &str) -> io::Result<Self> {
            let current = ServerOptions::new()
                .first_pipe_instance(true)
                .create(endpoint)?;
            Ok(Self {
                endpoint: endpoint.to_string(),
                current,
            })
        }

        /// Await the next client, read its peer credentials, and hand
        /// back the connected [`Stream`] plus [`PeerCreds`].
        ///
        /// # Errors
        ///
        /// - Underlying `io::Error` on a pipe-connect failure.
        /// - `io::Error` on the Win32 peer-credentials read (see
        ///   `read_peer_creds`) — the accepted client is dropped in
        ///   that case, the pipe instance recycled for the next call.
        pub async fn accept(&mut self) -> io::Result<(Stream, PeerCreds)> {
            // `connect()` awaits the next client on the current instance.
            self.current.connect().await?;
            // Read peer creds BEFORE handing the pipe over — they come
            // from Win32 on the raw handle of the connected instance.
            let creds = read_peer_creds(&self.current)?;
            // Swap: create the next instance to keep the pipe name
            // reserved, and hand the just-connected one to the caller.
            let next = ServerOptions::new().create(&self.endpoint)?;
            let just_connected = std::mem::replace(&mut self.current, next);
            Ok((Stream::Server(just_connected), creds))
        }
    }

    /// A per-connection stream. Two variants because tokio's named-pipe
    /// types are distinct on the server and client sides — same
    /// AsyncRead/AsyncWrite semantics, different concrete types. We
    /// dispatch in the poll_ methods rather than round-trip through the
    /// raw HANDLE (which would work syscall-wise but is not something
    /// tokio's API commits to supporting across versions).
    pub enum Stream {
        Server(NamedPipeServer),
        Client(NamedPipeClient),
    }

    impl AsyncRead for Stream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match &mut *self {
                Stream::Server(s) => Pin::new(s).poll_read(cx, buf),
                Stream::Client(c) => Pin::new(c).poll_read(cx, buf),
            }
        }
    }

    impl AsyncWrite for Stream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            match &mut *self {
                Stream::Server(s) => Pin::new(s).poll_write(cx, buf),
                Stream::Client(c) => Pin::new(c).poll_write(cx, buf),
            }
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            match &mut *self {
                Stream::Server(s) => Pin::new(s).poll_flush(cx),
                Stream::Client(c) => Pin::new(c).poll_flush(cx),
            }
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            match &mut *self {
                Stream::Server(s) => Pin::new(s).poll_shutdown(cx),
                Stream::Client(c) => Pin::new(c).poll_shutdown(cx),
            }
        }
    }

    /// The client half, used by [`crate::client::Client`]. On Windows a
    /// named-pipe client is `NamedPipeClient::open()` of the pipe name.
    ///
    /// # Errors
    ///
    /// `io::Error` from `ClientOptions::open` — typically
    /// `ERROR_FILE_NOT_FOUND` if no server is listening on the pipe
    /// name, or `ERROR_ACCESS_DENIED` if the pipe's ACL rejects the
    /// caller.
    pub async fn connect(endpoint: &str) -> io::Result<Stream> {
        let inner = ClientOptions::new().open(endpoint)?;
        Ok(Stream::Client(inner))
    }

    fn read_peer_creds(pipe: &NamedPipeServer) -> io::Result<PeerCreds> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        let raw = pipe.as_raw_handle() as HANDLE;
        let mut client_pid: u32 = 0;

        // SAFETY: `raw` is a valid HANDLE (obtained from the tokio
        // NamedPipeServer we still borrow). `client_pid` is a valid
        // `&mut u32` local. Windows writes at most a u32 to `client_pid`
        // and returns nonzero on success. No borrowed pointer escapes.
        let ok = unsafe { GetNamedPipeClientProcessId(raw, &mut client_pid) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: `client_pid` is a u32, passed by value. `PROCESS_QUERY_LIMITED_INFORMATION`
        // is the minimum right needed for `OpenProcessToken(TOKEN_QUERY, ...)` on
        // another process. Returns a HANDLE we own on success (nonnull) — we CloseHandle
        // it below in every exit path.
        let proc = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, client_pid) };
        if proc.is_null() {
            return Err(io::Error::last_os_error());
        }

        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: `proc` is a valid HANDLE we just opened. `token` is a valid
        // `&mut HANDLE` local; Windows writes a HANDLE into it on success. The
        // returned token is an owned HANDLE — CloseHandle'd below in every path.
        let ok = unsafe { OpenProcessToken(proc, TOKEN_QUERY, &mut token) };
        // SAFETY: `proc` is a valid HANDLE we opened; CloseHandle takes ownership.
        unsafe {
            CloseHandle(proc);
        }
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret_len: u32 = 0;
        // SAFETY: `token` is a valid HANDLE. `TokenElevation` is the correct
        // information class for `TOKEN_ELEVATION`. The buffer/size pair matches
        // the concrete type — no over- or under-run.
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                std::ptr::addr_of_mut!(elevation).cast(),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret_len,
            )
        };
        // SAFETY: `token` is a valid HANDLE we opened; CloseHandle takes ownership.
        unsafe {
            CloseHandle(token);
        }
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(PeerCreds {
            pid: client_pid,
            uid: None,
            is_elevated: Some(elevation.TokenIsElevated != 0),
        })
    }
}

// ── Unix (Linux, macOS) ──────────────────────────────────────────────────

#[cfg(unix)]
mod platform {
    use super::*;
    use tokio::net::{UnixListener, UnixStream};

    /// A Unix-domain-socket listener bound at the caller's endpoint
    /// path. The path is deleted on `bind` if it already exists (the
    /// same posture `systemd` service units take) — otherwise a fresh
    /// bind after a crash would fail with "address in use".
    pub struct Listener {
        inner: UnixListener,
    }

    impl Listener {
        /// Bind a Unix-domain-socket listener at `endpoint`.
        ///
        /// # Errors
        ///
        /// Underlying `io::Error` from `UnixListener::bind` — most
        /// often "permission denied" (the caller cannot write in the
        /// parent directory) or "no such file or directory" (parent
        /// missing).
        pub async fn bind(endpoint: &str) -> io::Result<Self> {
            // Best-effort remove of a stale socket file from a previous run.
            // Not a security concern (the socket path is under
            // /var/run/synthaea/, permissioned to root) — a bind failure
            // due to a stale socket is a service-startup failure, which
            // this line prevents.
            let _ = std::fs::remove_file(endpoint);
            let inner = UnixListener::bind(endpoint)?;
            Ok(Self { inner })
        }

        /// Await the next client and read its peer credentials.
        ///
        /// # Errors
        ///
        /// `io::Error` from `accept` or from the `SO_PEERCRED` /
        /// `LOCAL_PEERCRED` read on the just-accepted socket.
        pub async fn accept(&mut self) -> io::Result<(Stream, PeerCreds)> {
            let (unix, _addr) = self.inner.accept().await?;
            let creds = read_peer_creds(&unix)?;
            Ok((Stream { inner: unix }, creds))
        }
    }

    pub struct Stream {
        inner: UnixStream,
    }

    impl AsyncRead for Stream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for Stream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// Open a client-side connection to the Unix-domain socket at
    /// `endpoint`.
    ///
    /// # Errors
    ///
    /// `io::Error` from `UnixStream::connect` — typically
    /// "connection refused" if no server is listening.
    pub async fn connect(endpoint: &str) -> io::Result<Stream> {
        let inner = UnixStream::connect(endpoint).await?;
        Ok(Stream { inner })
    }

    fn read_peer_creds(sock: &UnixStream) -> io::Result<PeerCreds> {
        let ucred = sock.peer_cred()?;
        Ok(PeerCreds {
            pid: ucred.pid().map(|p| p as u32).unwrap_or(0),
            uid: Some(ucred.uid()),
            is_elevated: None,
        })
    }
}

pub use platform::{connect, Listener, Stream};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_uid_authorized_on_unix_side() {
        let creds = PeerCreds {
            pid: 100,
            uid: Some(0),
            is_elevated: None,
        };
        assert!(creds.check_authorized().is_ok());
    }

    #[test]
    fn non_root_uid_rejected_on_unix_side() {
        let creds = PeerCreds {
            pid: 100,
            uid: Some(1000),
            is_elevated: None,
        };
        let err = creds.check_authorized().unwrap_err();
        assert!(err.contains("1000"));
    }

    #[test]
    fn elevated_authorized_on_windows_side() {
        let creds = PeerCreds {
            pid: 4242,
            uid: None,
            is_elevated: Some(true),
        };
        assert!(creds.check_authorized().is_ok());
    }

    #[test]
    fn non_elevated_rejected_on_windows_side() {
        let creds = PeerCreds {
            pid: 4242,
            uid: None,
            is_elevated: Some(false),
        };
        let err = creds.check_authorized().unwrap_err();
        assert!(err.contains("4242"));
    }

    #[test]
    fn no_creds_at_all_is_unauthorized_by_default() {
        // Fail-closed: an accept path that somehow produced no
        // credentials MUST be treated as unauthorized. Regression
        // guard against a future "let this through, sensor was slow"
        // shortcut.
        let creds = PeerCreds {
            pid: 100,
            uid: None,
            is_elevated: None,
        };
        assert!(creds.check_authorized().is_err());
    }
}
