//! Shared test-fixture baselines (feature `test-fixtures`, dev-dependencies
//! only — never compiled into a shipping build).
//!
//! Before this module, every detection crate hand-wrote the same full event
//! literals in its test helpers (~12 copies), and each new field on an event
//! struct forced a mechanical edit in all of them. Tests now spell only the
//! fields they are about and take the rest from here via struct-update syntax:
//!
//! ```
//! use schema::{Event, ExecEvent, fixtures};
//!
//! let event = Event::Exec(ExecEvent {
//!     cmdline: "curl -fsSL https://x.test".into(),
//!     ..fixtures::exec()
//! });
//! ```
//!
//! Every value here is deliberately **neutral** (zero, empty, `Unknown`,
//! `None`): a test that asserts on a field it did not set is asserting on
//! nothing, and a neutral baseline makes that visible instead of smuggling in
//! plausible-looking data. The exception is addresses, which need *some*
//! value — they use TEST-NET-1 (`192.0.2.0/24`, RFC 5737) so a fixture address
//! can never be mistaken for a real one.
//!
//! `tests/golden.rs` deliberately does NOT use these: the golden suite pins
//! serialization, so it spells every field explicitly on purpose.

use core::net::{IpAddr, Ipv4Addr};

use crate::{
    AmsiContentEvent, AssemblyLoadEvent, AuthEvent, AuthKind, AuthOutcome, BpfEvent, CapSetEvent,
    ConnectEvent, DefenderEvent, DefenderEventKind, DnsQueryEvent, EventMeta, ExecEvent,
    FileChmodEvent, FileChownEvent, FileDeleteEvent, FileOpenEvent, FileQuarantineEvent,
    FileRemovexattrEvent, FileRenameEvent, FileSetxattrEvent, FileWriteEvent, HttpRequestEvent,
    HttpSignature, HttpSummaryEvent, IdentityChangeEvent, IdentityChangeKind, ImageLoadEvent,
    KernelModuleAction, KernelModuleEvent, ListenPortEvent, MemfdCreateEvent, NamespaceEvent,
    NamespaceSyscall, NetworkFlowEvent, PrctlEvent, ProcessVmReadEvent, ProcessVmWriteEvent,
    PtraceEvent, ReadlineInputEvent, RegistrySetEvent, ScriptBlockEvent, SessionEvent,
    SessionState, ShellType, SmbConnectEvent, SocketAcceptEvent, SocketBindEvent,
    SocketListenEvent, TlsCaptureEvent, TlsDirection, TlsLibraryType, UdpRecvEvent, UdpSendEvent,
    User, WmiActivityEvent,
};

/// The TEST-NET-1 address every address-carrying fixture defaults to.
pub const TEST_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

/// Neutral [`EventMeta`]: pid/ppid 0, [`User::Unknown`], timestamp 0, empty comm.
#[must_use]
pub fn meta() -> EventMeta {
    EventMeta {
        pid: 0,
        ppid: 0,
        user: User::Unknown,
        timestamp_ns: 0,
        comm: String::new(),
        container: None,
        process_generation: None,
        parent_process_generation: None,
    }
}

/// Neutral [`ExecEvent`].
#[must_use]
pub fn exec() -> ExecEvent {
    ExecEvent {
        meta: meta(),
        image_path: String::new(),
        cmdline: String::new(),
        argv: Vec::new(),
        parent_comm: None,
        parent_image_path: None,
        sha256: None,
        signature: None,
        env_security: Vec::new(),
    }
}

/// Neutral [`FileOpenEvent`] (`flags: 0` = `O_RDONLY`).
#[must_use]
pub fn file_open() -> FileOpenEvent {
    FileOpenEvent {
        meta: meta(),
        path: String::new(),
        flags: 0,
    }
}

/// Neutral [`ConnectEvent`] to [`TEST_ADDR`].
#[must_use]
pub fn connect() -> ConnectEvent {
    ConnectEvent {
        meta: meta(),
        daddr: TEST_ADDR,
        dport: 0,
    }
}

/// Neutral [`DnsQueryEvent`].
#[must_use]
pub fn dns_query() -> DnsQueryEvent {
    DnsQueryEvent {
        meta: meta(),
        query: String::new(),
        qtype: 0,
        result: None,
        status: 0,
    }
}

/// Neutral [`RegistrySetEvent`].
#[must_use]
pub fn registry_set() -> RegistrySetEvent {
    RegistrySetEvent {
        meta: meta(),
        key: String::new(),
        value_name: String::new(),
        data_type: 0,
        data: None,
    }
}

/// Neutral [`ImageLoadEvent`].
#[must_use]
pub fn image_load() -> ImageLoadEvent {
    ImageLoadEvent {
        meta: meta(),
        image_path: String::new(),
    }
}

/// Neutral [`DefenderEvent`].
#[must_use]
pub fn defender() -> DefenderEvent {
    DefenderEvent {
        meta: meta(),
        kind: DefenderEventKind::Detection,
        detection_id: None,
        threat_name: None,
        severity_id: None,
        category_id: None,
        action_id: None,
        path: None,
        process_name: None,
        user: None,
        setting: None,
        old_value: None,
        new_value: None,
    }
}

/// Neutral [`AmsiContentEvent`].
#[must_use]
pub fn amsi_content() -> AmsiContentEvent {
    AmsiContentEvent {
        meta: meta(),
        session: 0,
        app_name: String::new(),
        content_name: None,
        content_size: 0,
        original_size: 0,
        text: None,
        text_truncated: false,
        content_hash: String::new(),
        scan_result: 0,
    }
}

/// Neutral [`ScriptBlockEvent`].
#[must_use]
pub fn script_block() -> ScriptBlockEvent {
    ScriptBlockEvent {
        meta: meta(),
        script_block_id: String::new(),
        path: None,
        text: String::new(),
        message_number: 0,
        message_total: 0,
    }
}

/// Neutral [`WmiActivityEvent`].
#[must_use]
pub fn wmi_activity() -> WmiActivityEvent {
    WmiActivityEvent {
        meta: meta(),
        namespace: String::new(),
        query: None,
        method: None,
    }
}

/// Neutral [`AssemblyLoadEvent`].
#[must_use]
pub fn assembly_load() -> AssemblyLoadEvent {
    AssemblyLoadEvent {
        meta: meta(),
        assembly_name: String::new(),
        flags: 0,
    }
}

/// Neutral [`SmbConnectEvent`].
#[must_use]
pub fn smb_connect() -> SmbConnectEvent {
    SmbConnectEvent {
        meta: meta(),
        server_name: String::new(),
    }
}

/// Neutral [`UdpSendEvent`] to [`TEST_ADDR`].
#[must_use]
pub fn udp_send() -> UdpSendEvent {
    UdpSendEvent {
        meta: meta(),
        daddr: TEST_ADDR,
        dport: 0,
        size: 0,
    }
}

/// Neutral [`UdpRecvEvent`] from [`TEST_ADDR`].
#[must_use]
pub fn udp_recv() -> UdpRecvEvent {
    UdpRecvEvent {
        meta: meta(),
        peer_addr: TEST_ADDR,
        peer_port: 0,
        size: 0,
    }
}

/// Neutral successful-logon [`AuthEvent`].
#[must_use]
pub fn auth() -> AuthEvent {
    AuthEvent {
        meta: meta(),
        outcome: AuthOutcome::Success,
        kind: AuthKind::Logon,
        target_user: String::new(),
        target_user_sid: None,
        source_address: None,
        status_code: None,
    }
}

/// Neutral [`SessionEvent`]: a console logon to session 1, no account.
#[must_use]
pub fn session() -> SessionEvent {
    SessionEvent {
        meta: meta(),
        state: SessionState::Logon,
        session_id: Some(1),
        target_user: String::new(),
        source_address: None,
        console: true,
    }
}

/// Neutral [`FileQuarantineEvent`]: empty path, no agent or URLs.
#[must_use]
pub fn file_quarantine() -> FileQuarantineEvent {
    FileQuarantineEvent {
        meta: meta(),
        path: String::new(),
        agent: None,
        origin_url: None,
        referrer_url: None,
    }
}

/// Neutral [`ListenPortEvent`] on [`TEST_ADDR`].
#[must_use]
pub fn listen_port() -> ListenPortEvent {
    ListenPortEvent {
        meta: meta(),
        local_addr: TEST_ADDR,
        local_port: 0,
    }
}

/// Neutral [`NetworkFlowEvent`] to [`TEST_ADDR`], no counters.
#[must_use]
pub fn network_flow() -> NetworkFlowEvent {
    NetworkFlowEvent {
        meta: meta(),
        local_port: 0,
        daddr: TEST_ADDR,
        dport: 0,
        protocol: 0,
        bytes_sent: None,
        bytes_received: None,
        packets_sent: None,
        packets_received: None,
    }
}

/// Neutral [`TlsCaptureEvent`] (read direction, OpenSSL, empty payload).
#[must_use]
pub fn tls_capture() -> TlsCaptureEvent {
    TlsCaptureEvent {
        meta: meta(),
        direction: TlsDirection::Read,
        lib_type: TlsLibraryType::OpenSsl,
        data: Vec::new(),
    }
}

/// Neutral [`ReadlineInputEvent`] (bash, empty input).
#[must_use]
pub fn readline_input() -> ReadlineInputEvent {
    ReadlineInputEvent {
        meta: meta(),
        shell_type: ShellType::Bash,
        input: String::new(),
    }
}

/// Neutral [`FileWriteEvent`].
#[must_use]
pub fn file_write() -> FileWriteEvent {
    FileWriteEvent {
        meta: meta(),
        fd: 0,
        bytes_requested: 0,
    }
}

/// Neutral [`FileDeleteEvent`].
#[must_use]
pub fn file_delete() -> FileDeleteEvent {
    FileDeleteEvent {
        meta: meta(),
        path: String::new(),
    }
}

/// Neutral [`FileRenameEvent`].
#[must_use]
pub fn file_rename() -> FileRenameEvent {
    FileRenameEvent {
        meta: meta(),
        old_path: String::new(),
        new_path: String::new(),
        executable_path: None,
    }
}

/// Neutral [`SocketBindEvent`] on [`TEST_ADDR`].
#[must_use]
pub fn socket_bind() -> SocketBindEvent {
    SocketBindEvent {
        meta: meta(),
        local_addr: TEST_ADDR,
        local_port: 0,
    }
}

/// Neutral [`FileChmodEvent`].
#[must_use]
pub fn file_chmod() -> FileChmodEvent {
    FileChmodEvent {
        meta: meta(),
        path: String::new(),
        mode: 0,
    }
}

/// Neutral [`FileChownEvent`].
#[must_use]
pub fn file_chown() -> FileChownEvent {
    FileChownEvent {
        meta: meta(),
        path: String::new(),
        uid: 0,
        gid: 0,
    }
}

/// Neutral [`FileSetxattrEvent`].
#[must_use]
pub fn file_setxattr() -> FileSetxattrEvent {
    FileSetxattrEvent {
        meta: meta(),
        path: String::new(),
        name: String::new(),
    }
}

/// Neutral [`FileRemovexattrEvent`].
#[must_use]
pub fn file_removexattr() -> FileRemovexattrEvent {
    FileRemovexattrEvent {
        meta: meta(),
        path: String::new(),
        name: String::new(),
    }
}

/// Neutral [`SocketListenEvent`], address unresolved (the common neutral case —
/// bind-correlation is the exception this type has to account for, not the norm).
#[must_use]
pub fn socket_listen() -> SocketListenEvent {
    SocketListenEvent {
        meta: meta(),
        local_addr: None,
        local_port: None,
        backlog: 0,
    }
}

/// Neutral [`SocketAcceptEvent`] on [`TEST_ADDR`].
#[must_use]
pub fn socket_accept() -> SocketAcceptEvent {
    SocketAcceptEvent {
        meta: meta(),
        listen_fd: 0,
        accepted_fd: 0,
        peer_addr: TEST_ADDR,
        peer_port: 0,
    }
}

/// Neutral [`KernelModuleEvent`].
#[must_use]
pub fn kernel_module() -> KernelModuleEvent {
    KernelModuleEvent {
        meta: meta(),
        action: KernelModuleAction::Load,
        name: None,
        fd: None,
        path: None,
        image_len: None,
    }
}

/// Neutral [`BpfEvent`].
#[must_use]
pub fn bpf_operation() -> BpfEvent {
    BpfEvent {
        meta: meta(),
        cmd: 0,
    }
}

/// Neutral [`PtraceEvent`].
#[must_use]
pub fn ptrace() -> PtraceEvent {
    PtraceEvent {
        meta: meta(),
        request: 0,
        target_pid: 0,
        addr: 0,
        data: 0,
    }
}

/// Neutral [`ProcessVmReadEvent`].
#[must_use]
pub fn process_vm_read() -> ProcessVmReadEvent {
    ProcessVmReadEvent {
        meta: meta(),
        target_pid: 0,
        local_iov_count: 0,
        remote_iov_count: 0,
        remote_iov_len: 0,
    }
}

/// Neutral [`ProcessVmWriteEvent`].
#[must_use]
pub fn process_vm_write() -> ProcessVmWriteEvent {
    ProcessVmWriteEvent {
        meta: meta(),
        target_pid: 0,
        local_iov_count: 0,
        remote_iov_count: 0,
        remote_iov_len: 0,
    }
}

/// Neutral [`MemfdCreateEvent`].
#[must_use]
pub fn memfd_create() -> MemfdCreateEvent {
    MemfdCreateEvent {
        meta: meta(),
        name: String::new(),
        flags: 0,
        fd: 0,
    }
}

/// Neutral [`IdentityChangeEvent`].
#[must_use]
pub fn identity_change() -> IdentityChangeEvent {
    IdentityChangeEvent {
        meta: meta(),
        kind: IdentityChangeKind::SetUid,
        real: 0,
        effective: None,
        saved: None,
    }
}

/// Neutral [`CapSetEvent`].
#[must_use]
pub fn cap_set() -> CapSetEvent {
    CapSetEvent {
        meta: meta(),
        target_pid: 0,
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }
}

/// Neutral [`NamespaceEvent`].
#[must_use]
pub fn namespace() -> NamespaceEvent {
    NamespaceEvent {
        meta: meta(),
        syscall: NamespaceSyscall::SetNs,
        fd: None,
        flags: 0,
    }
}

/// Neutral [`HttpRequestEvent`].
#[must_use]
pub fn http_request() -> HttpRequestEvent {
    HttpRequestEvent {
        meta: meta(),
        client: None,
        method: None,
        path: String::new(),
        param_names: Vec::new(),
        status: 200,
        signature: HttpSignature::PathTraversal,
        evidence: None,
        scanner: None,
        truncated: false,
    }
}

/// Neutral [`HttpSummaryEvent`].
#[must_use]
pub fn http_summary() -> HttpSummaryEvent {
    HttpSummaryEvent {
        meta: meta(),
        source: String::new(),
        window_secs: 60,
        requests: 0,
        status_4xx: 0,
        status_5xx: 0,
        distinct_clients: 0,
        top_clients: Vec::new(),
    }
}

/// Neutral [`PrctlEvent`].
#[must_use]
pub fn prctl() -> PrctlEvent {
    PrctlEvent {
        meta: meta(),
        option: crate::PR_CAPBSET_DROP,
        arg: 0,
    }
}
