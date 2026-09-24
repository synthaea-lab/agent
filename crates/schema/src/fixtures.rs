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
    AssemblyLoadEvent, AuthEvent, AuthKind, AuthOutcome, BpfEvent, CapSetEvent, ConnectEvent,
    DnsQueryEvent, EventMeta, ExecEvent, FileChmodEvent, FileChownEvent, FileDeleteEvent,
    FileOpenEvent, FileRemovexattrEvent, FileRenameEvent, FileSetxattrEvent, FileWriteEvent,
    IdentityChangeEvent, IdentityChangeKind, ImageLoadEvent, KernelModuleAction, KernelModuleEvent,
    ListenPortEvent, MemfdCreateEvent, NamespaceEvent, NamespaceSyscall, NetworkFlowEvent,
    ProcessVmReadEvent, ProcessVmWriteEvent, PtraceEvent, ReadlineInputEvent, RegistrySetEvent,
    ScriptBlockEvent, ShellType, SmbConnectEvent, SocketAcceptEvent, SocketBindEvent,
    SocketListenEvent, TlsCaptureEvent, TlsDirection, TlsLibraryType, UdpSendEvent, User,
    WmiActivityEvent,
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
