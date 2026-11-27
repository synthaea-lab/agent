//! The one type every sensor emits and every engine reads.

use super::*;

/// The normalized event envelope.
///
/// `#[non_exhaustive]`: new telemetry categories (registry, DNS, image load, ...) are
/// added as variants without breaking sinks — consumers must have a fall-through arm
/// and treat unknown categories as "not for me".
///
/// Note: Control-plane messages like [`HealthBeacon`] are NOT part of this enum.
/// They flow through a separate channel at the transport layer to avoid polluting
/// the telemetry pipeline with non-process events.
///
/// On the wire an event is tagged by the `snake_case` variant name in a `"type"` field next to the
/// payload's own fields (`{"type": "exec", ...}`); the server and the fixtures key on it.
#[non_exhaustive]
#[expect(missing_docs, reason = "each variant wraps a documented payload type")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Exec(ExecEvent),
    FileOpen(FileOpenEvent),
    Connect(ConnectEvent),
    DnsQuery(DnsQueryEvent),
    RegistrySet(RegistrySetEvent),
    ImageLoad(ImageLoadEvent),
    ScriptBlock(ScriptBlockEvent),
    AmsiContent(AmsiContentEvent),
    Defender(DefenderEvent),
    LdapSearch(LdapSearchEvent),
    NtlmAuth(NtlmAuthEvent),
    LogCleared(LogClearedEvent),
    KerberosDelegationFailure(KerberosDelegationFailureEvent),
    WmiActivity(WmiActivityEvent),
    AssemblyLoad(AssemblyLoadEvent),
    SmbConnect(SmbConnectEvent),
    UdpSend(UdpSendEvent),
    UdpRecv(UdpRecvEvent),
    Auth(AuthEvent),
    Session(SessionEvent),
    ListenPort(ListenPortEvent),
    NetworkFlow(NetworkFlowEvent),
    TlsCapture(TlsCaptureEvent),
    ReadlineInput(ReadlineInputEvent),
    FileWrite(FileWriteEvent),
    FileDelete(FileDeleteEvent),
    FileRename(FileRenameEvent),
    FileSetTime(FileSetTimeEvent),
    RawVolumeOpen(RawVolumeOpenEvent),
    SocketBind(SocketBindEvent),
    FileChmod(FileChmodEvent),
    FileChown(FileChownEvent),
    SocketListen(SocketListenEvent),
    SocketAccept(SocketAcceptEvent),
    SocketCreate(SocketCreateEvent),
    TccDecision(TccDecisionEvent),
    GatekeeperVerdict(GatekeeperVerdictEvent),
    FileQuarantine(FileQuarantineEvent),
    Mount(MountEvent),
    Signal(SignalEvent),
    XpcConnect(XpcConnectEvent),
    FileSetxattr(FileSetxattrEvent),
    FileRemovexattr(FileRemovexattrEvent),
    PolicyDenial(PolicyDenialEvent),
    KernelModule(KernelModuleEvent),
    BpfOperation(BpfEvent),
    Ptrace(PtraceEvent),
    ProcessVmRead(ProcessVmReadEvent),
    ProcessVmWrite(ProcessVmWriteEvent),
    MemfdCreate(MemfdCreateEvent),
    IdentityChange(IdentityChangeEvent),
    CapSet(CapSetEvent),
    Namespace(NamespaceEvent),
    Prctl(PrctlEvent),
    HttpRequest(HttpRequestEvent),
    HttpSummary(HttpSummaryEvent),
    PackageChange(PackageChangeEvent),
    BitsJob(BitsJobEvent),
    UnitStop(UnitStopEvent),
    RemoteThread(RemoteThreadEvent),
    ProcessAccess(ProcessAccessEvent),
}

impl Event {
    /// Returns the process metadata common to all telemetry events.
    ///
    /// Deliberately exhaustive (no wildcard arm): every new [`Event`] variant must
    /// add its own arm here, so a missing one is a compile error rather than a
    /// silently-wrong fallback.
    #[must_use]
    pub fn meta(&self) -> &EventMeta {
        match self {
            Event::Exec(e) => &e.meta,
            Event::FileOpen(e) => &e.meta,
            Event::Connect(e) => &e.meta,
            Event::DnsQuery(e) => &e.meta,
            Event::RegistrySet(e) => &e.meta,
            Event::ImageLoad(e) => &e.meta,
            Event::ScriptBlock(e) => &e.meta,
            Event::AmsiContent(e) => &e.meta,
            Event::Defender(e) => &e.meta,
            Event::LdapSearch(e) => &e.meta,
            Event::NtlmAuth(e) => &e.meta,
            Event::LogCleared(e) => &e.meta,
            Event::KerberosDelegationFailure(e) => &e.meta,
            Event::WmiActivity(e) => &e.meta,
            Event::AssemblyLoad(e) => &e.meta,
            Event::SmbConnect(e) => &e.meta,
            Event::UdpSend(e) => &e.meta,
            Event::UdpRecv(e) => &e.meta,
            Event::Auth(e) => &e.meta,
            Event::Session(e) => &e.meta,
            Event::ListenPort(e) => &e.meta,
            Event::NetworkFlow(e) => &e.meta,
            Event::TlsCapture(e) => &e.meta,
            Event::ReadlineInput(e) => &e.meta,
            Event::FileWrite(e) => &e.meta,
            Event::FileDelete(e) => &e.meta,
            Event::FileRename(e) => &e.meta,
            Event::FileSetTime(e) => &e.meta,
            Event::RawVolumeOpen(e) => &e.meta,
            Event::SocketBind(e) => &e.meta,
            Event::FileChmod(e) => &e.meta,
            Event::FileChown(e) => &e.meta,
            Event::SocketListen(e) => &e.meta,
            Event::SocketAccept(e) => &e.meta,
            Event::SocketCreate(e) => &e.meta,
            Event::TccDecision(e) => &e.meta,
            Event::GatekeeperVerdict(e) => &e.meta,
            Event::FileQuarantine(e) => &e.meta,
            Event::Mount(e) => &e.meta,
            Event::Signal(e) => &e.meta,
            Event::XpcConnect(e) => &e.meta,
            Event::FileSetxattr(e) => &e.meta,
            Event::FileRemovexattr(e) => &e.meta,
            Event::PolicyDenial(e) => &e.meta,
            Event::KernelModule(e) => &e.meta,
            Event::BpfOperation(e) => &e.meta,
            Event::Ptrace(e) => &e.meta,
            Event::ProcessVmRead(e) => &e.meta,
            Event::ProcessVmWrite(e) => &e.meta,
            Event::MemfdCreate(e) => &e.meta,
            Event::IdentityChange(e) => &e.meta,
            Event::CapSet(e) => &e.meta,
            Event::Namespace(e) => &e.meta,
            Event::Prctl(e) => &e.meta,
            Event::HttpRequest(e) => &e.meta,
            Event::HttpSummary(e) => &e.meta,
            Event::PackageChange(e) => &e.meta,
            Event::BitsJob(e) => &e.meta,
            Event::UnitStop(e) => &e.meta,
            Event::RemoteThread(e) => &e.meta,
            Event::ProcessAccess(e) => &e.meta,
            // No wildcard arm, on purpose: #[non_exhaustive] has no effect inside
            // the defining crate, so a new variant without its arm here is a
            // compile error — the reminder the doc comment above promises.
        }
    }
}
