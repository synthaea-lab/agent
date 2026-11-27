//! Records of a process changing what it, or the kernel, may do.

use super::meta;
use schema::{
    BpfEvent, CapSetEvent, ContainerContext, Event, IdentityChangeEvent, IdentityChangeKind,
    KernelModuleAction, KernelModuleEvent, NamespaceEvent, NamespaceSyscall, PrctlEvent,
};
use sensor_linux_wire as wire;

/// `fd_path` is what `event.fd` pointed at when the event was drained (see
/// [`KernelModuleEvent::path`]); the caller resolves it, this stays pure.
#[must_use]
pub fn kernel_module(
    event: &wire::KernelModuleEvent,
    fd_path: Option<String>,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let action = match event.action {
        1 => KernelModuleAction::LoadFd,
        2 => KernelModuleAction::Unload,
        _ => KernelModuleAction::Load,
    };
    let name = if event.name_len > 0 {
        let raw = &event.name[..(event.name_len as usize).min(wire::MAX_MODULE_NAME_LEN)];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        Some(String::from_utf8_lossy(&raw[..end]).into_owned())
    } else {
        None
    };
    Event::KernelModule(KernelModuleEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        action,
        name,
        fd: (event.fd >= 0).then_some(event.fd),
        path: fd_path.filter(|_| event.action == 1),
        image_len: (event.image_len > 0).then_some(event.image_len),
    })
}

/// Maps a `wire::BpfEvent` to `Event::BpfOperation`; `cmd` is the raw `bpf(2)` command
/// (map create, program load or attach). `boot_epoch_offset_ns` and `container` as in [`file_open`](super::file_open).
#[must_use]
pub fn bpf_operation(
    event: &wire::BpfEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    Event::BpfOperation(BpfEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        cmd: event.cmd,
    })
}

/// Maps a `wire::PrctlEvent` to `Event::Prctl`. The probe only reports `PR_SET_SECUREBITS` and
/// `PR_CAPBSET_DROP`. `boot_epoch_offset_ns` and `container` as in [`file_open`](super::file_open).
#[must_use]
pub fn prctl(
    event: &wire::PrctlEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    Event::Prctl(PrctlEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        option: event.option,
        arg: event.arg,
    })
}

/// Maps a `wire::IdentityChangeEvent` to `Event::IdentityChange`. An unknown `kind` code is read as `SetUid`.
/// `effective` and `saved` are set only for the `setres*` calls. `boot_epoch_offset_ns` and `container` as in [`file_open`](super::file_open).
#[must_use]
pub fn identity_change(
    event: &wire::IdentityChangeEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let (kind, is_res) = match event.kind {
        1 => (IdentityChangeKind::SetGid, false),
        2 => (IdentityChangeKind::SetResUid, true),
        3 => (IdentityChangeKind::SetResGid, true),
        4 => (IdentityChangeKind::SetFsUid, false),
        5 => (IdentityChangeKind::SetFsGid, false),
        _ => (IdentityChangeKind::SetUid, false),
    };
    Event::IdentityChange(IdentityChangeEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        kind,
        real: event.real,
        effective: is_res.then_some(event.effective),
        saved: is_res.then_some(event.saved),
    })
}

/// Maps a `wire::CapSetEvent` to `Event::CapSet`: the target pid and the effective, permitted and inheritable
/// capability sets as bitmasks. `boot_epoch_offset_ns` and `container` as in [`file_open`](super::file_open).
#[must_use]
pub fn cap_set(
    event: &wire::CapSetEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    Event::CapSet(CapSetEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        target_pid: event.target_pid,
        effective: event.effective,
        permitted: event.permitted,
        inheritable: event.inheritable,
    })
}

/// Maps a `wire::NamespaceEvent` to `Event::Namespace`: `syscall` 0 is `setns(2)` (with its `fd`),
/// anything else `unshare(2)` (`fd` is `None`). `boot_epoch_offset_ns` and `container` as in [`file_open`](super::file_open).
#[must_use]
pub fn namespace(
    event: &wire::NamespaceEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let is_setns = event.syscall == 0;
    Event::Namespace(NamespaceEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        syscall: if is_setns {
            NamespaceSyscall::SetNs
        } else {
            NamespaceSyscall::Unshare
        },
        fd: is_setns.then_some(event.fd),
        flags: event.flags,
    })
}
