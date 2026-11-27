//! Code loaded into the kernel.

use super::*;

/// Which of the three kernel-module syscalls produced a [`KernelModuleEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelModuleAction {
    /// `init_module(2)` — raw ELF module image supplied directly in memory.
    Load,
    /// `finit_module(2)` — module image loaded from an already-open file
    /// descriptor.
    LoadFd,
    /// `delete_module(2)` — unload by name.
    Unload,
}

/// Kernel module load/unload (issue #264): `init_module(2)`, `finit_module(2)`,
/// `delete_module(2)`. The classic rootkit-installation primitive — unauthorized
/// module loading is one of the highest-signal kernel-tampering events on Linux.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelModuleEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Whether the module was loaded or unloaded.
    pub action: KernelModuleAction,
    /// The module name — only [`KernelModuleAction::Unload`] receives one
    /// directly as a syscall argument; `init_module`/`finit_module` load a raw
    /// ELF image whose module name lives inside the blob itself, not decoded
    /// here (see `sensor-linux-wire::KernelModuleEvent`'s doc).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The already-open file descriptor [`KernelModuleAction::LoadFd`] loads
    /// from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fd: Option<i32>,
    /// The file [`KernelModuleAction::LoadFd`]'s `fd` refers to, e.g.
    /// `/usr/lib/modules/<release>/kernel/drivers/net/dummy.ko.xz` (v29,
    /// #457). Resolved in userspace from `/proc/<pid>/fd/<fd>` when the event
    /// is drained, so it is best effort: `None` if the loader already closed
    /// the fd or exited. The module name itself still lives inside the image
    /// and is not decoded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Size in bytes of the raw module image [`KernelModuleAction::Load`]
    /// receives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_len: Option<u64>,
}

/// eBPF program/map lifecycle (issue #264): the `bpf(2)` syscall, filtered at
/// the source to `BPF_MAP_CREATE`/`BPF_PROG_LOAD`/`BPF_PROG_ATTACH` — every
/// other `bpf(2)` command (map lookups/updates, the overwhelming majority of
/// real traffic, including this agent's own sensor) never reaches this event
/// stream at all (see `sensor-linux-wire::BpfEvent`'s doc). eBPF-based defense
/// evasion and kernel backdoor detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BpfEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Raw `bpf_cmd` value (`<linux/bpf.h>`) — always one of the three
    /// filtered commands above; not decoded to a name here, same
    /// "sensor reports, detection interprets" split as `PtraceEvent::request`.
    pub cmd: u32,
}
