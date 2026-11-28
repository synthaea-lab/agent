//! Wire → schema normalization. Pure functions, platform-independent, unit-tested on
//! every CI leg — the Linux-only part of this crate is loading/draining, not this.
//!
//! `boot_epoch_offset_ns` is the difference between the epoch clock and the monotonic
//! clock the probes stamp events with (`bpf_ktime_get_ns`); the sensor computes it
//! once at startup and passes it here so schema timestamps are epoch nanoseconds.

use schema::{ContainerContext, EventMeta, User};
use sensor_linux_wire as wire;

mod file;
mod network;
mod privilege;
mod process;

pub use self::{
    file::{
        file_chmod, file_chown, file_delete, file_open, file_removexattr, file_rename,
        file_set_time, file_setxattr, file_write, mount,
    },
    network::{
        connect, dns_udp_query, socket_accept, socket_bind, socket_create, socket_listen, udp_recv,
        udp_send,
    },
    privilege::{bpf_operation, cap_set, identity_change, kernel_module, namespace, prctl},
    process::{
        SignalParties, exec, memfd_create, process_vm_read, process_vm_write, ptrace, signal,
        signals_lost,
    },
};

/// Tripwire: bumping the wire ABI must come here to revisit the mappings below.
///
/// v5 (#90) only added `TlsCaptureEvent`/`ReadlineInputEvent` — neither is imported
/// here, and none of the structs this module maps (`EventMeta`, `ExecEvent`,
/// `ConnectEvent`, `FileOpenEvent`, `ContainerContext`) changed shape, so the
/// mappings below still hold; bumped straight to 5 after that audit.
///
/// v6 (#262) added `FileWriteEvent`, `FileDeleteEvent`, `FileRenameEvent` — new
/// mapping functions `file_write`/`file_delete`/`file_rename` added below, same
/// `meta()` helper reused; no existing mapping changed shape.
///
/// v7 (#263) added `SocketBindEvent` — new `socket_bind` mapping function below,
/// same address-family logic as `connect`; no existing mapping changed shape.
///
/// v8 (#262 Phase 2) added `FileChmodEvent`/`FileChownEvent` — new mapping functions
/// `file_chmod`/`file_chown` added below, same path-decoding shape as `file_delete`;
/// no existing mapping changed shape.
///
/// v9 (#263 Phase 2) added `UdpSendEvent` — new `udp_send` mapping function below,
/// same address-family logic as `connect`/`socket_bind`, reusing the schema type
/// already shared with the Windows ETW UDP producer; no existing mapping changed
/// shape.
///
/// v10 (#263 Phase 2) added `SocketListenEvent` — new `socket_listen` mapping
/// function below, converting the wire struct's `addr_resolved` bool + zeroed
/// fields into `Option<IpAddr>`/`Option<u16>` on the schema side; no existing
/// mapping changed shape.
///
/// v11 (#263 Phase 2) added `SocketAcceptEvent` — new `socket_accept` mapping
/// function below, same address-family logic as `connect`/`socket_bind`; no
/// existing mapping changed shape.
///
/// v22 (#263) added `UdpRecvEvent` — new `udp_recv` mapping function below, the
/// peer-address counterpart of `udp_send`; no existing mapping changed shape.
///
/// v12 (#262 Phase 3) added `FileSetxattrEvent`/`FileRemovexattrEvent` — new
/// mapping functions `file_setxattr`/`file_removexattr` below, same path-decoding
/// shape as `file_chmod`/`file_chown` plus a second nul-padded field (the xattr
/// `name`); no existing mapping changed shape.
///
/// v13 (#362 and #264, originally claimed as v12 — see that constant's doc) added
/// `MountEvent`/`SignalEvent` and `KernelModuleEvent`/`BpfEvent`. `mount` turns
/// zero-length `source`/`fs_type` (umount2(2) has neither) into `None`, matching
/// how the macOS producer reports them absent. `signal` takes `target_image_path`
/// from the caller rather than the wire event — the probe filters to the agent's
/// own pid (v1 scope), which the sensor already knows its own exe path for
/// without a `/proc/<pid>/exe` readlink per event. `kernel_module` turns the wire
/// struct's `action: u8` discriminant into `schema::KernelModuleAction` and its
/// always-populated `fd`/`image_len` sentinels (`-1`/`0` when not applicable to
/// the action) into `Option`s. No existing mapping changed shape.
///
/// v14 (#265, originally claimed as v12 — see that constant's doc) added
/// `PtraceEvent`, `ProcessVmReadEvent`, `ProcessVmWriteEvent`, `MemfdCreateEvent`
/// — new `ptrace`/`process_vm_read`/`process_vm_write`/`memfd_create` mapping
/// functions below; no existing mapping changed shape.
///
/// v15 (#266, originally claimed as v12 — see that constant's doc) added
/// `IdentityChangeEvent`/`CapSetEvent`/`NamespaceEvent` — new
/// `identity_change`/`cap_set`/`namespace` mapping functions below.
/// `identity_change` turns the wire struct's `kind: u8` discriminant into
/// `schema::IdentityChangeKind` and only surfaces `effective`/`saved` as
/// `Some` for the two `SetRes*` kinds (never from the wire value itself,
/// which is always populated — see that struct's doc). `namespace` does the
/// same `syscall: u8` → enum conversion and surfaces `fd` as `Some` only for
/// `setns`. No existing mapping changed shape.
///
/// v16 (#267 Phase 1, originally claimed as v12 — see that constant's doc)
/// added `GetAddrInfoEvent` — not imported here either (the DNS uprobe pair
/// lives in `sensor-linux-uprobes`, not this crate's tracepoint-only
/// surface); no existing mapping changed shape.
///
/// v17 (#457) widened `CapSetEvent`'s `effective`/`permitted`/`inheritable`
/// from `u32` to `u64` (the probe now reads the capability high word too);
/// `cap_set` passes them through unchanged. `kernel_module` also takes the
/// resolved path of a `finit_module` fd from the caller (`sensor.rs` reads
/// `/proc/<pid>/fd/<fd>`), keeping this module free of filesystem access.
///
/// v18 (#510) added `MemfdCreateEvent::fd` (the descriptor `memfd_create(2)`
/// returned); `memfd_create` passes it through unchanged.
///
/// v19 (#457) added `PrctlEvent`; `prctl` maps it one-to-one.
///
/// v21 (#515) added `old_dfd`/`new_dfd` to `FileRenameEvent`; `file_rename` resolves a
/// relative path against them.
///
/// v22 (#263) added `UdpRecvEvent`; `udp_recv` maps it one-to-one.
///
/// v23 (#263) added `SocketCreateEvent` — new `socket_create` mapping function
/// below, maps `domain`/`socket_type`/`protocol`/`fd` one-to-one; no existing
/// mapping changed shape.
///
/// v24 (#784) added `grandparent_pid`/`parent_execd`/`grandparent_generation` to `ExecEvent`
/// and `execd` to `LineageEntry`; `exec` maps none of them (the parent-image cache reads them
/// from the wire event, see `parent_image`), so no mapping changed shape.
///
/// v25 (#458) changed `GetAddrInfoEvent` — not imported here (the uprobes crate maps it).
///
/// v26 (#458 part 3) added `DnsUdpQueryEvent` — new `dns_udp_query` mapping function below, which
/// parses the question out of the datagram and reuses `schema::DnsQueryEvent`; no existing mapping
/// changed shape.
///
/// v27 (#1036) added `FileSetTimeEvent` — new `file_set_time` mapping function below, to the
/// platform-neutral `schema::FileSetTimeEvent` (requested Unix times converted to `FILETIME`
/// units, only the fields the caller chose set); no existing mapping changed shape.
const _: () = assert!(wire::WIRE_VERSION == 29);

/// Same, but an empty buffer means "not captured" rather than the empty string —
/// the probe leaves `pcomm` zeroed when the fork-lineage map had no entry.
fn comm_opt(comm: &[u8; wire::TASK_COMM_LEN]) -> Option<String> {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    (end != 0).then(|| String::from_utf8_lossy(&comm[..end]).into_owned())
}

/// `container` is resolved by the caller: the id from `meta.cgroup_id` (captured
/// kernel-side, resolved against cgroupfs — issue #204) at drain time, `image`/
/// `name` from a cached Docker/containerd socket lookup keyed on that id (issue
/// #80 — both halves of the attribution this crate's doc comment on
/// `ContainerContext` originally deferred).
fn meta(
    meta: &wire::EventMeta,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> EventMeta {
    EventMeta {
        pid: meta.pid,
        ppid: meta.ppid,
        user: User::Unix {
            uid: meta.uid,
            gid: meta.gid,
        },
        timestamp_ns: meta.timestamp_ns.saturating_add(boot_epoch_offset_ns),
        comm: wire::comm_str(&meta.comm),
        container,
        // `0` is the wire's "no stamp" (a `PROC_LINEAGE` miss), which the schema
        // spells `None` so a consumer never mistakes it for a generation (#519).
        process_generation: (meta.process_generation != 0).then_some(meta.process_generation),
        parent_process_generation: (meta.parent_generation != 0).then_some(meta.parent_generation),
    }
}

#[cfg(test)]
mod tests;
