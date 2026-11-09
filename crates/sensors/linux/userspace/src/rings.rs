//! The ring buffers the Linux sensor polls, one per event category, taken out of the loaded
//! eBPF object and registered with tokio, plus the glue from a ready ring to one drain.

use aya::maps::{MapData, RingBuf};
use schema::{
    Event,
    sensor::{EventSink, SensorError},
};
use tokio::io::unix::{AsyncFd, AsyncFdReadyMutGuard};

use crate::{
    drain::{Drained, WireRecord, drain_records, read_wire},
    ebpf::err,
};

pub(crate) type Ring = AsyncFd<RingBuf<MapData>>;

/// One ring per eBPF event map. `file_set_time` is `None` when its LSM hook did not attach.
pub(crate) struct RingBuffers {
    pub(crate) exec: Ring,
    pub(crate) file_open: Ring,
    pub(crate) connect: Ring,
    pub(crate) file_write: Ring,
    pub(crate) file_delete: Ring,
    pub(crate) file_rename: Ring,
    pub(crate) socket_bind: Ring,
    pub(crate) file_chmod: Ring,
    pub(crate) file_set_time: Option<Ring>,
    pub(crate) file_chown: Ring,
    pub(crate) udp_send: Ring,
    pub(crate) udp_recv: Ring,
    pub(crate) dns_udp: Ring,
    pub(crate) socket_listen: Ring,
    pub(crate) socket_accept: Ring,
    pub(crate) socket_create: Ring,
    pub(crate) file_setxattr: Ring,
    pub(crate) file_removexattr: Ring,
    pub(crate) mount: Ring,
    pub(crate) signal: Ring,
    pub(crate) kernel_module: Ring,
    pub(crate) bpf: Ring,
    pub(crate) prctl: Ring,
    pub(crate) ptrace: Ring,
    pub(crate) process_vm_read: Ring,
    pub(crate) process_vm_write: Ring,
    pub(crate) memfd_create: Ring,
    pub(crate) identity_change: Ring,
    pub(crate) capset: Ring,
    pub(crate) namespace: Ring,
}

impl RingBuffers {
    /// Takes every event ring out of `ebpf`; `FILE_SET_TIME_EVENTS` only when `set_time_live`.
    pub(crate) fn open(ebpf: &mut aya::Ebpf, set_time_live: bool) -> Result<Self, SensorError> {
        let mut ring = |map: &str| open_ring(ebpf, map);
        Ok(Self {
            exec: ring("EXEC_EVENTS")?,
            file_open: ring("FILE_OPEN_EVENTS")?,
            connect: ring("CONNECT_EVENTS")?,
            file_write: ring("FILE_WRITE_EVENTS")?,
            file_delete: ring("FILE_DELETE_EVENTS")?,
            file_rename: ring("FILE_RENAME_EVENTS")?,
            socket_bind: ring("SOCKET_BIND_EVENTS")?,
            file_chmod: ring("FILE_CHMOD_EVENTS")?,
            file_set_time: if set_time_live {
                Some(ring("FILE_SET_TIME_EVENTS")?)
            } else {
                None
            },
            file_chown: ring("FILE_CHOWN_EVENTS")?,
            udp_send: ring("UDP_SEND_EVENTS")?,
            udp_recv: ring("UDP_RECV_EVENTS")?,
            dns_udp: ring("DNS_UDP_EVENTS")?,
            socket_listen: ring("SOCKET_LISTEN_EVENTS")?,
            socket_accept: ring("SOCKET_ACCEPT_EVENTS")?,
            socket_create: ring("SOCKET_CREATE_EVENTS")?,
            file_setxattr: ring("FILE_SETXATTR_EVENTS")?,
            file_removexattr: ring("FILE_REMOVEXATTR_EVENTS")?,
            mount: ring("MOUNT_EVENTS")?,
            signal: ring("SIGNAL_EVENTS")?,
            kernel_module: ring("KERNEL_MODULE_EVENTS")?,
            bpf: ring("BPF_EVENTS")?,
            prctl: ring("PRCTL_EVENTS")?,
            ptrace: ring("PTRACE_EVENTS")?,
            process_vm_read: ring("PROCESS_VM_READ_EVENTS")?,
            process_vm_write: ring("PROCESS_VM_WRITE_EVENTS")?,
            memfd_create: ring("MEMFD_CREATE_EVENTS")?,
            identity_change: ring("IDENTITY_CHANGE_EVENTS")?,
            capset: ring("CAPSET_EVENTS")?,
            namespace: ring("NAMESPACE_EVENTS")?,
        })
    }
}

fn open_ring(ebpf: &mut aya::Ebpf, map: &str) -> Result<Ring, SensorError> {
    let m = ebpf
        .take_map(map)
        .ok_or_else(|| err(format!("map {map} not found in eBPF object")))?;
    let rb =
        RingBuf::try_from(m).map_err(|e| err(format!("map {map} is not a ring buffer: {e}")))?;
    // SAFETY: `rb` is a `RingBuf<MapData>` taken out of the loaded `ebpf`; its fd is the
    // `OwnedFd` aya holds in the map, valid and open. aya offers no way to close, replace or
    // take that fd out of the ring buffer — it is closed only when the `RingBuf` drops, which
    // now happens when this `AsyncFd` drops. The fd stays open and the same one for the
    // `AsyncFd`'s whole life, and `as_raw_fd` returns it.
    unsafe { AsyncFd::register_with_interest(rb, tokio::io::Interest::READABLE) }
        .map_err(|e| err(format!("ring buffer fd for {map}: {e}")))
}

/// The readiness of an optional ring buffer: never ready when the program that fills it is
/// not attached, so a `select!` branch on it simply never fires.
pub(crate) async fn readable_or_pending(
    ring: &mut Option<Ring>,
) -> std::io::Result<AsyncFdReadyMutGuard<'_, RingBuf<MapData>>> {
    match ring {
        Some(ring) => ring.readable_mut().await,
        None => std::future::pending().await,
    }
}

/// Drains a ring `select!` found readable, clearing its readiness only once it ran dry: a
/// capped drain leaves it set so the next round drains it again (see `Drained::Capped`).
pub(crate) fn drain_ready<E: Into<Option<Event>>>(
    guard: std::io::Result<AsyncFdReadyMutGuard<'_, RingBuf<MapData>>>,
    sink: &dyn EventSink,
    own_pid: u32,
    to_event: impl FnMut(&[u8]) -> E,
) -> Result<(), SensorError> {
    let mut guard = guard.map_err(|e| err(format!("ring buffer poll failed: {e}")))?;
    if drain_records(guard.get_inner_mut(), sink, own_pid, to_event) == Drained::Dry {
        guard.clear_ready();
    }
    Ok(())
}

/// [`drain_ready`] for a ring of fixed-size `T` records; a record shorter than `T` is skipped.
pub(crate) fn drain_wire<T: WireRecord, E: Into<Option<Event>>>(
    guard: std::io::Result<AsyncFdReadyMutGuard<'_, RingBuf<MapData>>>,
    sink: &dyn EventSink,
    own_pid: u32,
    mut to_event: impl FnMut(&T) -> E,
) -> Result<(), SensorError> {
    drain_ready(guard, sink, own_pid, |record: &[u8]| {
        read_wire::<T>(record).and_then(|event| to_event(&event).into())
    })
}
