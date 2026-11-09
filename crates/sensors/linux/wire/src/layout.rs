//! Compile-time pins of every wire struct's layout: size, alignment and the offset of each field.
//!
//! The eBPF probes write these structs and the userspace loader reads them back from the same
//! source, so a field moved on one side is moved on the other and nothing catches it at runtime.
//! What it can break is what is outside this crate: the BTF-relocated reads that fill them, the
//! `bpf_ringbuf_output` sizes, and the variable-length exec record. These pins make any layout
//! change a deliberate, reviewed edit: change the table here and bump [`crate::WIRE_VERSION`] in
//! the same change, together with [`PINNED_WIRE_VERSION`]. That constant only enforces one
//! direction: a version bump that does not revisit this table fails to compile, but a table
//! edit without a bump still compiles, so the bump stays a review item. The values were taken
//! from the structs as they stood on 2026-11-09 (AS-030).
//!
//! 64-bit hosts only. Every field type here has the same size and alignment on bpfel and on
//! `x86_64`/`aarch64`, but `u64` aligns to 4 on i686, so a 32-bit userspace would read these
//! structs at other offsets than the probes write them. The `usize` assert below turns that
//! into one clear build error instead of a page of offset mismatches.

use core::mem::{align_of, offset_of, size_of};

use crate::*;

/// The [`WIRE_VERSION`] this table was last checked against. Bump both together.
const PINNED_WIRE_VERSION: u32 = 28;

const _: () = assert!(
    PINNED_WIRE_VERSION == WIRE_VERSION,
    "WIRE_VERSION changed: re-check the pins below, then update PINNED_WIRE_VERSION",
);
const _: () = assert!(
    size_of::<usize>() == 8,
    "the wire layout is pinned for 64-bit targets only (u64 aligns to 4 on i686)",
);

/// Asserts at compile time that `$ty` has exactly this size, alignment and field offsets.
macro_rules! pin_layout {
    ($ty:ty { size: $size:literal, align: $align:literal, $($field:ident: $offset:literal),+ $(,)? }) => {
        const _: () = {
            assert!(size_of::<$ty>() == $size, concat!(stringify!($ty), ": size changed"));
            assert!(align_of::<$ty>() == $align, concat!(stringify!($ty), ": alignment changed"));
            $(assert!(
                offset_of!($ty, $field) == $offset,
                concat!(stringify!($ty), ".", stringify!($field), ": offset changed"),
            );)+
        };
    };
}

pin_layout!(EventMeta {
    size: 64,
    align: 8,
    pid: 0,
    ppid: 4,
    uid: 8,
    gid: 12,
    timestamp_ns: 16,
    comm: 24,
    cgroup_id: 40,
    process_generation: 48,
    parent_generation: 56,
});

pin_layout!(ExecEvent {
    size: 368,
    align: 8,
    meta: 0,
    image: 64,
    image_len: 320,
    pcomm: 322,
    grandparent_pid: 340,
    parent_execd: 344,
    grandparent_generation: 352,
    argv_total: 360,
    argv_head_len: 364,
    argv_tail_len: 366,
});

pin_layout!(ExecRecord {
    size: 1392,
    align: 8,
    event: 0,
    argv: 368,
});

pin_layout!(LineageEntry {
    size: 40,
    align: 8,
    ppid: 0,
    comm: 4,
    execd: 20,
    generation: 24,
    parent_generation: 32,
});

pin_layout!(FileOpenEvent {
    size: 328,
    align: 8,
    meta: 0,
    path: 64,
    path_len: 320,
    flags: 324,
});

pin_layout!(FileWriteEvent {
    size: 80,
    align: 8,
    meta: 0,
    fd: 64,
    bytes_requested: 72,
});

pin_layout!(FileDeleteEvent {
    size: 328,
    align: 8,
    meta: 0,
    path: 64,
    path_len: 320,
});

pin_layout!(FileRenameEvent {
    size: 592,
    align: 8,
    meta: 0,
    old_path: 64,
    old_path_len: 320,
    new_path: 322,
    new_path_len: 578,
    reserved: 580,
    old_dfd: 584,
    new_dfd: 588,
});

pin_layout!(FileChmodEvent {
    size: 328,
    align: 8,
    meta: 0,
    path: 64,
    path_len: 320,
    mode: 324,
});

pin_layout!(FileChownEvent {
    size: 336,
    align: 8,
    meta: 0,
    path: 64,
    path_len: 320,
    uid: 324,
    gid: 328,
});

pin_layout!(FileSetTimeEvent {
    size: 360,
    align: 8,
    meta: 0,
    components: 64,
    depth: 320,
    reserved0: 321,
    flags: 322,
    reserved1: 324,
    atime_sec: 328,
    atime_nsec: 336,
    mtime_sec: 344,
    mtime_nsec: 352,
});

pin_layout!(FileSetxattrEvent {
    size: 584,
    align: 8,
    meta: 0,
    path: 64,
    path_len: 320,
    name: 322,
    name_len: 578,
});

pin_layout!(FileRemovexattrEvent {
    size: 584,
    align: 8,
    meta: 0,
    path: 64,
    path_len: 320,
    name: 322,
    name_len: 578,
});

pin_layout!(ConnectEvent {
    size: 88,
    align: 8,
    meta: 0,
    daddr_v4: 64,
    daddr_v6: 68,
    dport: 84,
    is_ipv6: 86,
});

pin_layout!(SocketBindEvent {
    size: 88,
    align: 8,
    meta: 0,
    laddr_v4: 64,
    laddr_v6: 68,
    lport: 84,
    is_ipv6: 86,
});

pin_layout!(UdpSendEvent {
    size: 96,
    align: 8,
    meta: 0,
    daddr_v4: 64,
    daddr_v6: 68,
    dport: 84,
    is_ipv6: 86,
    size: 88,
});

pin_layout!(UdpRecvEvent {
    size: 96,
    align: 8,
    meta: 0,
    peer_addr_v4: 64,
    peer_addr_v6: 68,
    peer_port: 84,
    is_ipv6: 86,
    size: 88,
});

pin_layout!(SocketListenEvent {
    size: 96,
    align: 8,
    meta: 0,
    laddr_v4: 64,
    laddr_v6: 68,
    lport: 84,
    is_ipv6: 86,
    addr_resolved: 87,
    backlog: 88,
});

pin_layout!(SocketAcceptEvent {
    size: 96,
    align: 8,
    meta: 0,
    listen_fd: 64,
    accepted_fd: 68,
    peer_addr_v4: 72,
    peer_addr_v6: 76,
    peer_port: 92,
    is_ipv6: 94,
});

pin_layout!(SocketCreateEvent {
    size: 80,
    align: 8,
    meta: 0,
    domain: 64,
    socket_type: 68,
    protocol: 72,
    fd: 76,
});

pin_layout!(MountEvent {
    size: 616,
    align: 8,
    meta: 0,
    mount_point: 64,
    mount_point_len: 320,
    source: 322,
    source_len: 578,
    fs_type: 580,
    fs_type_len: 612,
    readonly: 613,
    mounted: 614,
});

pin_layout!(SignalEvent {
    size: 72,
    align: 8,
    meta: 0,
    signal: 64,
    target_pid: 68,
});

pin_layout!(IdentityChangeEvent {
    size: 80,
    align: 8,
    meta: 0,
    kind: 64,
    real: 68,
    effective: 72,
    saved: 76,
});

pin_layout!(CapSetEvent {
    size: 96,
    align: 8,
    meta: 0,
    target_pid: 64,
    effective: 72,
    permitted: 80,
    inheritable: 88,
});

pin_layout!(NamespaceEvent {
    size: 80,
    align: 8,
    meta: 0,
    syscall: 64,
    fd: 68,
    flags: 72,
});

pin_layout!(PrctlEvent {
    size: 80,
    align: 8,
    meta: 0,
    option: 64,
    arg: 72,
});

pin_layout!(TlsCaptureEvent {
    size: 328,
    align: 8,
    meta: 0,
    direction: 64,
    lib_type: 65,
    bytes_len: 68,
    data: 72,
});

pin_layout!(ReadlineInputEvent {
    size: 584,
    align: 8,
    meta: 0,
    shell_type: 64,
    input_len: 68,
    input: 72,
});

pin_layout!(KernelModuleEvent {
    size: 152,
    align: 8,
    meta: 0,
    name: 64,
    name_len: 128,
    fd: 132,
    image_len: 136,
    flags: 144,
    action: 148,
});

pin_layout!(BpfEvent {
    size: 72,
    align: 8,
    meta: 0,
    cmd: 64,
});

pin_layout!(PtraceEvent {
    size: 96,
    align: 8,
    meta: 0,
    request: 64,
    target_pid: 72,
    addr: 80,
    data: 88,
});

pin_layout!(ProcessVmReadEvent {
    size: 96,
    align: 8,
    meta: 0,
    target_pid: 64,
    local_iov_count: 72,
    remote_iov_count: 80,
    remote_iov_len: 88,
});

pin_layout!(ProcessVmWriteEvent {
    size: 96,
    align: 8,
    meta: 0,
    target_pid: 64,
    local_iov_count: 72,
    remote_iov_count: 80,
    remote_iov_len: 88,
});

pin_layout!(MemfdCreateEvent {
    size: 336,
    align: 8,
    meta: 0,
    name: 64,
    name_len: 320,
    flags: 324,
    fd: 328,
});

pin_layout!(DnsAnswer {
    size: 17,
    align: 1,
    family: 0,
    address: 1,
});

pin_layout!(GetAddrInfoEvent {
    size: 744,
    align: 8,
    meta: 0,
    query: 64,
    query_len: 320,
    status: 324,
    answer_count: 328,
    answers_truncated: 329,
    answers: 330,
});

pin_layout!(DnsUdpQueryEvent {
    size: 368,
    align: 8,
    meta: 0,
    daddr_v4: 64,
    daddr_v6: 68,
    dport: 84,
    payload_len: 86,
    is_ipv6: 88,
    payload: 89,
});
