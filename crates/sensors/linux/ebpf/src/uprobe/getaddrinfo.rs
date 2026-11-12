//! Uprobes: DNS resolution capture (issue #267 Phase 1)
//!
//! getaddrinfo(3) uprobe/uretprobe pair, attached from userspace (sensor-linux-uprobes)
//! after resolving the symbol in libc with goblin — same shape as the SSL_read
//! entry/exit pair in `tls.rs`: the resolved address is only in `*res` once the call
//! returns, so entry stashes what's needed to read it back at exit.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::{ProbeContext, RetProbeContext},
};
use aya_log_ebpf::warn;
use sensor_linux_wire::{GetAddrInfoEvent, MAX_DNS_ANSWERS, TASK_COMM_LEN};

use crate::{AF_INET, AF_INET6, fill_lineage};

/// Ring buffer for DNS query events, shared with the `gethostbyname*_r` pair.
#[map]
pub(super) static DNS_QUERY_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `GetAddrInfoEvent` (see `EXEC_SCRATCH`).
#[map]
static DNS_SCRATCH: PerCpuArray<GetAddrInfoEvent> = PerCpuArray::with_max_entries(1, 0);

/// Tracks `getaddrinfo(3)` arguments between entry and return:
/// pid_tgid → (node_ptr, res_ptr_ptr). `getaddrinfo(const char *node, const char
/// *service, const struct addrinfo *hints, struct addrinfo **res)` only populates
/// `*res` on success, so the entry probe stashes the query-name pointer and the
/// address OF the caller's `res` output variable (not what it points to yet) — the
/// uretprobe dereferences it once glibc has filled it in. Same pid_tgid-keyed
/// correlation-map shape as `SSL_READ_ARGS` in `tls.rs`.
#[map]
static GETADDRINFO_ARGS: HashMap<u64, (u64, u64)> = HashMap::with_max_entries(1024, 0);

/// `struct addrinfo` field offsets (glibc, LP64 — `ai_flags`/`ai_family`/
/// `ai_socktype`/`ai_protocol` are each 4-byte `int`s, then `ai_addrlen`
/// (`socklen_t`, 4 bytes) plus 4 bytes of padding to align the pointer fields
/// that follow): `ai_family` at +4, the `struct sockaddr *ai_addr` pointer at
/// +24. This is a userspace ABI (glibc's `<netdb.h>`), not a kernel
/// tracepoint, so there is no i686-vs-x86_64 arg-slot-width concern here —
/// only genuine 32-bit-userspace `struct addrinfo` layout would differ, and
/// this sensor doesn't target 32-bit userspace processes.
const ADDRINFO_FAMILY_OFFSET: u64 = 4;
const ADDRINFO_ADDR_PTR_OFFSET: u64 = 24;
const ADDRINFO_NEXT_OFFSET: u64 = 40;

/// `sockaddr_in`/`sockaddr_in6` field offsets: the address bytes start right
/// after `sin_family`+`sin_port` (4 bytes) for IPv4, and after
/// `sin6_family`+`sin6_port`+`sin6_flowinfo` (8 bytes) for IPv6 — same
/// layout `sys_enter_connect`/`sys_enter_bind` in `main.rs` already rely on.
const SOCKADDR_IN_ADDR_OFFSET: u64 = 4;
const SOCKADDR_IN6_ADDR_OFFSET: u64 = 8;

/// Uprobe on `getaddrinfo(3)` entry: stash the query name and the `res`
/// output-parameter address for the uretprobe.
#[uprobe]
pub fn getaddrinfo_entry(ctx: ProbeContext) -> u32 {
    // int getaddrinfo(const char *node, const char *service,
    //                  const struct addrinfo *hints, struct addrinfo **res)
    if let (Some(node_ptr), Some(res_ptr_ptr)) = (ctx.arg::<u64>(0), ctx.arg::<u64>(3))
        && node_ptr != 0
    {
        let pid_tgid = bpf_get_current_pid_tgid();
        let _ = GETADDRINFO_ARGS.insert(&pid_tgid, &(node_ptr, res_ptr_ptr), 0);
    }
    0
}

/// Uretprobe on `getaddrinfo(3)` return: emits the query, status, and a bounded
/// answer set on success.
#[uretprobe]
pub fn getaddrinfo_exit(ctx: RetProbeContext) -> u32 {
    match try_getaddrinfo_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_getaddrinfo_exit(ctx: RetProbeContext) -> Result<u32, u32> {
    let status: i32 = ctx.ret::<i32>();

    let pid_tgid = bpf_get_current_pid_tgid();
    let (node_ptr, res_ptr_ptr) = match unsafe { GETADDRINFO_ARGS.get(&pid_tgid) } {
        Some(args) => *args,
        None => return Ok(0), // entry wasn't tracked (probe attached mid-call)
    };
    let _ = GETADDRINFO_ARGS.remove(&pid_tgid);

    // Build directly in per-CPU scratch: an answer array on the BPF stack made
    // LLVM emit a 136-byte memset inside the bounded list walk, which the 6.6
    // verifier expanded once per path until it exceeded its instruction limit.
    let e = DNS_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    // SAFETY: `e` is the writable value for this CPU in a one-entry PerCpuArray.
    // Clear it once before the walk so unused answers and query tail bytes cannot
    // retain data from an earlier invocation on this CPU.
    unsafe { core::ptr::write_bytes(e, 0, 1) };

    let mut answer_count = 0usize;
    let mut answers_truncated = false;

    if status == 0 && res_ptr_ptr != 0 {
        let mut current = unsafe { bpf_probe_read_user(res_ptr_ptr as *const u64) }.unwrap_or(0);
        // Keep this loop statically bounded. #429 showed that seemingly simple
        // iterator/loop code can multiply verifier work or exceed its instruction
        // budget across attached programs; no traversal runs beyond this cap.
        for index in 0..MAX_DNS_ANSWERS {
            if current == 0 {
                break;
            }

            let Ok(family) =
                (unsafe { bpf_probe_read_user((current + ADDRINFO_FAMILY_OFFSET) as *const i32) })
            else {
                break;
            };
            let Ok(sockaddr_ptr) = (unsafe {
                bpf_probe_read_user((current + ADDRINFO_ADDR_PTR_OFFSET) as *const u64)
            }) else {
                break;
            };
            let Ok(next) =
                (unsafe { bpf_probe_read_user((current + ADDRINFO_NEXT_OFFSET) as *const u64) })
            else {
                break;
            };

            if sockaddr_ptr != 0 && (family == i32::from(AF_INET) || family == i32::from(AF_INET6))
            {
                let address_offset = if family == i32::from(AF_INET) {
                    SOCKADDR_IN_ADDR_OFFSET
                } else {
                    SOCKADDR_IN6_ADDR_OFFSET
                };
                let Some(address_ptr) = sockaddr_ptr.checked_add(address_offset) else {
                    break;
                };

                let copied = copy_dns_answer!(e, answer_count, family, address_ptr);
                if copied.is_err() {
                    break;
                }
                answer_count += 1;
            }

            if index + 1 == MAX_DNS_ANSWERS {
                answers_truncated = next != 0;
                break;
            }
            current = next;
        }
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    unsafe {
        (*e).meta.pid = (pid_tgid >> 32) as u32;
        fill_lineage(&mut (*e).meta);
        (*e).meta.uid = uid_gid as u32;
        (*e).meta.gid = (uid_gid >> 32) as u32;
        (*e).meta.timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            (*e).meta.comm[i] = comm[i];
            i += 1;
        }

        if let Ok(query) = bpf_probe_read_user_str_bytes(node_ptr as *const u8, &mut (*e).query) {
            (*e).query_len = query.len() as u16;
        }
        (*e).status = status;
        (*e).answer_count = answer_count as u8;
        (*e).answers_truncated = answers_truncated;

        if DNS_QUERY_EVENTS.output::<GetAddrInfoEvent>(&*e, 0).is_err() {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping DNS query event"
            );
        }
    }

    Ok(0)
}
