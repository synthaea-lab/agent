//! Uprobes: DNS resolution through the legacy `gethostbyname*` API (agent#240)
//!
//! `gethostbyname` and `gethostbyname2` never call `getaddrinfo`, on glibc or on musl, so
//! the pair in `getaddrinfo.rs` missed them. Both libcs implement them on top of the
//! reentrant forms at their exported addresses (glibc: `gethostbyname` ->
//! `gethostbyname_r`, `gethostbyname2` -> `gethostbyname2_r`; musl: all of them ->
//! `gethostbyname2_r`, checked with gdb in 2026-11), so probing the two `_r` symbols
//! covers all four calls. Events go to the same ring buffer and wire struct as
//! `getaddrinfo`.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, PerCpuArray},
    programs::{ProbeContext, RetProbeContext},
};
use aya_log_ebpf::warn;
use sensor_linux_wire::{GetAddrInfoEvent, MAX_DNS_ANSWERS, TASK_COMM_LEN};

use super::getaddrinfo::DNS_QUERY_EVENTS;
use crate::{AF_INET, AF_INET6, fill_lineage};

/// Per-CPU scratch for one event, separate from `DNS_SCRATCH` so the two exit programs
/// never share a buffer.
#[map]
static GETHOSTBYNAME_SCRATCH: PerCpuArray<GetAddrInfoEvent> = PerCpuArray::with_max_entries(1, 0);

/// `pid_tgid` -> `(name_ptr, result_ptr_ptr)` between entry and return, like
/// `GETADDRINFO_ARGS`. musl's `gethostbyname_r` calls `gethostbyname2_r` with the same
/// name and result pointer: the inner entry overwrites the outer one with equal values,
/// the inner return emits and removes it, and the outer return finds nothing, so a
/// nested call yields one event.
#[map]
static GETHOSTBYNAME_ARGS: HashMap<u64, (u64, u64)> = HashMap::with_max_entries(1024, 0);

/// `struct hostent` (LP64, the same on glibc and musl): `char *h_name`, `char
/// **h_aliases`, `int h_addrtype`, `int h_length`, `char **h_addr_list`.
const HOSTENT_ADDRTYPE_OFFSET: u64 = 16;
const HOSTENT_LENGTH_OFFSET: u64 = 20;
const HOSTENT_ADDR_LIST_OFFSET: u64 = 24;

/// The caller's buffer was too small. Both libcs' non-reentrant forms retry with a larger
/// one (musl starts at 95 bytes), so this return is not a lookup result.
const ERANGE: i32 = 34;

/// Reported when no address came back. The `h_errno` that says why is the 7th argument
/// of `gethostbyname2_r`, on the stack on `x86_64`, and is not read; consumers only test
/// `status != 0`.
const EAI_NONAME: i32 = -2;
/// Reported when the function returned an errno other than `ERANGE`.
const EAI_SYSTEM: i32 = -11;

/// Uprobe on `gethostbyname_r(name, ret, buf, buflen, result, h_errnop)` entry.
#[uprobe]
pub fn gethostbyname_r_entry(ctx: ProbeContext) -> u32 {
    stash_args(ctx.arg::<u64>(0), ctx.arg::<u64>(4));
    0
}

/// Uprobe on `gethostbyname2_r(name, af, ret, buf, buflen, result, h_errnop)` entry.
#[uprobe]
pub fn gethostbyname2_r_entry(ctx: ProbeContext) -> u32 {
    stash_args(ctx.arg::<u64>(0), ctx.arg::<u64>(5));
    0
}

fn stash_args(name_ptr: Option<u64>, result_ptr_ptr: Option<u64>) {
    if let (Some(name_ptr), Some(result_ptr_ptr)) = (name_ptr, result_ptr_ptr)
        && name_ptr != 0
    {
        let pid_tgid = bpf_get_current_pid_tgid();
        let _ = GETHOSTBYNAME_ARGS.insert(&pid_tgid, &(name_ptr, result_ptr_ptr), 0);
    }
}

/// Uretprobe on both `_r` forms: emits the query, a status, and the bounded address list.
#[uretprobe]
pub fn gethostbyname_exit(ctx: RetProbeContext) -> u32 {
    match try_gethostbyname_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_gethostbyname_exit(ctx: RetProbeContext) -> Result<u32, u32> {
    let ret: i32 = ctx.ret::<i32>();

    let pid_tgid = bpf_get_current_pid_tgid();
    let (name_ptr, result_ptr_ptr) = match unsafe { GETHOSTBYNAME_ARGS.get(&pid_tgid) } {
        Some(args) => *args,
        None => return Ok(0), // entry not tracked, or a nested call already emitted
    };
    let _ = GETHOSTBYNAME_ARGS.remove(&pid_tgid);
    if ret == ERANGE {
        return Ok(0);
    }

    let e = GETHOSTBYNAME_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    // SAFETY: `e` is the writable value for this CPU in a one-entry PerCpuArray. Cleared
    // so unused answers and query tail bytes cannot retain an earlier invocation's data.
    unsafe { core::ptr::write_bytes(e, 0, 1) };

    let hostent = if ret == 0 && result_ptr_ptr != 0 {
        unsafe { bpf_probe_read_user(result_ptr_ptr as *const u64) }.unwrap_or(0)
    } else {
        0
    };

    let mut answer_count = 0usize;
    let mut answers_truncated = false;
    if hostent != 0 {
        let family =
            unsafe { bpf_probe_read_user((hostent + HOSTENT_ADDRTYPE_OFFSET) as *const i32) }
                .unwrap_or(0);
        let length =
            unsafe { bpf_probe_read_user((hostent + HOSTENT_LENGTH_OFFSET) as *const i32) }
                .unwrap_or(0);
        let addr_list =
            unsafe { bpf_probe_read_user((hostent + HOSTENT_ADDR_LIST_OFFSET) as *const u64) }
                .unwrap_or(0);
        let known = (family == i32::from(AF_INET) && length == 4)
            || (family == i32::from(AF_INET6) && length == 16);

        if known && addr_list != 0 {
            // Statically bounded, like the `ai_next` walk (#429).
            for index in 0..MAX_DNS_ANSWERS {
                let Ok(address_ptr) =
                    (unsafe { bpf_probe_read_user((addr_list + 8 * index as u64) as *const u64) })
                else {
                    break;
                };
                if address_ptr == 0 {
                    break;
                }
                if copy_dns_answer!(e, answer_count, family, address_ptr).is_err() {
                    break;
                }
                answer_count += 1;
                if index + 1 == MAX_DNS_ANSWERS {
                    let next = unsafe {
                        bpf_probe_read_user((addr_list + 8 * MAX_DNS_ANSWERS as u64) as *const u64)
                    }
                    .unwrap_or(0);
                    answers_truncated = next != 0;
                }
            }
        }
    }

    let status = if answer_count > 0 {
        0
    } else if ret == 0 {
        EAI_NONAME
    } else {
        EAI_SYSTEM
    };

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

        if let Ok(query) = bpf_probe_read_user_str_bytes(name_ptr as *const u8, &mut (*e).query) {
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
