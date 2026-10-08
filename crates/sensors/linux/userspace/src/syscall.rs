//! Populate the eBPF raw-syscall dispatcher from the host syscall ABI.

// The dispatcher is only populated when the probes are embedded; without
// bpf-linker (e.g. the plain `test` CI job) this module is compiled for its
// unit tests alone, so everything below that only `load_embedded` reaches is
// gated on `ebpf_embedded` too, or `-D warnings` rejects it as dead code.
#[cfg(ebpf_embedded)]
use aya::maps::Array;
#[cfg(ebpf_embedded)]
use schema::sensor::SensorError;

#[cfg(ebpf_embedded)]
use crate::ebpf::err;

/// Handler numbers must match the `raw_sys_enter` match in `ebpf/src/raw.rs`.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const DISPATCH_ENTRIES: &[(libc::c_long, u32)] = &[
    (libc::SYS_openat, 1),
    (libc::SYS_open, 2),
    (libc::SYS_connect, 3),
    (libc::SYS_write, 4),
    (libc::SYS_unlink, 5),
    (libc::SYS_unlinkat, 6),
    (libc::SYS_rename, 7),
    (libc::SYS_renameat, 8),
    (libc::SYS_renameat2, 9),
    (libc::SYS_bind, 10),
    (libc::SYS_chmod, 11),
    (libc::SYS_fchmodat, 12),
    (libc::SYS_chown, 13),
    (libc::SYS_lchown, 14),
    (libc::SYS_fchownat, 15),
    (libc::SYS_sendto, 16),
    (libc::SYS_listen, 17),
    (libc::SYS_accept, 18),
    (libc::SYS_accept4, 19),
    (libc::SYS_setxattr, 20),
    (libc::SYS_removexattr, 21),
    (libc::SYS_mount, 22),
    (libc::SYS_umount2, 23),
    (libc::SYS_kill, 24),
    (libc::SYS_tgkill, 25),
    (libc::SYS_init_module, 26),
    (libc::SYS_finit_module, 27),
    (libc::SYS_delete_module, 28),
    (libc::SYS_bpf, 29),
    (libc::SYS_prctl, 30),
    (libc::SYS_ptrace, 31),
    (libc::SYS_process_vm_readv, 32),
    (libc::SYS_process_vm_writev, 33),
    (libc::SYS_memfd_create, 34),
    (libc::SYS_setuid, 35),
    (libc::SYS_setgid, 36),
    (libc::SYS_setresuid, 37),
    (libc::SYS_setresgid, 38),
    (libc::SYS_setfsuid, 39),
    (libc::SYS_setfsgid, 40),
    (libc::SYS_capset, 41),
    (libc::SYS_setns, 42),
    (libc::SYS_unshare, 43),
    (libc::SYS_recvfrom, 44),
    (libc::SYS_socket, 45),
];

/// Linux's asm-generic syscall numbers used by native AArch64. Legacy syscalls
/// removed from that ABI (open, unlink, chmod, chown and rename) have no entry;
/// their `*at` equivalents remain routed to the existing handlers.
#[cfg(target_arch = "aarch64")]
const DISPATCH_ENTRIES: &[(libc::c_long, u32)] = &[
    (56, 1),   // openat
    (203, 3),  // connect
    (64, 4),   // write
    (35, 6),   // unlinkat
    (38, 8),   // renameat
    (276, 9),  // renameat2
    (200, 10), // bind
    (53, 12),  // fchmodat
    (54, 15),  // fchownat
    (206, 16), // sendto
    (201, 17), // listen
    (202, 18), // accept
    (242, 19), // accept4
    (5, 20),   // setxattr
    (14, 21),  // removexattr
    (40, 22),  // mount
    (39, 23),  // umount2
    (129, 24), // kill
    (131, 25), // tgkill
    (105, 26), // init_module
    (273, 27), // finit_module
    (106, 28), // delete_module
    (280, 29), // bpf
    (167, 30), // prctl
    (117, 31), // ptrace
    (270, 32), // process_vm_readv
    (271, 33), // process_vm_writev
    (279, 34), // memfd_create
    (146, 35), // setuid
    (144, 36), // setgid
    (147, 37), // setresuid
    (149, 38), // setresgid
    (151, 39), // setfsuid
    (152, 40), // setfsgid
    (91, 41),  // capset
    (268, 42), // setns
    (97, 43),  // unshare
    (207, 44), // recvfrom
    (198, 45), // socket
];

#[cfg(ebpf_embedded)]
pub(crate) fn populate_dispatch(ebpf: &mut aya::Ebpf) -> Result<(), SensorError> {
    let map = ebpf
        .map_mut("SYSCALL_DISPATCH")
        .ok_or_else(|| err("eBPF map SYSCALL_DISPATCH is missing".to_owned()))?;
    let mut dispatch: Array<_, u32> = Array::try_from(map)
        .map_err(|e| err(format!("SYSCALL_DISPATCH is not an array map: {e}")))?;

    for &(syscall_id, action) in DISPATCH_ENTRIES {
        let syscall_id = syscall_id_to_i64(syscall_id);
        if syscall_id < 0 || syscall_id >= i64::from(dispatch.len()) {
            return Err(err(format!(
                "syscall id {syscall_id} does not fit SYSCALL_DISPATCH"
            )));
        }
        dispatch
            .set(syscall_id as u32, action, 0)
            .map_err(|e| err(format!("populate SYSCALL_DISPATCH[{syscall_id}]: {e}")))?;
    }
    Ok(())
}

#[cfg(all(ebpf_embedded, target_arch = "x86"))]
fn syscall_id_to_i64(syscall_id: libc::c_long) -> i64 {
    i64::from(syscall_id)
}

#[cfg(all(ebpf_embedded, not(target_arch = "x86")))]
fn syscall_id_to_i64(syscall_id: libc::c_long) -> i64 {
    syscall_id
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::DISPATCH_ENTRIES;

    #[test]
    fn dispatch_actions_are_unique_and_in_range() {
        let mut actions = HashSet::new();
        for &(syscall_id, action) in DISPATCH_ENTRIES {
            assert!((0..1024).contains(&syscall_id));
            assert!((1..=45).contains(&action));
            assert!(
                actions.insert(action),
                "duplicate dispatcher action {action}"
            );
        }
        assert!(actions.contains(&1));
        assert!(actions.contains(&45));
    }
}
