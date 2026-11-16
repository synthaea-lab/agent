//! Explicit timestamp requests: `inode_setattr` LSM hook (#1036, #1044)
//!
//! Fires for every attribute change that reaches `notify_change`, whichever syscall (or
//! io_uring op) asked: `utimensat`, `utimes`, `futimens`. `ia_valid` tells which attributes
//! the caller named; `ATTR_ATIME_SET`/`ATTR_MTIME_SET` mean the caller chose the time itself,
//! as opposed to `ATTR_ATIME`/`ATTR_MTIME` alone, which the kernel fills with "now" (a write,
//! `touch` without `-d`, `UTIME_NOW`). Only the former is timestomping.
//!
//! The structs it reads (`iattr`, `dentry`, `qstr`) are read at offsets userspace resolves
//! from the kernel BTF and patches into the globals below, the same way as the scheduler
//! offsets: there are no vmlinux bindings here. Userspace sets `INODE_SETATTR_ENABLED` only
//! when every offset resolved, so a kernel whose layout was not understood emits nothing
//! rather than reading garbage.

use aya_ebpf::{
    Global,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes,
    },
    macros::{lsm, map},
    maps::{PerCpuArray, RingBuf},
    programs::LsmContext,
};
use aya_log_ebpf::warn;
use sensor_linux_wire::{
    FileSetTimeEvent, SET_TIME_ATIME, SET_TIME_COMPONENT_LEN, SET_TIME_COMPONENTS, SET_TIME_MTIME,
    SET_TIME_TRUNCATED, TASK_COMM_LEN,
};

use crate::fill_lineage;

/// 1 when the offsets below were resolved. Patched by the loader.
#[unsafe(no_mangle)]
static INODE_SETATTR_ENABLED: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
static IATTR_VALID_OFFSET: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
static IATTR_ATIME_OFFSET: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
static IATTR_MTIME_OFFSET: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
static DENTRY_PARENT_OFFSET: Global<u32> = Global::new(0);
/// `offsetof(struct dentry, d_name) + offsetof(struct qstr, name)`.
#[unsafe(no_mangle)]
static DENTRY_NAME_PTR_OFFSET: Global<u32> = Global::new(0);

/// `ATTR_ATIME_SET` / `ATTR_MTIME_SET` of `include/linux/fs.h`: bits 7 and 8 of `ia_valid`
/// since `ATTR_MODE` was bit 0 (stable uapi-adjacent values, not in BTF: they are macros).
const ATTR_ATIME_SET: u32 = 1 << 7;
const ATTR_MTIME_SET: u32 = 1 << 8;

/// Ring buffer shared with userspace for explicit timestamp requests. One event is about
/// 400 bytes and `tar x`/`cp -a` of a few thousand files emit one per file in a burst: 256 KiB
/// lost two thirds of a 3000-file unpack in the lab (#1044), so this one has 1 MiB.
#[map]
static FILE_SET_TIME_EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

/// Per-CPU scratch for building one `FileSetTimeEvent` (see `EXEC_SCRATCH`).
#[map]
static SET_TIME_SCRATCH: PerCpuArray<FileSetTimeEvent> = PerCpuArray::with_max_entries(1, 0);

/// Reads a `struct timespec64` (`tv_sec` at 0, `tv_nsec` at 8) at `base + offset`.
#[inline(always)]
fn read_timespec(base: *const u8, offset: u32) -> Option<(i64, i64)> {
    let at = unsafe { base.add(offset as usize) };
    let sec: i64 = unsafe { bpf_probe_read_kernel(at.cast::<i64>()) }.ok()?;
    let nsec: i64 = unsafe { bpf_probe_read_kernel(at.add(8).cast::<i64>()) }.ok()?;
    Some((sec, nsec))
}

#[lsm(hook = "inode_setattr")]
pub fn inode_setattr(ctx: LsmContext) -> i32 {
    match try_inode_setattr(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_inode_setattr(ctx: LsmContext) -> Result<i32, i32> {
    // `(struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *attr, int retval)`:
    // `arg(3)` is the verdict of an earlier LSM in the chain. Never override its deny; see
    // `try_file_open` for why the code is a constant and not forwarded.
    let retval: i32 = ctx.arg(3);
    if retval != 0 {
        return Ok(-1);
    }
    if INODE_SETATTR_ENABLED.load() == 0 {
        return Ok(0);
    }
    let dentry: *const u8 = ctx.arg(1);
    let attr: *const u8 = ctx.arg(2);
    if dentry.is_null() || attr.is_null() {
        return Ok(0);
    }

    let ia_valid: u32 = match unsafe {
        bpf_probe_read_kernel(attr.add(IATTR_VALID_OFFSET.load() as usize).cast::<u32>())
    } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };
    let mut flags: u16 = 0;
    if ia_valid & ATTR_ATIME_SET != 0 {
        flags |= SET_TIME_ATIME;
    }
    if ia_valid & ATTR_MTIME_SET != 0 {
        flags |= SET_TIME_MTIME;
    }
    if flags == 0 {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 0i32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();
    let e = SET_TIME_SCRATCH.get_ptr_mut(0).ok_or(0i32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);
        (*e).meta.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        fill_lineage(&mut (*e).meta);
        (*e).meta.uid = uid_gid as u32;
        (*e).meta.gid = (uid_gid >> 32) as u32;
        (*e).meta.timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        (*e).meta.cgroup_id = aya_ebpf::helpers::bpf_get_current_cgroup_id();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            (*e).meta.comm[i] = comm[i];
            i += 1;
        }

        if flags & SET_TIME_ATIME != 0
            && let Some((sec, nsec)) = read_timespec(attr, IATTR_ATIME_OFFSET.load())
        {
            (*e).atime_sec = sec;
            (*e).atime_nsec = nsec;
        }
        if flags & SET_TIME_MTIME != 0
            && let Some((sec, nsec)) = read_timespec(attr, IATTR_MTIME_OFFSET.load())
        {
            (*e).mtime_sec = sec;
            (*e).mtime_nsec = nsec;
        }

        // The dentry chain, file first, one fixed slot per name: a constant-bound loop the
        // verifier can follow (a variable-offset copy into one path buffer is what it
        // refuses). It ends at the filesystem root, whose `d_parent` is itself.
        let mut current = dentry;
        let mut depth = 0usize;
        let mut reached_root = false;
        while depth < SET_TIME_COMPONENTS {
            let parent: *const u8 = match bpf_probe_read_kernel(
                current
                    .add(DENTRY_PARENT_OFFSET.load() as usize)
                    .cast::<*const u8>(),
            ) {
                Ok(p) => p,
                Err(_) => break,
            };
            if parent == current || parent.is_null() {
                reached_root = true;
                break;
            }
            let name: *const u8 = match bpf_probe_read_kernel(
                current
                    .add(DENTRY_NAME_PTR_OFFSET.load() as usize)
                    .cast::<*const u8>(),
            ) {
                Ok(p) => p,
                Err(_) => break,
            };
            match bpf_probe_read_kernel_str_bytes(name, &mut (*e).components[depth]) {
                Ok(bytes) => {
                    if bytes.len() >= SET_TIME_COMPONENT_LEN - 1 {
                        flags |= SET_TIME_TRUNCATED;
                    }
                }
                Err(_) => break,
            }
            depth += 1;
            current = parent;
        }
        if !reached_root {
            flags |= SET_TIME_TRUNCATED;
        }
        (*e).depth = depth as u8;
        (*e).flags = flags;

        if FILE_SET_TIME_EVENTS
            .output::<FileSetTimeEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping set-time event"
            );
        }
    }
    Ok(0)
}
