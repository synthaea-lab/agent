//! Uprobes: TLS plaintext capture (issue #90)
//!
//! These uprobes attach to SSL_read/SSL_write in OpenSSL/BoringSSL/GnuTLS libraries.
//! Attachment is done from userspace (sensor-linux-uprobes) after resolving symbols
//! with goblin — the eBPF programs in this module are just the handlers.

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_buf},
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::{ProbeContext, RetProbeContext},
};
use aya_log_ebpf::warn;
use sensor_linux_wire::{MAX_TLS_CAPTURE, TASK_COMM_LEN, TlsCaptureEvent};

use crate::fill_lineage;

/// Ring buffer for TLS capture events.
#[map]
static TLS_CAPTURE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `TlsCaptureEvent` (256 bytes data budget).
#[map]
static TLS_SCRATCH: PerCpuArray<TlsCaptureEvent> = PerCpuArray::with_max_entries(1, 0);

/// Tracks SSL_read buffer pointers between entry and return: pid → (buf_ptr, num, lib_type).
/// SSL_read(SSL *ssl, void *buf, int num) fills `buf` on success, so we need to
/// stash the arguments at entry and read the buffer at return (uretprobe).
/// The lib_type (0=OpenSSL, 1=BoringSSL, 2=GnuTLS) is passed from entry to exit.
///
/// Three `u64`s, not `(u64, u32, u8)`: that tuple has 3 bytes of padding that are never
/// written, and the 5.15 and 6.1 verifiers refuse to pass uninitialized stack bytes to
/// `bpf_map_update_elem` (`invalid indirect read from stack`), so the SSL_read entry probes
/// did not load there (#204). 6.18 accepts it.
#[map]
static SSL_READ_ARGS: HashMap<u64, (u64, u64, u64)> = HashMap::with_max_entries(1024, 0);

/// Uprobe on SSL_write entry for OpenSSL (pre-encryption plaintext capture).
/// Signature: `int SSL_write(SSL *ssl, const void *buf, int num)`
/// Captures the first MAX_TLS_CAPTURE bytes of `buf` before encryption.
#[uprobe]
pub fn ssl_write_openssl(ctx: ProbeContext) -> u32 {
    match try_ssl_write(ctx, 0) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// Uprobe on SSL_write entry for BoringSSL (pre-encryption plaintext capture).
#[uprobe]
pub fn ssl_write_boringssl(ctx: ProbeContext) -> u32 {
    match try_ssl_write(ctx, 1) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// Uprobe on gnutls_record_send entry for GnuTLS (pre-encryption plaintext capture).
/// Signature: `ssize_t gnutls_record_send(gnutls_session_t session, const void *data, size_t data_size)`
#[uprobe]
pub fn ssl_write_gnutls(ctx: ProbeContext) -> u32 {
    match try_ssl_write(ctx, 2) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ssl_write(ctx: ProbeContext, lib_type: u8) -> Result<u32, u32> {
    // SSL_write(SSL *ssl, const void *buf, int num)
    // arg(0) = ssl, arg(1) = buf, arg(2) = num
    let buf_ptr: u64 = ctx.arg(1).ok_or(1u32)?;
    let num: i32 = ctx.arg(2).ok_or(1u32)?;

    if buf_ptr == 0 || num <= 0 {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = TLS_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        (*e).meta.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        fill_lineage(&mut (*e).meta);
        (*e).meta.uid = uid_gid as u32;
        (*e).meta.gid = (uid_gid >> 32) as u32;
        (*e).meta.timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            (*e).meta.comm[i] = comm[i];
            i += 1;
        }

        (*e).direction = 1; // write (pre-encryption)
        (*e).lib_type = lib_type; // Set by probe function (OpenSSL=0, BoringSSL=1, GnuTLS=2)

        // Capture first N bytes of plaintext (budget: MAX_TLS_CAPTURE).
        // TLS data is binary, not null-terminated, so we use bulk read helper.
        let to_read = if num as usize > MAX_TLS_CAPTURE {
            MAX_TLS_CAPTURE
        } else {
            num as usize
        };

        // Batch read: single bpf_probe_read_user_buf() call instead of 256
        // individual bpf_probe_read_user() calls (verifier-friendly).
        let data_slice = &mut (*e).data;
        (*e).bytes_len = if let Ok(()) =
            bpf_probe_read_user_buf(buf_ptr as *const u8, &mut data_slice[..to_read])
        {
            to_read as u32
        } else {
            0
        };

        if TLS_CAPTURE_EVENTS
            .output::<TlsCaptureEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping TLS write event"
            );
        }
    }

    Ok(0)
}

/// Uprobe on SSL_read entry for OpenSSL: stash arguments for the uretprobe.
/// Signature: `int SSL_read(SSL *ssl, void *buf, int num)`
#[uprobe]
pub fn ssl_read_entry_openssl(ctx: ProbeContext) -> u32 {
    try_ssl_read_entry(ctx, 0)
}

/// Uprobe on SSL_read entry for BoringSSL: stash arguments for the uretprobe.
#[uprobe]
pub fn ssl_read_entry_boringssl(ctx: ProbeContext) -> u32 {
    try_ssl_read_entry(ctx, 1)
}

/// Uprobe on gnutls_record_recv entry for GnuTLS: stash arguments for the uretprobe.
/// Signature: `ssize_t gnutls_record_recv(gnutls_session_t session, void *data, size_t data_size)`
#[uprobe]
pub fn ssl_read_entry_gnutls(ctx: ProbeContext) -> u32 {
    try_ssl_read_entry(ctx, 2)
}

fn try_ssl_read_entry(ctx: ProbeContext, lib_type: u8) -> u32 {
    // SSL_read(SSL *ssl, void *buf, int num) / gnutls_record_recv(session, data, size)
    // arg(0) = ssl/session, arg(1) = buf/data, arg(2) = num/size
    if let (Some(buf_ptr), Some(num)) = (ctx.arg::<u64>(1), ctx.arg::<i32>(2)) {
        if buf_ptr != 0 && num > 0 {
            let pid_tgid = bpf_get_current_pid_tgid();
            let args = (buf_ptr, u64::from(num as u32), u64::from(lib_type));
            let _ = SSL_READ_ARGS.insert(&pid_tgid, &args, 0);
        }
    }
    0
}

/// Uretprobe on SSL_read return for OpenSSL: capture decrypted plaintext.
/// The return value is the number of bytes read, or <= 0 on error.
#[uretprobe]
pub fn ssl_read_exit_openssl(ctx: RetProbeContext) -> u32 {
    match try_ssl_read_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// Uretprobe on SSL_read return for BoringSSL: capture decrypted plaintext.
#[uretprobe]
pub fn ssl_read_exit_boringssl(ctx: RetProbeContext) -> u32 {
    match try_ssl_read_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// Uretprobe on gnutls_record_recv return for GnuTLS: capture decrypted plaintext.
#[uretprobe]
pub fn ssl_read_exit_gnutls(ctx: RetProbeContext) -> u32 {
    match try_ssl_read_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ssl_read_exit(ctx: RetProbeContext) -> Result<u32, u32> {
    let retval: i32 = ctx.ret::<i32>(); // SSL_read's return value
    if retval <= 0 {
        return Ok(0); // Read failed or no data
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let (buf_ptr, _num, lib_type) = match unsafe { SSL_READ_ARGS.get(&pid_tgid) } {
        Some(args) => *args,
        None => return Ok(0), // Entry wasn't tracked
    };

    let _ = SSL_READ_ARGS.remove(&pid_tgid);

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = TLS_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

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

        (*e).direction = 0; // read (post-decryption)
        (*e).lib_type = lib_type as u8; // Retrieved from entry probe (OpenSSL=0, BoringSSL=1, GnuTLS=2)

        // Capture first N bytes of plaintext (budget: MAX_TLS_CAPTURE).
        let to_read = if retval as usize > MAX_TLS_CAPTURE {
            MAX_TLS_CAPTURE
        } else {
            retval as usize
        };

        // Batch read: single bpf_probe_read_user_buf() call instead of 256
        // individual bpf_probe_read_user() calls (verifier-friendly).
        let data_slice = &mut (*e).data;
        (*e).bytes_len = if let Ok(()) =
            bpf_probe_read_user_buf(buf_ptr as *const u8, &mut data_slice[..to_read])
        {
            to_read as u32
        } else {
            0
        };

        if TLS_CAPTURE_EVENTS
            .output::<TlsCaptureEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping TLS read event"
            );
        }
    }

    Ok(0)
}
