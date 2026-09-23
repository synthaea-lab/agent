//! The Windows-only half: IP Helper + `Toolhelp32` calls and the snapshot entry
//! points.

use std::{
    collections::HashMap,
    mem::{offset_of, size_of},
    net::{IpAddr, Ipv6Addr, SocketAddr},
};

use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, INVALID_HANDLE_VALUE, NO_ERROR},
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID,
        MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
    },
    Networking::WinSock::{AF_INET, AF_INET6},
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    },
};

use crate::{
    SocketsError,
    raw::{ListenerEntry, ipv4_from_row, port_from_row},
};

/// The table can grow between the sizing call and the fill call (a service
/// binding mid-poll); a few retries absorb that without looping forever.
const TABLE_FETCH_ATTEMPTS: usize = 4;

/// Fetches one `GetExtendedTcpTable` listener table into an owned byte buffer.
fn fetch_table(family: u16, label: &'static str) -> Result<Vec<u8>, SocketsError> {
    let mut size: u32 = 0;
    let mut buf: Vec<u8> = Vec::new();
    for _ in 0..TABLE_FETCH_ATTEMPTS {
        buf.resize(size as usize, 0);
        let ptr = if buf.is_empty() {
            std::ptr::null_mut()
        } else {
            buf.as_mut_ptr().cast()
        };
        // SAFETY: `ptr` is null (sizing call) or points to `size` writable bytes
        // owned by `buf`; `size` is a valid in/out pointer for the call.
        let rc = unsafe {
            GetExtendedTcpTable(
                ptr,
                &raw mut size,
                0,
                u32::from(family),
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        match rc {
            NO_ERROR => {
                buf.truncate(size as usize);
                return Ok(buf);
            }
            ERROR_INSUFFICIENT_BUFFER => {}
            code => {
                return Err(SocketsError::TcpTable {
                    family: label,
                    code,
                });
            }
        }
    }
    Err(SocketsError::TcpTable {
        family: label,
        code: ERROR_INSUFFICIENT_BUFFER,
    })
}

/// Reads the rows of a `MIB_*TABLE_OWNER_PID` buffer: a `u32` count at offset 0,
/// then `count` rows starting at `rows_offset`. A count that would overrun the
/// buffer is clamped to what the buffer holds rather than trusted.
fn rows<Row: Copy>(buf: &[u8], rows_offset: usize) -> Vec<Row> {
    if buf.len() < size_of::<u32>() {
        return Vec::new();
    }
    // SAFETY: at least 4 bytes are present (checked above); `read_unaligned`
    // needs no alignment from the `Vec<u8>` allocation.
    let declared = unsafe { std::ptr::read_unaligned(buf.as_ptr().cast::<u32>()) } as usize;
    let available = buf.len().saturating_sub(rows_offset) / size_of::<Row>();
    (0..declared.min(available))
        .map(|i| {
            // SAFETY: `i < available`, so the whole row lies within `buf`; `Row`
            // is a plain-old-data IP Helper struct, valid for any bit pattern.
            unsafe {
                std::ptr::read_unaligned(
                    buf.as_ptr()
                        .add(rows_offset + i * size_of::<Row>())
                        .cast::<Row>(),
                )
            }
        })
        .collect()
}

fn ipv4_listeners() -> Result<Vec<(u32, SocketAddr)>, SocketsError> {
    let buf = fetch_table(AF_INET, "IPv4")?;
    Ok(
        rows::<MIB_TCPROW_OWNER_PID>(&buf, offset_of!(MIB_TCPTABLE_OWNER_PID, table))
            .into_iter()
            .map(|row| {
                let addr = SocketAddr::new(
                    IpAddr::V4(ipv4_from_row(row.dwLocalAddr)),
                    port_from_row(row.dwLocalPort),
                );
                (row.dwOwningPid, addr)
            })
            .collect(),
    )
}

fn ipv6_listeners() -> Result<Vec<(u32, SocketAddr)>, SocketsError> {
    let buf = fetch_table(AF_INET6, "IPv6")?;
    Ok(
        rows::<MIB_TCP6ROW_OWNER_PID>(&buf, offset_of!(MIB_TCP6TABLE_OWNER_PID, table))
            .into_iter()
            .map(|row| {
                let addr = SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                    port_from_row(row.dwLocalPort),
                );
                (row.dwOwningPid, addr)
            })
            .collect(),
    )
}

/// pid → (ppid, executable name) from one `Toolhelp32` snapshot. Empty on
/// failure: listeners then keep their pid and lose only the enrichment.
fn process_table() -> HashMap<u32, (u32, String)> {
    let mut out = HashMap::new();
    // SAFETY: the snapshot handle is checked against INVALID_HANDLE_VALUE and
    // closed; PROCESSENTRY32W is zeroed with dwSize set before the first call,
    // and szExeFile reads are bounded by its NUL (or full length).
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            tracing::warn!("toolhelp snapshot failed — listeners reported without attribution");
            return out;
        }
        let mut entry: PROCESSENTRY32W = core::mem::zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &raw mut entry) != 0 {
            loop {
                let end = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                out.insert(
                    entry.th32ProcessID,
                    (
                        entry.th32ParentProcessID,
                        String::from_utf16_lossy(&entry.szExeFile[..end]),
                    ),
                );
                if Process32NextW(snap, &raw mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    out
}

/// Takes one snapshot of every listening TCP socket, IPv4 and IPv6.
///
/// A socket bound to both families appears once per family — they are distinct
/// kernel objects, and LISTENER-DRIFT keys on the address anyway.
///
/// # Errors
///
/// [`SocketsError::TcpTable`] when either family's table cannot be read. The
/// process snapshot failing is not an error (see [`ListenerEntry`]).
pub fn snapshot() -> Result<Vec<ListenerEntry>, SocketsError> {
    let mut sockets = ipv4_listeners()?;
    sockets.extend(ipv6_listeners()?);
    let processes = process_table();
    Ok(sockets
        .into_iter()
        .map(|(pid, local)| {
            let owner = processes.get(&pid);
            ListenerEntry {
                pid,
                ppid: owner.map(|(ppid, _)| *ppid),
                process_name: owner.map(|(_, name)| name.clone()),
                local,
            }
        })
        .collect())
}

/// One [`snapshot`] mapped to [`schema::Event::ListenPort`] events, stamped
/// with `timestamp_ns` as the snapshot time.
///
/// # Errors
///
/// Same failure mode as [`snapshot`], which this wraps.
pub fn listen_port_events(timestamp_ns: u64) -> Result<Vec<schema::Event>, SocketsError> {
    Ok(snapshot()?
        .iter()
        .map(|entry| crate::normalize::listen_port_event(entry, timestamp_ns))
        .collect())
}
