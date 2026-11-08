//! The Windows-only half: IP Helper + `Toolhelp32` calls and the snapshot entry
//! points.

use std::{
    collections::HashMap,
    mem::{offset_of, size_of},
    net::{IpAddr, Ipv6Addr, SocketAddr},
};

use schema::{IPPROTO_TCP, IPPROTO_UDP};
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, INVALID_HANDLE_VALUE, NO_ERROR},
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
        MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
        MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_LISTENER, UDP_TABLE_OWNER_PID,
    },
    Networking::WinSock::{AF_INET, AF_INET6},
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    },
};

use crate::{
    Protocol, SocketsError,
    raw::{ListenerEntry, ipv4_from_row, is_drift_relevant, port_from_row},
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
                return Err(SocketsError::Table {
                    protocol: Protocol::Tcp,
                    family: label,
                    code,
                });
            }
        }
    }
    Err(SocketsError::Table {
        protocol: Protocol::Tcp,
        family: label,
        code: ERROR_INSUFFICIENT_BUFFER,
    })
}

/// Fetches one `GetExtendedUdpTable` table into an owned byte buffer. Unlike
/// the TCP table there is no "listener" filter — `UDP_TABLE_OWNER_PID` returns
/// every bound UDP endpoint, server and client alike (<https://github.com/synthaea-lab/agent/issues/40>'s noise
/// problem; [`snapshot_for_drift`] is where the filter sits).
fn fetch_udp_table(family: u16, label: &'static str) -> Result<Vec<u8>, SocketsError> {
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
            GetExtendedUdpTable(
                ptr,
                &raw mut size,
                0,
                u32::from(family),
                UDP_TABLE_OWNER_PID,
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
                return Err(SocketsError::Table {
                    protocol: Protocol::Udp,
                    family: label,
                    code,
                });
            }
        }
    }
    Err(SocketsError::Table {
        protocol: Protocol::Udp,
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

/// Every bound IPv4 UDP endpoint (not just "servers" — see [`fetch_udp_table`]).
fn ipv4_udp_sockets() -> Result<Vec<(u32, SocketAddr)>, SocketsError> {
    let buf = fetch_udp_table(AF_INET, "IPv4")?;
    Ok(
        rows::<MIB_UDPROW_OWNER_PID>(&buf, offset_of!(MIB_UDPTABLE_OWNER_PID, table))
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

/// Every bound IPv6 UDP endpoint (not just "servers" — see [`fetch_udp_table`]).
fn ipv6_udp_sockets() -> Result<Vec<(u32, SocketAddr)>, SocketsError> {
    let buf = fetch_udp_table(AF_INET6, "IPv6")?;
    Ok(
        rows::<MIB_UDP6ROW_OWNER_PID>(&buf, offset_of!(MIB_UDP6TABLE_OWNER_PID, table))
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

/// Attributes `(pid, local)` to its owner from `processes`, a prior
/// [`process_table`] call.
fn attribute(
    processes: &HashMap<u32, (u32, String)>,
    (pid, local): (u32, SocketAddr),
    protocol: u8,
) -> ListenerEntry {
    let owner = processes.get(&pid);
    ListenerEntry {
        pid,
        ppid: owner.map(|(ppid, _)| *ppid),
        process_name: owner.map(|(_, name)| name.clone()),
        local,
        protocol,
    }
}

/// Every listening TCP socket, IPv4 and IPv6, attributed to its owner.
fn tcp_listeners(
    processes: &HashMap<u32, (u32, String)>,
) -> Result<Vec<ListenerEntry>, SocketsError> {
    let mut tcp = ipv4_listeners()?;
    tcp.extend(ipv6_listeners()?);
    Ok(tcp
        .into_iter()
        .map(|e| attribute(processes, e, IPPROTO_TCP))
        .collect())
}

/// Every bound UDP socket, IPv4 and IPv6, attributed to its owner. Best-effort:
/// a UDP table failure is logged and read as no UDP entries, so it never
/// discards the TCP listeners of the same snapshot (review of #1008: the
/// startup baseline going empty because IPv6 UDP errored would alert on every
/// pre-existing TCP listener on the first poll).
fn udp_sockets(processes: &HashMap<u32, (u32, String)>) -> Vec<ListenerEntry> {
    let mut udp = ipv4_udp_sockets().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "IPv4 UDP socket table unavailable, continuing without it");
        Vec::new()
    });
    udp.extend(ipv6_udp_sockets().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "IPv6 UDP socket table unavailable, continuing without it");
        Vec::new()
    }));
    udp.into_iter()
        .map(|e| attribute(processes, e, IPPROTO_UDP))
        .collect()
}

/// Takes one snapshot of every listening TCP socket and every bound UDP
/// socket, IPv4 and IPv6, unfiltered.
///
/// A socket bound to both families appears once per family: they are distinct
/// kernel objects, and LISTENER-DRIFT keys on the address and protocol anyway.
///
/// The UDP table has no "listener" filter: every bound UDP endpoint comes back,
/// DNS client sockets, QUIC/browser and media sockets on ephemeral ports
/// included. The agent reads [`snapshot_for_drift`], which drops those; this
/// is the raw table, for tests and diagnostics.
///
/// # Errors
///
/// [`SocketsError::Table`] when either TCP table (IPv4 or IPv6) cannot be
/// read. A UDP table failure is logged and read as no UDP entries instead,
/// and a failed process snapshot leaves entries unattributed (see
/// [`ListenerEntry`]).
pub fn snapshot() -> Result<Vec<ListenerEntry>, SocketsError> {
    let processes = process_table();
    let mut entries = tcp_listeners(&processes)?;
    entries.extend(udp_sockets(&processes));
    Ok(entries)
}

/// [`snapshot`] with the client sockets taken out: every TCP listener, and
/// the UDP sockets bound outside the ephemeral port range
/// ([`crate::raw::is_drift_relevant`], <https://github.com/synthaea-lab/agent/issues/40>). What the agent seeds the
/// LISTENER-DRIFT baseline from and polls.
///
/// # Errors
///
/// Same failure mode as [`snapshot`].
pub fn snapshot_for_drift() -> Result<Vec<ListenerEntry>, SocketsError> {
    let mut entries = snapshot()?;
    let before = entries.len();
    entries.retain(is_drift_relevant);
    tracing::debug!(
        kept = entries.len(),
        ephemeral_udp_dropped = before - entries.len(),
        "socket snapshot filtered for listener drift"
    );
    Ok(entries)
}

/// One [`snapshot_for_drift`] mapped to [`schema::Event::ListenPort`] events,
/// stamped with `timestamp_ns` as the snapshot time.
///
/// # Errors
///
/// Same failure mode as [`snapshot_for_drift`], which this wraps.
pub fn listen_port_events_for_drift(timestamp_ns: u64) -> Result<Vec<schema::Event>, SocketsError> {
    Ok(snapshot_for_drift()?
        .iter()
        .map(|entry| crate::normalize::listen_port_event(entry, timestamp_ns))
        .collect())
}
