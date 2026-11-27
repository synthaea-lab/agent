//! One process reaching into another's memory or threads.

use super::*;

/// Process debugging/injection primitive (issue #265): `ptrace(2)`, every request
/// unfiltered — the request code itself (`PTRACE_ATTACH`, `PTRACE_POKEDATA`, ...)
/// is the injection/debugger-abuse signal, not something this sensor pre-filters.
/// Linux-only (there is no Windows/macOS equivalent this reuses — `ptrace(2)` has
/// no cross-platform analogue the way logon/session events did for
/// [`AuthEvent`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtraceEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// The raw `request` argument (see `<sys/ptrace.h>`) — not decoded to a name
    /// here, same "sensor reports, detection interprets" split as elsewhere.
    pub request: u64,
    /// The target process being traced/attached/read.
    pub target_pid: u32,
    /// The `addr` argument — meaningful for PEEK/POKE*-family requests, passed
    /// through as-is for every request regardless (see
    /// `sensor-linux-wire::PtraceEvent`'s doc).
    pub addr: u64,
    /// The `data` argument — the value written for POKE* requests, a second
    /// pointer for several others.
    pub data: u64,
}

/// Cross-process memory read (issue #265): `process_vm_readv(2)` — reads another
/// process's memory directly, without `ptrace`'s attach/stop choreography. The
/// credential-dumping/memory-scraping primitive on Linux.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessVmReadEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// The process being read FROM.
    pub target_pid: u32,
    /// How many `struct iovec` entries the caller passed on each side — a real
    /// scatter-gather call can span several; only the first remote entry's length
    /// is resolved (`remote_iov_len`), not each one.
    pub local_iov_count: u64,
    /// Number of `struct iovec` entries on the remote (target) side.
    pub remote_iov_count: u64,
    /// `remote_iov[0].iov_len` — bytes of the target's memory the first requested
    /// region covers. `0` if `remote_iov_count` is `0` or the read failed.
    pub remote_iov_len: u64,
}

/// Cross-process memory write (issue #265): `process_vm_writev(2)` — the
/// write-direction mirror of [`ProcessVmReadEvent`]: injecting data into another
/// process's memory without `ptrace(PTRACE_POKEDATA, ...)`'s word-at-a-time
/// interface. Classic shellcode-injection primitive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessVmWriteEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// The process being written TO.
    pub target_pid: u32,
    /// Number of `struct iovec` entries on the local (calling) side.
    pub local_iov_count: u64,
    /// Number of `struct iovec` entries on the remote (target) side.
    pub remote_iov_count: u64,
    /// `remote_iov[0].iov_len` — bytes being written into the target's memory by
    /// the first requested region. Same caveats as
    /// [`ProcessVmReadEvent::remote_iov_len`].
    pub remote_iov_len: u64,
}

/// Anonymous in-memory file creation (issue #265): `memfd_create(2)` — the
/// fileless-execution primitive (`memfd_create` + a written ELF image +
/// `execveat(fd, "", ..., AT_EMPTY_PATH)` runs a binary that never touches a real
/// path on disk).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemfdCreateEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// The caller-supplied display name — cosmetic only per `memfd_create(2)`
    /// (shows up as the target of `/proc/<pid>/fd/<n>`), not a real path.
    pub name: String,
    /// `MFD_CLOEXEC`, `MFD_ALLOW_SEALING`, ...
    pub flags: u32,
    /// The file descriptor `memfd_create(2)` returned (#510). Only successful
    /// creations are reported, so this is always `>= 0`. It is what the exec
    /// path's `<n>` in `/proc/self/fd/<n>` names, which is the one piece of
    /// evidence that the executed fd *is* this memfd and not an unrelated
    /// descriptor opened in the same window.
    pub fd: i32,
}

/// A thread created in another process (<https://github.com/synthaea-lab/agent/issues/41>): the native equivalent of Sysmon event 8
/// (`CreateRemoteThread`), the classic injection primitive (T1055).
///
/// On Windows: a Microsoft-Windows-Kernel-Process `ThreadStart` (EID 3) whose creating
/// process, the record header's pid, is not the process that owns the new thread. `meta`
/// is the creating process. The sensor drops the thread starts that are not injections by
/// construction before building this event: a thread started by its own process, one
/// started by the kernel (pid 0 or 4), and the initial thread of a new process (its creator
/// already appears as the [`ExecEvent`]'s parent). What is left is cross-process but not
/// necessarily hostile: debuggers, installers and services that start threads in their
/// clients look the same (#715 measured about 1 to 2 per second on an idle host).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteThreadEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// The process that owns the new thread.
    pub target_pid: u32,
    /// The owning process's image, as the sensor's pid store knew it; `None` when it did not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_image_path: Option<String>,
    /// The new thread's id.
    pub thread_id: u32,
    /// The address the thread starts at, in the owning process: the user-mode start
    /// address (`Win32StartAddr`, what `CreateRemoteThread` was given), or the kernel's
    /// `StartAddr` when the former is 0. Not resolved to a module.
    ///
    /// Chosen by the creator: an injector can start the thread at an `ntdll` or
    /// `kernel32` routine and redirect it from there, so an address inside a module is no
    /// evidence the thread is benign, and a rule must not read it as such.
    pub start_address: u64,
}

/// One process opening another for access (<https://github.com/synthaea-lab/agent/issues/41>): the native equivalent of Sysmon event 10
/// (`ProcessAccess`).
///
/// On Windows: a Microsoft-Windows-Kernel-Audit-API-Calls `PsOpenProcess` (EID 5), whose
/// caller is the record header's pid. The sensor reports only opens of LSASS that ask for
/// a right that reaches its memory, the credential-dumping step (T1003.001): read or write
/// it (`PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`), run code in it
/// (`PROCESS_CREATE_THREAD`), get a full handle out of it (`PROCESS_DUP_HANDLE`) or clone it
/// (`PROCESS_CREATE_PROCESS`), or a generic or maximum right that includes one of them.
/// Every other open is dropped before this event is built. Denied opens are reported too,
/// with their status: a refused attempt on a protected LSASS is still an attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessAccessEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// The caller's full image path, when the sensor could resolve it: the evidence an
    /// expected-reader exclusion decides on (<https://github.com/synthaea-lab/agent/issues/45>), since `meta.comm` is only its file
    /// name, which a renamed tool chooses. `None` when unresolved; never a bare name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_image_path: Option<String>,
    /// The process that was opened.
    pub target_pid: u32,
    /// The opened process's image, when the sensor knew it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_image_path: Option<String>,
    /// The access mask the caller asked for, as passed (generic bits not mapped).
    pub desired_access: u32,
    /// The `NTSTATUS` of the open: 0 when it succeeded.
    pub status: u32,
}
