# Process memory

Fileless payloads (a `memfd` executed in place, an injected region) leave nothing on disk for a file
scan. [`sensor-linux-procmem`](../../../crates/sensors/linux/procmem/src/lib.rs) is the mechanism
the YARA memory scan uses to look at a running process: list its mappings and read bytes from them.
It holds no policy. Which regions to read, how much and when is the `yara` crate's memory module;
the agent adapts the two in [`memscan.rs`](../../../agent/src/memscan.rs).

## API

| Function | Reads | Returns |
| --- | --- | --- |
| [`parse_maps_line`](../../../crates/sensors/linux/procmem/src/lib.rs) | one `/proc/<pid>/maps` line | `MapsEntry { start, end, perms, pathname }` or `MapsError` |
| [`parse_maps`](../../../crates/sensors/linux/procmem/src/lib.rs) | a whole maps file | entries and the count of malformed lines |
| [`read_maps`](../../../crates/sensors/linux/procmem/src/lib.rs) | `/proc/<pid>/maps` | entries and malformed count |
| [`read_memory`](../../../crates/sensors/linux/procmem/src/lib.rs) | `/proc/<pid>/mem` at `start` | up to `len` bytes |

## Behaviour

- **Untrusted input.** The pathname column is whatever the process named its file, including a
  `memfd` name with arbitrary bytes. The maps file is read as bytes and decoded lossily: strict
  UTF-8 would fail the whole file and let exactly the process being scanned opt out. Pathnames may
  contain spaces; the parser takes everything after the fifth field. A malformed line is counted,
  not fatal.
- **Reads are bounded** by the caller's `len` and by what the kernel returns. A short read stops;
  a hole partway through (a guard page) keeps what was read; an unreadable first byte is an error
  (the region was unmapped since the maps were read). `EINTR` is retried.
- **Permission.** The kernel gates `/proc/<pid>/mem` with `ptrace_may_access`: same uid and
  dumpable, or `CAP_SYS_PTRACE`. Without it the open fails with `PermissionDenied`, which the scan
  queue counts as unreadable. Granting the agent `CAP_SYS_PTRACE` is an operator choice.
- On non-Unix targets `read_memory` returns `Unsupported`.

## Testing

Unit tests cover maps lines with spaces, deleted files, `memfd` names (including one named with
bytes that are not UTF-8), anonymous mappings and malformed ranges, and read the test process's own
memory through `/proc/self`.
