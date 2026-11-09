# Wire format

[`sensor-linux-wire`](../../../crates/sensors/linux/wire/src/lib.rs) defines the bytes that cross
the ring buffers between the eBPF programs and userspace. It is `no_std` so the probe crate can use
it; the `user` feature adds `std` helpers for the userspace crates.

These types are an internal ABI, not the agent's event model. Userspace converts every record
into a `schema` event ([normalization](userspace-loader.md#normalization)), and both sides must be
built from the same revision.

## Versioning: `WIRE_VERSION`

Ring-buffer items carry no header and no version. [`WIRE_VERSION`](../../../crates/sensors/linux/wire/src/lib.rs)
is a build-time tripwire instead: [`normalize.rs`](../../../crates/sensors/linux/userspace/src/normalize.rs)
asserts `const _: () = assert!(wire::WIRE_VERSION == N)`, so a layout change that does not revisit
the mappings fails to compile. Bump it on any change to a struct's size, field order or meaning,
and update the assertion after checking each mapping.

The version also names the bpffs pin of `SIGNAL_TAMPER_LAST`
([`tamper_pin_path`](../../../crates/sensors/linux/userspace/src/ebpf.rs)): aya reuses an existing
pin without checking its value size, so a pin from another layout must never be picked up.

The history of what each version added is in `git log` for this file; the current layout is what
the struct definitions say.

## Layout rules

- Every struct is `#[repr(C)]`, `Copy`, and made of integers and byte arrays, so every bit pattern
  is valid. Userspace reads fixed records with `read_unaligned` after checking the length.
- **No implicit padding.** Where alignment would insert padding, an explicit field takes its place
  (`reserved`, `reserved0`, `reserved1`, or a meaningful field such as `execd` and `parent_execd`).
  Implicit padding is uninitialised memory to the verifier, and aya's `Pod` impls on the userspace
  newtypes (`PodLineage`, `PodSignal` in [`ebpf.rs`](../../../crates/sensors/linux/userspace/src/ebpf.rs))
  are only sound without it.
- Strings are fixed byte arrays plus a length. The kernel's `_str_bytes` helpers stop at NUL;
  userspace also stops at the first NUL and decodes lossily, never failing on invalid UTF-8.
- Truncation at a bound is a sensor property, not a schema limit.

## Bounds

| Constant | Value | Applies to | Why this value |
| --- | --- | --- | --- |
| `TASK_COMM_LEN` | 16 | `comm`, `pcomm` | Kernel's own size (15 bytes + NUL) |
| `MAX_PATH_LEN` | 256 | paths, image, mount source | Fits the per-CPU scratch pattern |
| `ARGV_WINDOW_BYTES` | 1024 | exec argv | Whole block when it fits, else head + tail |
| `ARGV_HEAD_BYTES` / `ARGV_TAIL_BYTES` | 768 / 256 | exec argv over the window | Tail defeats front padding |
| `MAX_XATTR_NAME_LEN` | 255 | xattr name | Kernel's `XATTR_NAME_MAX`, so no truncation case exists |
| `MAX_FS_TYPE_LEN` | 32 | mount fs type | fs type names are short |
| `MAX_MODULE_NAME_LEN` | 64 | `delete_module` name | Kernel `MODULE_NAME_LEN` is 56 |
| `MAX_DNS_QUERY_LEN` | 256 | `getaddrinfo` name | RFC 1035 name length fits |
| `MAX_DNS_ANSWERS` | 24 | `getaddrinfo` results walked | Constant loop bound for the verifier; `answers_truncated` marks more |
| `MAX_DNS_UDP_PAYLOAD` | 272 | UDP/53 datagram copy | 12-byte header + 255-byte name + type and class + 1 |
| `MAX_TLS_CAPTURE` | 256 | TLS plaintext | First bytes of each call |
| `MAX_READLINE_INPUT` | 512 | readline line | Interactive commands |
| `SET_TIME_COMPONENTS` × `SET_TIME_COMPONENT_LEN` | 8 × 32 | `inode_setattr` dentry names | Constant-bound dentry walk |
| `SIGNAL_WATCH_TOOLS_ENTRIES` | 8192 | tool watch map | Checked at compile time against the per-unit caps |

## `EventMeta`

Every record begins with [`EventMeta`](../../../crates/sensors/linux/wire/src/lib.rs):

| Field | Source | Meaning of 0 |
| --- | --- | --- |
| `pid` | `bpf_get_current_pid_tgid() >> 32` (the tgid) | |
| `ppid` | `PROC_LINEAGE[tgid].ppid` | parent unknown (forked before attach and priming missed it, or map full) |
| `uid`, `gid` | `bpf_get_current_uid_gid()` | root |
| `timestamp_ns` | `bpf_ktime_get_ns()`, monotonic since boot | userspace adds the boot-to-epoch offset |
| `comm` | `bpf_get_current_comm()` | |
| `cgroup_id` | `bpf_get_current_cgroup_id()` at probe time | helper failed; also always 0 on uprobe records |
| `process_generation` | `PROC_LINEAGE[tgid].generation` | no stamp (never a real generation) |
| `parent_generation` | `PROC_LINEAGE[tgid].parent_generation` | unknown |

The generation fields are explained in [process context](process-context.md#process-generations).

## The exec record

The exec record is the only variable-length record. The probe builds an
[`ExecRecord`](../../../crates/sensors/linux/wire/src/lib.rs) (the fixed `ExecEvent` followed by a
1024-byte `argv` area) in per-CPU scratch and emits only
`size_of::<ExecEvent>() + argv_head_len + argv_tail_len` bytes. A compile-time assertion pins
`offset_of!(ExecRecord, argv) == size_of::<ExecEvent>()`, which both the probe's slice and the
parser rely on.

A fixed 1 KiB argv area in every record would have cut the ring's capacity by about four for a
sample whose p99.9 command line is a few hundred bytes. With variable-length records the ring was
raised from 256 to 512 KiB, which holds about as many records as before.

```text
| ExecEvent (fixed) ................................ | head bytes ......... | tail bytes ... |
  meta, image, pcomm, grandparent_*, parent_execd,     argv[..head]          argv[head..head+tail]
  argv_total, argv_head_len, argv_tail_len
```

### Parsing it

The lengths in the record describe bytes a process chose, so userspace never trusts them.
[`parse_exec_record`](../../../crates/sensors/linux/wire/src/lib.rs) accepts exactly the shapes the
probe writes and returns [`ExecRecordError`](../../../crates/sensors/linux/wire/src/lib.rs) otherwise:

| `head` | `tail` | `total` | Meaning |
| --- | --- | --- | --- |
| 0 | 0 | any | Probe read nothing; fall back to `/proc/<pid>/cmdline` |
| `== total` | 0 | `<= 1024` | Whole block captured |
| 768 | 256 | `> 1024` | Head and tail captured |
| 768 | 0 | `> 1024` | Tail read failed; head only |

Anything else is `BadLengths`; a record shorter than its fixed part is `Short`; shorter than the
fixed part plus the announced lengths is `Truncated`. A refused record is dropped and counted by
the drain (`EXEC_RECORDS_REFUSED`, the first and every thousandth logged), never read past its end.
The parser has a deterministic test suite in
[`tests/exec_record.rs`](../../../crates/sensors/linux/wire/tests/exec_record.rs) and a fuzz target,
[`exec_record_parse`](../../../tests/fuzz/fuzz_targets/exec_record_parse.rs).

How the windows become `argv` tokens is in [process context](process-context.md#argv).

## `LineageEntry`

The value type of `PROC_LINEAGE`. It is written by the kernel (fork and exec probes) and by
userspace (priming), so its layout is shared:

| Field | Meaning |
| --- | --- |
| `ppid`, `comm` | Parent tgid and parent comm at fork |
| `execd` | 1 once this process has exec'd since the fork; 1 for primed processes |
| `generation` | `bpf_ktime_get_ns()` at fork, or `starttime` with `PRIMED_GENERATION_BIT` set when primed |
| `parent_generation` | The parent's `generation` at the time of the fork |

[`PRIMED_GENERATION_BIT`](../../../crates/sensors/linux/wire/src/lib.rs) (bit 63) keeps a primed
stamp (clock ticks) from ever equalling a live one (nanoseconds since boot never reach bit 63).

## Shared helpers

- [`is_filtered_path`](../../../crates/sensors/linux/wire/src/path_filter.rs): the in-kernel path
  filter, also called by the agent's deception module to check a decoy path would be visible.
- [`comm_str`](../../../crates/sensors/linux/wire/src/lib.rs) and
  [`boot_epoch_offset_ns`](../../../crates/sensors/linux/wire/src/lib.rs): shared by `sensor-linux`
  and `sensor-linux-uprobes` so the two cannot drift. The offset is computed once at start; if
  `CLOCK_MONOTONIC` cannot be read it is 0 and timestamps stay monotonic.
- [`SIGNAL_SENDER_UNRELIABLE`](../../../crates/sensors/linux/wire/src/lib.rs): bit 31 of
  `SignalEvent::signal`, see [signals](signals.md#signal_generate).

## Changing the format

1. Edit the struct; keep explicit padding so `size_of` has no holes.
2. Bump `WIRE_VERSION` and the assertion in `normalize.rs`; revisit every mapping.
3. If the record becomes variable-length, write a parser in this crate, a robustness test and a fuzz
   target, as for the exec record.
4. Rebuild both the probes and the loader (they are always built together by `build.rs`).
