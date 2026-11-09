# BPF-LSM hooks

BPF-LSM programs run at the kernel's security decision points rather than at the syscall boundary.
Two properties make them worth having next to the tracepoints:

- **Entry-path independence.** An operation reaches its LSM hook however it was submitted,
  including through `io_uring`, which never passes `sys_enter` and so blinds a tracepoint-only
  sensor.
- **A blocking path.** An LSM program can return `-EPERM`. Tracepoints cannot prevent anything.

Both hooks live in the same eBPF object as the tracepoints
([`main.rs`](../../../crates/sensors/linux/ebpf/src/main.rs)). They need a kernel with
`CONFIG_BPF_LSM` and BTF, and `bpf` in the active `lsm=` boot list. Both are optional: when either
cannot attach the agent logs why and runs without it.

| Hook | Attached by | Produces | Status |
| --- | --- | --- | --- |
| `file_open` | the agent, in a second copy of the object ([`attach_lsm_hooks`](../../../apps/agent/src/commands/linux.rs)) | a per-CPU hit counter | observation only |
| `inode_setattr` | `LinuxSensor`, in its own object ([`attach_inode_setattr`](../../../crates/sensors/linux/userspace/src/ebpf.rs)) | `FileSetTimeEvent` | built |

## Detecting support

[`detect_hook_support`](../../../crates/sensors/linux/lsm/src/attach.rs) checks that the kernel BTF
has a `bpf_lsm_<hook>` function. It needs no privilege and no `bpf(2)` call. A `false` is
definitive; a `true` is not a guarantee: the hook can be compiled in while `bpf` is missing from
`lsm=`, in which case the attach fails. [`attach_file_open`](../../../crates/sensors/linux/lsm/src/attach.rs)
reports which step failed (`LsmAttachError`: no BTF, program missing, load refused, attach refused).

## `file_open`

[`file_open`](../../../crates/sensors/linux/ebpf/src/main.rs) increments `LSM_FILE_OPEN_HITS` and
allows the open. [`file_open_hit_count`](../../../crates/sensors/linux/lsm/src/attach.rs) sums the
counter. It reads no `struct file` field and emits no `FileOpenEvent`: an LSM-sourced open and the
tracepoint-sourced one would double-count the same open until a deduplication rule exists. Its
purpose today is to prove the hook fires, including for `io_uring` opens, which
[`lsm_io_uring_evasion.rs`](../../../apps/agent/tests/lsm_io_uring_evasion.rs) checks on a real
BPF-LSM kernel with `fio --ioengine=io_uring`.

### Deferring to an earlier deny

The hook's last argument is the verdict of the LSM programs that ran before it. If it is non-zero,
the program returns a constant `-1` (`-EPERM`) instead of its own `0`, so it never overrides an
earlier deny with an allow. It cannot forward the exact value: the verifier requires every return
path of an LSM program to be provably within `[-4095, 0]`, and the argument reaches it as an
unconstrained scalar. Clamping or branching on it compiles to a branchless select the verifier's
range tracking does not see through. The consequence for anyone adding enforcement: the value the
hook returns is a generic deny, not the original LSM's errno.

### Not built

- Inline blocking on a policy verdict. There is no verdict source for the hook to consult yet.
- `bprm_check_security` and `socket_connect` hooks.
- A structured capability report of LSM coverage. The outcome is a log line: attached, not
  supported, or compiled in but not live.

## `inode_setattr`

Timestomping (T1070.006) sets a file's times to a value the caller chose. The hook
([`inode_setattr`](../../../crates/sensors/linux/ebpf/src/main.rs)) fires for every attribute change
that reaches `notify_change`, whichever syscall or `io_uring` op asked (`utimensat`, `utimes`,
`futimens`). It reads `iattr.ia_valid` and emits only when `ATTR_ATIME_SET` or `ATTR_MTIME_SET` is
set, which means the caller named the time. `ATTR_ATIME`/`ATTR_MTIME` alone are the kernel's own
"now" (a write, `touch` without `-d`, `UTIME_NOW`) and are ignored.

The hook gets a dentry, not a path, and `bpf_d_path` is not allowed in it. The probe walks
`d_parent` up to [`SET_TIME_COMPONENTS`](../../../crates/sensors/linux/wire/src/lib.rs) (8) levels,
copying each `d_name` into a 32-byte slot; `SET_TIME_TRUNCATED` marks a deeper chain or a longer
name. Userspace joins the names root first and prefixes an incomplete chain with `/...`, so it never
passes for an absolute path. A file on a mount other than `/` lacks its mount prefix. The raw
`timespec64` values are converted to `FILETIME` units so one rule serves Linux and Windows
([`file_set_time`](../../../crates/sensors/linux/userspace/src/normalize.rs)).

### Kernel requirements

- The probe reads arguments by position for the `(idmap, dentry, attr)` signature of kernel 6.3 and
  later. [`parse_inode_setattr_offsets`](../../../crates/sensors/linux/userspace/src/btf.rs) checks
  `bpf_lsm_inode_setattr`'s parameter names in the BTF and leaves the hook disabled on any other
  shape, because reading an older layout by this one would take the wrong pointers.
- The `iattr`, `dentry` and `qstr` offsets come from BTF; `INODE_SETATTR_ENABLED` stays 0 unless
  all resolved.
- Its ring, `FILE_SET_TIME_EVENTS`, is 1 MiB because unpacking an archive emits one event per file
  in a burst.

## Testing

- [`attach.rs`](../../../crates/sensors/linux/lsm/src/attach.rs) unit test (an unknown hook name is
  rejected) and the live [`lsm_io_uring_evasion.rs`](../../../apps/agent/tests/lsm_io_uring_evasion.rs)
  for `file_open`. The live test needs root, a BPF-LSM kernel and `fio`, and skips itself otherwise.
- BTF parser tests in [`btf.rs`](../../../crates/sensors/linux/userspace/src/btf.rs): a hook with
  another signature is disabled, offsets through an anonymous union, missing structs refused, and
  the running kernel's BTF when available.
