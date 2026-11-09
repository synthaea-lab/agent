#!/usr/bin/env python3
"""Check the syscall tracepoint offsets of the eBPF probes against the tracepoint layout.

Every `syscalls:sys_enter_*` / `sys_exit_*` record is `struct trace_entry` (8 bytes), then
`int __syscall_nr`, then the arguments (or `ret`) as `unsigned long`. So argument `i` sits at
`16 + 8*i` on x86_64/aarch64 and at `12 + 4*i` on i686: the layout verified for
`sys_enter_openat` on both (see `OPENAT_*_OFFSET`). An i686 offset is usually inferred, since
no lab machine runs one, and the i686 probes are not built in CI. This check makes each
`#[cfg]` pair of `*_OFFSET` constants agree with that rule, so an inferred i686 value cannot
drift from its 64-bit twin unnoticed (ptrace and process_vm_*v were 4 bytes off).

Run from the repository root: `python3 tools/check-ebpf-offsets.py`
Exits non-zero listing every pair that breaks the rule.
"""

import re
import sys
from pathlib import Path

SRC = Path("crates/sensors/linux/ebpf/src")
PAIR = re.compile(
    r'#\[cfg\((any\(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"\)|bpf_target_arch = "x86")\)\]'
    r"\s*\n\s*(?:pub\(crate\) )?const (\w+_OFFSET): usize = (\d+);"
)

# A pair that legitimately breaks the rule, with the reason. Empty today.
EXCEPTIONS: dict[str, str] = {}


def main() -> int:
    pairs: dict[tuple[str, str], dict[str, int]] = {}
    for path in sorted(SRC.rglob("*.rs")):
        for m in PAIR.finditer(path.read_text(encoding="utf-8")):
            arch = "i686" if m.group(1) == 'bpf_target_arch = "x86"' else "64"
            pairs.setdefault((str(path), m.group(2)), {})[arch] = int(m.group(3))
    errors = []
    for (path, name), values in sorted(pairs.items()):
        if name in EXCEPTIONS:
            continue
        wide, narrow = values.get("64"), values.get("i686")
        if wide is None or narrow is None:
            errors.append(f"{path}: {name} has no {'i686' if narrow is None else '64-bit'} twin")
            continue
        index, rem = divmod(wide - 16, 8)
        if rem or index < 0 or narrow != 12 + 4 * index:
            want = f"{12 + 4 * index}" if not rem and index >= 0 else "?"
            errors.append(f"{path}: {name} is {wide} (64-bit) but {narrow} on i686, expected {want}")
    for e in errors:
        print(e)
    print(f"{len(pairs)} offset pairs checked, {len(errors)} wrong")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
