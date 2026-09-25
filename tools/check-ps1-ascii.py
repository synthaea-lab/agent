#!/usr/bin/env python3
"""Keep every tracked PowerShell script ASCII-only.

Windows PowerShell 5.1, the only PowerShell on a stock Windows, reads a
BOM-less script as the ANSI code page: an em dash (E2 80 94) decodes to a
closing smart quote and the script fails to parse, or worse, parses into
something else (#433). A BOM would also fix it, but editors strip BOMs
silently; ASCII-only is the invariant that survives.

Run from the repository root: `python3 tools/check-ps1-ascii.py`
Exits non-zero listing every offending line. CI runs this on every push.
"""

import subprocess
import sys


def main() -> int:
    files = subprocess.run(
        ["git", "ls-files", "*.ps1", "*.psm1", "*.psd1"],
        check=True, capture_output=True, text=True,
    ).stdout.split()
    violations = []
    for path in files:
        with open(path, "rb") as f:
            for number, line in enumerate(f, start=1):
                if any(byte > 0x7F for byte in line):
                    text = line.decode("utf-8", errors="replace").rstrip()
                    violations.append(f"{path}:{number}: {text}")
    for violation in violations:
        print(violation)
    if violations:
        print(f"\n{len(violations)} non-ASCII line(s) in PowerShell scripts "
              "(Windows PowerShell 5.1 misreads them, see #433)")
        return 1
    print(f"{len(files)} PowerShell script(s), all ASCII")
    return 0


if __name__ == "__main__":
    sys.exit(main())
