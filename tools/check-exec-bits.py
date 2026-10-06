#!/usr/bin/env python3
"""Keep every tracked shell script with a shebang executable in git.

Our docs and scripts run them by path (`./lab/scenarios/log-clear.sh`,
`"$REPO_ROOT/lab/provisioning/ort-static-link-flags.sh"`). A script committed
as mode 100644 fails there with `Permission denied`, and inside `eval "$(...)"`
that is silent: the substitution is empty, `eval` returns 0, and the caller
carries on without whatever the script was meant to produce. That is how #647's
static .deb lost its ONNX Runtime link flags and failed 50 minutes later at
link time, a week after #555 hit the same defect.

The mode that counts is the one in the git index, not the one on disk (a
Windows checkout shows everything as executable), so this reads
`git ls-files --stage`. To fix a file:

    git update-index --chmod=+x path/to/script.sh

Run from the repository root: `python3 tools/check-exec-bits.py`
Exits non-zero listing every offender. CI runs this on every push.
"""

import subprocess
import sys

EXECUTABLE = "100755"


def tracked_shell_scripts() -> list[tuple[str, str]]:
    """(mode, path) of every tracked *.sh, from the index."""
    out = subprocess.run(
        ["git", "ls-files", "--stage", "-z", "--", "*.sh"],
        check=True, capture_output=True, text=True,
    ).stdout
    entries = []
    for record in out.split("\0"):
        if not record:
            continue
        meta, path = record.split("\t", 1)
        entries.append((meta.split()[0], path))
    return entries


def has_shebang(path: str) -> bool:
    # The staged blob, so the check holds even when the working tree differs.
    blob = subprocess.run(
        ["git", "show", f":{path}"], check=True, capture_output=True
    ).stdout
    return blob.startswith(b"#!")


def main() -> int:
    scripts = tracked_shell_scripts()
    offenders = [
        path for mode, path in scripts
        if mode != EXECUTABLE and has_shebang(path)
    ]
    for path in offenders:
        print(f"{path}: has a shebang but is not executable in git")
    if offenders:
        print(
            f"\n{len(offenders)} script(s) not executable. Fix with "
            "`git update-index --chmod=+x <path>`: invoked by path, they fail "
            "with 'Permission denied' (silently inside eval, see #647)."
        )
        return 1
    print(f"{len(scripts)} shell script(s), every one with a shebang is executable")
    return 0


if __name__ == "__main__":
    sys.exit(main())
