#!/usr/bin/env python3
"""Keep platform-specific Rust code where CLAUDE.md ("Platform code") allows it.

Core crates compile on all three OSes. Platform branches (`#[cfg(target_os = ...)]`,
`cfg(windows)`, `cfg(unix)`, `cfg!(...)` and the like) belong to a short list of places;
anywhere else a new one is drift that CLAUDE.md says should not happen and nothing used to
catch (#150).

Three kinds of path:

- **Allowed**: `crates/sensors/`, `crates/updater/`, `crates/response/src/quarantine.rs`
  (CLAUDE.md), `apps/` (each binary owns its OS entry point), `tools/` (the release tool is
  an operator binary) and test code (any `tests` directory, `tests.rs`, a file's own `#[cfg(test)]` module). No limit.
- **Exceptions**: the core-crate files in `EXCEPTIONS`, each with the number of platform
  branches it holds today and the reason. The number is a ceiling: a file may lose branches
  (lower the number in the same change), never gain them. A new exception needs a line here
  with its reason, and the same reason in CLAUDE.md.
- **Everything else**: no platform branch at all.

Counting is by source line: a non-comment line with `cfg(`, `cfg!(` or `cfg_attr(` followed by
`target_os`, `target_family`, `windows`, `unix`, `macos` or `linux`. A `cfg(test)` or
`cfg(feature = ...)` line does not count.

Run from the repository root: `python3 tools/check-platform-cfg.py`
Exits non-zero listing every offender. CI runs this in the `content` job.
"""

from __future__ import annotations

import re
import subprocess
import sys

ALLOWED_PREFIXES = (
    "crates/sensors/",
    "crates/updater/",
    "crates/response/src/quarantine.rs",
    "apps/",
    "tools/",
)

# path -> (ceiling, reason). The reasons are the ones CLAUDE.md gives.
EXCEPTIONS: dict[str, tuple[int, str]] = {
    "crates/config/src/discovery.rs": (
        4, "the default config path is the OS's own location for it"),
    "crates/config/src/load.rs": (
        2, "ipc.endpoint has a different shape per OS (named pipe or absolute socket path)"),
    "crates/config/src/template.rs": (
        3, "the shipped default template carries Linux paths; other OSes write a neutral one"),
    "crates/enrich/src/lib.rs": (
        3, "code-signature and PE enrichment, FFI per OS; moving it to a sensor is #151"),
    "crates/enrich/src/pe_info.rs": (
        3, "reads PE metadata through the Windows API; moving it is #151"),
    "crates/enrich/src/sig.rs": (
        6, "WinVerifyTrust/CryptCATAdmin on Windows, codesign on macOS; moving it is #151"),
    "crates/ipc/src/stream.rs": (
        2, "the one place that picks a Unix socket or a Windows named pipe, with peer credentials"),
    "crates/rules/src/stateless/impair_defenses.rs": (
        2, "signal numbers differ between Linux and macOS and events carry the host's own"),
    "crates/sigma/src/engine.rs": (
        3, "picks the content directory of the OS the binary is built for"),
    "crates/yara/src/access.rs": (
        5, "opens a file as the requesting user (uid check), which only Unix has"),
}

_CFG = re.compile(r"\bcfg(?:_attr)?!?\(")
_PLATFORM = re.compile(r"\b(?:target_os|target_family|windows|unix|macos|linux)\b")


def is_test_path(path: str) -> bool:
    parts = path.split("/")
    return "tests" in parts[:-1] or parts[-1] == "tests.rs"


def count_platform_cfg(text: str) -> int:
    """Source lines of `text` that hold a platform `cfg`, comments and unit tests left out.

    The unit tests of a file are its `#[cfg(test)]` module, which by convention starts at
    column 0 and runs to the end of the file; platform branches in it are test fixtures.
    """
    count = 0
    for line in text.splitlines():
        if line.startswith("#[cfg(test)]"):
            break
        if line.lstrip().startswith("//"):
            continue
        found = _CFG.search(line)
        if found and _PLATFORM.search(line, found.end()):
            count += 1
    return count


def violations(counts: dict[str, int]) -> list[str]:
    """One message per file that holds more platform branches than it may.

    `counts` maps a tracked `.rs` path to its `count_platform_cfg`.
    """
    problems = []
    for path, count in sorted(counts.items()):
        if count == 0 or path.startswith(ALLOWED_PREFIXES) or is_test_path(path):
            continue
        ceiling = EXCEPTIONS.get(path, (0, ""))[0]
        if count > ceiling:
            problems.append(
                f"{path}: {count} platform cfg line(s), allowed {ceiling}. "
                "Move the platform code into a sensor, or add the file to EXCEPTIONS "
                "with its reason (and to CLAUDE.md)."
            )
    for path in sorted(EXCEPTIONS):
        if path not in counts:
            problems.append(f"{path}: listed in EXCEPTIONS but not a tracked .rs file")
    return problems


def tracked_rust_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.rs"],
        check=True, capture_output=True, text=True,
    ).stdout
    return [p for p in out.split("\0") if p]


def main() -> int:
    counts = {}
    for path in tracked_rust_files():
        with open(path, encoding="utf-8") as source:
            counts[path] = count_platform_cfg(source.read())
    problems = violations(counts)
    for problem in problems:
        print(problem)
    if problems:
        print(
            f"\n{len(problems)} problem(s). CLAUDE.md, \"Platform code\", lists where "
            "platform branches may live.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
