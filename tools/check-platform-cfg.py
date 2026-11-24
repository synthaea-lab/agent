#!/usr/bin/env python3
"""Keep platform-specific Rust code where CLAUDE.md ("Platform code") allows it.

Core crates compile on all three OSes. Platform branches (`#[cfg(target_os = ...)]`,
`cfg(windows)`, `cfg(unix)`, `cfg!(...)` and the like) belong to a short list of places;
anywhere else a new one is drift that CLAUDE.md says should not happen and nothing used to
catch (#150).

Three kinds of path:

- **Allowed**: `crates/sensors/`, `crates/updater/`, `crates/response/src/quarantine.rs`
  (CLAUDE.md), `apps/` (each binary owns its OS entry point), `tools/` (the release tool is
  an operator binary) and test code (any `tests` directory, `tests.rs`, and the items a
  `#[cfg(test)]` at column 0 opens). No limit.
- **Exceptions**: the core-crate files in `EXCEPTIONS`, each with the number of platform
  branches it holds today and the reason. The number is a ceiling: a file may lose branches
  (lower the number in the same change), never gain them. A new exception needs a line here
  with its reason, and the same reason in CLAUDE.md.
- **Everything else**: no platform branch at all.

Counting is by attribute or macro: a `cfg(`, `cfg!(` or `cfg_attr(` in a non-comment line,
read up to its closing parenthesis (rustfmt splits a long one over several lines), that names
`target_os`, `target_family`, `windows`, `unix`, `macos` or `linux`. A `cfg(test)` or
`cfg(feature = ...)` does not count. An item behind a column-0 `#[cfg(test)]` is skipped:
a one-line item (`use`, `mod tests;`) alone, a block (`mod tests { ... }`) up to the `}` at
column 0 that closes it (the next line must start another item, since a raw-string fixture can
hold a `}` at column 0). Code after it is counted.

Not checked: the other half of the CLAUDE.md rule, that platform dependencies are
target-gated (`[target.'cfg(windows)'.dependencies]`) in `Cargo.toml`.

Run from the repository root: `python3 tools/check-platform-cfg.py`
Exits non-zero listing every offender. CI runs this in the `lint` job.
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


_LOOKAHEAD = 20  # lines an attribute may span; an unbalanced one is not chased further


def _cfg_text(lines: list[str], index: int, start: int) -> str:
    """The `cfg(...)` that begins at `lines[index][start:]`, up to its closing parenthesis."""
    text = lines[index][start:]
    depth = text.count("(") - text.count(")")
    following = index + 1
    while depth > 0 and following < min(len(lines), index + _LOOKAHEAD):
        text += " " + lines[following].strip()
        depth += lines[following].count("(") - lines[following].count(")")
        following += 1
    return text


def _skip_test_item(lines: list[str], index: int) -> int:
    """Index of the first line after the item a column-0 `#[cfg(test)]` at `index` opens.

    A one-line item or one that ends in `;` is skipped alone; an item with a body runs to the
    `}` at column 0 that rustfmt puts at its end.
    """
    i = index + 1
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith("#[") or line == "":
            i += 1
            continue
        if line.endswith(";"):
            return i + 1
        if "{" in line:
            while i < len(lines) and not _closes_item(lines, i):
                i += 1
            return i + 1
        i += 1
    return i


_ITEM_START = re.compile(
    r"(?:#\[|#!\[|//|/\*|pub\b|use\b|mod\b|fn\b|const\b|static\b|struct\b|enum\b|"
    r"union\b|trait\b|impl\b|type\b|extern\b|unsafe\b|async\b|macro_rules!)"
)


def _closes_item(lines: list[str], index: int) -> bool:
    """Whether `lines[index]` is the `}` at column 0 that ends a top-level item.

    A `}` at column 0 can also sit inside a raw string (a test fixture), so the next non-blank
    line must be the end of the file or start another item.
    """
    if lines[index] != "}":
        return False
    for following in lines[index + 1:]:
        if following.strip() == "":
            continue
        return _ITEM_START.match(following) is not None
    return True


def count_platform_cfg(text: str) -> int:
    """Platform `cfg` attributes and macros in `text`, comments and `#[cfg(test)]` items left out."""
    lines = text.splitlines()
    count = 0
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("#[cfg(test)]"):
            i = _skip_test_item(lines, i)
            continue
        i += 1
        if line.lstrip().startswith("//"):
            continue
        found = _CFG.search(line)
        if found and _PLATFORM.search(_cfg_text(lines, i - 1, found.start())):
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
