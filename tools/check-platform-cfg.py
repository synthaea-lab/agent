#!/usr/bin/env python3
"""Keep platform-specific Rust code where CLAUDE.md ("Platform code") allows it.

Core crates compile on all three OSes. Platform branches (`#[cfg(target_os = ...)]`,
`cfg(windows)`, `cfg(unix)`, `cfg!(...)` and the like) belong to a short list of places;
anywhere else a new one is drift that CLAUDE.md says should not happen and nothing used to
catch (#150).

Three kinds of path:

- **Allowed**: `crates/sensors/`, `crates/updater/`, `crates/response/src/quarantine/`
  (CLAUDE.md), `apps/` (each binary owns its OS entry point), `tools/` (the release tool is
  an operator binary) and test code (any `tests` directory, `tests.rs`, and the items a
  `#[cfg(test)]` at column 0 opens). No limit.
- **Exceptions**: the core-crate files in `EXCEPTIONS`, each with the number of platform
  branches it holds today and the reason. The number is a ceiling: a file may not gain branches, and
  when it loses some the check fails until the number is lowered in the same change (and the
  entry removed at 0). A new exception needs a line here
  with its reason, and the same reason in CLAUDE.md.
- **Everything else**: no platform branch at all.

Counting is by attribute or macro: a `cfg(`, `cfg!(` or `cfg_attr(` in a non-comment line,
read up to its matching closing parenthesis (rustfmt splits a long one over several lines),
that names `target_os`, `target_family`, `target_vendor`, `target_env`, `windows`, `unix`,
`macos` or `linux`. A `cfg(test)` or `cfg(feature = ...)` does not count. The item behind a
column-0 `#[cfg(test)]` is skipped: the scanner walks it by bracket depth, stepping over
comments, strings, raw strings and char literals, and stops at the `;` or the closing `}` that
ends the item (for `use`, `const` and `static` only the `;` does, since their braces are part
of the expression). Code after it is counted.

Not checked: the other half of the CLAUDE.md rule, that platform dependencies are
target-gated (`[target.'cfg(windows)'.dependencies]`) in `Cargo.toml`; and a `build.rs` that
branches on `CARGO_CFG_TARGET_OS` at run time.

Run `python3 tools/check-platform-cfg.py` (from any directory: it works on the repository root).
Exits non-zero listing every offender. CI runs this in the `lint` job.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ALLOWED_PREFIXES = (
    "crates/sensors/",
    "crates/updater/",
    "crates/response/src/quarantine/",
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
    "crates/delivery/src/lib.rs": (
        1, "the `release` module drives updater::layout, which exists on Linux only"),
    "crates/pipeline/src/lib.rs": (
        1, "the `integrity` module verifies updater::layout, which exists on Linux only"),
    "crates/pipeline/src/host.rs": (
        8, "the one place the pipeline states what it knows about the OS it was built for"),
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
_PLATFORM = re.compile(r"\b(?:target_os|target_family|target_vendor|target_env|windows|unix|macos|linux)\b")


def is_test_path(path: str) -> bool:
    parts = path.split("/")
    return "tests" in parts[:-1] or parts[-1] == "tests.rs"


_LOOKAHEAD = 20  # lines an attribute may span; an unbalanced one is not chased further


def _code(line: str) -> str:
    """`line` without its trailing `//` comment."""
    return line.split("//", 1)[0]


_STRING = re.compile(r'"[^"]*"')
_TARGET_KEY = re.compile(r"target_\w+\s*=\s*$")


def _without_feature_strings(text: str) -> str:
    """`text` with every string removed except the value of a `target_*` key.

    `target_os = "linux"` names a platform; `feature = "unix-socket"` only contains the word.
    """
    return _STRING.sub(
        lambda found: found.group() if _TARGET_KEY.search(text[: found.start()]) else '""',
        text,
    )


def _cfg_text(lines: list[str], index: int, start: int) -> str:
    """The `cfg(...)` that begins at `lines[index][start:]`, up to its matching `)`."""
    text = _code(lines[index])[start:]
    following = index + 1
    while following < min(len(lines), index + _LOOKAHEAD):
        end = _matching_paren(text)
        if end is not None:
            return text[: end + 1]
        text += " " + _code(lines[following]).strip()
        following += 1
    end = _matching_paren(text)
    return text if end is None else text[: end + 1]


def _matching_paren(text: str) -> int | None:
    """Index of the `)` that closes the first `(` of `text`, or None while it is open."""
    depth = 0
    for position, char in enumerate(text):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return position
    return None


_RAW_STRING = re.compile(r'(?:b|c)?r(#*)"')
_CHAR_LITERAL = re.compile(r"'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|[^\n])|[^\\'\n])'")
_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# Items whose body is a `{ ... }` block: the closing brace ends the item.
_BLOCK_KEYWORDS = frozenset(
    {"fn", "mod", "impl", "struct", "enum", "trait", "union", "extern", "macro_rules"}
)
# Items whose braces belong to an expression or a use tree: only the `;` ends the item.
_EXPRESSION_KEYWORDS = frozenset({"use", "const", "static"})


def _skip_test_item(lines: list[str], index: int) -> int:
    """Index of the first line after the item a column-0 `#[cfg(test)]` at `index` opens.

    The source after the attribute is walked by bracket depth. Comments, strings, raw strings
    and char literals are stepped over (a `}` or `;` inside them ends nothing). The item ends
    at a `;` at depth 0, or at the `}` that brings the depth back to 0 unless the item is a
    `use`, `const` or `static` (their braces are an expression, the `;` follows). A `const fn`
    and an `impl<const N: usize>` are block items: the first block keyword decides.
    """
    source = lines[index][len("#[cfg(test)]"):] + "\n" + "\n".join(lines[index + 1:])
    depth = 0
    position = 0
    expression = False
    block = False
    while position < len(source):
        char = source[position]
        if source.startswith("//", position):
            newline = source.find("\n", position)
            position = len(source) if newline < 0 else newline
            continue
        if source.startswith("/*", position):
            position = _end_of_block_comment(source, position)
            continue
        raw = _RAW_STRING.match(source, position) if char in "rbc" else None
        if raw and (position == 0 or not (source[position - 1].isalnum() or source[position - 1] == "_")):
            closing = '"' + raw.group(1)
            end = source.find(closing, raw.end())
            position = len(source) if end < 0 else end + len(closing)
            continue
        if char == '"':
            position = _end_of_string(source, position)
            continue
        if char == "'":
            literal = _CHAR_LITERAL.match(source, position)
            position = literal.end() if literal else position + 1
            continue
        if char.isalpha() or char == "_":
            word = _WORD.match(source, position)
            assert word is not None
            if depth == 0 and not block:
                if word.group() in _BLOCK_KEYWORDS:
                    block = True
                    expression = False
                elif word.group() in _EXPRESSION_KEYWORDS:
                    expression = True
            position = word.end()
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if char == "}" and depth <= 0 and not expression:
                return index + source.count("\n", 0, position) + 1
        elif char == ";" and depth <= 0:
            return index + source.count("\n", 0, position) + 1
        position += 1
    return len(lines)


def _end_of_block_comment(source: str, position: int) -> int:
    """Index after the `*/` that closes the (nested) block comment opened at `position`."""
    depth = 0
    while position < len(source):
        if source.startswith("/*", position):
            depth += 1
            position += 2
        elif source.startswith("*/", position):
            depth -= 1
            position += 2
            if depth == 0:
                return position
        else:
            position += 1
    return position


def _end_of_string(source: str, position: int) -> int:
    """Index after the closing quote of the string opened at `position`."""
    position += 1
    while position < len(source):
        if source[position] == "\\":
            position += 2
        elif source[position] == '"':
            return position + 1
        else:
            position += 1
    return position


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
        found = _CFG.search(_code(line))
        if found and _PLATFORM.search(
            _without_feature_strings(_cfg_text(lines, i - 1, found.start()))
        ):
            count += 1
    return count


def violations(counts: dict[str, int]) -> list[str]:
    """One message per file that holds more platform branches than it may.

    `counts` maps a tracked `.rs` path to its `count_platform_cfg`.
    """
    problems = []
    for path, count in sorted(counts.items()):
        if path.startswith(ALLOWED_PREFIXES) or is_test_path(path):
            continue
        ceiling = EXCEPTIONS.get(path, (0, ""))[0]
        if count > ceiling:
            problems.append(
                f"{path}: {count} platform cfg line(s), allowed {ceiling}. "
                "Move the platform code into a sensor, or add the file to EXCEPTIONS "
                "with its reason (and to CLAUDE.md)."
            )
        elif count < ceiling:
            action = "remove it from EXCEPTIONS (and CLAUDE.md)" if count == 0 else (
                f"lower EXCEPTIONS[{path!r}] to {count}"
            )
            problems.append(
                f"{path}: {count} platform cfg line(s), below its ceiling of {ceiling}. "
                f"A ceiling only goes down: {action}."
            )
    for path in sorted(EXCEPTIONS):
        if path not in counts:
            problems.append(f"{path}: listed in EXCEPTIONS but not a tracked .rs file")
    return problems


REPO = Path(__file__).resolve().parents[1]


def tracked_rust_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.rs"],
        check=True, capture_output=True, text=True, cwd=REPO,
    ).stdout
    return [p for p in out.split("\0") if p]


def main() -> int:
    counts = {}
    for path in tracked_rust_files():
        with open(REPO / path, encoding="utf-8") as source:
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
