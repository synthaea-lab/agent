#!/usr/bin/env python3
"""Enforce the module layering inside the agent binary (`apps/agent/src`).

Rules (see docs/architecture.md, "Layers inside the agent binary"):
  - `main.rs` and `commands/` are the wiring: they start the sensors and hand events to the
    rest. No other module names `crate::commands` or an item `main.rs` defines.
  - The other modules form layers: module imports never close a cycle. A cycle means two
    modules cannot be understood, tested or moved to a crate one without the other.

Test code is exempt: a test may reach sideways for a fixture.

Run from the workspace root: `python3 tools/check-agent-layers.py`
Exits non-zero listing every violation. CI runs this on every push.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

SOURCE_ROOT = Path("apps/agent/src")
WIRING = "commands"
CRATE_ROOT = "main"
CRATE_PATH = re.compile(r"\bcrate::")
IDENTIFIER = re.compile(r"\w+")
TEST_MODULE = re.compile(r"#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*mod \w+\s*\{")
STRING = re.compile(r'"(?:\\.|[^"\\])*"')
LINE_COMMENT = re.compile(r"//[^\n]*")


def production_code(text: str) -> str:
    """`text` without comments, string contents and inline `#[cfg(test)]` modules."""
    text = LINE_COMMENT.sub("", STRING.sub('""', text))
    while match := TEST_MODULE.search(text):
        text = text[:match.start()] + text[closing_brace(text, match.end() - 1) + 1:]
    return text


def closing_brace(text: str, opening: int) -> int:
    """Index of the brace closing the one at `opening`, or the end of `text` if unbalanced."""
    depth = 0
    for index in range(opening, len(text)):
        depth += {"{": 1, "}": -1}.get(text[index], 0)
        if depth == 0:
            return index
    return len(text) - 1


def crate_roots_named(code: str) -> set[str]:
    """First path segment of every `crate::…` path in `code`, grouped imports included."""
    names: set[str] = set()
    for match in CRATE_PATH.finditer(code):
        rest = code[match.end():]
        if rest.startswith("{"):
            names |= group_heads(rest[1:closing_brace(rest, 0)])
        elif head := IDENTIFIER.match(rest):
            names.add(head.group())
    return names


def group_heads(group: str) -> set[str]:
    """First segment of each comma-separated path directly inside a `{…}` import group."""
    heads, depth, start = set(), 0, 0
    for index, char in enumerate(group + ","):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        elif char == "," and depth == 0:
            if head := IDENTIFIER.search(group[start:index]):
                heads.add(head.group())
            start = index + 1
    return heads


def is_test_file(path: Path) -> bool:
    return path.stem == "tests" or path.stem.endswith("_tests") or "tests" in path.parts


def module_of(path: Path, root: Path) -> str:
    """The top-level module a source file belongs to."""
    return path.relative_to(root).parts[0].removesuffix(".rs")


def module_graph(root: Path) -> dict[str, set[str]]:
    """Top-level module -> the `crate::` first segments its production code names."""
    graph: dict[str, set[str]] = {}
    for path in sorted(root.rglob("*.rs")):
        if is_test_file(path.relative_to(root)):
            continue
        module = module_of(path, root)
        named = crate_roots_named(production_code(path.read_text()))
        graph.setdefault(module, set()).update(named - {module})
    return graph


def wiring_violations(graph: dict[str, set[str]]) -> list[str]:
    """Modules below the wiring that name it, or an item only `main.rs` defines."""
    modules = set(graph)
    violations = []
    for module, named in sorted(graph.items()):
        if module in (WIRING, CRATE_ROOT):
            continue
        for name in sorted(named):
            if name == WIRING:
                violations.append(f"  {module} -> {WIRING} (the wiring is the top layer)")
            elif name not in modules:
                violations.append(f"  {module} -> crate::{name} (an item of main.rs)")
    return violations


def cycle_violations(graph: dict[str, set[str]]) -> list[str]:
    """One line per import cycle among the modules, each cycle reported once."""
    cycles: set[tuple[str, ...]] = set()
    finished: set[str] = set()

    def visit(module: str, trail: list[str]) -> None:
        if module in trail:
            cycle = trail[trail.index(module):]
            pivot = cycle.index(min(cycle))
            cycles.add(tuple(cycle[pivot:] + cycle[:pivot]))
            return
        if module in finished:
            return
        for dependency in sorted(graph.get(module, set()) & set(graph)):
            visit(dependency, trail + [module])
        finished.add(module)

    for module in sorted(graph):
        visit(module, [])
    return [f"  cycle: {' -> '.join(cycle + (cycle[0],))}" for cycle in sorted(cycles)]


def main() -> None:
    graph = module_graph(SOURCE_ROOT)
    violations = wiring_violations(graph) + cycle_violations(graph)
    if violations:
        print("Agent binary layering violations:")
        print("\n".join(violations))
        print("\nSee docs/architecture.md, \"Layers inside the agent binary\".")
        sys.exit(1)
    print(f"ok: {len(graph)} modules of the agent binary respect the layering")


if __name__ == "__main__":
    main()
