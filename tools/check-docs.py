#!/usr/bin/env python3
"""Check the Markdown documentation for broken links.

Validates, for README.md and every docs/**/*.md file:

* every relative link points to an existing file or directory;
* every ``#anchor`` (in the same file or in another Markdown file) matches a
  heading, using GitHub's heading-slug rules;
* every ``planned`` or ``partial`` row of docs/capabilities.md links a GitHub
  issue URL.

Standard library only; runs the same on Linux, macOS and Windows.
Exit status: 0 when clean, 1 when a problem was found.

Usage: python3 tools/check-docs.py [repo-root]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote

LINK_RE = re.compile(r"(?<!\!)\[(?:[^\[\]]|\[[^\]]*\])*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
IMAGE_RE = re.compile(r"!\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
FENCE_RE = re.compile(r"^\s*(```|~~~)")
ISSUE_URL_RE = re.compile(r"https://github\.com/[\w.-]+/[\w.-]+/issues/\d+")
EXTERNAL_PREFIXES = ("http://", "https://", "mailto:", "tel:")


def strip_code(lines: list[str]) -> list[str]:
    """Blank out fenced code blocks and inline code spans, keeping line numbers."""
    out: list[str] = []
    fence: str | None = None
    for line in lines:
        m = FENCE_RE.match(line)
        if fence is not None:
            if m and m.group(1) == fence:
                fence = None
            out.append("")
            continue
        if m:
            fence = m.group(1)
            out.append("")
            continue
        out.append(re.sub(r"`[^`]*`", lambda s: _keep_link_text(s.group(0)), line))
    return out


def _keep_link_text(span: str) -> str:
    # Inline code may itself be link text ("[`foo`](path)"); keep a placeholder
    # of the same length so the link regex still sees the brackets around it.
    return "x" * len(span)


def slugify(text: str) -> str:
    """GitHub's heading anchor: lowercase, drop punctuation, spaces to hyphens."""
    text = re.sub(r"<[^>]+>", "", text)  # inline HTML
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)  # links keep their text
    text = text.replace("`", "").strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def anchors_of(path: Path, cache: dict[Path, set[str]]) -> set[str]:
    if path in cache:
        return cache[path]
    seen: dict[str, int] = {}
    anchors: set[str] = set()
    lines = path.read_text(encoding="utf-8").splitlines()
    fence: str | None = None
    for line in lines:
        m = FENCE_RE.match(line)
        if fence is not None:
            if m and m.group(1) == fence:
                fence = None
            continue
        if m:
            fence = m.group(1)
            continue
        h = HEADING_RE.match(line)
        if not h:
            continue
        base = slugify(h.group(2))
        n = seen.get(base, 0)
        seen[base] = n + 1
        anchors.add(base if n == 0 else f"{base}-{n}")
    for explicit in re.findall(r'<a\s+(?:name|id)="([^"]+)"', "\n".join(lines)):
        anchors.add(explicit)
    cache[path] = anchors
    return anchors


def check_links(md: Path, root: Path, cache: dict[Path, set[str]]) -> list[str]:
    errors: list[str] = []
    lines = strip_code(md.read_text(encoding="utf-8").splitlines())
    rel = md.relative_to(root).as_posix()
    for lineno, line in enumerate(lines, 1):
        targets = LINK_RE.findall(line) + IMAGE_RE.findall(line)
        for target in targets:
            if target.startswith(EXTERNAL_PREFIXES):
                continue
            path_part, _, anchor = target.partition("#")
            path_part = unquote(path_part)
            dest = md if not path_part else (md.parent / path_part)
            if path_part and not dest.exists():
                errors.append(f"{rel}:{lineno}: broken link '{target}' (no such file: {path_part})")
                continue
            if anchor and dest.is_file() and dest.suffix.lower() == ".md":
                if unquote(anchor).lower() not in anchors_of(dest.resolve(), cache):
                    where = "this file" if not path_part else path_part
                    errors.append(f"{rel}:{lineno}: broken anchor '#{anchor}' in {where}")
    return errors


def check_capabilities(path: Path, root: Path) -> list[str]:
    errors: list[str] = []
    if not path.is_file():
        return [f"{path.relative_to(root).as_posix()}: missing"]
    rel = path.relative_to(root).as_posix()
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.lstrip().startswith("|"):
            continue
        cells = [c.strip().strip("*").lower() for c in line.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue
        if cells[1] in ("planned", "partial") and not ISSUE_URL_RE.search(line):
            errors.append(f"{rel}:{lineno}: '{cells[1]}' capability without a tracking issue URL: {cells[0]}")
    return errors


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent).resolve()
    files = sorted((root / "docs").rglob("*.md"))
    if (root / "README.md").is_file():
        files.insert(0, root / "README.md")
    cache: dict[Path, set[str]] = {}
    errors: list[str] = []
    for md in files:
        errors += check_links(md, root, cache)
    errors += check_capabilities(root / "docs" / "capabilities.md", root)
    for e in errors:
        print(e)
    if errors:
        print(f"check-docs: {len(errors)} problem(s) in {len(files)} file(s)", file=sys.stderr)
        return 1
    print(f"check-docs: {len(files)} file(s) OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
