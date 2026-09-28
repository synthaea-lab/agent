#!/usr/bin/env python3
"""Generates docs/detection/attack-coverage.md from ATT&CK technique identifiers
tagged in source — issue #74. Static scan, stdlib only, same posture as
tools/check-deps.py: no third-party deps, shells out to nothing, exits non-zero
naming the problem on any error.

What it scans:
- crates/rules/src/*.rs, crates/correlator/src/rules.rs: `technique: "..."`
  string literals (the literal "BAYES" sentinel — correlator's own Bayesian
  case-scoring alert, not an ATT&CK technique — is skipped).
- rules/sigma/**/*.yml: `- attack.tXXXX[.YYY]` tag lines.
- rules/yara/**/*.yar: `technique = "..."` meta lines.

Every discovered id is validated against T\\d{4}(\\.\\d{3})? — a malformed match
is a hard error naming the file, not a silently-dropped row.

Layer per technique is a static table below the `SOURCES` list, taken from
docs/detection/layers.md's "What implements it" column.

Tactic per technique is the one piece this script cannot derive from our own
source — ATT&CK tactic membership is external MITRE taxonomy. TECHNIQUE_TACTIC
below covers every id this scan currently finds; add an entry when a genuinely
new technique family is tagged. A discovered id missing from the table renders
under an explicit "Unmapped" bucket instead of being silently dropped, so a
stale table is visible in the output.

The generated file only proves positive coverage (what IS tagged) — it does
not attempt the roadmap-style gap analysis (what's planned, what's out of
scope and why) the hand-written predecessor doc carried; that lives in the
coverage-pack issues (#376-#381) instead.

Usage:
    python3 tools/attack-coverage.py          # regenerate docs/detection/attack-coverage.md
    python3 tools/attack-coverage.py --check  # verify it's up to date; exit 1 if stale (CI)
"""

import argparse
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
OUTPUT = REPO_ROOT / "docs/detection/attack-coverage.md"

TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
BAYES_SENTINEL = "BAYES"


def rust_technique_field(path: pathlib.Path) -> set[str]:
    ids: set[str] = set()
    for match in re.finditer(r'technique:\s*"([^"]+)"', path.read_text()):
        raw = match.group(1)
        if raw == BAYES_SENTINEL:
            continue
        ids.update(raw.split("/"))
    return ids


def sigma_tags(path: pathlib.Path) -> set[str]:
    ids: set[str] = set()
    for match in re.finditer(
        r"-\s*(attack\.t\d{4}(?:\.\d{3})?)", path.read_text(), re.IGNORECASE
    ):
        tag = match.group(1).lower()
        ids.add("T" + tag[len("attack.t") :])
    return ids


def yara_meta(path: pathlib.Path) -> set[str]:
    match = re.search(r'technique\s*=\s*"([^"]+)"', path.read_text())
    return {match.group(1)} if match else set()


# (source label, glob relative to repo root, extractor, layer per docs/detection/layers.md)
SOURCES = [
    ("rules", "crates/rules/src/*.rs", rust_technique_field, 3),
    ("correlator", "crates/correlator/src/rules.rs", rust_technique_field, 6),
    ("sigma", "rules/sigma/**/*.yml", sigma_tags, 3),
    ("yara", "rules/yara/**/*.yar", yara_meta, 1),
]

TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# The one hand-maintained table (see module docstring). Extend when a genuinely
# new technique family is tagged in source.
TECHNIQUE_TACTIC = {
    "T1027": "Defense Evasion",
    "T1036": "Defense Evasion",
    "T1036.005": "Defense Evasion",
    "T1037.004": "Persistence",
    "T1041": "Exfiltration",
    "T1048.003": "Exfiltration",
    "T1053.003": "Persistence",
    "T1053.005": "Persistence",
    "T1055": "Defense Evasion",
    "T1059": "Execution",
    "T1059.001": "Execution",
    "T1059.004": "Execution",
    "T1070.002": "Defense Evasion",
    "T1071": "Command and Control",
    "T1071.004": "Command and Control",
    "T1098.004": "Persistence",
    "T1105": "Command and Control",
    "T1110": "Credential Access",
    "T1127": "Defense Evasion",
    "T1136.001": "Persistence",
    "T1204": "Execution",
    "T1218": "Defense Evasion",
    "T1218.011": "Defense Evasion",
    "T1490": "Impact",
    "T1543.001": "Persistence",
    "T1543.002": "Persistence",
    "T1543.003": "Persistence",
    "T1547.015": "Persistence",
    "T1548": "Privilege Escalation",
    "T1562.001": "Defense Evasion",
    "T1571": "Command and Control",
    "T1574.006": "Defense Evasion",
    "T1611": "Privilege Escalation",
    "T1620": "Defense Evasion",
    "T1021.002": "Lateral Movement",
}

UNMAPPED_TACTIC = "Unmapped — add to TECHNIQUE_TACTIC"


def discover() -> dict[str, dict[str, set]]:
    findings: dict[str, dict[str, set]] = {}
    for label, pattern, extractor, layer in SOURCES:
        for path in sorted(REPO_ROOT.glob(pattern)):
            for technique_id in extractor(path):
                if not TECHNIQUE_RE.match(technique_id):
                    rel = path.relative_to(REPO_ROOT)
                    print(
                        f"error: malformed technique id {technique_id!r} in {rel}",
                        file=sys.stderr,
                    )
                    sys.exit(1)
                entry = findings.setdefault(technique_id, {"layers": set(), "sources": set()})
                entry["layers"].add(layer)
                entry["sources"].add(f"{label}:{path.relative_to(REPO_ROOT)}")
    return findings


def render(findings: dict[str, dict[str, set]]) -> str:
    by_tactic: dict[str, list[str]] = {}
    for technique_id in findings:
        tactic = TECHNIQUE_TACTIC.get(technique_id, UNMAPPED_TACTIC)
        by_tactic.setdefault(tactic, []).append(technique_id)

    lines = [
        "<!-- GENERATED by tools/attack-coverage.py — do not hand-edit. -->",
        "<!-- Run `python3 tools/attack-coverage.py` to regenerate. -->",
        "",
        "# ATT&CK Coverage Matrix",
        "",
        "Generated from ATT&CK technique identifiers tagged in source "
        "(`crates/rules`, `crates/correlator`, `rules/sigma/`, `rules/yara/`) — "
        "what has named detection content today, grouped by MITRE tactic and "
        "by layer (`docs/detection/layers.md`). This proves positive coverage "
        "only: a technique absent here may still be planned, tracked, or out "
        "of scope for other reasons — see the coverage-pack issues "
        "(#376-#381) for that roadmap view.",
        "",
    ]

    order = TACTIC_ORDER + sorted(t for t in by_tactic if t not in TACTIC_ORDER)
    for tactic in order:
        ids = by_tactic.get(tactic)
        if not ids:
            continue
        lines.append(f"## {tactic}")
        lines.append("")
        lines.append("| Technique | Layer(s) | Source(s) |")
        lines.append("| --- | --- | --- |")
        for technique_id in sorted(ids):
            info = findings[technique_id]
            layers = ", ".join(str(layer) for layer in sorted(info["layers"]))
            sources = ", ".join(f"`{s}`" for s in sorted(info["sources"]))
            lines.append(f"| {technique_id} | {layers} | {sources} |")
        lines.append("")

    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the committed doc is up to date; exit 1 if stale (CI)",
    )
    args = parser.parse_args()

    findings = discover()
    content = render(findings)

    if args.check:
        current = OUTPUT.read_text() if OUTPUT.exists() else ""
        if current != content:
            print(
                f"error: {OUTPUT} is stale — run `python3 tools/attack-coverage.py` to regenerate",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"ok: {OUTPUT} is up to date ({len(findings)} techniques)")
        return

    OUTPUT.write_text(content)
    print(f"wrote {OUTPUT} ({len(findings)} techniques)")


if __name__ == "__main__":
    main()
