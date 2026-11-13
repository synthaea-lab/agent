#!/usr/bin/env python3
"""Generates docs/attack-coverage.md from ATT&CK technique identifiers
tagged in source. Static scan, stdlib only, same posture as
tools/check-deps.py: no third-party deps, shells out to nothing, exits non-zero
naming the problem on any error.

What it scans:
- crates/rules/src/*.rs, crates/correlator/src/rules.rs: `technique: "..."`
  string literals (the literal "BAYES" sentinel — correlator's own Bayesian
  case-scoring alert, not an ATT&CK technique — is skipped), plus T-shaped
  `const NAME: &str = "T..."` values for techniques referenced by name.
- rules/sigma/**/*.yml: `- attack.tXXXX[.YYY]` tag lines.
- rules/yara/**/*.yar: `technique = "..."` meta lines.

Every discovered id is validated against T\\d{4}(\\.\\d{3})? — a malformed match
is a hard error naming the file, not a silently-dropped row.

Layer per technique is fixed per source in the `SOURCES` list (the detection
stack's numbering: 1 signatures/hashes, 3 behavioral rules, 6 attack-chain
correlation).

Tactic per technique is the one piece this script cannot derive from our own
source — ATT&CK tactic membership is external MITRE taxonomy. TECHNIQUE_TACTIC
below covers every id this scan currently finds; add an entry when a genuinely
new technique family is tagged. A discovered id missing from the table renders
under an explicit "Unmapped" bucket instead of being silently dropped, so a
stale table is visible in the output.

The generated file only proves positive coverage (what IS tagged) — it does
not attempt the roadmap-style gap analysis (what's planned, what's out of
scope and why) the hand-written predecessor doc carried; that lives in the
issue tracker instead.

The scan spans repos: `crates/` is this one, while `rules/` is a sibling
checkout of synthaea-lab/rules next to this repo, found under $SYNTHAEA_ROOT
when set and the parent of this repo otherwise (the same lookup as
`crates/siblings`). A missing sibling is a hard error, never a partial matrix.
Paths in the output stay relative to their own repo (`crates/...`, `rules/...`).
The output, docs/attack-coverage.md, lives in this repo.

Usage:
    python3 tools/attack-coverage.py          # regenerate docs/attack-coverage.md
    python3 tools/attack-coverage.py --check  # verify it's up to date; exit 1 if stale (CI)
"""

import argparse
import os
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
# The directory holding this repo's sibling checkouts (`rules/`).
SIBLINGS_ROOT = pathlib.Path(os.environ.get("SYNTHAEA_ROOT") or REPO_ROOT.parent).resolve()
OUTPUT = REPO_ROOT / "docs/attack-coverage.md"

TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
BAYES_SENTINEL = "BAYES"


# A technique named once as a `const` and referenced by name (#474's
# `CLEAR_WINDOWS_EVENT_LOGS`, #499's persistence-path table) never appears as a
# `technique: "..."` literal; scanning only the field let those vanish from the
# doc while `--check` still passed (#467 review). Only T-shaped values, so other
# `&str` consts aren't swept in and then rejected by the id validation.
RUST_TECHNIQUE_CONST_RE = re.compile(
    r"""const\s+\w+\s*:\s*&(?:'static\s+)?str\s*=\s*"(T\d{4}[^"]*)\""""
)


def rust_technique_field(path: pathlib.Path) -> set[str]:
    ids: set[str] = set()
    text = path.read_text(encoding="utf-8")
    for match in re.finditer(r'technique:\s*"([^"]+)"', text):
        raw = match.group(1)
        if raw == BAYES_SENTINEL:
            continue
        ids.update(raw.split("/"))
    for match in RUST_TECHNIQUE_CONST_RE.finditer(text):
        ids.update(match.group(1).split("/"))
    return ids


def sigma_tags(path: pathlib.Path) -> set[str]:
    ids: set[str] = set()
    for match in re.finditer(
        r"-\s*(attack\.t\d{4}(?:\.\d{3})?)", path.read_text(encoding="utf-8"), re.IGNORECASE
    ):
        tag = match.group(1).lower()
        ids.add("T" + tag[len("attack.t") :])
    return ids


def yara_meta(path: pathlib.Path) -> set[str]:
    match = re.search(r'technique\s*=\s*"([^"]+)"', path.read_text(encoding="utf-8"))
    return {match.group(1)} if match else set()


# (source label, root the glob is relative to, glob, extractor, detection layer)
SOURCES = [
    ("rules", REPO_ROOT, "crates/rules/src/*.rs", rust_technique_field, 3),
    # `src/tests/` is left out: its expected-alert literals are not detections.
    ("rules", REPO_ROOT, "crates/rules/src/stateless/*.rs", rust_technique_field, 3),
    ("correlator", REPO_ROOT, "crates/correlator/src/rules.rs", rust_technique_field, 6),
    ("sigma", SIBLINGS_ROOT, "rules/sigma/**/*.yml", sigma_tags, 3),
    ("yara", SIBLINGS_ROOT, "rules/yara/**/*.yar", yara_meta, 1),
]

# Sibling directories the scan and the output need; checked up front.
REQUIRED_SIBLINGS = ["rules/sigma", "rules/yara"]


def require_siblings() -> None:
    missing = [d for d in REQUIRED_SIBLINGS if not (SIBLINGS_ROOT / d).is_dir()]
    if missing:
        print(
            f"error: sibling repo directories missing under {SIBLINGS_ROOT}: "
            f"{', '.join(missing)} — check out synthaea-lab/rules next to this "
            "repo as rules/, or set SYNTHAEA_ROOT to the directory holding it",
            file=sys.stderr,
        )
        sys.exit(2)

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
    "T1003.001": "Credential Access",
    "T1003.002": "Credential Access",
    "T1003.003": "Credential Access",
    "T1003.004": "Credential Access",
    "T1003.008": "Credential Access",
    "T1047": "Execution",
    "T1078": "Initial Access",
    "T1189": "Initial Access",
    "T1190": "Initial Access",
    "T1006": "Defense Evasion",
    "T1027": "Defense Evasion",
    "T1036": "Defense Evasion",
    "T1036.005": "Defense Evasion",
    "T1037.004": "Persistence",
    "T1041": "Exfiltration",
    "T1048.003": "Exfiltration",
    "T1074.001": "Collection",
    "T1053.003": "Persistence",
    "T1053.005": "Persistence",
    "T1055": "Defense Evasion",
    "T1056.002": "Credential Access",
    "T1059": "Execution",
    "T1059.002": "Execution",
    "T1059.001": "Execution",
    "T1059.004": "Execution",
    "T1070.001": "Defense Evasion",
    "T1070.002": "Defense Evasion",
    "T1070.006": "Defense Evasion",
    "T1071": "Command and Control",
    "T1071.004": "Command and Control",
    "T1098.004": "Persistence",
    "T1105": "Command and Control",
    "T1110": "Credential Access",
    "T1127": "Defense Evasion",
    "T1136.001": "Persistence",
    "T1197": "Defense Evasion",
    "T1204": "Execution",
    "T1204.002": "Execution",
    "T1566.001": "Initial Access",
    "T1218": "Defense Evasion",
    "T1218.011": "Defense Evasion",
    "T1490": "Impact",
    "T1543.001": "Persistence",
    "T1543.002": "Persistence",
    "T1543.003": "Persistence",
    "T1546.004": "Persistence",
    "T1547.015": "Persistence",
    "T1548": "Privilege Escalation",
    "T1548.001": "Privilege Escalation",
    "T1552": "Credential Access",
    "T1552.001": "Credential Access",
    "T1552.004": "Credential Access",
    "T1553.005": "Defense Evasion",
    "T1555.001": "Credential Access",
    "T1555.003": "Credential Access",
    "T1562.001": "Defense Evasion",
    "T1562.004": "Defense Evasion",
    "T1567.002": "Exfiltration",
    "T1567.003": "Exfiltration",
    "T1571": "Command and Control",
    "T1574.006": "Defense Evasion",
    "T1611": "Privilege Escalation",
    "T1620": "Defense Evasion",
    "T1021.002": "Lateral Movement",
    "T1563.002": "Lateral Movement",
    "T1021.004": "Lateral Movement",
    "T1518.001": "Discovery",
    "T1489": "Impact",
    "T1529": "Impact",
    "T1016": "Discovery",
    "T1057": "Discovery",
    "T1082": "Discovery",
    "T1087": "Discovery",
}

UNMAPPED_TACTIC = "Unmapped — add to TECHNIQUE_TACTIC"


def discover() -> dict[str, dict[str, set]]:
    findings: dict[str, dict[str, set]] = {}
    for label, root, pattern, extractor, layer in SOURCES:
        for path in sorted(root.glob(pattern)):
            for technique_id in extractor(path):
                if not TECHNIQUE_RE.match(technique_id):
                    rel = path.relative_to(root)
                    print(
                        f"error: malformed technique id {technique_id!r} in {rel}",
                        file=sys.stderr,
                    )
                    sys.exit(1)
                entry = findings.setdefault(technique_id, {"layers": set(), "sources": set()})
                entry["layers"].add(layer)
                entry["sources"].add(f"{label}:{path.relative_to(root).as_posix()}")
    return findings


# Coverage a tag does not yet claim, rendered after the matrix so a reader of the
# T1566.001 row does not assume a mail client the rule never saw.
UNVERIFIED_NOTES = [
    "T1566.001 (mail attachment) is tagged only for a mark whose quarantine agent is "
    "`Mail` (Apple Mail). That string is the **expected** one and is **not yet "
    "captured**: no `com.apple.quarantine` value from a saved Mail attachment is in "
    "the repo, and if a Mac shows another string the tag does not fire. Outlook is "
    "**not verified** either. Hypothesis: the opened attachment is copied under the "
    "`Content.Outlook` folder; whether it carries a mark, and which process writes "
    "it, is still to be observed. Thunderbird is not verified. Neither is in the "
    "rule until a lab capture shows the mark and its writer "
    "(https://github.com/synthaea-lab/agent/issues/17).",
    "T1204.002 on Linux joins a browser download through the rename of its partial "
    "file (`.crdownload`, `.opdownload`, `.part`), by the renaming process's `executable_path`; "
    "verified once, on a Fedora 43 lab VM (Chromium 156, Firefox 159, Chrome 157, Edge, "
    "Brave 1.99, Opera, Vivaldi 8.3, headed under Xvfb, profile without a download "
    "dialog; a second run with the download directory on the temp directory's "
    "filesystem, for Chromium, Chrome, Edge and Opera, gives the same final rename and "
    "the same `executable_path`; on a Rocky 9.8 VM, Firefox 140 ESR from the distribution "
    "package has the same `/usr/lib64/firefox/firefox` and a `.part` rename). "
    "The Firefox family is matched by shape (file name `firefox`, `firefox-bin` or "
    "`firefox-esr` under a directory named `firefox` or `firefox-esr`), which covers the "
    "tarball (`firefox-bin`, captured), Debian's `firefox-esr` (captured on a Debian 13 VM, "
    "with the sensor, kernel 6.12, where the `file_rename` event carries that "
    "`executable_path` with comm `BgIOThr~Pool #1` and the main process's pid, and under "
    "strace; an end-to-end run of the shape-match build there, with headless firefox-esr downloading an ELF that was then run, raised T1204.002 `marked by firefox-esr` in 2 of 2 runs, and nothing for a `curl` plus `mv` control) and the Snap path "
    "(`/snap/firefox/<rev>/usr/lib/firefox/firefox`). **Not verified:** the Snap was never "
    "run (its path is read from the snap launcher), the Flatpak's real path is unknown "
    "(a Flatpak-shaped path matches), and Firefox forks under another directory name "
    "(`librewolf`, `firefox-developer-edition`) are not matched, so they raise nothing; "
    "Chromium-family Snap, Flatpak and other distributions' image paths until captured; "
    "a Wayland session; a download through a Save-as dialog. Resumed "
    "downloads were captured: Chrome resumes by itself, and after a browser kill and "
    "relaunch a manual Resume ends with the same single `.crdownload` -> final rename "
    "(same `executable_path`); Firefox's manual retry ends with the same `.part` -> "
    "final rename. An empty `executable_path` marks nothing: the "
    "process-lineage fallback is not implemented, and the capture ran under `strace` "
    "so its lineage was not real "
    "(https://github.com/synthaea-lab/agent/issues/221).",
]


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
        "by detection layer (1 signatures/hashes, 3 behavioral rules, "
        "6 attack-chain correlation). This proves positive coverage "
        "only: a technique absent here may still be planned, tracked, or out "
        "of scope for other reasons — see the issue tracker for that roadmap view.",
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

    lines.append("## Not verified")
    lines.append("")
    lines.extend(f"- {note}" for note in UNVERIFIED_NOTES)
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

    require_siblings()
    findings = discover()
    content = render(findings)

    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != content:
            print(
                f"error: {OUTPUT} is stale — run `python3 tools/attack-coverage.py` to regenerate",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"ok: {OUTPUT} is up to date ({len(findings)} techniques)")
        return

    OUTPUT.write_text(content, encoding="utf-8", newline="\n")
    print(f"wrote {OUTPUT} ({len(findings)} techniques)")


if __name__ == "__main__":
    main()
