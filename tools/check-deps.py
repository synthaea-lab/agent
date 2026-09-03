#!/usr/bin/env python3
"""Enforce the workspace dependency direction.

Rules (see CLAUDE.md):
  - `schema` depends on no workspace crate; `policy` depends only on `schema`.
    Together they are the BASE tier every other crate may use.
  - Sensor crates (`sensor-*`) depend only on `schema`.
  - Detection crates (rules, sigma, correlator, ml, yara, enrich) depend on the base
    tier, each other, and `store` — never on a sensor crate.
  - Leaf crates (response, transport, ipc, sinks, updater, config, store, conformance)
    depend only on the base tier.
  - Only the binaries (`agent`, `watchdog`, `cli`) may depend on anything.
  - No crate depends on a binary.

Run from the workspace root: `python3 tools/check-deps.py`
Exits non-zero listing every violation. CI runs this on every push.
"""

import json
import subprocess
import sys

SCHEMA = "schema"
BASE = {"schema", "policy"}
DETECTION = {"rules", "sigma", "correlator", "ml", "yara", "enrich", "intel",
             "deception"}
LEAF = {"response", "transport", "ipc", "sinks", "updater", "config", "store",
        "conformance", "live-response", "tamper", "mesh", "device-control", "inventory"}
BINARIES = {"agent", "watchdog", "cli"}
WIRE_CRATES = {"sensor-linux-wire"}


def allowed(crate: str) -> set[str] | None:
    """Workspace crates `crate` may depend on; None means unrestricted."""
    if crate in BINARIES:
        return None
    if crate == SCHEMA:
        return set()
    if crate == "policy":
        return {SCHEMA}
    if crate.startswith("sensor-"):
        # A platform's wire crate (its kernel<->userspace ABI) is shared within that
        # platform's sensor pair — e.g. sensor-linux -> sensor-linux-wire.
        return {SCHEMA} | {c for c in WIRE_CRATES if crate.startswith(c.removesuffix("-wire"))}
    if crate in DETECTION:
        return BASE | DETECTION | {"store"}
    if crate in LEAF:
        return set(BASE)
    print(f"error: crate `{crate}` is not covered by the dependency rules — "
          f"add it to tools/check-deps.py")
    sys.exit(2)


def main() -> None:
    meta = json.loads(subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        check=True, capture_output=True, text=True,
    ).stdout)

    workspace = {p["name"]: p for p in meta["packages"]}
    violations = []

    for name, pkg in workspace.items():
        rules = allowed(name)
        if rules is None:
            continue
        for dep in pkg["dependencies"]:
            if dep["name"] in workspace and dep["name"] not in rules:
                violations.append(f"  {name} -> {dep['name']}")
        for dep in pkg["dependencies"]:
            if dep["name"] in BINARIES:
                violations.append(f"  {name} -> {dep['name']} (binary)")

    if violations:
        print("Dependency direction violations:")
        print("\n".join(sorted(set(violations))))
        print("\nSee CLAUDE.md for the dependency rules.")
        sys.exit(1)
    print(f"ok: {len(workspace)} workspace crates respect the dependency rules")


if __name__ == "__main__":
    main()
