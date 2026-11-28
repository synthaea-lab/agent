#!/usr/bin/env python3
"""Enforce the workspace dependency direction.

Rules (see CLAUDE.md):
  - `schema` depends on no workspace crate; `policy` depends only on `schema`.
    Together they are the BASE tier every other crate may use.
  - Sensor crates (`sensor-*`) depend only on `schema`, plus their own platform's
    shared crates (`sensor-linux-wire`, `sensor-linux-container`) and the helpers any
    sensor may use (`bounded-lines`), which depend on no workspace crate.
  - Detection crates (rules, sigma, correlator, verdict, ml, yara, enrich) depend on
    the base tier, each other, `store` and `event-window` — never on a sensor crate.
  - Within detection, the engines never depend on the stages that consume their output
    (`correlator`, `verdict`): what both sides share lives in `event-window`.
  - Leaf crates (response, transport, ipc, sinks, updater, config, store)
    depend only on the base tier.
  - Only the binaries (`agent`, `watchdog`, `cli`) may depend on anything.
  - Utility crates (`file-hash`, `workers`) depend on no workspace crate; any detection or leaf crate
    may use them. They exist so two tiers that may not depend on each other need not
    each keep a copy of the same code.
  - Test-support crates (`siblings`) depend on no workspace crate and may be a
    dev-dependency of anything — never a normal or build dependency.
  - No crate depends on a binary.

Run from the workspace root: `python3 tools/check-deps.py`
Exits non-zero listing every violation. CI runs this on every push.
"""

import json
import subprocess
import sys

SCHEMA = "schema"
BASE = {"schema", "policy"}
DETECTION = {"rules", "sigma", "correlator", "verdict", "ml", "yara", "enrich",
             "intel", "deception"}
# The stages fed by the engines' output; an engine depending on one would close a loop.
DETECTION_CONSUMERS = {"correlator", "verdict"}
# Leaf crates every detection crate may build on: bounded state, and the event window.
DETECTION_SHARED = {"store", "event-window"}
LEAF = {"response", "transport", "ipc", "sinks", "updater", "config", "store", "event-window",
        "tamper", "inventory", "redact", "health"}
BINARIES = {"agent", "watchdog", "cli", "release-tool"}
# Crates shared by one platform's sensors, keyed to that platform's package prefix:
# the wire crate (kernel<->userspace ABI) and the container-attribution runtime.
PLATFORM_SHARED = {
    "sensor-linux-wire": "sensor-linux",
    "sensor-linux-container": "sensor-linux",
}
# Helpers the detection and leaf tiers share instead of copying: no workspace deps.
UTILITY = {"file-hash", "workers"}
# Helpers sensors on different platforms share instead of copying: no workspace deps.
SENSOR_SHARED = {"bounded-lines"}
# Dev-only helpers: leaves with no workspace deps, usable as a dev-dependency anywhere.
TEST_SUPPORT = {"siblings"}


def allowed(crate: str) -> set[str] | None:
    """Workspace crates `crate` may depend on; None means unrestricted."""
    if crate in BINARIES:
        return None
    if crate == SCHEMA or crate in TEST_SUPPORT | SENSOR_SHARED | UTILITY:
        return set()
    if crate == "policy":
        return {SCHEMA}
    if crate.startswith("sensor-"):
        # Shared crates depend only on `schema`, so they never pull a sibling sensor in.
        if crate in PLATFORM_SHARED:
            return {SCHEMA}
        own_platform = {c for c, prefix in PLATFORM_SHARED.items() if crate.startswith(prefix)}
        return {SCHEMA} | SENSOR_SHARED | own_platform
    if crate in DETECTION_CONSUMERS:
        return BASE | DETECTION | DETECTION_SHARED | UTILITY
    if crate in DETECTION:
        return BASE | (DETECTION - DETECTION_CONSUMERS) | DETECTION_SHARED | UTILITY
    if crate in LEAF:
        return BASE | UTILITY
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
        for dep in pkg["dependencies"]:
            if dep["name"] in TEST_SUPPORT and dep["kind"] != "dev":
                violations.append(f"  {name} -> {dep['name']} (test-support crate: "
                                  f"dev-dependencies only)")
        rules = allowed(name)
        if rules is None:
            continue
        for dep in pkg["dependencies"]:
            if dep["name"] in TEST_SUPPORT:
                continue
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
