"""Tests for tools/check-deps.py: who may depend on whom inside the detection tier, and the real tree."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "check-deps.py"
REPO = TOOL.parents[1]

spec = importlib.util.spec_from_file_location("check_deps", TOOL)
assert spec is not None and spec.loader is not None
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class DetectionTier(unittest.TestCase):
    def test_an_engine_may_not_depend_on_a_stage_that_consumes_its_output(self) -> None:
        for engine in ("ml", "rules", "sigma", "yara", "intel", "enrich", "deception"):
            with self.subTest(engine=engine):
                self.assertNotIn("correlator", tool.allowed(engine))
                self.assertNotIn("verdict", tool.allowed(engine))

    def test_a_consuming_stage_may_depend_on_the_engines(self) -> None:
        self.assertIn("ml", tool.allowed("correlator"))
        self.assertIn("rules", tool.allowed("verdict"))

    def test_both_sides_may_read_the_event_window(self) -> None:
        self.assertIn("event-window", tool.allowed("ml"))
        self.assertIn("event-window", tool.allowed("correlator"))

    def test_the_event_window_depends_on_the_base_tier_only(self) -> None:
        self.assertEqual(tool.allowed("event-window"), tool.BASE)

    def test_no_detection_crate_may_depend_on_a_sensor(self) -> None:
        for crate in sorted(tool.DETECTION):
            with self.subTest(crate=crate):
                self.assertFalse(any(dep.startswith("sensor-") for dep in tool.allowed(crate)))


class RealTree(unittest.TestCase):
    def test_the_workspace_respects_the_rules(self) -> None:
        result = subprocess.run([sys.executable, str(TOOL)], cwd=REPO, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
