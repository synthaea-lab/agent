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


class SensorTier(unittest.TestCase):
    def test_a_sensor_may_use_the_shared_line_reader_on_any_platform(self) -> None:
        for sensor in ("sensor-linux-journal", "sensor-macos-unifiedlog", "sensor-windows-eventlog"):
            with self.subTest(sensor=sensor):
                self.assertIn("bounded-lines", tool.allowed(sensor))

    def test_a_sensor_may_not_depend_on_another_platforms_sensor_crates(self) -> None:
        self.assertNotIn("sensor-linux-wire", tool.allowed("sensor-macos"))
        self.assertNotIn("sensor-linux-container", tool.allowed("sensor-windows"))

    def test_a_shared_sensor_helper_depends_on_no_workspace_crate(self) -> None:
        self.assertEqual(tool.allowed("bounded-lines"), set())


class RealTree(unittest.TestCase):
    def test_the_workspace_respects_the_rules(self) -> None:
        result = subprocess.run([sys.executable, str(TOOL)], cwd=REPO, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
