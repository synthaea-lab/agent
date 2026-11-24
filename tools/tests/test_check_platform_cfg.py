"""Tests for tools/check-platform-cfg.py: the counting rule, the path rules, and the real tree."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "check-platform-cfg.py"
REPO = TOOL.parents[1]

spec = importlib.util.spec_from_file_location("check_platform_cfg", TOOL)
assert spec is not None and spec.loader is not None
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class CountPlatformCfg(unittest.TestCase):
    def test_every_spelling_of_a_platform_branch_counts_once_per_line(self) -> None:
        text = "\n".join([
            '#[cfg(target_os = "linux")]',
            "#[cfg(windows)]",
            "#[cfg(not(unix))]",
            "#[cfg(all(test, target_os = \"macos\"))]",
            "if cfg!(windows) { 1 } else { 2 }",
            '#[cfg_attr(unix, allow(dead_code))]',
            '#[cfg(target_family = "unix")]',
        ])
        self.assertEqual(tool.count_platform_cfg(text), 7)

    def test_other_cfgs_comments_and_words_do_not_count(self) -> None:
        text = "\n".join([
            '#[cfg(feature = "tls")]',
            "// #[cfg(windows)] in a comment",
            "//! `cfg(unix)` in a doc comment",
            "let linux = windows + unix;",
            "#[derive(Debug)]",
        ])
        self.assertEqual(tool.count_platform_cfg(text), 0)

    def test_a_files_own_unit_tests_are_not_counted(self) -> None:
        text = "\n".join([
            '#[cfg(windows)]',
            "fn real() {}",
            "#[cfg(test)]",
            "mod tests {",
            "    #[cfg(unix)]",
            "    #[test] fn t() {}",
            "}",
        ])
        self.assertEqual(tool.count_platform_cfg(text), 1)


def tree(extra: dict[str, int]) -> dict[str, int]:
    """A tree where every exception sits at its ceiling, plus `extra` files."""
    counts = {path: ceiling for path, (ceiling, _) in tool.EXCEPTIONS.items()}
    counts.update(extra)
    return counts


class Violations(unittest.TestCase):
    def test_a_core_crate_cannot_gain_a_platform_branch(self) -> None:
        problems = tool.violations(tree({"crates/rules/src/new_rule.rs": 1}))
        self.assertEqual(len(problems), 1)
        self.assertIn("crates/rules/src/new_rule.rs", problems[0])

    def test_the_allowed_places_have_no_limit(self) -> None:
        counts = {
            "crates/sensors/linux/lsm/src/lib.rs": 50,
            "crates/updater/src/lib.rs": 9,
            "crates/response/src/quarantine.rs": 4,
            "apps/agent/src/main.rs": 14,
            "tools/release/src/keyfile.rs": 2,
            "crates/ipc/tests/e2e.rs": 6,
            "crates/rules/src/tests/linux.rs": 3,
            "crates/sigma/src/tests.rs": 3,
        }
        self.assertEqual(tool.violations(tree(counts)), [])

    def test_an_exception_is_a_ceiling_not_a_licence(self) -> None:
        path = "crates/yara/src/access.rs"
        ceiling = tool.EXCEPTIONS[path][0]
        self.assertEqual(tool.violations(tree({path: ceiling})), [])
        self.assertEqual(tool.violations(tree({path: ceiling - 1})), [])
        self.assertEqual(len(tool.violations(tree({path: ceiling + 1}))), 1)

    def test_an_exception_for_a_file_that_is_gone_is_reported(self) -> None:
        counts = tree({})
        gone = next(iter(tool.EXCEPTIONS))
        del counts[gone]
        problems = tool.violations(counts)
        self.assertEqual(len(problems), 1)
        self.assertIn(gone, problems[0])

    def test_every_exception_has_a_reason(self) -> None:
        for path, (ceiling, reason) in tool.EXCEPTIONS.items():
            self.assertGreater(ceiling, 0, path)
            self.assertTrue(reason.strip(), path)


class RealTree(unittest.TestCase):
    def test_the_repository_passes(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL)], cwd=REPO, capture_output=True, text=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
