"""Tests for tools/check-agent-layers.py: the wiring stays on top, modules never form a cycle."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "check-agent-layers.py"
REPO = TOOL.parents[1]

spec = importlib.util.spec_from_file_location("check_agent_layers", TOOL)
assert spec is not None and spec.loader is not None
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


def graph_of(files: dict[str, str]) -> dict[str, set[str]]:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for name, text in files.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text)
        return tool.module_graph(root)


class CratePaths(unittest.TestCase):
    def test_a_plain_path_names_its_first_segment(self) -> None:
        self.assertEqual(tool.crate_roots_named("use crate::sink::DetectionSink;"), {"sink"})

    def test_a_grouped_import_names_every_head_but_no_nested_item(self) -> None:
        code = "use crate::{\n    health::{Counter, spawn},\n    sync::LockExt,\n    upload,\n};"
        self.assertEqual(tool.crate_roots_named(code), {"health", "sync", "upload"})

    def test_a_path_inside_an_expression_counts(self) -> None:
        self.assertEqual(tool.crate_roots_named("let a = crate::alerts::open(path)?;"), {"alerts"})


class ProductionCode(unittest.TestCase):
    def test_comments_and_strings_do_not_count(self) -> None:
        code = tool.production_code('// see crate::commands\nlet s = "crate::commands";\n')
        self.assertEqual(tool.crate_roots_named(code), set())

    def test_an_inline_test_module_does_not_count(self) -> None:
        text = "use crate::sync::LockExt;\n#[cfg(test)]\nmod tests {\n    use crate::commands::x;\n}\n"
        self.assertEqual(tool.crate_roots_named(tool.production_code(text)), {"sync"})

    def test_a_test_file_does_not_count(self) -> None:
        graph = graph_of({"sink/mod.rs": "", "sink/tests.rs": "use crate::commands::x;", "commands/mod.rs": ""})
        self.assertEqual(graph["sink"], set())


class Wiring(unittest.TestCase):
    def test_a_module_naming_the_wiring_is_a_violation(self) -> None:
        graph = graph_of({"main.rs": "", "commands/mod.rs": "use crate::sink::S;", "sink.rs": "use crate::commands::run;"})
        self.assertEqual(len(tool.wiring_violations(graph)), 1)
        self.assertIn("sink -> commands", tool.wiring_violations(graph)[0])

    def test_a_module_naming_an_item_of_main_is_a_violation(self) -> None:
        graph = graph_of({"main.rs": "", "upload.rs": "use crate::ExitCode;"})
        self.assertIn("upload -> crate::ExitCode", tool.wiring_violations(graph)[0])

    def test_the_wiring_may_name_any_module(self) -> None:
        graph = graph_of({"main.rs": "use crate::commands::run;", "commands/linux.rs": "use crate::sink::S;", "sink.rs": ""})
        self.assertEqual(tool.wiring_violations(graph), [])


class Cycles(unittest.TestCase):
    def test_layered_modules_have_no_cycle(self) -> None:
        graph = {"sink": {"upload", "sync"}, "upload": {"sync"}, "sync": set()}
        self.assertEqual(tool.cycle_violations(graph), [])

    def test_a_cycle_is_reported_once_whatever_module_the_walk_starts_from(self) -> None:
        graph = {"alerts": {"sink"}, "sink": {"upload"}, "upload": {"alerts"}}
        self.assertEqual(tool.cycle_violations(graph), ["  cycle: alerts -> sink -> upload -> alerts"])

    def test_two_modules_importing_each_other_are_a_cycle(self) -> None:
        self.assertEqual(len(tool.cycle_violations({"ioc": {"own_traffic"}, "own_traffic": {"ioc"}})), 1)


class RealTree(unittest.TestCase):
    def test_the_agent_binary_respects_the_layering(self) -> None:
        result = subprocess.run([sys.executable, str(TOOL)], cwd=REPO, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
