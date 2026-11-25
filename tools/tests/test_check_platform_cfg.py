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


class CfgTestItems(unittest.TestCase):
    """What a column-0 `#[cfg(test)]` hides, and what it must not."""

    def test_a_cfg_test_use_does_not_hide_the_code_after_it(self) -> None:
        text = "\n".join([
            "#[cfg(test)]",
            "use ring::signature::KeyPair;",
            "",
            "#[cfg(windows)]",
            "fn platform_branch() {}",
        ])
        self.assertEqual(tool.count_platform_cfg(text), 1)

    def test_a_cfg_test_mod_declaration_does_not_hide_the_code_after_it(self) -> None:
        text = "\n".join([
            "#[cfg(test)]",
            "mod tests;",
            "#[cfg(target_os = \"linux\")]",
            "fn platform_branch() {}",
        ])
        self.assertEqual(tool.count_platform_cfg(text), 1)

    def test_a_one_line_braced_item_does_not_hide_the_code_after_it(self) -> None:
        for item in ("fn helper() {}", "struct S {}", "impl Trait for X {}"):
            with self.subTest(item=item):
                text = "\n".join([
                    "#[cfg(test)]",
                    item,
                    "",
                    "#[cfg(windows)]",
                    "fn platform_branch() {",
                    "}",
                ])
                self.assertEqual(tool.count_platform_cfg(text), 1)

    def test_an_item_on_the_attribute_line_does_not_hide_the_next_item(self) -> None:
        text = "\n".join([
            "#[cfg(test)] use a::b;",
            "#[cfg(windows)]",
            "fn platform_branch() {",
            "}",
        ])
        self.assertEqual(tool.count_platform_cfg(text), 1)

    def test_an_attribute_line_item_with_a_body_is_skipped_whole(self) -> None:
        text = "\n".join([
            "#[cfg(test)] mod tests {",
            "    #[cfg(unix)]",
            "    fn fixture() {}",
            "}",
            "#[cfg(windows)]",
            "fn real() {}",
        ])
        self.assertEqual(tool.count_platform_cfg(text), 1)

    def test_a_test_module_in_the_middle_hides_only_itself(self) -> None:
        text = "\n".join([
            "#[cfg(test)]",
            "mod first {",
            "    #[cfg(unix)]",
            "    fn fixture() {}",
            "}",
            "",
            "#[cfg(windows)]",
            "fn between() {}",
            "",
            "#[cfg(test)]",
            "mod second {",
            "    #[cfg(unix)]",
            "    fn fixture() {}",
            "}",
            "#[cfg(unix)]",
            "fn after() {}",
        ])
        self.assertEqual(tool.count_platform_cfg(text), 2)

    def test_a_brace_at_column_zero_inside_a_raw_string_does_not_end_the_module(self) -> None:
        text = "\n".join([
            "#[cfg(test)]",
            "mod tests {",
            '    const RULE: &str = r#"',
            "rule x {",
            "}",
            '"#;',
            "    #[cfg(unix)]",
            "    fn fixture() {}",
            "}",
            "#[cfg(windows)]",
            "fn real() {}",
        ])
        self.assertEqual(tool.count_platform_cfg(text), 1)

    def test_a_cfg_test_module_with_attributes_and_blank_lines_is_skipped(self) -> None:
        text = "\n".join([
            "#[cfg(test)]",
            "#[allow(clippy::unwrap_used)]",
            "",
            "mod tests {",
            "    #[cfg(windows)]",
            "    fn fixture() {}",
            "}",
        ])
        self.assertEqual(tool.count_platform_cfg(text), 0)


class MultiLineCfg(unittest.TestCase):
    def test_a_cfg_split_over_several_lines_counts_once(self) -> None:
        text = "\n".join([
            "#[cfg(any(",
            '    target_os = "linux",',
            '    target_os = "macos",',
            "))]",
            "fn platform_branch() {}",
        ])
        self.assertEqual(tool.count_platform_cfg(text), 1)

    def test_a_split_cfg_without_a_platform_does_not_count(self) -> None:
        text = "\n".join([
            "#[cfg(all(",
            '    feature = "tls",',
            "    not(test),",
            "))]",
            "fn gated() {}",
        ])
        self.assertEqual(tool.count_platform_cfg(text), 0)

    def test_a_platform_word_after_the_closing_parenthesis_does_not_count(self) -> None:
        text = "\n".join([
            '#[cfg(feature = "tls")]',
            "fn linux() {}",
        ])
        self.assertEqual(tool.count_platform_cfg(text), 0)

    def test_an_unbalanced_cfg_does_not_run_away(self) -> None:
        text = "\n".join(["#[cfg(any("] + ["let x = 1;"] * 100 + ["#[cfg(windows)]", "fn f() {}"])
        self.assertGreaterEqual(tool.count_platform_cfg(text), 1)


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
