"""Black-box tests for tools/check-no-temporary-keys.sh on hand-built key directories."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check-no-temporary-keys.sh"
REPO = SCRIPT.parents[1]
# A key that is not one of the temporary ones: what a ceremony would commit.
KEY = "aa" * 32
# The three temporary public keys committed on 2026-11-12.
TEMPORARY = {
    "release": "05a0a338b23f35b05c690095f54d7a857d195912f92543de8f5330bbf17f945a",
    "content": "5331efd87507ab8b0e7c3910b04e3bf87eee73699fcfadeda7e34b6930e20b02",
    "recovery": "16f3001ea2181b1cb7c98b9659c8edc125156fd4abacb0239bdfd34275df4e7d",
}


def run(directory: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(SCRIPT), str(directory)], capture_output=True, text=True, check=False
    )


class CheckNoTemporaryKeys(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write(self, name: str, body: str) -> None:
        (self.dir / name).write_text(body)

    def test_provisioned_and_unprovisioned_files_pass(self) -> None:
        self.write("release.pub", f"# The release key.\n{KEY}\n")
        self.write("snapshot.pub", "# Not provisioned.\nunprovisioned\n")
        result = run(self.dir)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_one_temporary_key_fails_and_is_named(self) -> None:
        self.write("release.pub", f"# TEMPORARY (2026-11-12): outside the ceremony.\n{KEY}\n")
        self.write("content.pub", f"# The content key.\n{KEY}\n")
        result = run(self.dir)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release.pub", result.stderr)
        self.assertNotIn("content.pub", result.stderr)

    def test_an_empty_directory_fails_instead_of_passing_blind(self) -> None:
        result = run(self.dir)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("without looking", result.stderr)

    def test_a_missing_directory_fails_instead_of_passing_blind(self) -> None:
        result = run(self.dir / "nope")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("without looking", result.stderr)

    def test_a_temporary_key_whose_comment_was_removed_still_fails(self) -> None:
        # The build embeds the first non-comment line, so dropping the "TEMPORARY" header keeps
        # the same key embedded: the check must read the key, not the comment.
        for role, value in TEMPORARY.items():
            with self.subTest(role=role):
                self.write(f"{role}.pub", f"# The {role} key.\n{value}\n")
        self.write("snapshot.pub", "# Not provisioned.\nunprovisioned\n")
        result = run(self.dir)
        self.assertNotEqual(result.returncode, 0)
        for role in TEMPORARY:
            self.assertIn(f"{role}.pub", result.stderr)
        self.assertNotIn("snapshot.pub", result.stderr)

    def test_a_temporary_key_in_upper_case_or_padded_still_fails(self) -> None:
        self.write("release.pub", f"\n  {TEMPORARY['release'].upper()}  \n")
        result = run(self.dir)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release.pub", result.stderr)

    def test_the_key_line_is_the_first_non_comment_line(self) -> None:
        # A temporary key written after another key line is not the one the build embeds.
        self.write("release.pub", f"# The release key.\n{KEY}\n{TEMPORARY['release']}\n")
        result = run(self.dir)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_relative_directory_is_read_from_the_callers_directory(self) -> None:
        self.write("release.pub", f"# The release key.\n{KEY}\n")
        result = subprocess.run(
            [str(SCRIPT), self.dir.name],
            capture_output=True,
            text=True,
            check=False,
            cwd=self.dir.parent,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_the_committed_keys_are_read(self) -> None:
        # The default directory must exist and hold key files; whether they are still temporary
        # is the very thing the release guard decides, so only "the script ran and looked at the
        # key files" is asserted: it exits 0 or 1 (not 126/127: exec bit lost, bash missing) and
        # names a key file or says how many it read.
        result = subprocess.run(
            [str(SCRIPT)], capture_output=True, text=True, check=False, cwd=REPO
        )
        self.assertIn(result.returncode, (0, 1), result.stderr)
        output = result.stdout + result.stderr
        self.assertNotIn("without looking", output)
        self.assertTrue(".pub" in output or "key file(s)" in output, output)


if __name__ == "__main__":
    unittest.main()
