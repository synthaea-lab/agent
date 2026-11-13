"""Black-box tests for tools/check-no-temporary-keys.sh on hand-built key directories."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check-no-temporary-keys.sh"
REPO = SCRIPT.parents[1]
KEY = "05a0a338b23f35b05c690095f54d7a857d195912f92543de8f5330bbf17f945a"


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

    def test_the_committed_keys_are_read(self) -> None:
        # The default directory must exist and hold key files; whether they are still temporary
        # is the very thing the release guard decides, so only the "looked at files" half is
        # asserted here.
        result = subprocess.run(
            [str(SCRIPT)], capture_output=True, text=True, check=False, cwd=REPO
        )
        self.assertNotIn("without looking", result.stderr)


if __name__ == "__main__":
    unittest.main()
