"""Black-box tests for tools/check-pe-imports.py using tiny hand-built PE files."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
import struct


CHECKER = Path(__file__).resolve().parents[1] / "check-pe-imports.py"
FILE_SIZE = 0x1200
SECTION_RVA = 0x1000
SECTION_RAW = 0x200
SECTION_SIZE = 0x1000


def build_pe(
    regular_imports: tuple[str, ...] = (),
    delay_imports: tuple[str, ...] = (),
    *,
    pe32plus: bool = True,
) -> bytes:
    """Create one-section PE bytes and import descriptor tables without PE libraries."""
    optional_size = 0xF0 if pe32plus else 0xE0
    machine = 0x8664 if pe32plus else 0x014C
    data = bytearray(FILE_SIZE)
    data[:2] = b"MZ"
    pe_offset = 0x80
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset : pe_offset + 4] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        data,
        pe_offset + 4,
        machine,
        1,
        0,
        0,
        0,
        optional_size,
        0x2022,
    )

    optional = pe_offset + 24
    struct.pack_into("<H", data, optional, 0x20B if pe32plus else 0x10B)
    directories_offset = 112 if pe32plus else 96
    count_offset = 108 if pe32plus else 92
    struct.pack_into("<I", data, optional + count_offset, 16)

    section = optional + optional_size
    data[section : section + 8] = b".rdata\0\0"
    struct.pack_into(
        "<IIII",
        data,
        section + 8,
        SECTION_SIZE,
        SECTION_RVA,
        SECTION_SIZE,
        SECTION_RAW,
    )

    def raw_offset(rva: int) -> int:
        return SECTION_RAW + rva - SECTION_RVA

    names: dict[str, int] = {}
    next_name_rva = 0x1200
    for name in (*regular_imports, *delay_imports):
        if name not in names:
            names[name] = next_name_rva
            encoded = name.encode("ascii") + b"\0"
            offset = raw_offset(next_name_rva)
            data[offset : offset + len(encoded)] = encoded
            next_name_rva += len(encoded)

    regular_rva = 0x1000
    regular_size = (len(regular_imports) + 1) * 20
    for index, name in enumerate(regular_imports):
        struct.pack_into(
            "<IIIII",
            data,
            raw_offset(regular_rva) + index * 20,
            0,
            0,
            0,
            names[name],
            0,
        )

    delayed_rva = 0x1080
    delayed_size = (len(delay_imports) + 1) * 32
    for index, name in enumerate(delay_imports):
        struct.pack_into(
            "<IIIIIIII",
            data,
            raw_offset(delayed_rva) + index * 32,
            1,
            names[name],
            0,
            0,
            0,
            0,
            0,
            0,
        )

    directories = optional + directories_offset
    struct.pack_into("<II", data, directories + 8, regular_rva, regular_size)
    struct.pack_into("<II", data, directories + 13 * 8, delayed_rva, delayed_size)
    return bytes(data)


class CheckPeImportsTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = Path(__file__).resolve().parents[2] / "target" / "pe-import-test-tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.directory = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_pe(self, name: str, **kwargs: object) -> Path:
        path = self.directory / name
        path.write_bytes(build_pe(**kwargs))
        return path

    def run_checker(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CHECKER), *arguments],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_fixture_header_matches_an_independent_struct_reader(self) -> None:
        path = self.write_pe(
            "headers.exe",
            regular_imports=("kernel32.dll", "directml.dll"),
            delay_imports=("kernel32.dll", "directml.dll"),
        )
        reference = r"""
import struct, sys
data = open(sys.argv[1], 'rb').read()
pe = struct.unpack_from('<I', data, 0x3c)[0]
assert data[:2] == b'MZ' and data[pe:pe+4] == b'PE\0\0'
machine, sections, _, _, _, optional_size, _ = struct.unpack_from('<HHIIIHH', data, pe+4)
optional = pe + 24
assert (machine, sections, optional_size) == (0x8664, 1, 0xf0)
assert struct.unpack_from('<H', data, optional)[0] == 0x20b
directories = optional + 112
assert struct.unpack_from('<II', data, directories + 8) == (0x1000, 60)
assert struct.unpack_from('<II', data, directories + 13*8) == (0x1080, 96)
"""
        result = subprocess.run(
            [sys.executable, "-I", "-c", reference, str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        imports = self.run_checker(str(path))
        self.assertEqual(imports.returncode, 1)
        for expected in (
            "import      kernel32.dll",
            "import      directml.dll",
            "delay-load  kernel32.dll",
            "delay-load  directml.dll",
        ):
            self.assertIn(expected, imports.stdout)

    def test_exit_zero_for_allowed_regular_and_delay_imports(self) -> None:
        path = self.write_pe(
            "allowed.exe",
            regular_imports=("kernel32.dll",),
            delay_imports=("user32.dll",),
        )
        result = self.run_checker(str(path))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("import      kernel32.dll", result.stdout)
        self.assertIn("delay-load  user32.dll", result.stdout)

    def test_repeated_forbid_options_accumulate_and_keep_defaults(self) -> None:
        path = self.write_pe(
            "forbidden.exe",
            regular_imports=("foo.dll", "bar.dll", "directml.dll"),
        )
        result = self.run_checker(
            "--forbid", "foo.dll", "--forbid", "bar.dll", "--", str(path)
        )
        self.assertEqual(result.returncode, 1)
        for name in ("foo.dll", "bar.dll", "directml.dll"):
            self.assertIn(f"FORBIDDEN   {name}", result.stdout)

    def test_forbid_last_before_separator_applies_to_following_file(self) -> None:
        path = self.write_pe("extra.exe", regular_imports=("extra.dll",))
        result = self.run_checker("--forbid", "extra.dll", "--", str(path))
        self.assertEqual(result.returncode, 1)
        self.assertIn("FORBIDDEN   extra.dll", result.stdout)

    def test_delay_load_only_forbidden_dll_is_detected(self) -> None:
        path = self.write_pe(
            "delay-only.exe",
            regular_imports=("kernel32.dll",),
            delay_imports=("directml.dll",),
        )
        result = self.run_checker(str(path))
        self.assertEqual(result.returncode, 1)
        self.assertIn("delay-load  directml.dll", result.stdout)
        self.assertIn("FORBIDDEN   directml.dll", result.stdout)
        self.assertNotIn("import      directml.dll", result.stdout)

    def test_glob_expands_two_files(self) -> None:
        self.write_pe("first.exe", regular_imports=("kernel32.dll",))
        self.write_pe("second.exe", regular_imports=("user32.dll",))
        result = self.run_checker(str(self.directory / "*.exe"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("first.exe", result.stdout)
        self.assertIn("second.exe", result.stdout)

    def test_glob_without_matches_exits_two(self) -> None:
        result = self.run_checker(str(self.directory / "missing-*.exe"))
        self.assertEqual(result.returncode, 2)
        self.assertIn("no file matches", result.stderr)

    def test_pe32_and_non_pe_files_exit_two(self) -> None:
        pe32 = self.directory / "32-bit.exe"
        pe32.write_bytes(build_pe(pe32plus=False))
        non_pe = self.directory / "not-pe.exe"
        non_pe.write_bytes(b"plain text, not an executable")

        for path, message in ((pe32, "not a 64-bit PE"), (non_pe, "not a PE file")):
            with self.subTest(path=path.name):
                result = self.run_checker(str(path))
                self.assertEqual(result.returncode, 2)
                self.assertIn(message, result.stderr)


if __name__ == "__main__":
    unittest.main()
