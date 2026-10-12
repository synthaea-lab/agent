"""Black-box tests for tools/check-macho-imports.py using tiny hand-built Mach-O files.

The files are built from the documented layout (`mach-o/loader.h`, `mach-o/fat.h`), not from
a real linker's output: whether the parser agrees with a real binary is checked where one
exists, by the macOS static-agent workflow, which runs the tool on the agent it just linked
(and prints `otool -L` beside it).
"""

from __future__ import annotations

import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CHECKER = Path(__file__).resolve().parents[1] / "check-macho-imports.py"

MH_MAGIC_64 = 0xFEEDFACF
MH_MAGIC = 0xFEEDFACE
CPU_ARM64 = 0x0100000C
CPU_X86_64 = 0x01000007
CPU_I386 = 0x00000007
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_RPATH = 0x8000001C
LC_SEGMENT_64 = 0x19

SYSTEM = ("/usr/lib/libSystem.B.dylib", "/usr/lib/libc++.1.dylib")


def padded(text: str) -> bytes:
    raw = text.encode() + b"\0"
    return raw + b"\0" * (-len(raw) % 8)


def dylib_command(cmd: int, name: str) -> bytes:
    body = padded(name)
    size = 24 + len(body)
    return struct.pack("<IIIIII", cmd, size, 24, 0, 0x10000, 0x10000) + body


def rpath_command(path: str) -> bytes:
    body = padded(path)
    return struct.pack("<III", LC_RPATH, 12 + len(body), 12) + body


def segment_command() -> bytes:
    """A command the parser has no interest in, to be skipped by its size."""
    return struct.pack("<II", LC_SEGMENT_64, 72) + b"\0" * 64


def thin(
    commands: list[bytes], cpu: int = CPU_ARM64, *, wide: bool = True, ncmds: int | None = None
) -> bytes:
    body = b"".join(commands)
    header = struct.pack(
        "<IiiIIII",
        MH_MAGIC_64 if wide else MH_MAGIC,
        cpu,
        3,
        2,
        len(commands) if ncmds is None else ncmds,
        len(body),
        0,
    )
    return header + (b"\0" * 4 if wide else b"") + body


def fat(*slices: bytes, wide: bool = False) -> bytes:
    entry = 32 if wide else 20
    header = struct.pack(">II", 0xCAFEBABF if wide else 0xCAFEBABE, len(slices))
    offset = 8 + entry * len(slices)
    offset += -offset % 16384
    table, payload = b"", b""
    for blob in slices:
        (cpu,) = struct.unpack_from("<i", blob, 4)
        if wide:
            table += struct.pack(">iiQQII", cpu, 0, offset + len(payload), len(blob), 14, 0)
        else:
            table += struct.pack(">iiIII", cpu, 0, offset + len(payload), len(blob), 14)
        payload += blob
    return header + table + b"\0" * (offset - 8 - len(table)) + payload


class CheckMachoImportsTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = Path(__file__).resolve().parents[2] / "target" / "macho-import-test-tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.directory = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, name: str, data: bytes) -> Path:
        path = self.directory / name
        path.write_bytes(data)
        return path

    def run_checker(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CHECKER), *arguments],
            check=False,
            capture_output=True,
            text=True,
        )

    def system_only(self, cpu: int = CPU_ARM64) -> bytes:
        return thin(
            [segment_command(), *(dylib_command(LC_LOAD_DYLIB, name) for name in SYSTEM)], cpu
        )

    def test_a_binary_that_loads_only_system_libraries_passes(self) -> None:
        path = self.write("agent", self.system_only())
        result = self.run_checker(str(path))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("[arm64]", result.stdout)
        self.assertIn("/usr/lib/libSystem.B.dylib", result.stdout)
        self.assertNotIn("<-", result.stdout)

    def test_the_shared_onnxruntime_build_is_forbidden(self) -> None:
        path = self.write(
            "agent",
            thin([dylib_command(LC_LOAD_DYLIB, "@rpath/libonnxruntime.1.30.0.dylib"), *[
                dylib_command(LC_LOAD_DYLIB, name) for name in SYSTEM
            ]]),
        )
        result = self.run_checker(str(path))
        self.assertEqual(result.returncode, 1)
        self.assertIn("FORBIDDEN (names onnxruntime)", result.stdout)

    def test_onnxruntime_is_forbidden_even_under_an_allowed_prefix(self) -> None:
        path = self.write("agent", thin([dylib_command(LC_LOAD_DYLIB, "/usr/lib/libOnnxRuntime.dylib")]))
        result = self.run_checker("--allow", "/usr/lib/", str(path))
        self.assertEqual(result.returncode, 1)
        self.assertIn("FORBIDDEN", result.stdout)

    def test_a_library_outside_the_system_is_refused_until_it_is_allowed(self) -> None:
        path = self.write("agent", thin([dylib_command(LC_LOAD_DYLIB, "/opt/homebrew/lib/libfoo.dylib")]))
        refused = self.run_checker(str(path))
        self.assertEqual(refused.returncode, 1)
        self.assertIn("NOT A SYSTEM LIBRARY", refused.stdout)
        allowed = self.run_checker("--allow", "/opt/homebrew/lib/", "--", str(path))
        self.assertEqual(allowed.returncode, 0, allowed.stderr)

    def test_an_rpath_relative_library_is_refused_whatever_its_name(self) -> None:
        path = self.write("agent", thin([dylib_command(LC_LOAD_DYLIB, "@rpath/libz.dylib")]))
        self.assertEqual(self.run_checker(str(path)).returncode, 1)

    def test_weak_and_reexported_libraries_count_like_any_other(self) -> None:
        for cmd in (LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB):
            with self.subTest(cmd=hex(cmd)):
                path = self.write(f"agent-{cmd:x}", thin([dylib_command(cmd, "@rpath/libonnxruntime.dylib")]))
                result = self.run_checker(str(path))
                self.assertEqual(result.returncode, 1)
                self.assertIn("FORBIDDEN", result.stdout)

    def test_rpaths_are_listed_and_do_not_fail_by_themselves(self) -> None:
        path = self.write("agent", thin([rpath_command("@executable_path/../lib"), dylib_command(LC_LOAD_DYLIB, SYSTEM[0])]))
        result = self.run_checker(str(path))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("rpath     @executable_path/../lib", result.stdout)

    def test_every_slice_of_a_universal_binary_is_judged(self) -> None:
        good = self.system_only(CPU_X86_64)
        bad = thin([dylib_command(LC_LOAD_DYLIB, "@rpath/libonnxruntime.dylib")], CPU_ARM64)
        for wide in (False, True):
            with self.subTest(wide=wide):
                ok = self.write(f"ok-{wide}", fat(good, self.system_only(), wide=wide))
                result = self.run_checker(str(ok))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("[x86_64]", result.stdout)
                self.assertIn("[arm64]", result.stdout)
                mixed = self.write(f"mixed-{wide}", fat(good, bad, wide=wide))
                result = self.run_checker(str(mixed))
                self.assertEqual(result.returncode, 1)
                self.assertIn("FORBIDDEN", result.stdout)

    def test_a_32_bit_slice_is_read_too(self) -> None:
        path = self.write("agent32", thin([dylib_command(LC_LOAD_DYLIB, SYSTEM[0])], CPU_I386, wide=False))
        result = self.run_checker(str(path))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("[i386]", result.stdout)

    def test_a_file_that_is_not_a_macho_is_exit_2_not_a_pass(self) -> None:
        for name, data in (
            ("elf", b"\x7fELF" + b"\0" * 64),
            ("empty", b""),
            ("text", b"#!/bin/sh\necho hi\n"),
            ("big-endian", struct.pack(">I", MH_MAGIC_64) + b"\0" * 60),
        ):
            with self.subTest(name=name):
                result = self.run_checker(str(self.write(name, data)))
                self.assertEqual(result.returncode, 2, result.stdout)

    def test_truncated_and_inconsistent_files_are_exit_2(self) -> None:
        whole = self.system_only()
        cases = {
            "cut-in-the-commands": whole[: len(whole) - 20],
            "cut-in-the-header": whole[:20],
            "ncmds-past-the-area": thin([dylib_command(LC_LOAD_DYLIB, SYSTEM[0])], ncmds=5),
            "implausible-ncmds": thin([], ncmds=10**6),
            "fat-slice-outside": struct.pack(">II", 0xCAFEBABE, 1) + struct.pack(">iiIII", CPU_ARM64, 0, 4096, 99999, 14),
            "fat-with-no-archs": struct.pack(">II", 0xCAFEBABE, 0),
        }
        for name, data in cases.items():
            with self.subTest(name=name):
                result = self.run_checker(str(self.write(name, data)))
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertNotIn("Traceback", result.stderr)

    def test_a_dylib_name_that_points_outside_its_command_is_exit_2(self) -> None:
        command = bytearray(dylib_command(LC_LOAD_DYLIB, SYSTEM[0]))
        struct.pack_into("<I", command, 8, 9999)
        result = self.run_checker(str(self.write("bad-offset", thin([bytes(command)]))))
        self.assertEqual(result.returncode, 2)

    def test_a_pattern_that_matches_nothing_is_exit_2(self) -> None:
        result = self.run_checker(str(self.directory / "nothing-*"))
        self.assertEqual(result.returncode, 2)
        self.assertIn("no file matches", result.stderr)

    def test_a_pattern_is_expanded_and_every_match_is_judged(self) -> None:
        self.write("ml-1", self.system_only())
        self.write("ml-2", thin([dylib_command(LC_LOAD_DYLIB, "@rpath/libonnxruntime.dylib")]))
        result = self.run_checker(str(self.directory / "ml-*"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("ml-1", result.stdout)
        self.assertIn("ml-2", result.stdout)


if __name__ == "__main__":
    unittest.main()
