"""Black-box tests for tools/check-ebpf-symbols.py using tiny hand-built ELF files."""

from __future__ import annotations

import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CHECKER = Path(__file__).resolve().parents[1] / "check-ebpf-symbols.py"
SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE = 0x2, 0x4, 0x1
SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB = 1, 2, 3
STB_LOCAL, STB_GLOBAL = 0, 1
STT_OBJECT, STT_FUNC = 1, 2

# (name, flags): the content sections of the object, in section-index order from 1.
CONTENT_SECTIONS = (
    ("tracepoint/sched/sched_process_exec", SHF_ALLOC | SHF_EXECINSTR),
    (".text", SHF_ALLOC | SHF_EXECINSTR),
    ("maps", SHF_ALLOC | SHF_WRITE),
    (".maps", SHF_ALLOC | SHF_WRITE),
    (".rodata", SHF_ALLOC),
)
SECTION_INDEX = {
    name: index for index, (name, _flags) in enumerate(CONTENT_SECTIONS, start=1)
}

# (name, binding, type, section, size in bytes)
DEFAULT_SYMBOLS = (
    (
        "sched_process_exec",
        STB_GLOBAL,
        STT_FUNC,
        "tracepoint/sched/sched_process_exec",
        40 * 8,
    ),
    ("fill_lineage", STB_LOCAL, STT_FUNC, "tracepoint/sched/sched_process_exec", 6 * 8),
    ("shared_subprogram", STB_GLOBAL, STT_FUNC, ".text", 9 * 8),
    ("EXEC_EVENTS", STB_GLOBAL, STT_OBJECT, "maps", 28),
    ("PROC_LINEAGE", STB_GLOBAL, STT_OBJECT, ".maps", 32),
    ("ARGV_LIMIT", STB_GLOBAL, STT_OBJECT, ".rodata", 4),
)


def string_table(names: list[str]) -> tuple[bytes, dict[str, int]]:
    table, offsets = bytearray(b"\0"), {}
    for name in names:
        offsets[name] = len(table)
        table += name.encode() + b"\0"
    return bytes(table), offsets


def build_elf(
    symbols: tuple[tuple[str, int, int, str, int], ...] = DEFAULT_SYMBOLS,
) -> bytes:
    """A relocatable eBPF ELF with the content sections above, a symbol table and its string tables."""
    strtab, name_offsets = string_table([name for name, *_ in symbols])
    symtab = bytearray(24)  # the null symbol
    for name, binding, kind, section, size in symbols:
        symtab += struct.pack(
            "<IBBHQQ",
            name_offsets[name],
            (binding << 4) | kind,
            0,
            SECTION_INDEX[section],
            0,
            size,
        )
    section_names = [name for name, _flags in CONTENT_SECTIONS] + [
        ".symtab",
        ".strtab",
        ".shstrtab",
    ]
    shstrtab, section_name_offsets = string_table(section_names)

    payloads = [b"\0" * 8 for _ in CONTENT_SECTIONS] + [bytes(symtab), strtab, shstrtab]
    data, offsets = bytearray(64), []
    for payload in payloads:
        offsets.append(len(data))
        data += payload
    sh_offset = len(data)
    symtab_index, strtab_index = len(CONTENT_SECTIONS) + 1, len(CONTENT_SECTIONS) + 2
    headers = [struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]
    for index, (name, payload) in enumerate(zip(section_names, payloads), start=1):
        flags = CONTENT_SECTIONS[index - 1][1] if index <= len(CONTENT_SECTIONS) else 0
        kind = {
            ".symtab": SHT_SYMTAB,
            ".strtab": SHT_STRTAB,
            ".shstrtab": SHT_STRTAB,
        }.get(name, SHT_PROGBITS)
        link, entry_size = (strtab_index, 24) if kind == SHT_SYMTAB else (0, 0)
        headers.append(
            struct.pack(
                "<IIQQQQIIQQ",
                section_name_offsets[name],
                kind,
                flags,
                0,
                offsets[index - 1],
                len(payload),
                link,
                0,
                8,
                entry_size,
            )
        )
    data += b"".join(headers)

    data[:4] = b"\x7fELF"
    data[4:7] = bytes((2, 1, 1))  # 64-bit, little-endian, ELF version 1
    struct.pack_into("<HHI", data, 0x10, 1, 247, 1)  # ET_REL, EM_BPF
    struct.pack_into("<Q", data, 0x28, sh_offset)
    struct.pack_into(
        "<HHHHHH", data, 0x34, 64, 0, 0, 64, len(headers), symtab_index + 2
    )
    return bytes(data)


EXPECTED_LIST = (
    "map .maps PROC_LINEAGE\n"
    "map maps EXEC_EVENTS\n"
    "program tracepoint/sched/sched_process_exec sched_process_exec\n"
)


class CheckEbpfSymbolsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def object_file(self, data: bytes | None = None) -> Path:
        path = self.dir / "sensor-linux-ebpf"
        path.write_bytes(build_elf() if data is None else data)
        return path

    def expected_file(self, text: str = EXPECTED_LIST) -> Path:
        path = self.dir / "symbols.txt"
        path.write_text(text, encoding="utf-8", newline="\n")
        return path

    def run_checker(self, *args: str | Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CHECKER), *map(str, args)],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_lists_global_programs_and_maps_but_not_locals_text_or_other_data(
        self,
    ) -> None:
        listed = self.dir / "written.txt"
        result = self.run_checker("--write", self.object_file(), listed)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(listed.read_text(encoding="utf-8"), EXPECTED_LIST)

    def test_a_matching_list_passes(self) -> None:
        result = self.run_checker(self.object_file(), self.expected_file())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("3 program and map names match", result.stdout)

    def test_a_list_checked_out_with_crlf_endings_still_matches(self) -> None:
        crlf_list = self.dir / "symbols.txt"
        crlf_list.write_bytes(EXPECTED_LIST.replace("\n", "\r\n").encode())
        result = self.run_checker(self.object_file(), crlf_list)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_renamed_program_fails_with_a_diff(self) -> None:
        renamed = tuple(
            ("sched_exec", *rest) if name == "sched_process_exec" else (name, *rest)
            for name, *rest in DEFAULT_SYMBOLS
        )
        result = self.run_checker(
            self.object_file(build_elf(renamed)), self.expected_file()
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "-program tracepoint/sched/sched_process_exec sched_process_exec",
            result.stdout,
        )
        self.assertIn(
            "+program tracepoint/sched/sched_process_exec sched_exec", result.stdout
        )

    def test_a_program_moved_to_another_section_fails(self) -> None:
        moved = tuple(
            (
                name,
                binding,
                kind,
                ".text" if name == "sched_process_exec" else section,
                size,
            )
            for name, binding, kind, section, size in DEFAULT_SYMBOLS
        )
        result = self.run_checker(
            self.object_file(build_elf(moved)), self.expected_file()
        )
        self.assertEqual(result.returncode, 1)

    def test_a_local_helper_renamed_by_a_move_still_passes(self) -> None:
        renamed = tuple(
            ("exec_fill_lineage", *rest) if name == "fill_lineage" else (name, *rest)
            for name, *rest in DEFAULT_SYMBOLS
        )
        result = self.run_checker(
            self.object_file(build_elf(renamed)), self.expected_file()
        )
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_sizes_prints_each_programs_instruction_count(self) -> None:
        result = self.run_checker("--sizes", self.object_file())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.split(),
            ["40", "tracepoint/sched/sched_process_exec", "sched_process_exec"],
        )

    def test_a_file_that_is_not_elf_exits_2(self) -> None:
        result = self.run_checker(
            self.object_file(b"MZ" + b"\0" * 100), self.expected_file()
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("not an ELF file", result.stderr)

    def test_a_truncated_elf_exits_2_not_a_traceback(self) -> None:
        result = self.run_checker(
            self.object_file(build_elf()[:80]), self.expected_file()
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)

    def test_the_expected_list_is_required_without_sizes(self) -> None:
        result = self.run_checker(self.object_file())
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
