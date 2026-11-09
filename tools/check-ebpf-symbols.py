#!/usr/bin/env python3
"""Diff the program and map names of the built eBPF object against a checked-in list.

The userspace loader finds every probe and map by name (`bpf.program_mut("...")`,
`bpf.map_mut("...")`), so a rename, a dropped `#[no_mangle]` or a program moved to
another section only fails when the agent loads the probes on a kernel. This reads
the ELF symbol table with the standard library and makes such a change fail the build
instead: AS-003's pure moves must leave the list unchanged.

    python3 tools/check-ebpf-symbols.py OBJECT crates/sensors/linux/ebpf/symbols.txt
    python3 tools/check-ebpf-symbols.py --write OBJECT crates/sensors/linux/ebpf/symbols.txt
    python3 tools/check-ebpf-symbols.py --sizes OBJECT

One line per global symbol: `program <section> <name>` for a function in an executable
section other than `.text`, `map <section> <name>` for an object in `maps` or `.maps`.
Local symbols (inlined helpers, `.text` subprograms) are left out: moving code between
modules may rename them without changing what the loader sees.

`--sizes` prints each program's instruction count instead (`st_size / 8`), to compare
before and after a change; it is not part of the checked-in list, so ordinary probe
changes do not have to regenerate it.

Exits 0 when the lists match, 1 when they differ (with a diff), 2 on a file that is not
a 64-bit little-endian ELF.
"""

from __future__ import annotations

import argparse
import difflib
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

SHF_EXECINSTR = 0x4
SHT_SYMTAB = 2
STB_GLOBAL = 1
STT_OBJECT = 1
STT_FUNC = 2
SHN_LORESERVE = 0xFF00
BPF_INSN_BYTES = 8
MAP_SECTIONS = ("maps", ".maps")


@dataclass(frozen=True)
class Section:
    name: str
    kind: int
    flags: int
    offset: int
    size: int
    link: int
    entry_size: int


@dataclass(frozen=True)
class Symbol:
    name: str
    kind: int
    binding: int
    section: int
    size: int


def read_cstr(data: bytes, offset: int) -> str:
    end = data.index(b"\0", offset)
    return data[offset:end].decode("utf-8", errors="replace")


def sections(data: bytes) -> list[Section]:
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    if data[4] != 2 or data[5] != 1:
        raise ValueError("not a 64-bit little-endian ELF file")
    sh_offset = struct.unpack_from("<Q", data, 0x28)[0]
    sh_entry_size, sh_count, sh_names_index = struct.unpack_from("<HHH", data, 0x3A)
    raw = [
        struct.unpack_from("<IIQQQQIIQQ", data, sh_offset + i * sh_entry_size)
        for i in range(sh_count)
    ]
    names_offset = raw[sh_names_index][4]
    return [
        Section(
            read_cstr(data, names_offset + name),
            kind,
            flags,
            offset,
            size,
            link,
            entry_size,
        )
        for name, kind, flags, _addr, offset, size, link, _info, _align, entry_size in raw
    ]


def symbols(data: bytes, all_sections: list[Section]) -> list[Symbol]:
    table = next((s for s in all_sections if s.kind == SHT_SYMTAB), None)
    if table is None:
        raise ValueError("no symbol table")
    names_offset = all_sections[table.link].offset
    found = []
    for offset in range(table.offset, table.offset + table.size, table.entry_size):
        name, info, _other, section, _value, size = struct.unpack_from(
            "<IBBHQQ", data, offset
        )
        found.append(
            Symbol(
                read_cstr(data, names_offset + name),
                info & 0xF,
                info >> 4,
                section,
                size,
            )
        )
    return found


def loader_symbols(path: Path) -> list[tuple[str, str, str, int]]:
    """(kind, section, name, instruction count) for each program and map the loader can name.

    A truncated or malformed file raises `ValueError`, so the caller reports it with
    exit code 2 rather than a traceback.
    """
    data = path.read_bytes()
    try:
        all_sections = sections(data)
        listed = []
        for symbol in symbols(data, all_sections):
            if (
                symbol.binding != STB_GLOBAL
                or symbol.section == 0
                or symbol.section >= SHN_LORESERVE
            ):
                continue
            section = all_sections[symbol.section]
            if (
                symbol.kind == STT_FUNC
                and section.flags & SHF_EXECINSTR
                and section.name != ".text"
            ):
                listed.append(
                    (
                        "program",
                        section.name,
                        symbol.name,
                        symbol.size // BPF_INSN_BYTES,
                    )
                )
            elif symbol.kind == STT_OBJECT and section.name in MAP_SECTIONS:
                listed.append(("map", section.name, symbol.name, 0))
        return sorted(listed)
    except (struct.error, IndexError) as error:
        raise ValueError(f"truncated or malformed ELF file ({error})") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "object", type=Path, help="the built eBPF object (sensor-linux-ebpf)"
    )
    parser.add_argument(
        "expected", type=Path, nargs="?", help="the checked-in list to compare with"
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--write", action="store_true", help="rewrite the expected list from the object"
    )
    mode.add_argument(
        "--sizes", action="store_true", help="print each program's instruction count"
    )
    args = parser.parse_args()
    if not args.sizes and args.expected is None:
        parser.error("the expected list is required unless --sizes is given")

    try:
        listed = loader_symbols(args.object)
    except (OSError, ValueError) as error:
        print(f"{args.object}: {error}", file=sys.stderr)
        return 2
    if args.sizes:
        for kind, section, name, count in listed:
            if kind == "program":
                print(f"{count:6} {section} {name}")
        return 0

    actual = [f"{kind} {section} {name}\n" for kind, section, name, _count in listed]
    if args.write:
        args.expected.write_text("".join(actual), encoding="utf-8", newline="\n")
        print(f"wrote {len(actual)} names to {args.expected}")
        return 0
    expected = args.expected.read_text(encoding="utf-8").splitlines(keepends=True)
    if actual == expected:
        print(f"{len(actual)} program and map names match {args.expected}")
        return 0
    sys.stdout.writelines(
        difflib.unified_diff(expected, actual, str(args.expected), str(args.object))
    )
    print(
        "\nThe loader looks these up by name. If the change is intended, regenerate the list with"
        " --write and update the loader in the same change.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
