#!/usr/bin/env python3
"""List the dynamic libraries a macOS executable loads, and fail on the ones a static ONNX
Runtime build must not need (#338, ADR-0002).

`otool -L` exists only on a Mac with the command line tools; this reads the Mach-O load
commands directly with the standard library (thin and universal binaries, 32 and 64 bit,
little-endian), so the same check runs on the runner that built the binary and on a
developer machine without Xcode.

    python3 tools/check-macho-imports.py target/release/agent
    python3 tools/check-macho-imports.py --allow /opt/homebrew/lib/ -- agent

Patterns with `*` or `?` are expanded by the script. `--allow` adds a path prefix to the
default list and can be repeated; put `--` before the files when it is the last option.

A library is accepted only if its install name starts with `/usr/lib/` or
`/System/Library/` (the OS: libSystem, libc++, the frameworks). Anything else fails, and
that is deliberate: an `@rpath/libonnxruntime.dylib` is the shared build this check exists
to catch, but so is any other dylib that would have to be shipped, signed and versioned
next to the agent (ADR-0002: one binary, no library to hijack). A name containing
`onnxruntime` fails even under an allowed prefix.

Exits 1 if any slice of any file loads a library that is not accepted. Exits 2 on a file
that is not a Mach-O executable or is truncated or malformed, and on a pattern that
matches nothing (a check that looked at nothing must not pass).
"""

import argparse
import glob
import struct
import sys

DEFAULT_ALLOWED_PREFIXES = ("/usr/lib/", "/System/Library/")
FORBIDDEN_SUBSTRINGS = ("onnxruntime",)

MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF

LC_LOAD_DYLIB = 0xC
LC_LAZY_LOAD_DYLIB = 0x20
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_RPATH = 0x8000001C
LC_REEXPORT_DYLIB = 0x8000001F
LC_LOAD_UPWARD_DYLIB = 0x80000023
DYLIB_COMMANDS = {
    LC_LOAD_DYLIB: "load",
    LC_LAZY_LOAD_DYLIB: "lazy",
    LC_LOAD_WEAK_DYLIB: "weak",
    LC_REEXPORT_DYLIB: "reexport",
    LC_LOAD_UPWARD_DYLIB: "upward",
}

CPU_TYPES = {
    0x00000007: "i386",
    0x01000007: "x86_64",
    0x0000000C: "arm",
    0x0100000C: "arm64",
}

# Mach-O load commands are bounded by the header's own sizes; this guards a hostile
# `ncmds` from looping over a file that is smaller than it claims.
MAX_COMMANDS = 4096


def read_cstr(data: bytes, offset: int, limit: int) -> str:
    end = data.find(b"\0", offset, limit)
    if end == -1:
        raise ValueError("unterminated string in a load command")
    return data[offset:end].decode("utf-8", errors="replace")


class Slice:
    """One architecture of a Mach-O file: its CPU name, loaded libraries and rpaths."""

    def __init__(self, arch: str) -> None:
        self.arch = arch
        self.libraries: list[tuple[str, str]] = []  # (kind, install name)
        self.rpaths: list[str] = []


def parse(data: bytes) -> list[Slice]:
    """The slices of a Mach-O file. `ValueError` for anything that is not one, truncated or
    malformed, so the caller reports it with exit code 2 and not as a traceback."""
    try:
        return _parse(data)
    except struct.error as error:
        raise ValueError(f"truncated or malformed Mach-O file ({error})") from error


def _parse(data: bytes) -> list[Slice]:
    if len(data) < 4:
        raise ValueError("not a Mach-O file (too short)")
    (magic_be,) = struct.unpack_from(">I", data, 0)
    if magic_be in (FAT_MAGIC, FAT_MAGIC_64):
        return _parse_fat(data, wide=magic_be == FAT_MAGIC_64)
    return [_parse_thin(data, 0, len(data))]


def _parse_fat(data: bytes, wide: bool) -> list[Slice]:
    (count,) = struct.unpack_from(">I", data, 4)
    if count == 0 or count > 16:
        raise ValueError(f"not a plausible universal binary ({count} architectures)")
    slices = []
    for index in range(count):
        if wide:
            cpu, _sub, offset, size, _align, _reserved = struct.unpack_from(
                ">iiQQII", data, 8 + 32 * index
            )
        else:
            cpu, _sub, offset, size, _align = struct.unpack_from(">iiIII", data, 8 + 20 * index)
        if offset + size > len(data) or size == 0:
            raise ValueError("a universal-binary slice lies outside the file")
        slices.append(_parse_thin(data, offset, offset + size))
    return slices


def _parse_thin(data: bytes, start: int, end: int) -> Slice:
    (magic,) = struct.unpack_from("<I", data, start)
    if magic == MH_MAGIC_64:
        header_size = 32
    elif magic == MH_MAGIC:
        header_size = 28
    else:
        raise ValueError(
            "not a little-endian Mach-O file (bad magic "
            f"{magic:#010x}; big-endian PowerPC binaries are not supported)"
        )
    cpu, _sub, _filetype, ncmds, sizeofcmds, _flags = struct.unpack_from("<iiIIII", data, start + 4)
    if ncmds > MAX_COMMANDS:
        raise ValueError(f"implausible command count ({ncmds})")
    result = Slice(CPU_TYPES.get(cpu, f"cpu {cpu:#x}"))
    pos = start + header_size
    commands_end = pos + sizeofcmds
    if commands_end > end:
        raise ValueError("load commands run past the end of the file")
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, pos)
        if size < 8 or pos + size > commands_end:
            raise ValueError("a load command runs past the load-command area")
        if cmd in DYLIB_COMMANDS:
            (name_offset,) = struct.unpack_from("<I", data, pos + 8)
            if not 8 <= name_offset < size:
                raise ValueError("a dylib name offset lies outside its load command")
            result.libraries.append(
                (DYLIB_COMMANDS[cmd], read_cstr(data, pos + name_offset, pos + size))
            )
        elif cmd == LC_RPATH:
            (path_offset,) = struct.unpack_from("<I", data, pos + 8)
            if not 8 <= path_offset < size:
                raise ValueError("an rpath offset lies outside its load command")
            result.rpaths.append(read_cstr(data, pos + path_offset, pos + size))
        pos += size
    return result


def judge(name: str, allowed: tuple[str, ...]) -> str | None:
    """Why `name` is not acceptable, or None."""
    lowered = name.lower()
    for forbidden in FORBIDDEN_SUBSTRINGS:
        if forbidden in lowered:
            return f"FORBIDDEN (names {forbidden})"
    if not name.startswith(allowed):
        return "NOT A SYSTEM LIBRARY"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+")
    parser.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="PREFIX",
        help="an extra install-name prefix to accept, added to the default list "
        f"({', '.join(DEFAULT_ALLOWED_PREFIXES)}); repeatable",
    )
    args = parser.parse_args()
    allowed = DEFAULT_ALLOWED_PREFIXES + tuple(args.allow)
    paths = []
    for pattern in args.files:
        matches = sorted(glob.glob(pattern)) if glob.has_magic(pattern) else [pattern]
        if not matches:
            print(f"{pattern}: no file matches", file=sys.stderr)
            return 2
        paths.extend(matches)
    status = 0
    for path in paths:
        try:
            with open(path, "rb") as f:
                slices = parse(f.read())
        except (OSError, ValueError) as error:
            print(f"{path}: {error}", file=sys.stderr)
            return 2
        print(path)
        for one in slices:
            print(f"  [{one.arch}]")
            for kind, name in sorted(set(one.libraries)):
                verdict = judge(name, allowed)
                suffix = f"  <- {verdict}" if verdict else ""
                print(f"    {kind:<9} {name}{suffix}")
                if verdict:
                    status = 1
            for rpath in sorted(set(one.rpaths)):
                print(f"    rpath     {rpath}")
    return status


if __name__ == "__main__":
    sys.exit(main())
