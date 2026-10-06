#!/usr/bin/env python3
"""List the DLLs a Windows executable imports, and fail on the ones a static ONNX
Runtime build must not need (#337, ADR-0002).

`dumpbin /dependents` needs a Visual Studio developer prompt; this reads the PE
import tables directly (regular and delay-load) with the standard library, so it
runs anywhere Python does.

    python3 tools/check-pe-imports.py target/release/deps/ml-*.exe
    python3 tools/check-pe-imports.py --forbid directml.dll agent.exe

Exits 1 if any file imports a forbidden DLL (default: onnxruntime.dll, the shared
build; directml.dll and d3d12.dll, the DirectML execution provider the prebuilt
download links and the agent never uses). dxgi.dll is not forbidden: it is an OS
component that onnxruntime's own device discovery imports even in a CPU-only build,
so it stays in a source build too. Exits 2 on a file that is not a 64-bit PE.
"""

import argparse
import struct
import sys

DEFAULT_FORBIDDEN = ("onnxruntime.dll", "directml.dll", "d3d12.dll")


def read_cstr(data: bytes, offset: int) -> str:
    end = data.index(b"\0", offset)
    return data[offset:end].decode("ascii", errors="replace")


def imports(path: str) -> tuple[list[str], list[str]]:
    """(regular imports, delay-load imports) as lower-case DLL names."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:2] != b"MZ":
        raise ValueError("not a PE file (no MZ header)")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe : pe + 4] != b"PE\0\0":
        raise ValueError("not a PE file (no PE signature)")
    n_sections = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    opt = pe + 24
    if struct.unpack_from("<H", data, opt)[0] != 0x20B:
        raise ValueError("not a 64-bit PE (PE32+) file")
    # Data directories start after the 112-byte fixed part of the PE32+ header.
    directories = opt + 112
    sections = []
    table = opt + opt_size
    for i in range(n_sections):
        base = table + 40 * i
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, base + 8)
        sections.append((vaddr, max(vsize, rawsize), rawptr))

    def rva(value: int) -> int:
        for vaddr, size, rawptr in sections:
            if vaddr <= value < vaddr + size:
                return value - vaddr + rawptr
        raise ValueError(f"RVA {value:#x} outside every section")

    def directory(index: int) -> tuple[int, int]:
        return struct.unpack_from("<II", data, directories + 8 * index)

    regular, delayed = [], []
    start, size = directory(1)  # import table
    if start:
        pos = rva(start)
        while True:
            name_rva = struct.unpack_from("<I", data, pos + 12)[0]
            if name_rva == 0:
                break
            regular.append(read_cstr(data, rva(name_rva)).lower())
            pos += 20
    start, size = directory(13)  # delay-load import table
    if start:
        pos = rva(start)
        while True:
            attrs, name_rva = struct.unpack_from("<II", data, pos)
            if name_rva == 0:
                break
            delayed.append(read_cstr(data, rva(name_rva)).lower())
            pos += 32
    return regular, delayed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+")
    parser.add_argument(
        "--forbid", nargs="*", default=list(DEFAULT_FORBIDDEN),
        help="DLL names that must not be imported (default: %(default)s)",
    )
    args = parser.parse_args()
    forbidden = {name.lower() for name in args.forbid}
    status = 0
    for path in args.files:
        try:
            regular, delayed = imports(path)
        except (OSError, ValueError) as error:
            print(f"{path}: {error}", file=sys.stderr)
            return 2
        print(f"{path}")
        for name in sorted(set(regular)):
            print(f"  import      {name}")
        for name in sorted(set(delayed)):
            print(f"  delay-load  {name}")
        bad = sorted((set(regular) | set(delayed)) & forbidden)
        for name in bad:
            print(f"  FORBIDDEN   {name}")
        if bad:
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
