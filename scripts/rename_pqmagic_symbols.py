#!/usr/bin/env python3
"""Rename all defined global symbols in a static archive with a prefix.

PQMagic builds one static library per hash variant (SM3 / SHAKE) and both
variants export identical symbol names.  PQCFuzz differential binaries link
both variants at once, so the SHAKE archive must be symbol-renamed.

The input archive contains duplicate member names (one set of objects per
algorithm mode) which plain `ar x` cannot extract unambiguously, so this
script parses the ar container itself and renames every member with
`objcopy --redefine-syms`.

Usage:
    python3 scripts/rename_pqmagic_symbols.py <input.a> <prefix> <output.a>
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path


def read_members(path: bytes):
    members = []
    strtab = b""
    with open(path, "rb") as fh:
        magic = fh.read(8)
        if magic != b"!<arch>\n":
            raise ValueError(f"not an ar archive: {magic!r}")
        while True:
            hdr = fh.read(60)
            if len(hdr) < 60:
                break
            if hdr[58:60] != b"`\n":
                raise ValueError("corrupt ar member header")
            raw_name = hdr[:16]
            size_field = hdr[48:58].rstrip()
            size = int(size_field or b"0")
            data = fh.read(size)
            if size % 2:
                fh.read(1)
            stripped = raw_name.rstrip()
            if stripped == b"/":
                continue  # symbol table
            if stripped in (b"", b"//"):
                # BSD-style / GNU long-name string table
                strtab = data
                continue
            if stripped.startswith(b"/"):
                # GNU extended name: "/<offset>" into the string table
                try:
                    offset = int(stripped[1:] or b"0")
                except ValueError:
                    raise
                if offset < len(strtab):
                    end = strtab.index(b"/\n", offset)
                    stripped = strtab[offset:end]
            name = stripped.rstrip(b"/")
            members.append((name.decode("latin1", "replace"), data))
    return members


def collect_map(members, prefix: bytes) -> dict[bytes, bytes]:
    names: set[bytes] = set()
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        for idx, (_, data) in enumerate(members):
            obj = tmp_path / f"m{idx}.o"
            obj.write_bytes(data)
            out = subprocess.run(
                ["nm", "--defined-only", str(obj)],
                capture_output=True, text=True,
            ).stdout
            for line in out.splitlines():
                parts = line.split()
                # Include lowercase (local) definitions as well: clang's
                # fuzzer-no-link build wraps every function in a COMDAT group
                # whose signature is the (possibly local) function symbol or
                # its NOTYPE $hash alias.  Renaming locals changes those group
                # signatures so the two hash-variant archives no longer
                # deduplicate each other's identical code sections.
                if len(parts) >= 3 and parts[1] in "TDBRWVtdbrwv":
                    names.add(parts[2].encode())
                elif len(parts) >= 3 and parts[1] == "n" and not parts[2].startswith("."):
                    names.add(parts[2].encode())
    keep = {b"randombytes"}  # resolved by the PQCFuzz harness RNG override
    return {
        name: prefix + name
        for name in names
        if not name.startswith(prefix) and name not in keep
    }


def rename_member(obj_path: Path, mapping: dict[bytes, bytes]):
    if not mapping:
        return
    map_path = obj_path.with_suffix(".map")
    with open(map_path, "wb") as fh:
        for old, new in sorted(mapping.items()):
            fh.write(old + b" " + new + b"\n")
    subprocess.run(
        ["objcopy", "--redefine-syms=" + str(map_path), str(obj_path)],
        check=True, capture_output=True,
    )
    map_path.unlink()


def main() -> int:
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} <input.a> <prefix> <output.a>", file=sys.stderr)
        return 2
    archive, prefix, out_path = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
    if not archive.is_file():
        print(f"error: archive not found: {archive}", file=sys.stderr)
        return 1

    members = read_members(os.fsencode(archive))
    mapping = collect_map(members, prefix.encode())
    print(f"rename map has {len(mapping)} symbols", file=sys.stderr)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        names = []
        for idx, (_, data) in enumerate(members):
            obj = tmp_path / f"obj_{idx}.o"
            obj.write_bytes(data)
            rename_member(obj, mapping)
            names.append(obj.name)
        subprocess.run(
            ["ar", "rcs", str(out_path), *names],
            cwd=tmp, check=True,
        )
    print(f"renamed archive written to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
