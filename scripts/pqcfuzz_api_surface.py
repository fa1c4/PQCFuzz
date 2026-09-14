#!/usr/bin/env python3
"""Static API-surface and zeroization inspection (design doc Sections 30.10/49).

Enumerates exported cryptographic symbols from a binary (via nm when available)
and scans source files for zeroization sites.  The report is diagnostic
evidence, not a conformance verdict.

Usage:
    python3 scripts/pqcfuzz_api_surface.py --binary path/to/lib.a [--json]
    python3 scripts/pqcfuzz_api_surface.py --source src/adapters --json
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

SYMBOL_RE = re.compile(r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*_(crypto_|keypair|encaps|decaps|sign|verify)[A-Za-z0-9_]*)$")
EXPORT_RE = re.compile(r"^(?:OQS_|PQCLEAN_|pqmagic_|crypto_)")
ZEROIZATION_RE = re.compile(r"(memset\s*\([^;]*,\s*0\s*,|explicit_bzero|secure_zero|OPENSSL_cleanse|sodium_memzero)")


def scan_binary(path: Path) -> list[str]:
    nm = shutil.which("nm")
    if nm is None or not path.is_file():
        return []
    try:
        completed = subprocess.run(
            [nm, "--defined-only", "-g", str(path)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    symbols: list[str] = []
    for line in completed.stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        name = parts[-1]
        if EXPORT_RE.search(name) or SYMBOL_RE.match(name):
            symbols.append(name)
    return sorted(set(symbols))


def scan_zeroization(root: Path) -> list[dict[str, object]]:
    sites: list[dict[str, object]] = []
    if not root.exists():
        return sites
    files = [root] if root.is_file() else sorted(root.rglob("*.[ch]"))
    for path in files:
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for number, line in enumerate(lines, start=1):
            if ZEROIZATION_RE.search(line):
                sites.append({"file": str(path), "line": number, "text": line.strip()[:160]})
    return sites


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", action="append", default=[])
    parser.add_argument("--source", action="append", default=[])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    report: dict[str, object] = {
        "binaries": args.binary,
        "sources": args.source,
        "exported_symbols": [],
        "zeroization_sites": [],
    }
    for binary in args.binary:
        report["exported_symbols"].extend(scan_binary(Path(binary)))  # type: ignore[attr-defined]
    report["exported_symbols"] = sorted(set(report["exported_symbols"]))  # type: ignore[arg-type]
    for source in args.source:
        report["zeroization_sites"].extend(scan_zeroization(Path(source)))  # type: ignore[attr-defined]

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"exported symbols: {len(report['exported_symbols'])}")
        for symbol in report["exported_symbols"]:
            print(f"  {symbol}")
        print(f"zeroization sites: {len(report['zeroization_sites'])}")
        for site in report["zeroization_sites"]:
            print(f"  {site['file']}:{site['line']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
