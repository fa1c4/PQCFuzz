#!/usr/bin/env python3
"""Patch vulnerable liboqs 0.14.0 ML-DSA empty-context copy layouts.

The no-context public API enters the copied ML-DSA implementation with
``ctx == NULL`` and ``ctxlen == 0``.  Calling memcpy with that pointer is
undefined behaviour even when the requested length is zero.  This helper
guards each affected ``memcpy`` in the checked-out liboqs source and records
exactly what it changed so the evaluation remains auditable.  Recent 0.14.0
sources use a bounded copy loop instead; that layout is already safe when
``ctxlen == 0`` and must remain untouched.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


PATCH_ID = "liboqs-0.14.0-mldsa-empty-context-v2"
SOURCE_PATTERN = "pqcrystals-dilithium-standard_ml-dsa-*_{implementation}/sign.c"
OLD = "  memcpy(&pre[2], ctx, ctxlen);"
NEW = "  if (ctxlen > 0) {\n    memcpy(&pre[2], ctx, ctxlen);\n  }"
IMPLEMENTATIONS = ("ref", "avx2")
EXPECTED_FILES = 6
EXPECTED_COPY_SITES = 12
SAFE_LOOP = re.compile(
    r"for\s*\(\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)*i\s*=\s*0\s*;\s*i\s*<\s*ctxlen\s*;\s*(?:\+\+i|i\+\+)\s*\)\s*"
    r"(?:\{\s*)?pre\s*\[\s*2\s*\+\s*i\s*\]\s*=\s*ctx\s*\[\s*i\s*\]\s*;\s*(?:\}\s*)?"
)


def source_files(source_root: Path) -> list[Path]:
    paths: list[Path] = []
    for implementation in IMPLEMENTATIONS:
        paths.extend((source_root / "src" / "sig" / "ml_dsa").glob(SOURCE_PATTERN.format(implementation=implementation)))
    return sorted(paths)


def apply_patch(source_root: Path) -> dict[str, object]:
    paths = source_files(source_root)
    if len(paths) != EXPECTED_FILES:
        raise RuntimeError(f"expected {EXPECTED_FILES} ML-DSA sign.c files, found {len(paths)}")

    patched: list[dict[str, object]] = []
    already_patched: list[str] = []
    already_safe: list[str] = []
    replacements = 0
    for path in paths:
        original = path.read_text(encoding="utf-8")
        occurrences = len(re.findall(r"(?m)^  memcpy\(&pre\[2\], ctx, ctxlen\);$", original))
        if occurrences == 0:
            if original.count(NEW) == 2:
                already_patched.append(str(path))
                continue
            if len(SAFE_LOOP.findall(original)) == 2:
                already_safe.append(str(path))
                continue
            raise RuntimeError(f"unexpected empty-context copy layout: {path}")
        if occurrences != 2:
            raise RuntimeError(f"expected two empty-context copies in {path}, found {occurrences}")
        patched_source, substitutions = re.subn(
            r"(?m)^  memcpy\(&pre\[2\], ctx, ctxlen\);$", NEW, original
        )
        if substitutions != occurrences:
            raise RuntimeError(f"failed to replace all empty-context copies in {path}")
        path.write_text(patched_source, encoding="utf-8")
        replacements += occurrences
        patched.append({"path": str(path), "replacements": occurrences})

    accounted_for = len(patched) + len(already_patched) + len(already_safe)
    if accounted_for != EXPECTED_FILES:
        raise RuntimeError("partial ML-DSA empty-context patch state")

    if patched:
        state = "applied"
    elif already_safe and not already_patched:
        state = "not-required"
    elif already_patched and not already_safe:
        state = "already-applied"
    else:
        state = "already-safe"

    return {
        "patch_id": PATCH_ID,
        "source_root": str(source_root),
        "expected_files": EXPECTED_FILES,
        "expected_copy_sites": EXPECTED_COPY_SITES,
        "replacements": replacements,
        "patched": patched,
        "already_patched": already_patched,
        "already_safe": already_safe,
        "state": state,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    manifest = apply_patch(args.source_root)
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(args.manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
