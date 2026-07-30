#!/usr/bin/env python3
"""Write a non-destructive migration manifest for legacy PQCFuzz findings."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any


CURRENT_SEMANTICS_VERSION = 4


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def iter_findings(root: Path) -> list[Path]:
    if root.is_file():
        return [root] if root.name == "finding.json" else []
    findings: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in {".git", "__pycache__", "build", "corpus"}]
        if "finding.json" in filenames:
            findings.append(Path(dirpath) / "finding.json")
    return sorted(findings)


def migration_entries(roots: list[Path]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    seen: set[Path] = set()
    for root in roots:
        for finding_path in iter_findings(root):
            resolved = finding_path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            finding = load_json(finding_path)
            semantics = finding.get("oracle_semantics_version")
            if semantics == CURRENT_SEMANTICS_VERSION:
                continue
            entries.append(
                {
                    "finding_path": str(finding_path),
                    "sha256": sha256_file(finding_path),
                    "oracle_semantics_version": semantics,
                    "legacy": True,
                    "validated": False,
                    "invalidation_reason": "legacy_semantics_requires_v4_replay",
                }
            )
    return entries


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roots", nargs="+")
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = {
        "version": 1,
        "oracle_semantics_version": CURRENT_SEMANTICS_VERSION,
        "entries": migration_entries([Path(root) for root in args.roots]),
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
