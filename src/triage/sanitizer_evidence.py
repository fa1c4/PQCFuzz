#!/usr/bin/env python3
"""Normalize sanitizer reports into stable PQCFuzz evidence fingerprints."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


FINGERPRINT_VERSION = "sanitizer-fingerprint-v1"
ASAN_CLASS = re.compile(r"(?:ERROR|SUMMARY): AddressSanitizer:\s+([A-Za-z0-9_-]+)")
UBSAN_CLASS = re.compile(r"runtime error:\s+(.+)$")
FRAME = re.compile(
    r"#\d+\s+(?:0x(?:[0-9a-fA-F]+|ADDR)\s+)?(?:in\s+)?(?P<function>[A-Za-z_][A-Za-z0-9_:~<>., *&-]*)\s+"
    r"(?P<file>(?:/[^\s:]+|[A-Za-z]:[^\s:]+))(?::\d+)?(?::\d+)?"
)
PID = re.compile(r"==\d+==")
ADDRESS = re.compile(r"0x[0-9a-fA-F]+")
TMP_PREFIX = re.compile(r"/(?:tmp|var/tmp|private/tmp)/[^\s:]*/")


def normalize_text(report: str) -> str:
    text = PID.sub("==PID==", report)
    text = ADDRESS.sub("0xADDR", text)
    text = TMP_PREFIX.sub("/BUILD/", text)
    return text


def stable_file(path: str) -> str:
    parts = [part for part in Path(path).parts if part not in {"/", ""}]
    return "/".join(parts[-2:]) if len(parts) >= 2 else (parts[-1] if parts else "")


def report_class(report: str) -> tuple[str, str]:
    if "AddressSanitizer" in report:
        match = ASAN_CLASS.search(report)
        return "address", match.group(1) if match else "address-sanitizer"
    if "UndefinedBehaviorSanitizer" in report or "runtime error:" in report:
        match = UBSAN_CLASS.search(report)
        subtype = " ".join(match.group(1).split()) if match else "undefined-behavior"
        return "undefined", subtype
    if "MemorySanitizer" in report:
        return "memory", "memory-sanitizer"
    return "process", "unknown"


def stable_frames(report: str) -> list[dict[str, str]]:
    frames: list[dict[str, str]] = []
    for line in normalize_text(report).splitlines():
        match = FRAME.search(line)
        if not match:
            continue
        function = " ".join(match.group("function").split())
        frames.append({"function": function, "file": stable_file(match.group("file"))})
        if len(frames) == 5:
            break
    return frames


def fingerprint_payload(report: str, provenance: dict[str, str] | None = None) -> dict[str, Any]:
    sanitizer, subtype = report_class(report)
    payload: dict[str, Any] = {
        "fingerprint_version": FINGERPRINT_VERSION,
        "sanitizer": sanitizer,
        "subtype": subtype,
        "frames": stable_frames(report),
    }
    if provenance:
        payload["provenance"] = {key: str(provenance.get(key, "")) for key in sorted(provenance)}
    material = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload["fingerprint"] = "sha256:" + hashlib.sha256(material).hexdigest()
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", help="sanitizer stderr/report file")
    parser.add_argument("--target-version", default="")
    parser.add_argument("--algorithm", default="")
    parser.add_argument("--oracle-id", default="")
    parser.add_argument("--backend", default="")
    parser.add_argument("--implementation-id", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    provenance = {
        "target_version": args.target_version,
        "algorithm": args.algorithm,
        "oracle_id": args.oracle_id,
        "backend": args.backend,
        "implementation_id": args.implementation_id,
    }
    print(json.dumps(fingerprint_payload(Path(args.report).read_text(encoding="utf-8", errors="replace"), provenance), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
