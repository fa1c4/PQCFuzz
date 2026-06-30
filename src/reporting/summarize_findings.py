#!/usr/bin/env python3
"""Summarize PQCFuzz finding artifacts into stable rows."""

from __future__ import annotations

import argparse
import json
import os
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any


REPORT_COLUMNS = [
    "version",
    "algorithm",
    "primitive",
    "oracle_suite",
    "relation_mode",
    "oracle_id",
    "field",
    "expected_relation",
    "observed_relation",
    "finding_class",
    "finding_subclass",
    "baseline_status",
    "mutated_status",
    "baseline_accepted",
    "mutated_accepted",
    "crash_signal",
    "timeout_seconds",
    "artifact_path",
    "replay_command",
]

SUMMARY_COLUMNS = [
    "count",
    "summary_mode",
    "group_key",
    "version",
    "algorithm",
    "primitive",
    "oracle_suite",
    "relation_mode",
    "oracle_id",
    "field",
    "expected_relation",
    "observed_relation",
    "finding_class",
    "finding_subclass",
    "baseline_status",
    "mutated_status",
    "baseline_accepted",
    "mutated_accepted",
    "crash_signal",
    "timeout_seconds",
    "exemplar_artifact_path",
    "exemplar_replay_command",
]

SUMMARY_KEY_COLUMNS = [
    "version",
    "algorithm",
    "primitive",
    "oracle_suite",
    "relation_mode",
    "oracle_id",
    "field",
    "expected_relation",
    "observed_relation",
    "finding_class",
    "finding_subclass",
]

PRUNED_DIR_NAMES = {
    ".git",
    "__pycache__",
    "build",
    "corpus",
    "crashes",
    "docker",
    "launchers",
    "logs",
    "poc",
    "runs",
    "status",
}

VERSION_RE = re.compile(r"liboqs[-_](\d+\.\d+\.\d+)")
ARTIFACT_NAME_RE = re.compile(r"^(?P<class>.+)_[0-9a-fA-F]{16}$")


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def primitive_for_algorithm(algorithm: str) -> str:
    if "KEM" in algorithm or "Kyber" in algorithm:
        return "kem"
    if "DSA" in algorithm or "Dilithium" in algorithm or "SPHINCS" in algorithm:
        return "sig"
    return ""


def primitive_from_path(path: Path) -> str:
    for part in reversed(path.parts):
        if part in {"kem", "sig"}:
            return part
    return ""


def version_from_text(value: str) -> str:
    match = VERSION_RE.search(value)
    return match.group(1) if match else ""


def version_from_path(path: Path) -> str:
    for part in path.parts:
        if part.startswith("liboqs-"):
            return part.removeprefix("liboqs-")
    return version_from_text(str(path))


def version_from_finding(finding: dict[str, Any], path: Path, trace: dict[str, Any] | None = None) -> str:
    for key in ("version_label", "target_version", "liboqs_version"):
        value = str(finding.get(key) or "")
        if value:
            return value
    for key in ("job_id", "pair_id"):
        value = version_from_text(str(finding.get(key) or ""))
        if value:
            return value
    if trace:
        for key in ("liboqs_version", "target_version"):
            value = str(trace.get(key) or "")
            if value:
                return value
        for key in ("job_id", "pair_id"):
            value = version_from_text(str(trace.get(key) or ""))
            if value:
                return value
    return version_from_path(path)


def first_finding(trace: dict[str, Any]) -> dict[str, Any]:
    findings = trace.get("findings")
    if isinstance(findings, list) and findings:
        first = findings[0]
        if isinstance(first, dict):
            return first
    return {}


def candidate_result_roots(root: Path) -> list[Path]:
    if not root.exists() or root.is_file():
        return []
    candidates: list[Path] = []
    if root.name == "results":
        candidates.append(root)
    for child in (root / "results", root / "workspace" / "results"):
        if child.is_dir():
            candidates.append(child)
    campaign_root = root / "campaigns"
    if campaign_root.is_dir():
        for child in os.scandir(campaign_root):
            if not child.is_dir():
                continue
            result_root = Path(child.path) / "workspace" / "results"
            if result_root.is_dir():
                candidates.append(result_root)
    return candidates


def unique_paths(paths: list[Path]) -> list[Path]:
    unique: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = os.path.abspath(os.fspath(path))
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def iter_result_finding_files(result_root: Path) -> Iterator[Path]:
    """Yield finding files from the standard results/{kem,sig}/* layout."""
    yielded = False
    for primitive in ("kem", "sig"):
        primitive_root = result_root / primitive
        if not primitive_root.is_dir():
            continue
        with os.scandir(primitive_root) as entries:
            for entry in entries:
                if not entry.is_dir():
                    continue
                finding_path = Path(entry.path) / "finding.json"
                if finding_path.is_file():
                    yielded = True
                    yield finding_path
    if yielded:
        return
    yield from walk_finding_files(result_root)


def iter_result_artifact_dirs(result_root: Path) -> Iterator[Path]:
    for primitive in ("kem", "sig"):
        primitive_root = result_root / primitive
        if not primitive_root.is_dir():
            continue
        with os.scandir(primitive_root) as entries:
            for entry in entries:
                if entry.is_dir():
                    yield Path(entry.path)


def walk_finding_files(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in PRUNED_DIR_NAMES]
        if "finding.json" in filenames:
            yield Path(dirpath) / "finding.json"


def finding_class_from_artifact_name(name: str) -> str:
    match = ARTIFACT_NAME_RE.match(name)
    if match:
        return match.group("class")
    return name.split("_", 1)[0] if "_" in name else name


def iter_finding_artifact_dirs(roots: list[Path]) -> Iterator[Path]:
    seen: set[str] = set()
    for root in roots:
        result_roots = unique_paths(candidate_result_roots(root))
        if not result_roots and root.exists() and root.is_dir():
            result_roots = [root]
        for result_root in result_roots:
            for artifact_dir in iter_result_artifact_dirs(result_root):
                key = os.path.abspath(os.fspath(artifact_dir))
                if key in seen:
                    continue
                seen.add(key)
                yield artifact_dir


def iter_finding_files(roots: list[Path]) -> Iterator[Path]:
    seen: set[str] = set()
    for root in roots:
        if root.is_file():
            candidates: Iterator[Path] = iter([root]) if root.name == "finding.json" else iter(())
        else:
            result_roots = unique_paths(candidate_result_roots(root))
            if result_roots:
                def result_candidates() -> Iterator[Path]:
                    for result_root in result_roots:
                        yield from iter_result_finding_files(result_root)

                candidates = result_candidates()
            else:
                candidates = walk_finding_files(root) if root.exists() else iter(())
        for path in candidates:
            key = os.path.abspath(os.fspath(path))
            if key in seen:
                continue
            seen.add(key)
            yield path


def find_finding_files(root: Path) -> list[Path]:
    return list(iter_finding_files([root]))


def artifact_dir_for_finding(finding: dict[str, Any], path: Path) -> Path:
    raw = str(finding.get("artifact_dir") or "")
    if not raw:
        return path.parent
    return Path(raw)


def trace_path_for_finding(finding: dict[str, Any], path: Path, artifact_dir: Path) -> Path:
    raw = str(finding.get("trace_path") or "")
    if raw:
        trace_path = Path(raw)
        if trace_path.is_absolute() or trace_path.exists():
            return trace_path
        artifact_trace = artifact_dir / trace_path.name
        if artifact_trace.exists():
            return artifact_trace
    return artifact_dir / "oracle_trace.json"


def base_row_from_finding(path: Path, finding: dict[str, Any]) -> dict[str, str]:
    artifact_dir = artifact_dir_for_finding(finding, path)
    algorithm = str(finding.get("algorithm") or "")
    primitive = str(finding.get("primitive") or primitive_from_path(path) or primitive_for_algorithm(algorithm))
    row = {
        "version": version_from_finding(finding, path),
        "algorithm": algorithm,
        "primitive": primitive,
        "oracle_suite": str(finding.get("oracle_suite") or ""),
        "relation_mode": str(finding.get("relation_mode") or ""),
        "oracle_id": str(finding.get("oracle_id") or ""),
        "field": "",
        "expected_relation": "",
        "observed_relation": "",
        "finding_class": str(finding.get("finding_class") or ""),
        "finding_subclass": str(finding.get("finding_subclass") or ""),
        "baseline_status": "",
        "mutated_status": "",
        "baseline_accepted": "",
        "mutated_accepted": "",
        "crash_signal": "",
        "timeout_seconds": "",
        "artifact_path": str(artifact_dir),
        "replay_command": str(finding.get("replay_command") or ""),
    }
    return {column: row.get(column, "") for column in REPORT_COLUMNS}


def augment_row_with_trace(row: dict[str, str], path: Path, finding: dict[str, Any]) -> dict[str, str]:
    artifact_dir = artifact_dir_for_finding(finding, path)
    trace = load_json(trace_path_for_finding(finding, path, artifact_dir))
    trace_finding = first_finding(trace)
    baseline = trace.get("baseline") if isinstance(trace.get("baseline"), dict) else {}
    mutated = trace.get("mutated") if isinstance(trace.get("mutated"), dict) else {}
    row = dict(row)
    row["version"] = row.get("version") or version_from_finding(finding, path, trace)
    row["algorithm"] = row.get("algorithm") or str(trace.get("algorithm") or "")
    row["primitive"] = row.get("primitive") or primitive_for_algorithm(row.get("algorithm", ""))
    row["oracle_suite"] = row.get("oracle_suite") or str(trace.get("oracle_suite") or "")
    row["relation_mode"] = row.get("relation_mode") or str(trace.get("relation_mode") or "")
    row["oracle_id"] = row.get("oracle_id") or str(trace.get("oracle_id") or "")
    row["field"] = str(trace.get("field") or trace.get("mutation_target") or "")
    row["expected_relation"] = str(trace.get("expected_relation") or "")
    row["observed_relation"] = str(trace.get("observed_relation") or "")
    row["finding_class"] = row.get("finding_class") or str(
        trace.get("finding_class") or trace_finding.get("class") or ""
    )
    row["finding_subclass"] = row.get("finding_subclass") or str(
        trace.get("finding_subclass") or trace_finding.get("subclass") or ""
    )
    row["baseline_status"] = str(baseline.get("status") or "")
    row["mutated_status"] = str(mutated.get("status") or "")
    row["baseline_accepted"] = "" if "accepted" not in baseline else str(bool(baseline.get("accepted"))).lower()
    row["mutated_accepted"] = "" if "accepted" not in mutated else str(bool(mutated.get("accepted"))).lower()
    row["crash_signal"] = str(trace.get("crash_signal") or "")
    row["timeout_seconds"] = str(trace.get("timeout_seconds") or "")
    return {column: row.get(column, "") for column in REPORT_COLUMNS}


def row_from_finding(path: Path, load_trace: bool = True) -> dict[str, str]:
    finding = load_json(path)
    row = base_row_from_finding(path, finding)
    if load_trace:
        row = augment_row_with_trace(row, path, finding)
    return row


def iter_finding_rows(roots: list[Path], load_traces: bool = True) -> Iterator[dict[str, str]]:
    for finding_path in iter_finding_files(roots):
        yield row_from_finding(finding_path, load_trace=load_traces)


def summarize_roots(roots: list[Path]) -> list[dict[str, str]]:
    return list(iter_finding_rows(roots, load_traces=True))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roots", nargs="+", help="artifact roots to scan")
    parser.add_argument(
        "--no-traces",
        action="store_true",
        help="summarize from finding.json only; faster but omits trace-only columns",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rows = list(iter_finding_rows([Path(root) for root in args.roots], load_traces=not args.no_traces))
    print(json.dumps(rows, indent=2) + "\n", end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
