#!/usr/bin/env python3
"""Write PQCFuzz JSON/TSV reports from finding artifacts."""

from __future__ import annotations

import argparse
import csv
import json
import os
from collections import defaultdict
from pathlib import Path
from typing import TextIO

from summarize_findings import (
    REPORT_COLUMNS,
    SUMMARY_COLUMNS,
    SUMMARY_KEY_COLUMNS,
    augment_row_with_trace,
    base_row_from_finding,
    candidate_result_roots,
    finding_class_from_artifact_name,
    iter_finding_artifact_dirs,
    iter_finding_files,
    load_json,
    primitive_from_path,
    semantics_status,
    unique_paths,
    version_from_path,
)


EXEMPLAR_KEY_COLUMNS = [
    "version",
    "oracle_semantics_version",
    "semantics_status",
    "algorithm",
    "primitive",
    "oracle_suite",
    "relation_mode",
    "oracle_id",
    "finding_class",
    "finding_subclass",
]

COUNTER_ROW_COLUMNS = [
    "version",
    "oracle_semantics_version",
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
    "validated",
]


class JsonArrayWriter:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = path.open("w", encoding="utf-8")
        self.first = True
        self.handle.write("[\n")

    def write_row(self, row: dict[str, str]) -> None:
        if not self.first:
            self.handle.write(",\n")
        self.first = False
        self.handle.write(json.dumps(row, sort_keys=True))

    def close(self) -> None:
        self.handle.write("\n]\n")
        self.handle.close()


def normalize_formats(raw: str) -> set[str]:
    formats = {item.strip() for item in raw.split(",") if item.strip()}
    invalid = formats.difference({"json", "tsv"})
    if invalid:
        raise ValueError(f"unsupported report format(s): {', '.join(sorted(invalid))}")
    return formats


def open_tsv(path: Path, columns: list[str]) -> tuple[TextIO, csv.DictWriter]:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("w", encoding="utf-8", newline="")
    writer = csv.DictWriter(handle, delimiter="\t", fieldnames=columns)
    writer.writeheader()
    return handle, writer


def summary_key(row: dict[str, str]) -> tuple[str, ...]:
    return tuple(row.get(column, "") for column in SUMMARY_KEY_COLUMNS)


def exemplar_key(row: dict[str, str]) -> tuple[str, ...]:
    return tuple(row.get(column, "") for column in EXEMPLAR_KEY_COLUMNS)


def summary_from_row(
    row: dict[str, str],
    count: int,
    summary_mode: str = "exact",
    group_key: str = "",
) -> dict[str, str]:
    summary = {column: "" for column in SUMMARY_COLUMNS}
    summary["count"] = str(count)
    summary["summary_mode"] = summary_mode
    summary["group_key"] = group_key
    for column in SUMMARY_KEY_COLUMNS:
        summary[column] = row.get(column, "")
    for column in (
        "baseline_status",
        "mutated_status",
        "baseline_accepted",
        "mutated_accepted",
        "crash_signal",
        "timeout_seconds",
    ):
        summary[column] = row.get(column, "")
    summary["exemplar_artifact_path"] = row.get("artifact_path", "")
    summary["exemplar_replay_command"] = row.get("replay_command", "")
    return summary


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_tsv(path: Path, rows: list[dict[str, str]], columns: list[str]) -> None:
    handle, writer = open_tsv(path, columns)
    try:
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in columns})
    finally:
        handle.close()


def sorted_summary_rows(
    counts: dict[tuple[str, ...], int],
    exemplars: dict[tuple[str, ...], dict[str, str]],
    summary_mode: str = "exact",
) -> list[dict[str, str]]:
    return [
        summary_from_row(exemplars[key], counts[key], summary_mode, "|".join(key))
        for key in sorted(counts)
    ]


def sorted_counter_summary_rows(
    counts: dict[tuple[str, ...], int],
    exemplars: dict[tuple[str, ...], dict[str, str]],
    group_keys: dict[tuple[str, ...], str],
) -> list[dict[str, str]]:
    return [
        summary_from_row(exemplars[key], counts[key], "grouped-counter", group_keys.get(key, "|".join(key)))
        for key in sorted(counts)
    ]


def write_summary_reports(
    summaries: list[dict[str, str]],
    output_root: Path,
    formats: set[str],
) -> None:
    if "json" in formats:
        write_json(output_root / "findings_summary.json", summaries)
    if "tsv" in formats:
        write_tsv(output_root / "findings_summary.tsv", summaries, SUMMARY_COLUMNS)

    by_version: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in summaries:
        by_version[row.get("version", "")].append(row)
    for version, rows in by_version.items():
        if not version:
            continue
        version_root = output_root / version
        if "json" in formats:
            write_json(version_root / "findings_summary.json", rows)
        if "tsv" in formats:
            write_tsv(version_root / "findings_summary.tsv", rows, SUMMARY_COLUMNS)


def fast_row_from_artifact_dir(artifact_dir: Path, trace_mode: str) -> dict[str, str]:
    finding_path = artifact_dir / "finding.json"
    finding = load_json(finding_path)
    if finding:
        row = base_row_from_finding(finding_path, finding)
        if trace_mode in {"exemplar", "all"}:
            row = augment_row_with_trace(row, finding_path, finding)
    else:
        row = {column: "" for column in REPORT_COLUMNS}
        row["artifact_path"] = str(artifact_dir)
        row["version"] = version_from_path(artifact_dir)
        row["primitive"] = primitive_from_path(artifact_dir)
    if not row.get("finding_class"):
        row["finding_class"] = finding_class_from_artifact_name(artifact_dir.name)
    return row


def fast_summary_key(artifact_dir: Path, row: dict[str, str]) -> tuple[str, ...]:
    return (
        row.get("version") or version_from_path(artifact_dir),
        row.get("oracle_semantics_version"),
        row.get("semantics_status"),
        row.get("primitive") or primitive_from_path(artifact_dir),
        row.get("finding_class") or finding_class_from_artifact_name(artifact_dir.name),
    )


def counter_files_for_roots(roots: list[Path]) -> list[Path]:
    files: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        candidates: list[Path] = []
        if root.is_file() and root.name == "finding_counts.tsv":
            candidates.append(root)
        elif root.is_dir():
            result_roots = unique_paths(candidate_result_roots(root))
            if not result_roots and root.name in {"kem", "sig"}:
                result_roots = [root.parent]
            for result_root in result_roots:
                for primitive in ("kem", "sig"):
                    candidates.append(result_root / primitive / "finding_counts.tsv")
                if result_root.name in {"kem", "sig"}:
                    candidates.append(result_root / "finding_counts.tsv")
        for path in candidates:
            if not path.is_file():
                continue
            key = os.path.abspath(os.fspath(path))
            if key in seen:
                continue
            seen.add(key)
            files.append(path)
    return files


def artifact_dir_from_counter(counter_file: Path, row: dict[str, str]) -> Path:
    raw = row.get("exemplar_artifact_path") or row.get("artifact_path") or ""
    if raw:
        path = Path(raw)
        if path.is_absolute() or path.exists():
            return path
        local = counter_file.parent / path
        if local.exists():
            return local
        return path
    finding_id = row.get("finding_id") or ""
    return counter_file.parent / finding_id if finding_id else counter_file.parent


def counter_group_key(counter_file: Path, item: dict[str, str], row: dict[str, str]) -> str:
    group_key = item.get("group_key", "")
    if group_key:
        return group_key
    missing = [column for column in SUMMARY_KEY_COLUMNS if not row.get(column)]
    if missing:
        finding_id = item.get("finding_id") or row.get("artifact_path") or counter_file.name
        return f"malformed-counter:{counter_file}:{finding_id}:missing={','.join(missing)}"
    return "|".join(summary_key(row))


def apply_counter_fields(counter_file: Path, artifact_dir: Path, row: dict[str, str], item: dict[str, str]) -> None:
    for column in COUNTER_ROW_COLUMNS:
        if item.get(column) and not row.get(column):
            row[column] = item[column]
    if not row.get("version"):
        row["version"] = item.get("version") or version_from_path(artifact_dir)
    if not row.get("primitive"):
        row["primitive"] = item.get("primitive") or primitive_from_path(artifact_dir) or primitive_from_path(counter_file.parent)
    if not row.get("finding_class"):
        row["finding_class"] = item.get("finding_class") or finding_class_from_artifact_name(artifact_dir.name) or "malformed_counter"
    if not row.get("finding_subclass") and row.get("finding_class") == "malformed_counter":
        row["finding_subclass"] = "missing_counter_fields"
    row["semantics_status"] = semantics_status(row.get("oracle_semantics_version", ""))


def counter_rows(counter_file: Path, trace_mode: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    with counter_file.open(encoding="utf-8", newline="") as handle:
        for item in csv.DictReader(handle, delimiter="\t"):
            artifact_dir = artifact_dir_from_counter(counter_file, item)
            row = fast_row_from_artifact_dir(artifact_dir, trace_mode)
            apply_counter_fields(counter_file, artifact_dir, row, item)
            finding_path = artifact_dir / "finding.json"
            if finding_path.is_file():
                validation_row = augment_row_with_trace(row, finding_path, load_json(finding_path))
                if validation_row.get("validated") != "true" or validation_row.get("invalidated") == "true":
                    continue
            elif row.get("validated") != "true" or row.get("oracle_semantics_version") != "3":
                continue
            if item.get("exemplar_replay_command"):
                row["replay_command"] = item["exemplar_replay_command"]
            if item.get("exemplar_artifact_path"):
                row["artifact_path"] = item["exemplar_artifact_path"]
            try:
                count = int(item.get("count", "0"))
            except ValueError:
                count = 0
            if count <= 0:
                continue
            rows.append({"row": row, "count": count, "group_key": counter_group_key(counter_file, item, row)})
    return rows


def result_dir_key(path: Path) -> str:
    return os.path.abspath(os.fspath(path))


def write_fast_summary_reports(roots: list[Path], output_root: Path, formats: set[str], trace_mode: str) -> None:
    counts: dict[tuple[str, ...], int] = {}
    exemplars: dict[tuple[str, ...], dict[str, str]] = {}
    group_keys: dict[tuple[str, ...], str] = {}
    counter_keys: set[tuple[str, ...]] = set()
    counter_result_dirs: set[str] = set()

    for counter_file in counter_files_for_roots(roots):
        counter_result_dirs.add(result_dir_key(counter_file.parent))
        for item in counter_rows(counter_file, trace_mode):
            row = item["row"]
            assert isinstance(row, dict)
            key = summary_key(row)
            counter_keys.add(key)
            counts[key] = counts.get(key, 0) + int(item["count"])
            exemplars.setdefault(key, row)
            group_key = str(item.get("group_key") or "")
            if group_key:
                group_keys.setdefault(key, group_key)

    for artifact_dir in iter_finding_artifact_dirs(roots):
        if result_dir_key(artifact_dir.parent) in counter_result_dirs:
            continue
        row = fast_row_from_artifact_dir(artifact_dir, trace_mode)
        if row.get("oracle_semantics_version") != "3":
            continue
        row["version"] = row.get("version") or version_from_path(artifact_dir)
        row["primitive"] = row.get("primitive") or primitive_from_path(artifact_dir)
        row["finding_class"] = row.get("finding_class") or finding_class_from_artifact_name(artifact_dir.name)
        key = fast_summary_key(artifact_dir, row)
        counts[key] = counts.get(key, 0) + 1
        if key not in exemplars:
            exemplars[key] = fast_row_from_artifact_dir(artifact_dir, trace_mode)

    summaries = sorted_counter_summary_rows(
        {key: count for key, count in counts.items() if key in counter_keys},
        {key: row for key, row in exemplars.items() if key in counter_keys},
        group_keys,
    )
    summaries.extend(
        sorted_summary_rows(
            {key: count for key, count in counts.items() if key not in counter_keys},
            {key: row for key, row in exemplars.items() if key not in counter_keys},
            "fast-directory",
        )
    )
    write_summary_reports(summaries, output_root, formats)


def write_reports(
    roots: list[Path],
    output_root: Path,
    formats: set[str],
    trace_mode: str = "exemplar",
    findings_mode: str = "full",
) -> None:
    output_root.mkdir(parents=True, exist_ok=True)
    if findings_mode == "fast-summary":
        write_fast_summary_reports(roots, output_root, formats, trace_mode)
        return

    write_findings = findings_mode == "full"
    findings_json = JsonArrayWriter(output_root / "findings.json") if write_findings and "json" in formats else None
    diagnostics_json = JsonArrayWriter(output_root / "diagnostics.json") if "json" in formats else None
    findings_tsv_handle = None
    findings_tsv_writer = None
    if write_findings and "tsv" in formats:
        findings_tsv_handle, findings_tsv_writer = open_tsv(output_root / "findings.tsv", REPORT_COLUMNS)
    diagnostics_tsv_handle = None
    diagnostics_tsv_writer = None
    if "tsv" in formats:
        diagnostics_tsv_handle, diagnostics_tsv_writer = open_tsv(output_root / "diagnostics.tsv", REPORT_COLUMNS)

    counts: dict[tuple[str, ...], int] = {}
    exemplars: dict[tuple[str, ...], dict[str, str]] = {}

    try:
        for finding_path in iter_finding_files(roots):
            finding = load_json(finding_path)
            row = base_row_from_finding(finding_path, finding)
            # Validation and legacy invalidation are trace-backed properties;
            # load the trace even when the public finding table is exemplar-only.
            trace_row = augment_row_with_trace(row, finding_path, finding)
            row = trace_row if trace_mode == "all" else row
            eligible = trace_row.get("validated") == "true" and trace_row.get("invalidated") != "true"

            if not eligible:
                if diagnostics_json is not None:
                    diagnostics_json.write_row(trace_row)
                if diagnostics_tsv_writer is not None:
                    diagnostics_tsv_writer.writerow({column: trace_row.get(column, "") for column in REPORT_COLUMNS})
                continue

            if findings_json is not None:
                findings_json.write_row(row)
            if findings_tsv_writer is not None:
                findings_tsv_writer.writerow({column: row.get(column, "") for column in REPORT_COLUMNS})

            key_row = row
            key = summary_key(key_row) if trace_mode == "all" else exemplar_key(key_row)
            if key not in counts and trace_mode == "exemplar":
                key_row = augment_row_with_trace(row, finding_path, finding)
            counts[key] = counts.get(key, 0) + 1
            exemplars.setdefault(key, key_row)
    finally:
        if findings_json is not None:
            findings_json.close()
        if findings_tsv_handle is not None:
            findings_tsv_handle.close()
        if diagnostics_json is not None:
            diagnostics_json.close()
        if diagnostics_tsv_handle is not None:
            diagnostics_tsv_handle.close()

    write_summary_reports(sorted_summary_rows(counts, exemplars), output_root, formats)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-root", action="append", required=True, help="artifact root to scan; repeatable")
    parser.add_argument("--output-root", default="workspace/pqcfuzz_eval", help="report output root")
    parser.add_argument("--formats", default="json,tsv", help="comma-separated report formats: json,tsv")
    parser.add_argument(
        "--trace-mode",
        choices=("none", "exemplar", "all"),
        default="exemplar",
        help=(
            "trace loading policy: none reads only finding.json, exemplar reads one oracle_trace.json "
            "per summary bucket, all restores full per-finding trace details"
        ),
    )
    parser.add_argument(
        "--findings-mode",
        choices=("full", "summary-only", "fast-summary"),
        default="full",
        help=(
            "full writes per-finding findings.* files; summary-only exact-counts all finding.json files; "
            "fast-summary counts artifact directories and reads one exemplar per group"
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    formats = normalize_formats(args.formats)
    write_reports(
        [Path(root) for root in args.input_root],
        Path(args.output_root),
        formats,
        args.trace_mode,
        args.findings_mode,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
