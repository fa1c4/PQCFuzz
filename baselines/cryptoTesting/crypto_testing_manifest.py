#!/usr/bin/env python3
"""Write durable cryptoTesting campaign accounting for mounted AFL output.

The cryptoTesting upstream workflow creates one AFL tree per cloned test
directory.  This helper only reads the explicit output root used by the local
runner; it intentionally never falls back to the ephemeral liboqs checkout.
"""

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


FINDING_KINDS = (
    "malleability",
    "mismatch",
    "sanitizer-crash",
    "hang",
    "operation-diagnostic",
)


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path, fallback: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return fallback


def replay_record(output_root: Path, artifact: Path) -> Optional[Dict[str, Any]]:
    path = output_root / "metadata" / "replays" / f"{sha256(artifact)}.json"
    record = read_json(path, None)
    return record if isinstance(record, dict) else None


def write_json(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def property_for(alg_dir: Path, afl_root: Path) -> str:
    try:
        return str(alg_dir.parent.relative_to(afl_root))
    except ValueError:
        return "unknown"


def algorithm_for(alg_dir: Path) -> str:
    try:
        value = (alg_dir / "alg.txt").read_text(encoding="utf-8").strip()
        return value or alg_dir.name
    except OSError:
        return alg_dir.name


def report_records(reports_dir: Path) -> List[Dict[str, Any]]:
    """Read cryptoTesting's authoritative functional classifications.

    AFL aborts when ``Match`` observes an expected relation violation.  Its
    crash directory therefore contains both genuine process failures and
    functional findings; report.py has already disambiguated them in SQLite.
    """

    records: List[Dict[str, Any]] = []
    for database in reports_dir.glob("*.db"):
        try:
            # Ubuntu 18.04's sqlite binding does not accept PathLike values.
            with sqlite3.connect(os.fspath(database)) as connection:
                columns = {row[1] for row in connection.execute("PRAGMA table_info(crashes)")}
                if not {"test", "name"}.issubset(columns):
                    continue
                selected_columns = ["test", "name"]
                for column in ("error", "expected", "gotten"):
                    selected_columns.append(column if column in columns else f"NULL AS {column}")
                query = f"SELECT {', '.join(selected_columns)} FROM crashes"
                for test, name, error, expected, gotten in connection.execute(query):
                    if not isinstance(test, str) or not isinstance(name, str):
                        continue
                    normalized_error = error.strip().lower() if isinstance(error, str) else ""
                    normalized_expected = expected.strip().lower() if isinstance(expected, str) else ""
                    normalized_gotten = gotten.strip().lower() if isinstance(gotten, str) else ""
                    classification: Optional[str] = None
                    if normalized_error:
                        if "hang" in normalized_error:
                            classification = "hang"
                        elif any(marker in normalized_error for marker in (
                            "addresssanitizer", "asan", "sanitizer", "segv",
                            "buffer-overflow", "stack-overflow",
                        )):
                            classification = "sanitizer-crash"
                        else:
                            classification = "operation-diagnostic"
                    elif normalized_expected and normalized_gotten:
                        if normalized_expected == "unequal" and normalized_gotten.startswith("equal"):
                            classification = "malleability"
                        elif normalized_expected == "equal" and normalized_gotten.startswith("unequal"):
                            classification = "mismatch"
                        else:
                            classification = "operation-diagnostic"
                    records.append({
                        "database": database.name,
                        "group": f"{test}|{name}",
                        "test": test,
                        "algorithm": name,
                        "error": error,
                        "expected": expected,
                        "gotten": gotten,
                        "classification": classification,
                    })
        except sqlite3.Error:
            # A partial report is kept for diagnosis.  The runner will mark it
            # incomplete rather than treating it as evidence.
            continue
    return records


def report_groups(records: List[Dict[str, Any]]) -> Set[str]:
    return {record["group"] for record in records if isinstance(record.get("group"), str)}


def scan(output_root: Path, mode: str, version: str, reports_dir: Path) -> Dict[str, Any]:
    afl_root = output_root / "afl"
    campaign = read_json(output_root / "metadata" / "campaign.json", {})
    liboqs = campaign.get("liboqs", "<liboqs-target>") if isinstance(campaign, dict) else "<liboqs-target>"
    artifacts: List[Dict[str, Any]] = []
    raw_groups: Set[str] = set()
    group_replays: Dict[str, List[str]] = {}
    kinds = {
        "crashes": "crash",
        "hangs": "hang",
        "setup-timeout": "setup-timeout",
    }

    if afl_root.is_dir():
        for kind_dir in sorted(afl_root.rglob("*")):
            if not kind_dir.is_dir() or kind_dir.name not in kinds:
                continue
            # AFL output is always .../<property>/alg-*/fuzzoutputs/<instance>/<kind>.
            try:
                instance = kind_dir.parent.name
                alg_dir = kind_dir.parents[2]
                alg_dir.relative_to(afl_root)
            except (IndexError, AttributeError, ValueError):
                continue
            prop = property_for(alg_dir, afl_root)
            algorithm = algorithm_for(alg_dir)
            group = f"{prop}|{algorithm}"
            for file in sorted(kind_dir.rglob("*")):
                if not file.is_file() or file.name == "README.txt":
                    continue
                kind = kinds[kind_dir.name]
                source_reference = None
                if "src:" in file.name:
                    source_reference = file.name.split("src:", 1)[1].split(",", 1)[0]
                replay_status = "not-required" if kind == "setup-timeout" else "not-run"
                replay = replay_record(output_root, file)
                result = replay.get("result") if isinstance(replay, dict) else None
                if isinstance(replay, dict):
                    replay_status = replay.get("status", replay_status)
                command = [
                    "python3", "crypto_testing_replay.py", "--output-root", str(output_root),
                    "--artifact", str(file), "--mode", mode, "--liboqs", str(liboqs),
                    "--property", prop, "--algorithm-index", alg_dir.name,
                ]
                artifact = {
                    "algorithm": algorithm,
                    "property": prop,
                    "kind": kind,
                    "afl_instance": instance,
                    "afl_queue_or_seed_reference": source_reference,
                    "relative_artifact_path": str(file.relative_to(output_root)),
                    "size": file.stat().st_size,
                    "sha256": sha256(file),
                    "classification": "setup-timeout" if kind == "setup-timeout" else (result or "unvalidated"),
                    "replay": {
                        "required": kind != "setup-timeout",
                        "status": replay_status,
                        "result": result,
                        "command": command,
                    },
                }
                artifacts.append(artifact)
                if kind != "setup-timeout":
                    raw_groups.add(group)
                    group_replays.setdefault(group, []).append(replay_status)

    task_dir = output_root / "metadata" / "tasks"
    task_records = [read_json(path, None) for path in sorted(task_dir.glob("*.json"))] if task_dir.is_dir() else []
    tasks = [record for record in task_records if isinstance(record, dict)]
    if not tasks:
        tasks = read_json(output_root / "metadata" / "tasks.json", [])
    schedule = read_json(output_root / "metadata" / "schedule.json", {})
    if not isinstance(tasks, list):
        tasks = []
    driver_error = read_json(output_root / "metadata" / "driver-error.json", None)
    if not isinstance(driver_error, dict):
        driver_error = None
    states = Counter(
        item.get("state", "unknown") for item in tasks if isinstance(item, dict)
    )
    terminal = {"completed", "skipped", "setup-timeout", "target-failed", "interrupted"}
    scheduled_tasks = [
        item for item in tasks if isinstance(item, dict) and item.get("state") != "skipped"
    ]
    scheduled = len(scheduled_tasks)
    terminal_count = sum(item.get("state") in terminal for item in scheduled_tasks)
    task_coverage = {
        "scheduled": scheduled,
        "terminal": terminal_count,
        "incomplete": scheduled - terminal_count,
        "fraction": round(terminal_count / scheduled, 6) if scheduled else 0.0,
    }
    complete = bool(tasks) and all(
        isinstance(item, dict) and item.get("state") in terminal for item in tasks
    )
    reports = report_records(reports_dir)
    reported = report_groups(reports)
    report_findings = [
        record for record in reports if record.get("classification") in FINDING_KINDS
    ]
    report_finding_counts = Counter(record["classification"] for record in report_findings)
    groups_with_reproducer = reported & raw_groups
    groups_replayed = {
        group for group in groups_with_reproducer if group_replays.get(group) and all(
            status == "reproduced" for status in group_replays[group]
        )
    }
    report_files = sorted(str(path.relative_to(reports_dir)) for path in reports_dir.glob("*") if path.is_file())
    scheduled_entries = schedule.get("tasks", []) if isinstance(schedule, dict) else []
    enabled_entries = [item for item in scheduled_entries if isinstance(item, dict) and item.get("enabled", True)]
    skipped_tasks = [item for item in tasks if item.get("state") == "skipped"]
    full_matrix_complete = bool(tasks) and not skipped_tasks and all(
        item.get("state") == "completed" for item in tasks
    )
    target_failed_tasks = [item for item in tasks if item.get("state") == "target-failed"]

    budget_exhausted = os.environ.get("CRYPTO_TESTING_BUDGET_EXHAUSTED") == "1"
    return {
        "schema_version": 1,
        "baseline": "cryptoTesting",
        "mode": mode,
        "version": version,
        "generated_at": now(),
        "output_root": str(output_root),
        "artifacts": artifacts,
        "artifact_counts": dict(sorted(Counter(item["kind"] for item in artifacts).items())),
        "task_states": dict(sorted(states.items())),
        "scheduled_tasks": scheduled,
        "task_coverage": task_coverage,
        "tasks_terminal": complete,
        "full_matrix_complete": full_matrix_complete,
        "target_failed_task_count": len(target_failed_tasks),
        "driver_error": driver_error,
        "budget_exhausted": budget_exhausted,
        "schedule": schedule if isinstance(schedule, dict) else {},
        "algorithm_list": sorted({item["algorithm"] for item in enabled_entries if isinstance(item.get("algorithm"), str)}),
        "property_list": sorted({item["property"] for item in enabled_entries if isinstance(item.get("property"), str)}),
        "report_files": report_files,
        "reported_groups": len(reported),
        "report_findings": report_findings,
        "report_finding_counts": {
            kind: report_finding_counts.get(kind, 0) for kind in FINDING_KINDS
        },
        "semantic_finding_count": (
            report_finding_counts.get("malleability", 0)
            + report_finding_counts.get("mismatch", 0)
        ),
        "malleability_count": report_finding_counts.get("malleability", 0),
        "mismatch_count": report_finding_counts.get("mismatch", 0),
        "sanitizer_crash_count": report_finding_counts.get("sanitizer-crash", 0),
        "hang_count": report_finding_counts.get("hang", 0),
        "operation_diagnostic_count": report_finding_counts.get("operation-diagnostic", 0),
        "groups_with_reproducer": len(groups_with_reproducer),
        "groups_replayed": len(groups_replayed),
        "groups_missing_reproducer": len(reported - groups_with_reproducer),
        "reported_group_keys": sorted(reported),
        "groups_missing_reproducer_keys": sorted(reported - groups_with_reproducer),
        "classification_taxonomy": {
            "setup-timeout": "setup-timeout",
            "raw-crash": "crash",
            "raw-hang": "unvalidated until replay; then target-hang, crash, operation-error, accepted-mutation, mismatch, or unreproduced",
            "report": "report.py SQLite classifications are authoritative for result totals",
        },
        "unvalidated_artifact_count": sum(
            item.get("classification") == "unvalidated" for item in artifacts
        ),
        "resource_allocation": {
            "requested_workers": campaign.get("requested_workers") if isinstance(campaign, dict) else None,
            "effective_workers": campaign.get("effective_workers") if isinstance(campaign, dict) else None,
            "cpu_allocation": campaign.get("cpu_allocation") if isinstance(campaign, dict) else None,
        },
    }


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--mode", choices=("functional", "vanilla"), required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--reports-dir", type=Path, required=True)
    parser.add_argument("--require-report-evidence", action="store_true")
    parser.add_argument("--require-full-matrix", action="store_true")
    args = parser.parse_args(argv)

    document = scan(args.output_root, args.mode, args.version, args.reports_dir)
    write_json(args.output_root / "manifest.json", document)
    finding_count = sum(document["report_finding_counts"].values())
    if document["driver_error"] is not None:
        status = "harness-error"
        normalized_outcome = "operation_error"
        stop_reason = "driver-error"
    elif document["target_failed_task_count"]:
        status = "target-failed"
        normalized_outcome = "operation_error"
        stop_reason = "target-failed"
    elif document["tasks_terminal"] and not document["full_matrix_complete"]:
        status = "completed-with-coverage-gap"
        normalized_outcome = "coverage_incomplete"
        stop_reason = "task-coverage-incomplete"
    elif document["tasks_terminal"] and finding_count:
        status = "completed-with-findings"
        normalized_outcome = "invariant_violation"
        stop_reason = "all-tasks-terminal"
    elif document["tasks_terminal"]:
        status = "completed"
        normalized_outcome = "ok"
        stop_reason = "all-tasks-terminal"
    elif document["budget_exhausted"]:
        status = "completed-at-budget-incomplete"
        normalized_outcome = "coverage_incomplete"
        stop_reason = "fuzzing-time-budget"
    else:
        status = "timed-out-partial"
        normalized_outcome = "process_hang"
        stop_reason = "interrupted"
    write_json(
        args.output_root / "summary.json",
        {
            "baseline": "cryptoTesting",
            "label": f"cryptoTesting-{args.mode}",
            "mode": args.mode,
            "version": args.version,
            "status": status,
            "normalized_outcome": normalized_outcome,
            "stop_reason": stop_reason,
            "budget_exhausted": document["budget_exhausted"],
            "raw_output_root": str(args.output_root),
            "task_states": document["task_states"],
            "scheduled_tasks": document["scheduled_tasks"],
            "task_coverage": document["task_coverage"],
            "tasks_terminal": document["tasks_terminal"],
            "full_matrix_complete": document["full_matrix_complete"],
            "target_failed_task_count": document["target_failed_task_count"],
            "driver_error": document["driver_error"],
            "raw_artifact_counts": document["artifact_counts"],
            "unvalidated_artifact_count": document["unvalidated_artifact_count"],
            "reported_groups": document["reported_groups"],
            "report_finding_counts": document["report_finding_counts"],
            "semantic_finding_count": document["semantic_finding_count"],
            "malleability_count": document["malleability_count"],
            "mismatch_count": document["mismatch_count"],
            "sanitizer_crash_count": document["sanitizer_crash_count"],
            "hang_count": document["hang_count"],
            "operation_diagnostic_count": document["operation_diagnostic_count"],
            "groups_with_reproducer": document["groups_with_reproducer"],
            "groups_replayed": document["groups_replayed"],
            "groups_missing_reproducer": document["groups_missing_reproducer"],
            "reports": document["report_files"],
            "worker_count": document["resource_allocation"]["effective_workers"],
            "requested_workers": document["resource_allocation"]["requested_workers"],
            "cpu_allocation": document["resource_allocation"]["cpu_allocation"],
            "schedule": document["schedule"],
            "algorithm_list": document["algorithm_list"],
            "property_list": document["property_list"],
            "skipped_tasks": [
                task for task in document["schedule"].get("tasks", [])
                if isinstance(task, dict) and not task.get("enabled", True)
            ] if isinstance(document["schedule"], dict) else [],
        },
    )
    if args.require_report_evidence and document["reported_groups"]:
        if not document["artifacts"] or document["groups_missing_reproducer"]:
            print("cryptoTesting report groups are missing retained raw reproducers", file=sys.stderr)
            return 1
    if args.require_full_matrix and not document["full_matrix_complete"]:
        print("cryptoTesting did not complete every available scheduled task", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
