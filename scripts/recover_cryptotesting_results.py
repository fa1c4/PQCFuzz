#!/usr/bin/env python3
"""Recover completed cryptoTesting campaigns whose result finalization failed."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_WRITER = ROOT / "baselines" / "cryptoTesting" / "crypto_testing_manifest.py"
COMPACTOR = ROOT / "scripts" / "compact_baseline_results.py"


def write_json(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".recovery.", dir=str(path.parent))
    with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
        json.dump(document, destination, indent=2, sort_keys=True)
        destination.write("\n")
    os.replace(temporary, path)


def load_json(path: Path) -> dict:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"invalid JSON at {path}: {error}") from error
    if not isinstance(document, dict):
        raise RuntimeError(f"expected a JSON object at {path}")
    return document


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eval-root", type=Path, default=ROOT / "workspace" / "baselines_eval")
    parser.add_argument("--version", required=True, choices=("0.14.0", "0.8.0", "0.4.0"))
    parser.add_argument("--mode", choices=("compact", "all"), default="compact")
    args = parser.parse_args(argv)

    eval_root = args.eval_root.resolve()
    campaign = f"cryptoTesting-{args.version}"
    workspace_root = eval_root / "campaigns" / campaign / "workspace"
    raw_root = workspace_root / "cryptoTesting" / "targets-run" / "raw" / campaign / "functional"
    reports_dir = workspace_root / "cryptoTesting" / "targets-run" / "reports" / f"{campaign}-functional"
    status_path = eval_root / "status" / f"{campaign}.json"

    if not raw_root.is_dir() or not reports_dir.is_dir():
        raise RuntimeError(f"missing raw output or reports for {campaign}")
    if not status_path.is_file():
        raise RuntimeError(f"missing evaluator status for {campaign}")

    subprocess.run(
        [
            sys.executable,
            str(MANIFEST_WRITER),
            "--output-root",
            str(raw_root),
            "--mode",
            "functional",
            "--version",
            args.version,
            "--reports-dir",
            str(reports_dir),
            "--require-report-evidence",
        ],
        cwd=ROOT,
        check=True,
    )
    manifest = load_json(raw_root / "manifest.json")
    summary = load_json(raw_root / "summary.json")
    if not manifest.get("tasks_terminal") or manifest.get("groups_missing_reproducer", 0):
        raise RuntimeError(f"{campaign} does not have complete, validated report evidence")
    if summary.get("status") != "completed":
        raise RuntimeError(f"{campaign} recovery produced {summary.get('status')!r}, expected 'completed'")

    compaction_status = 0
    compaction_manifest = workspace_root / "cryptoTesting" / "compaction_manifest.json"
    if args.mode == "compact":
        subprocess.run(
            [
                sys.executable,
                str(COMPACTOR),
                "--workspace-root",
                str(workspace_root),
                "--baseline",
                "cryptoTesting",
                "--version",
                args.version,
                "--mode",
                "compact",
            ],
            cwd=ROOT,
            check=True,
        )

    status = load_json(status_path)
    previous_result = status.get("result")
    status.update(
        {
            "phase": "finished",
            "state": "finished",
            "result": "completed",
            "final_status": 0,
            "fuzz_status": 0,
            "compaction_status": compaction_status,
            "compaction_manifest": os.path.relpath(compaction_manifest, ROOT),
            "recovered_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "recovery": {
                "previous_result": previous_result,
                "reason": "manifest finalization failed after terminal task completion",
                "tasks_terminal": True,
                "reported_groups": manifest.get("reported_groups", 0),
                "groups_missing_reproducer": manifest.get("groups_missing_reproducer", 0),
            },
        }
    )
    write_json(status_path, status)
    print(f"recovered {campaign}: {raw_root}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (RuntimeError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
