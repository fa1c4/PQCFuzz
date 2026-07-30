from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]


def passing_summary() -> dict[str, Any]:
    security_oracles = ["kem_decaps_c", "sig_verify_m", "sig_verify_sig", "sig_verify_pk"]
    return {
        "oracle_semantics_version": 4,
        "artifact_semantics_versions": [4],
        "full_test_suite": {
            "status": "passed",
            "failed": 0,
            "skipped": 0,
            "timed_out": False,
            "compile_failures": 0,
        },
        "finding_counts": {
            "unsupported": 0,
            "unknown_oracle": 0,
            "noop_mutation": 0,
            "baseline_reject_verify": 0,
            "mutated_target_not_reached": 0,
        },
        "smoke_matrix": {
            "liboqs_version": "0.14.0",
            "security_oracles": security_oracles,
        },
        "enabled_oracles": [
            {
                "oracle_id": oracle_id,
                "job_id": f"liboqs-0.14.0-{oracle_id}",
                "seed": f"seeds/{oracle_id}.bin",
                "budget_seconds": 150,
                "run_dir": f"runs/0.14.0/{oracle_id}",
            }
            for oracle_id in security_oracles
        ],
        "security_oracle_funnel": {
            oracle_id: {
                "total_inputs": 1,
                "baseline_setup_valid": 1,
                "mutation_effective": 1,
                "mutated_target_reached": 1,
                "relation_evaluable": 1,
            }
            for oracle_id in security_oracles
        },
        "context_contract": {"0": "passed", "1": "passed", "255": "passed", "256": "passed"},
        "rng_scope": {
            "restoration": True,
            "nesting": True,
            "non_periodicity": True,
            "causal_streams": True,
        },
        "sanitizer_process_validation": {
            "fingerprint_required": True,
            "exact_provenance_required": True,
        },
        "reporting": {
            "reconciled": True,
            "full_confirmed": 0,
            "summary_confirmed": 0,
            "fast_confirmed": 0,
        },
        "harness_errors": 0,
        "leak_detection": {"state": "on", "no_leaks_claim": True},
        "schemas_valid": True,
        "false_positive_regressions": {"xfail_count": 0},
        "long_campaign_run": False,
    }


def run_gate(tmp_path: Path, summary: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    path = tmp_path / "summary.json"
    path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return subprocess.run(
        [sys.executable, "scripts/check_false_positive_gate.py", str(path)],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
    )


def test_false_positive_gate_accepts_complete_bounded_smoke_summary(tmp_path: Path) -> None:
    result = run_gate(tmp_path, passing_summary())

    assert result.returncode == 0, result.stderr
    assert "Gate A passed" in result.stdout


def test_false_positive_gate_rejects_forbidden_finding_counts(tmp_path: Path) -> None:
    summary = passing_summary()
    summary["finding_counts"]["baseline_reject_verify"] = 1

    result = run_gate(tmp_path, summary)

    assert result.returncode == 1
    assert "finding_counts.baseline_reject_verify must be 0" in result.stderr


def test_false_positive_gate_rejects_no_leaks_claim_when_leak_detection_is_off(tmp_path: Path) -> None:
    summary = passing_summary()
    summary["leak_detection"] = {"state": "off", "no_leaks_claim": True}

    result = run_gate(tmp_path, summary)

    assert result.returncode == 1
    assert "disabled leak detection cannot support a no-leaks claim" in result.stderr
