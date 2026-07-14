from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator


REPO_ROOT = Path(__file__).resolve().parents[1]


def load_schema(name: str) -> dict:
    return json.loads((REPO_ROOT / "src" / "schemas" / name).read_text(encoding="utf-8"))


def test_v3_trace_requires_disposition() -> None:
    trace = {
        "version": 3,
        "oracle_semantics_version": 3,
        "job_id": "schema-test",
        "pair_id": "schema-test",
        "algorithm": "ML-KEM-768",
        "oracle_id": "mlkem_local_roundtrip",
        "mutation_target": "",
        "left_status": "OK",
        "right_status": "OK",
        "verify_result": False,
        "legal_negative_outcome": False,
        "baseline_setup_valid": True,
        "mutated_setup_valid": True,
        "baseline_adapter_entered": True,
        "baseline_target_entered": True,
        "mutated_adapter_entered": True,
        "mutated_target_entered": True,
        "relation_evaluable": True,
        "intervention_supported": True,
        "intervention_effective": True,
        "diagnostics": [],
        "subtests": [],
        "mutations": [],
        "rng_interventions": [],
        "findings": [],
    }

    errors = list(Draft202012Validator(load_schema("oracle_trace.schema.json")).iter_errors(trace))

    assert any(error.validator == "required" and "disposition" in error.message for error in errors)


def test_v3_finding_rejects_unsupported_class() -> None:
    finding = {
        "version": 3,
        "oracle_semantics_version": 3,
        "evidence_kind": "semantic",
        "finding_id": "schema-test",
        "job_id": "schema-test",
        "pair_id": "schema-test",
        "algorithm": "ML-KEM-768",
        "oracle_id": "mlkem_local_roundtrip",
        "finding_class": "unsupported",
        "finding_subclass": "",
        "summary": "unsupported API",
        "fingerprint": "test",
        "trace_path": "oracle_trace.json",
        "artifact_dir": ".",
        "validation_state": "raw",
        "validated": False,
        "validation_attempts": 0,
        "validation_failure_reason": "pending_deterministic_replay",
    }

    errors = list(Draft202012Validator(load_schema("finding.schema.json")).iter_errors(finding))

    assert any(error.validator == "enum" and list(error.path) == ["finding_class"] for error in errors)
