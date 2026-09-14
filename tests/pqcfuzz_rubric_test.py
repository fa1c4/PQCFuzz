from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_oracle_rubric as rubric  # noqa: E402


def test_repository_oracle_records_pass_the_rubric() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/check_oracle_rubric.py", "--json"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    rows = json.loads(result.stdout)
    assert len(rows) >= 64
    assert all(row["total"] >= 17 for row in rows)


def test_sparse_record_scores_zero_on_mandatory_dimensions() -> None:
    scores = rubric.score_record(
        {
            "oracle_id": "sparse",
            "algorithm_family": "ML-KEM",
            "primitive_type": "kem",
        },
        fips=True,
    )
    assert sum(scores.values()) < 17
    assert scores["source_grounding"] == 0
    assert scores["predicate"] == 0
    assert scores["verdict_semantics"] == 0
    assert scores["evidence_separation"] == 0


def test_invalid_evidence_class_scores_zero() -> None:
    scores = rubric.score_record(
        {
            "oracle_id": "bad-evidence",
            "algorithm_family": "ML-KEM",
            "primitive_type": "kem",
            "claim": "claim",
            "evidence_class": "MADE_UP",
            "source_reference": "FIPS 203 Section 7.2",
            "limitations": ["limitation"],
            "scope": {"api_layer": "external"},
            "expected_relation": "SAME_SHARED_SECRET",
            "comparator": "bytes_equal",
            "controls": {"positive_control": "a", "negative_control": "b"},
        },
        fips=True,
    )
    assert scores["verdict_semantics"] == 0
    assert scores["evidence_separation"] == 0
