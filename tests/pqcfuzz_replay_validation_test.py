from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from replay.replay_one import replay_equivalence_error, validate_replay_trace


def test_replay_validation_requires_effective_intervention() -> None:
    trace = {
        "oracle_semantics_version": 2,
        "algorithm": "ML-KEM-768",
        "configured_algorithm": "ML-KEM-768",
        "adapter_algorithm": "ML-KEM-768",
        "valid_setup": True,
        "intervention_supported": True,
        "intervention_effective": False,
        "findings": [{"class": "malleability"}],
    }
    valid, reason = validate_replay_trace(trace, {"algorithm": "ML-KEM-768"})
    assert not valid
    assert reason == "ineffective_intervention"


def test_replay_equivalence_rejects_rng_digest_changes() -> None:
    trace = {
        "oracle_semantics_version": 2,
        "algorithm": "ML-KEM-768",
        "configured_algorithm": "ML-KEM-768",
        "adapter_algorithm": "ML-KEM-768",
        "project_id": "liboqs",
        "implementation_id": "impl",
        "oracle_id": "kem_keygen_badrng",
        "observed_relation": "OBSERVED_EQUAL",
        "baseline": {"status": "OK"},
        "mutated": {"status": "OK"},
        "mutations": [],
        "rng_interventions": [{"baseline_tape_sha256": "a", "mutated_tape_sha256": "b"}],
    }
    changed = {**trace, "rng_interventions": [{"baseline_tape_sha256": "a", "mutated_tape_sha256": "c"}]}
    assert replay_equivalence_error(trace, changed) == "replay_rng_tape_digest_mismatch"
