from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

import pytest

from replay.replay_one import ReplayError, replay_equivalence_error, selected_oracle_id, trace_semantics_status, validate_replay_trace


def test_replay_validation_requires_effective_intervention() -> None:
    trace = {
        "version": 4,
        "oracle_semantics_version": 4,
        "disposition": "not_evaluable",
        "algorithm": "ML-KEM-768",
        "configured_algorithm": "ML-KEM-768",
        "adapter_algorithm": "ML-KEM-768",
        "baseline_setup_valid": True,
        "mutated_setup_valid": True,
        "baseline_adapter_entered": True,
        "baseline_target_entered": True,
        "mutated_adapter_entered": True,
        "mutated_target_entered": True,
        "relation_evaluable": False,
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


def test_v2_and_v3_traces_remain_readable_but_are_marked_legacy_semantics() -> None:
    trace = {
        "version": 2,
        "oracle_semantics_version": 2,
        "algorithm": "ML-KEM-768",
        "findings": [],
    }

    assert trace_semantics_status(trace) == "legacy_semantics"
    assert trace_semantics_status({**trace, "version": 3, "oracle_semantics_version": 3}) == "legacy_semantics"


def test_replay_rejects_oracle_mismatch_without_fallback() -> None:
    with pytest.raises(ReplayError, match="does not match job oracle"):
        selected_oracle_id({"oracles": ["kem_decaps_c"]}, {"oracle_id": "kem_encaps_pk"})
