from __future__ import annotations

import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "pqcfuzz_eval.sh"


def run_dry(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SCRIPT), "--dry-run", "--versions", "0.14.0", *args],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
    )


def test_dry_run_uses_the_requested_sanitizer_profile_and_auto_leak_policy() -> None:
    result = run_dry("--sanitizers", "undefined")

    assert result.returncode == 0, result.stderr
    assert "sanitizers: undefined" in result.stdout
    assert "leak check: off" in result.stdout


def test_dry_run_enables_leak_check_for_address_sanitizer() -> None:
    result = run_dry("--sanitizers", "address")

    assert result.returncode == 0, result.stderr
    assert "sanitizers: address" in result.stdout
    assert "leak check: on" in result.stdout


def test_invalid_sanitizer_combinations_fail_before_creating_eval_artifacts() -> None:
    result = run_dry("--sanitizers", "address,memory")

    assert result.returncode == 2
    assert "memory cannot be combined with address" in result.stderr


def test_preflight_only_is_visible_in_dry_run_and_keeps_the_fast_gate_explicit() -> None:
    result = run_dry("--preflight-only")

    assert result.returncode == 0, result.stderr
    assert "preflight only: 1" in result.stdout
    assert "preflight-only; execute each comparable target's complete seeded oracle corpus" in result.stdout


def test_fuzz_effectiveness_threshold_is_visible_in_dry_run() -> None:
    result = run_dry("--fuzz-effectiveness-min-evaluable-rate", "0.8")

    assert result.returncode == 0, result.stderr
    assert "fuzz effectiveness min evaluable rate: 0.8" in result.stdout
    assert "fuzz_effectiveness_min_evaluable_rate: 0.8" in result.stdout


def test_oracle_set_security_is_visible_in_dry_run() -> None:
    result = run_dry("--oracle-set", "security")

    assert result.returncode == 0, result.stderr
    assert "oracle_set: security" in result.stdout


def test_output_root_can_isolate_concurrent_eval_runs() -> None:
    result = run_dry("--output-root", "workspace/pqcfuzz_eval_gate")

    assert result.returncode == 0, result.stderr
    assert "output root: " in result.stdout
    assert "workspace/pqcfuzz_eval_gate" in result.stdout


def test_output_root_rejects_paths_that_escape_the_repository() -> None:
    result = run_dry("--output-root", "../pqcfuzz_eval")

    assert result.returncode == 2
    assert "--output-root must be a nonempty relative path without '..'" in result.stderr
