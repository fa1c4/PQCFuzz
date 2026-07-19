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
