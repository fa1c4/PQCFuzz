from __future__ import annotations

import os
import shutil
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


def test_full_test_dry_run_schedules_both_suites_per_version() -> None:
    result = run_dry("--full-test")

    assert result.returncode == 0, result.stderr
    assert "full test: 1" in result.stdout
    assert "campaign: liboqs-0.14.0-metamorphic" in result.stdout
    assert "campaign: liboqs-0.14.0-fips" in result.stdout
    assert "suite: metamorphic" in result.stdout
    assert "suite: fips" in result.stdout
    assert "session: pqcfuzz-liboqs-0_14_0-metamorphic" in result.stdout
    assert "session: pqcfuzz-liboqs-0_14_0-fips" in result.stdout


def test_single_suite_dry_run_still_schedules_one_campaign() -> None:
    result = run_dry("--oracle-suite", "fips")

    assert result.returncode == 0, result.stderr
    assert "full test: 0" in result.stdout
    assert "campaign: liboqs-0.14.0" in result.stdout
    assert "campaign: liboqs-0.14.0-fips" not in result.stdout
    assert "suite: fips" in result.stdout


def test_full_test_overrides_oracle_suite_and_embeds_per_campaign_suite(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    tmux = bin_dir / "tmux"
    tmux.write_text(
        "#!/usr/bin/env bash\nif [ \"$1\" = \"has-session\" ]; then exit 1; fi\nexit 0\n",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    tmux.chmod(0o755)

    output_root = f"workspace/pqcfuzz_eval_test_{os.getpid()}"
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
    result = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "--full-test",
            "--oracle-suite",
            "fips",
            "--versions",
            "0.14.0",
            "--output-root",
            output_root,
        ],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
    )

    try:
        assert result.returncode in {0, 1}, result.stderr
        metamorphic_launcher = REPO_ROOT / output_root / "launchers" / "liboqs-0.14.0-metamorphic.sh"
        fips_launcher = REPO_ROOT / output_root / "launchers" / "liboqs-0.14.0-fips.sh"
        assert metamorphic_launcher.is_file()
        assert fips_launcher.is_file()
        assert "ORACLE_SUITE=metamorphic" in metamorphic_launcher.read_text(encoding="utf-8")
        assert "ORACLE_SUITE=fips" in fips_launcher.read_text(encoding="utf-8")
    finally:
        shutil.rmtree(REPO_ROOT / output_root, ignore_errors=True)


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
