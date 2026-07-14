from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "baselines" / "libFuzzer" / "run.sh"


def write_executable(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def write_fake_fuzzer(path: Path) -> None:
    write_executable(
        path,
        """#!/usr/bin/env bash
set -eu

target="${PQCDF_LIBFUZZER_TARGET:?}"
profile="${PQCDF_LIBFUZZER_PROFILE:?}"
metadata="${PQCDF_LIBFUZZER_METADATA_FILE:?}"
mkdir -p "$(dirname "$metadata")"
printf '%s\\n' '{"enabled_algorithms":["fake-'"$target"'"],"property_ids":["fake_property"]}' > "$metadata"

if [ "$profile" = semantic ]; then
  mkdir -p "${PQCDF_LIBFUZZER_FINDINGS_DIR:?}"
  printf '%s\\n' '{"algorithm":"fake-'"$target"'","property_id":"fake_property","outcome":"invariant_violation"}' \\
    > "${PQCDF_LIBFUZZER_FINDINGS_DIR}/${target}.json"
fi

if [ "${FAKE_ASAN_TARGET:-}" = "$target" ]; then
  prefix=""
  for arg in "$@"; do
    case "$arg" in
      -artifact_prefix=*) prefix="${arg#-artifact_prefix=}" ;;
    esac
  done
  mkdir -p "$prefix"
  : > "${prefix}crash-fake"
  echo 'ERROR: AddressSanitizer: fake failure' >&2
  exit 1
fi
""",
    )


def runner_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env["PQCDF_LIBFUZZER_IN_DOCKER"] = "1"
    if extra:
        env.update(extra)
    return env


def run_runner(
    tmp_path: Path,
    *args: str,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    build_dir = tmp_path / "build"
    run_dir = tmp_path / "run"
    return subprocess.run(
        ["bash", str(RUNNER), str(ROOT / "baselines" / "libFuzzer"), str(build_dir), str(run_dir), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        env=runner_env(extra_env),
    )


def install_fake_targets(tmp_path: Path) -> None:
    for target in ("kem", "sig"):
        write_fake_fuzzer(tmp_path / "build" / "liboqs-0.14.0" / "libFuzzer" / f"fuzz_{target}")


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_profile_is_required(tmp_path: Path) -> None:
    result = run_runner(tmp_path, "--version", "0.14.0")

    assert result.returncode == 2
    assert "--profile is required" in result.stderr


def test_profiles_and_target_summaries_are_isolated(tmp_path: Path) -> None:
    install_fake_targets(tmp_path)
    semantic = run_runner(
        tmp_path,
        "--profile",
        "semantic",
        "--version",
        "0.14.0",
        "--target",
        "all",
        "--runs",
        "1",
    )
    assert semantic.returncode == 0, semantic.stderr

    memory = run_runner(
        tmp_path,
        "--profile",
        "memory-safety",
        "--version",
        "0.14.0",
        "--target",
        "all",
        "--runs",
        "1",
    )
    assert memory.returncode == 0, memory.stderr

    version_root = tmp_path / "run" / "liboqs-0.14.0"
    for target in ("kem", "sig"):
        index = read_json(version_root / target / "summary.json")
        assert set(index["profiles"]) == {"memory-safety", "semantic"}
        assert index["profiles"]["semantic"]["status"] == "completed-with-findings"
        assert index["profiles"]["semantic"]["semantic_finding_count"] == 1
        assert index["profiles"]["semantic"]["corpus_seed_count"] == 1
        assert index["profiles"]["memory-safety"]["status"] == "completed"
        assert index["profiles"]["memory-safety"]["semantic_finding_count"] == 0
        assert (version_root / target / "summary.semantic.json").is_file()
        assert (version_root / target / "summary.memory-safety.json").is_file()

    aggregate = read_json(version_root / "summary.json")
    assert set(aggregate["profiles"]) == {"memory-safety", "semantic"}
    assert "semantic_finding_count" not in aggregate
    assert aggregate["profiles"]["semantic"]["semantic_finding_count"] == 2
    assert aggregate["profiles"]["memory-safety"]["semantic_finding_count"] == 0


def test_sanitizer_failure_is_a_target_crash_and_not_a_semantic_success(tmp_path: Path) -> None:
    install_fake_targets(tmp_path)
    result = run_runner(
        tmp_path,
        "--profile",
        "semantic",
        "--version",
        "0.14.0",
        "--target",
        "kem",
        "--runs",
        "1",
        extra_env={"FAKE_ASAN_TARGET": "kem"},
    )

    assert result.returncode != 0
    detail = read_json(tmp_path / "run" / "liboqs-0.14.0" / "kem" / "summary.semantic.json")
    assert detail["status"] == "target-crash"
    assert detail["effective_exit_status"] != 0
    assert detail["sanitizer_artifact_count"] == 1
    assert detail["sanitizer_artifacts"] == ["crashes/semantic/crash-fake"]


def test_clean_full_time_budget_is_recorded_without_a_failure_exit(tmp_path: Path) -> None:
    install_fake_targets(tmp_path)
    result = run_runner(
        tmp_path,
        "--profile",
        "semantic",
        "--version",
        "0.14.0",
        "--target",
        "kem",
        "--mode",
        "full",
        "--max-total-time",
        "1",
    )

    assert result.returncode == 0, result.stderr
    detail = read_json(tmp_path / "run" / "liboqs-0.14.0" / "kem" / "summary.semantic.json")
    assert detail["status"] == "completed-with-findings"
    assert detail["stop_reason"] == "max-total-time"
    assert detail["effective_exit_status"] == 0
