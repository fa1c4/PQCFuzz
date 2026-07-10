import base64
import hashlib
import json
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVAL_SCRIPT = ROOT / "scripts" / "eval_baselines_fuzzing.sh"
CRYPTOFUZZ_RUNNER = ROOT / "scripts" / "baselines" / "cryptofuzz" / "run.sh"
CLFUZZ_RUNNER = ROOT / "scripts" / "baselines" / "CLFuzz" / "run.sh"
CRYPTOTESTING_RUNNER = ROOT / "scripts" / "baselines" / "cryptoTesting" / "run.sh"
CLFUZZ_OV_REPLAY_FIXTURE = ROOT / "tests" / "seeds" / "clfuzz_ov_is_pkc_skc_0.14.0.input.b64"
CLFUZZ_OV_REPLAY_MANIFEST = ROOT / "tests" / "seeds" / "clfuzz_ov_is_pkc_skc_0.14.0.replay.json"


def write_executable(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")
    path.chmod(0o755)


def env_with_temp_root(tmp_path: Path, root: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["PQCDF_ROOT_DIR"] = str(root)
    env["PATH"] = f"{tmp_path / 'bin'}{os.pathsep}{env['PATH']}"
    return env


def make_root(tmp_path: Path, run_baseline: str = "#!/usr/bin/env bash\nexit 0\n") -> Path:
    root = tmp_path / "repo"
    write_executable(root / "scripts" / "run_baseline.sh", run_baseline)
    return root


def make_tmux(tmp_path: Path, body: str) -> None:
    write_executable(tmp_path / "bin" / "tmux", "#!/usr/bin/env bash\n" + body)


def load_status(root: Path, campaign: str) -> dict:
    path = root / "workspace" / "baselines_eval" / "status" / f"{campaign}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def load_summary(root: Path) -> dict:
    path = root / "workspace" / "baselines_eval" / "summary.json"
    return json.loads(path.read_text(encoding="utf-8"))


def load_clfuzz_ov_replay_fixture() -> tuple[dict, bytes]:
    manifest = json.loads(CLFUZZ_OV_REPLAY_MANIFEST.read_text(encoding="utf-8"))
    encoded = "".join(CLFUZZ_OV_REPLAY_FIXTURE.read_text(encoding="ascii").split())
    fixture = base64.b64decode(encoded, validate=True)
    assert len(fixture) == manifest["input_size"]
    assert hashlib.sha256(fixture).hexdigest() == manifest["input_sha256"]
    return manifest, fixture


def run_eval(tmp_path: Path, root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(EVAL_SCRIPT), *args],
        cwd=ROOT,
        env=env_with_temp_root(tmp_path, root),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def install_fake_cryptofuzz_binary(build_dir: Path) -> None:
    write_executable(
        build_dir / "liboqs-0.14.0" / "cryptofuzz" / "cryptofuzz",
        """#!/usr/bin/env bash
set -eu

marker="${FAKE_MARKER:?}"
artifact_prefix=""
for arg in "$@"; do
  case "$arg" in
    -artifact_prefix=*) artifact_prefix="${arg#-artifact_prefix=}" ;;
  esac
done

printf '%s begin\\n' "$marker" >> fuzz-0.log
printf '%s stdout\\n' "$marker"
sleep 0.2
printf '%s end\\n' "$marker" >> fuzz-0.log

mkdir -p "${PQCDF_CRYPTOFUZZ_FINDINGS_DIR:?}" "${PQCDF_CRYPTOFUZZ_DIAGNOSTICS_DIR:?}"
printf '{"module_version":"fake-module","algorithm":"%s","property_id":"fake-property","semantic_relation":"fake-relation","replay":{"required":true,"result":"reproduced"}}\\n' "$marker" \\
  > "${PQCDF_CRYPTOFUZZ_FINDINGS_DIR}/finding-${marker}.json"
printf '{"module_version":"fake-module","algorithm":"%s","property_id":"fake-diagnostic"}\\n' "$marker" \\
  > "${PQCDF_CRYPTOFUZZ_DIAGNOSTICS_DIR}/diagnostic-${marker}.json"
mkdir -p "$artifact_prefix"
: > "${artifact_prefix}crash-${marker}"
: > "${artifact_prefix}timeout-${marker}"
""",
    )


def cryptofuzz_runner_env(marker: str) -> dict[str, str]:
    env = os.environ.copy()
    env["PQCDF_CRYPTOFUZZ_IN_DOCKER"] = "1"
    env["PQCDF_CRYPTOFUZZ_CPU_ALLOCATION"] = "test-cpu"
    env["FAKE_MARKER"] = marker
    return env


def install_fake_clfuzz_binary(build_dir: Path) -> None:
    write_executable(
        build_dir / "liboqs-0.14.0" / "clfuzz" / "clfuzz",
        """#!/usr/bin/env bash
set -eu

marker="${FAKE_MARKER:?}"
artifact_prefix=""
for arg in "$@"; do
  case "$arg" in
    -artifact_prefix=*) artifact_prefix="${arg#-artifact_prefix=}" ;;
  esac
done

printf '%s begin\\n' "$marker" >> fuzz-0.log
printf '%s stdout\\n' "$marker"
sleep 0.2
printf '%s end\\n' "$marker" >> fuzz-0.log

mkdir -p "${PQCDF_LIBOQS_FINDINGS_DIR:?}" "${PQCDF_LIBOQS_DIAGNOSTICS_DIR:?}" "${PQCDF_LIBOQS_METADATA_DIR:?}"
printf '{"format_version":1,"baseline":"CLFuzz","module_version":"fake-module","algorithm":"%s","property_id":"fake-property","semantic_relation":"fake-relation","mutation_effective":true,"mutation_operation":"xor","mutation_before_digest":"before","mutation_after_digest":"after","replay":{"required":true,"result":"reproduced","attempts_completed":3,"reproduced_count":3,"attempt_results":["reproduced","reproduced","reproduced"]}}\\n' "$marker" \\
  > "${PQCDF_LIBOQS_FINDINGS_DIR}/finding-${marker}.json"
printf '{"format_version":1,"baseline":"CLFuzz","module_version":"fake-module","algorithm":"%s","property_id":"fake-diagnostic"}\\n' "$marker" \\
  > "${PQCDF_LIBOQS_DIAGNOSTICS_DIR}/diagnostic-${marker}.json"
printf '{"module_version":"fake-module"}\\n' > "${PQCDF_LIBOQS_METADATA_DIR}/metadata-${marker}.json"
printf '%s' "${PQCDF_LIBOQS_REPLAY_MODE:-}" > "${PQCDF_LIBOQS_METADATA_DIR}/replay-mode.txt"
if [ "${PQCDF_LIBOQS_REPLAY_MODE:-}" = raw-input-v1 ]; then
  printf '%s|%s|%s|%s|%s|%s\\n' \\
    "${PQCDF_LIBOQS_REPLAY_ALGORITHM:?}" \\
    "${PQCDF_LIBOQS_REPLAY_PROPERTY:?}" \\
    "${PQCDF_LIBOQS_MUTATION_SEMANTICS:?}" \\
    "${PQCDF_LIBOQS_REPLAY_ATTEMPTS:?}" \\
    "${PQCDF_LIBOQS_REPLAY_INPUT_SHA256:?}" \\
    "${PQCDF_LIBOQS_REPLAY_INPUT_RELATIVE_PATH:?}" \\
    > "${PQCDF_LIBOQS_METADATA_DIR}/replay-env.txt"
fi
mkdir -p "$artifact_prefix"
if [ "${FAKE_CLFUZZ_FATAL:-0}" = 1 ] || [ "${FAKE_CLFUZZ_ZERO_EXIT_CRASH:-0}" = 1 ]; then
  : > "${artifact_prefix}crash-${marker}"
  if [ "${FAKE_CLFUZZ_FATAL:-0}" = 1 ]; then
    exit 77
  fi
fi
""",
    )


def clfuzz_runner_env(marker: str) -> dict[str, str]:
    env = os.environ.copy()
    env["PQCDF_CLFUZZ_IN_DOCKER"] = "1"
    env["PQCDF_CLFUZZ_CPU_ALLOCATION"] = "test-cpu"
    env["FAKE_MARKER"] = marker
    return env


def test_campaign_filter_dry_run_selects_one_campaign(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    result = run_eval(
        tmp_path,
        root,
        "--dry-run",
        "--fuzzing-time",
        "1s",
        "--campaign",
        "libFuzzer-0.14.0",
    )

    assert result.returncode == 0
    assert "[dry-run] campaign: libFuzzer-0.14.0" in result.stdout
    assert "[dry-run] campaign: libFuzzer-0.8.0" not in result.stdout
    assert "[eval] selected campaigns: libFuzzer-0.14.0" in result.stdout
    assert "libFuzzer run --profile semantic --version 0.14.0 --target kem" in result.stdout


def test_campaign_filter_rejects_unknown_campaign(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    result = run_eval(tmp_path, root, "--dry-run", "--campaign", "unknown-0.14.0")

    assert result.returncode == 2
    assert "unknown campaign 'unknown-0.14.0'" in result.stderr


def test_cryptotesting_timeout_is_timed_out_partial_not_success(tmp_path: Path) -> None:
    root = make_root(
        tmp_path,
        """#!/usr/bin/env bash
if [ "$1" = cryptoTesting ] && [ "$2" = run ]; then
  sleep 5
fi
exit 0
""",
    )
    make_tmux(
        tmp_path,
        """
case "$1" in
  has-session) exit 1 ;;
  new-session) launcher="${@: -1}"; "$launcher" >/dev/null 2>&1 || true; exit 0 ;;
esac
exit 0
""",
    )

    result = run_eval(
        tmp_path, root, "--campaign", "cryptoTesting-0.14.0", "--result-save-mode", "all",
        "--fuzzing-time", "1s", "--progress-interval", "1",
    )

    assert result.returncode == 1
    status = load_status(root, "cryptoTesting-0.14.0")
    assert status["result"] == "timed-out-partial"
    assert status["final_status"] == 124


def test_cryptotesting_success_without_summary_is_failure(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    make_tmux(
        tmp_path,
        """
case "$1" in
  has-session) exit 1 ;;
  new-session) launcher="${@: -1}"; "$launcher" >/dev/null 2>&1 || true; exit 0 ;;
esac
exit 0
""",
    )

    result = run_eval(
        tmp_path, root, "--campaign", "cryptoTesting-0.14.0", "--result-save-mode", "all",
        "--fuzzing-time", "1s", "--progress-interval", "1",
    )

    assert result.returncode == 1
    summary = load_summary(root)
    assert summary["campaigns"][0]["result"] == "missing-summary"
    assert summary["campaigns"][0]["missing_expected_summary"] is True


def test_cryptotesting_reproduce_selects_functional_and_vanilla_drivers(tmp_path: Path) -> None:
    source_dir = ROOT / "baselines" / "cryptoTesting"
    work = tmp_path / "cryptoTesting"
    work.mkdir()
    write_executable(work / "reproduce.sh", (source_dir / "reproduce.sh").read_text(encoding="utf-8"))
    (work / "crypto_testing_manifest.py").write_text(
        (source_dir / "crypto_testing_manifest.py").read_text(encoding="utf-8"), encoding="utf-8"
    )
    write_executable(tmp_path / "bin" / "make", "#!/usr/bin/env bash\nexit 0\n")
    driver = """from pathlib import Path
import json
import sys

root = Path(sys.argv[sys.argv.index('--output-root') + 1])
root.mkdir(parents=True, exist_ok=True)
(root / 'metadata').mkdir(exist_ok=True)
(root / 'metadata' / 'tasks.json').write_text(json.dumps([{'state': 'completed'}]))
(root / 'metadata' / 'schedule.json').write_text(json.dumps({'tasks': []}))
(root / ('driver-' + Path(__file__).stem + '.txt')).write_text('ran')
"""
    report = """from pathlib import Path
import sys

directory = Path(sys.argv[sys.argv.index('--report-dir') + 1])
directory.mkdir(parents=True, exist_ok=True)
(directory / 'report.xlsx').write_text('report')
"""
    for name in ("fuzz_liboqs.py", "fuzz_liboqs_baseline.py"):
        (work / name).write_text(driver, encoding="utf-8")
    for name in ("report.py", "report_baseline.py"):
        (work / name).write_text(report, encoding="utf-8")

    env = os.environ.copy()
    env["PATH"] = f"{tmp_path / 'bin'}{os.pathsep}{env['PATH']}"
    for mode, baseline_token, marker in (
        ("functional", [], "driver-fuzz_liboqs.txt"),
        ("vanilla", ["baseline"], "driver-fuzz_liboqs_baseline.txt"),
    ):
        raw = tmp_path / f"raw-{mode}"
        reports = tmp_path / f"reports-{mode}"
        result = subprocess.run(
            [
                "bash", "reproduce.sh", "ches_liboqs", *baseline_token,
                "--output-root", str(raw), "--reports-dir", str(reports),
                "--workers", "1", "--version", "0.14.0",
            ],
            cwd=work, env=env, text=True, capture_output=True,
        )
        assert result.returncode == 0, result.stderr
        assert (raw / marker).is_file()
        assert json.loads((raw / "manifest.json").read_text(encoding="utf-8"))["mode"] == mode


def test_cryptotesting_runner_rejects_nonpositive_worker_count(tmp_path: Path) -> None:
    result = subprocess.run(
        ["bash", str(CRYPTOTESTING_RUNNER), "baseline", str(tmp_path / "build"), str(tmp_path / "run"), "--workers", "0"],
        cwd=ROOT, text=True, capture_output=True,
    )

    assert result.returncode == 2
    assert "positive integer" in result.stderr


def test_launch_failure_writes_finished_status_and_summary(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    make_tmux(
        tmp_path,
        """
case "$1" in
  has-session) exit 1 ;;
  new-session) exit 1 ;;
esac
exit 0
""",
    )

    result = run_eval(
        tmp_path,
        root,
        "--campaign",
        "libFuzzer-0.14.0",
        "--result-save-mode",
        "all",
        "--fuzzing-time",
        "1s",
        "--progress-interval",
        "1",
    )

    assert result.returncode == 1
    status = load_status(root, "libFuzzer-0.14.0")
    assert status["phase"] == "finished"
    assert status["state"] == "finished"
    assert status["result"] == "launch-failed"
    assert status["final_status"] == 1
    assert status["launcher"].endswith("workspace/baselines_eval/launchers/libFuzzer-0.14.0.sh")
    assert status["script_snapshot_hash"]

    summary = load_summary(root)
    assert summary["campaigns"][0]["result"] == "launch-failed"
    assert summary["campaigns"][0]["aggregate_status"] == 1


def test_early_dead_session_is_classified_as_launcher_exited_no_status(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    make_tmux(
        tmp_path,
        """
case "$1" in
  has-session) exit 1 ;;
  new-session) exit 0 ;;
esac
exit 0
""",
    )

    result = run_eval(
        tmp_path,
        root,
        "--campaign",
        "cryptofuzz-0.8.0",
        "--result-save-mode",
        "all",
        "--fuzzing-time",
        "1s",
        "--progress-interval",
        "1",
    )

    assert result.returncode == 1
    status = load_status(root, "cryptofuzz-0.8.0")
    assert status["phase"] == "queued"
    assert status["state"] == "queued"
    assert status["final_status"] is None

    summary = load_summary(root)
    assert summary["campaigns"][0]["result"] == "launcher-exited-no-status"
    assert summary["campaigns"][0]["aggregate_status"] == 1


def test_unexpected_launcher_exit_trap_writes_failure_status(tmp_path: Path) -> None:
    root = make_root(
        tmp_path,
        "#!/usr/bin/env bash\nkill -TERM \"$PPID\"\nexit 77\n",
    )
    make_tmux(
        tmp_path,
        """
case "$1" in
  has-session)
    exit 1
    ;;
  new-session)
    launcher="${@: -1}"
    "$launcher" >/dev/null 2>&1 || true
    exit 0
    ;;
esac
exit 0
""",
    )

    result = run_eval(
        tmp_path,
        root,
        "--campaign",
        "CLFuzz-0.4.0",
        "--result-save-mode",
        "all",
        "--fuzzing-time",
        "1s",
        "--progress-interval",
        "1",
    )

    assert result.returncode == 1
    status = load_status(root, "CLFuzz-0.4.0")
    assert status["phase"] == "finished"
    assert status["state"] == "finished"
    assert status["result"] == "launcher-exited-unexpectedly"
    assert status["final_status"] != 0

    summary = load_summary(root)
    assert summary["campaigns"][0]["result"] == "launcher-exited-unexpectedly"
    assert summary["campaigns"][0]["aggregate_status"] == 1


def test_cryptofuzz_concurrent_campaigns_isolate_worker_logs_and_summary_paths(tmp_path: Path) -> None:
    caller = tmp_path / "caller"
    caller.mkdir()
    campaigns: dict[str, tuple[Path, Path]] = {}
    processes: dict[str, subprocess.Popen[str]] = {}

    for marker in ("campaign-a", "campaign-b"):
        build_dir = tmp_path / marker / "build"
        run_dir = tmp_path / marker / "run"
        install_fake_cryptofuzz_binary(build_dir)
        campaigns[marker] = (build_dir, run_dir)
        processes[marker] = subprocess.Popen(
            [
                "bash",
                str(CRYPTOFUZZ_RUNNER),
                str(ROOT / "baselines" / "cryptofuzz"),
                str(build_dir),
                str(run_dir),
                "--version",
                "0.14.0",
                "--runs",
                "1",
            ],
            cwd=caller,
            env=cryptofuzz_runner_env(marker),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    for marker, process in processes.items():
        stdout, stderr = process.communicate(timeout=15)
        assert process.returncode == 0, f"{marker}: stdout={stdout}\nstderr={stderr}"

    assert not (caller / "fuzz-0.log").exists()
    for marker, (_, run_dir) in campaigns.items():
        other_marker = "campaign-b" if marker == "campaign-a" else "campaign-a"
        campaign_root = run_dir / "liboqs-0.14.0"
        log_dir = campaign_root / "logs"
        worker_log = log_dir / "fuzz-0.log"
        runner_log = log_dir / "smoke.log"

        assert marker in worker_log.read_text(encoding="utf-8")
        assert other_marker not in worker_log.read_text(encoding="utf-8")
        assert marker in runner_log.read_text(encoding="utf-8")
        assert other_marker not in runner_log.read_text(encoding="utf-8")

        summary = json.loads((campaign_root / "summary.json").read_text(encoding="utf-8"))
        assert summary["status"] == "completed-with-findings"
        assert summary["working_directory"] == str(log_dir.resolve())
        assert summary["resolved_paths"]["log_file"] == str(runner_log.resolve())
        assert summary["worker_logs"] == ["logs/fuzz-0.log"]
        assert summary["semantic_finding_count"] == 1
        assert summary["operation_diagnostic_count"] == 1
        assert summary["sanitizer_crash_count"] == 1
        assert summary["hang_count"] == 1
        assert summary["algorithm_list"] == [marker]
        assert summary["property_list"] == ["fake-diagnostic", "fake-property"]
        assert summary["worker_count"] == 1
        assert summary["cpu_allocation"] == "test-cpu"
        assert summary["stop_reason"] == "runs-limit"


def test_clfuzz_concurrent_campaigns_isolate_worker_logs_and_summary_paths(tmp_path: Path) -> None:
    caller = tmp_path / "caller"
    caller.mkdir()
    shared_run_dir = tmp_path / "shared-run"
    campaigns: dict[str, tuple[Path, Path]] = {}
    processes: dict[str, subprocess.Popen[str]] = {}

    for marker in ("campaign-a", "campaign-b"):
        build_dir = tmp_path / marker / "build"
        run_dir = shared_run_dir
        install_fake_clfuzz_binary(build_dir)
        campaigns[marker] = (build_dir, run_dir)
        processes[marker] = subprocess.Popen(
            [
                "bash",
                str(CLFUZZ_RUNNER),
                str(ROOT / "baselines" / "CLFuzz"),
                str(build_dir),
                str(run_dir),
                "--version",
                "0.14.0",
                "--runs",
                "1",
                "--profile",
                marker,
            ],
            cwd=caller,
            env=clfuzz_runner_env(marker),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    for marker, process in processes.items():
        stdout, stderr = process.communicate(timeout=15)
        assert process.returncode == 0, f"{marker}: stdout={stdout}\nstderr={stderr}"

    assert not (caller / "fuzz-0.log").exists()
    for marker, (_, run_dir) in campaigns.items():
        other_marker = "campaign-b" if marker == "campaign-a" else "campaign-a"
        campaign_root = run_dir / "liboqs-0.14.0" / marker
        log_dir = campaign_root / "logs"
        worker_log = log_dir / "fuzz-0.log"
        runner_log = log_dir / "smoke.log"

        assert marker in worker_log.read_text(encoding="utf-8")
        assert other_marker not in worker_log.read_text(encoding="utf-8")
        assert marker in runner_log.read_text(encoding="utf-8")
        assert other_marker not in runner_log.read_text(encoding="utf-8")

        summary = json.loads((campaign_root / "summary.json").read_text(encoding="utf-8"))
        assert summary["status"] == "completed-with-findings"
        assert summary["working_directory"] == str(log_dir.resolve())
        assert summary["resolved_paths"]["log_file"] == str(runner_log.resolve())
        assert summary["worker_logs"] == ["logs/fuzz-0.log"]
        assert summary["semantic_finding_count"] == 1
        assert summary["operation_diagnostic_count"] == 1
        assert summary["sanitizer_crash_count"] == 0
        assert summary["hang_count"] == 0
        assert summary["algorithm_list"] == [marker]
        assert summary["property_list"] == ["fake-diagnostic", "fake-property"]
        assert summary["exercised_algorithm_list"] == [marker]
        assert summary["exercised_property_list"] == ["fake-diagnostic", "fake-property"]
        assert summary["worker_count"] == 1
        assert summary["cpu_allocation"] == "test-cpu"
        assert summary["stop_reason"] == "runs-limit"
        assert summary["module_version"] == "fake-module"
        assert summary["profile"] == marker
        assert (campaign_root / "metadata" / "replay-mode.txt").read_text(encoding="utf-8") == ""


def test_clfuzz_replay_copies_fixture_and_sets_exact_replay_contract(tmp_path: Path) -> None:
    build_dir = tmp_path / "build"
    run_dir = tmp_path / "run"
    fixture = tmp_path / "ov.input"
    fixture.write_bytes(b"deterministic-clfuzz-replay-fixture")
    install_fake_clfuzz_binary(build_dir)

    result = subprocess.run(
        [
            "bash",
            str(CLFUZZ_RUNNER),
            str(ROOT / "baselines" / "CLFuzz"),
            str(build_dir),
            str(run_dir),
            "--version",
            "0.14.0",
            "--mode",
            "replay",
            "--replay-input",
            str(fixture),
            "--replay-algorithm",
            "OV-Is-pkc-skc",
            "--replay-property",
            "sig_verify_pk",
            "--replay-mutation-semantics",
            "legacy-or-one-v1",
            "--replay-attempts",
            "3",
        ],
        cwd=tmp_path,
        env=clfuzz_runner_env("replay"),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert result.returncode == 0, result.stderr
    campaign_root = run_dir / "liboqs-0.14.0" / "replay"
    summary = json.loads((campaign_root / "summary.json").read_text(encoding="utf-8"))
    replay = summary["replay"]
    copied = Path(replay["input_path"])
    assert copied.read_bytes() == fixture.read_bytes()
    assert replay["algorithm"] == "OV-Is-pkc-skc"
    assert replay["property_id"] == "sig_verify_pk"
    assert replay["mutation_semantics"] == "legacy-or-one-v1"
    assert replay["attempts"] == 3
    assert copied.parent == campaign_root / "findings" / "replay-inputs"
    assert summary["stop_reason"] == "replay-completed"
    replay_env = (campaign_root / "metadata" / "replay-env.txt").read_text(encoding="utf-8")
    assert replay_env.startswith("OV-Is-pkc-skc|sig_verify_pk|legacy-or-one-v1|3|")


def test_clfuzz_terminal_crash_artifact_is_nonzero_even_if_the_wrapper_returns_zero(tmp_path: Path) -> None:
    build_dir = tmp_path / "build"
    run_dir = tmp_path / "run"
    install_fake_clfuzz_binary(build_dir)
    env = clfuzz_runner_env("fatal")
    env["FAKE_CLFUZZ_ZERO_EXIT_CRASH"] = "1"

    result = subprocess.run(
        [
            "bash",
            str(CLFUZZ_RUNNER),
            str(ROOT / "baselines" / "CLFuzz"),
            str(build_dir),
            str(run_dir),
            "--version",
            "0.14.0",
            "--runs",
            "1",
            "--profile",
            "fatal",
        ],
        cwd=tmp_path,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert result.returncode == 77
    summary = json.loads(
        (run_dir / "liboqs-0.14.0" / "fatal" / "summary.json").read_text(encoding="utf-8")
    )
    assert summary["status"] == "target-crash"
    assert summary["exit_status"] == 0
    assert summary["effective_exit_status"] == 77
    assert summary["sanitizer_crash_count"] == 1


def test_clfuzz_replay_rejects_parallel_workers_and_runs_limits(tmp_path: Path) -> None:
    fixture = tmp_path / "fixture.bin"
    fixture.write_bytes(b"fixture")
    result = subprocess.run(
        [
            "bash",
            str(CLFUZZ_RUNNER),
            str(ROOT / "baselines" / "CLFuzz"),
            str(tmp_path / "build"),
            str(tmp_path / "run"),
            "--mode",
            "replay",
            "--replay-input",
            str(fixture),
            "--replay-algorithm",
            "OV-Is-pkc-skc",
            "--replay-property",
            "sig_verify_pk",
            "--workers",
            "2",
        ],
        cwd=tmp_path,
        env=clfuzz_runner_env("parallel-replay"),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert result.returncode == 2
    assert "requires one worker/job" in result.stderr


def test_clfuzz_replays_archived_ov_exemplar_with_legacy_mutation_semantics(tmp_path: Path) -> None:
    manifest, fixture_bytes = load_clfuzz_ov_replay_fixture()
    assert manifest["algorithm"] == "OV-Is-pkc-skc"
    assert manifest["property_id"] == "sig_verify_pk"
    assert manifest["mutation"]["historical_semantics"] == "legacy-or-one-v1"
    assert manifest["mutation"]["historical_effective_delta_hex"] == "69"
    assert int.from_bytes(fixture_bytes[20:28], "little") == manifest["selector"]

    build_dir = tmp_path / "build"
    run_dir = tmp_path / "run"
    fixture = tmp_path / "archived-ov.input"
    fixture.write_bytes(fixture_bytes)
    install_fake_clfuzz_binary(build_dir)

    result = subprocess.run(
        [
            "bash",
            str(CLFUZZ_RUNNER),
            str(ROOT / "baselines" / "CLFuzz"),
            str(build_dir),
            str(run_dir),
            "--version",
            "0.14.0",
            "--mode",
            "replay",
            "--replay-input",
            str(fixture),
            "--replay-algorithm",
            manifest["algorithm"],
            "--replay-property",
            manifest["property_id"],
            "--replay-mutation-semantics",
            manifest["mutation"]["historical_semantics"],
            "--replay-attempts",
            str(manifest["replay_attempts"]),
        ],
        cwd=tmp_path,
        env=clfuzz_runner_env("archived-ov"),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert result.returncode == 0, result.stderr
    campaign_root = run_dir / "liboqs-0.14.0" / "replay"
    summary = json.loads((campaign_root / "summary.json").read_text(encoding="utf-8"))
    replay = summary["replay"]
    copied = Path(replay["input_path"])
    assert copied.read_bytes() == fixture_bytes
    assert replay["input_sha256"] == manifest["input_sha256"]
    assert replay["algorithm"] == manifest["algorithm"]
    assert replay["property_id"] == manifest["property_id"]
    assert replay["mutation_semantics"] == manifest["mutation"]["historical_semantics"]
    assert replay["attempts"] == manifest["replay_attempts"]
    expected_relative_path = f"replay-inputs/{manifest['input_sha256']}.bin"
    replay_env = (campaign_root / "metadata" / "replay-env.txt").read_text(encoding="utf-8")
    assert replay_env == (
        f"OV-Is-pkc-skc|sig_verify_pk|legacy-or-one-v1|3|"
        f"{manifest['input_sha256']}|{expected_relative_path}\n"
    )


def test_cryptofuzz_runner_rejects_a_campaign_path_that_escapes_root(tmp_path: Path) -> None:
    build_dir = tmp_path / "build"
    run_dir = tmp_path / "run"
    install_fake_cryptofuzz_binary(build_dir)
    campaign_root = run_dir / "liboqs-0.14.0"
    outside = tmp_path / "outside"
    outside.mkdir()
    campaign_root.mkdir(parents=True)
    (campaign_root / "corpus").symlink_to(outside, target_is_directory=True)

    result = subprocess.run(
        [
            "bash",
            str(CRYPTOFUZZ_RUNNER),
            str(ROOT / "baselines" / "cryptofuzz"),
            str(build_dir),
            str(run_dir),
            "--version",
            "0.14.0",
            "--runs",
            "1",
        ],
        cwd=tmp_path,
        env=cryptofuzz_runner_env("escape"),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert result.returncode != 0
    assert "outside campaign root" in result.stderr
    assert not (outside / "seed").exists()


def test_cryptofuzz_missing_binary_writes_an_infrastructure_summary(tmp_path: Path) -> None:
    build_dir = tmp_path / "build"
    run_dir = tmp_path / "run"

    result = subprocess.run(
        [
            "bash",
            str(CRYPTOFUZZ_RUNNER),
            str(ROOT / "baselines" / "cryptofuzz"),
            str(build_dir),
            str(run_dir),
            "--version",
            "0.14.0",
            "--runs",
            "1",
        ],
        cwd=tmp_path,
        env=cryptofuzz_runner_env("missing"),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert result.returncode != 0
    summary_path = run_dir / "liboqs-0.14.0" / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["status"] == "infrastructure-failed"
    assert summary["stop_reason"] == "missing-binary"
    assert summary["exit_status"] != 0
    assert summary["resolved_paths"]["campaign_root"] == str(summary_path.parent.resolve())
    assert "binary not found" in Path(summary["log"]).read_text(encoding="utf-8")


def test_cryptofuzz_runner_rejects_output_path_override_in_extra_fuzzer_args(tmp_path: Path) -> None:
    build_dir = tmp_path / "build"
    run_dir = tmp_path / "run"
    outside = tmp_path / "outside"
    install_fake_cryptofuzz_binary(build_dir)

    result = subprocess.run(
        [
            "bash",
            str(CRYPTOFUZZ_RUNNER),
            str(ROOT / "baselines" / "cryptofuzz"),
            str(build_dir),
            str(run_dir),
            "--version",
            "0.14.0",
            "--runs",
            "1",
            f"-artifact_prefix={outside}",
        ],
        cwd=tmp_path,
        env=cryptofuzz_runner_env("override"),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert result.returncode == 2
    assert "runner-managed output path" in result.stderr
    assert not outside.exists()


def test_eval_reports_cryptofuzz_structured_findings_without_a_failure(tmp_path: Path) -> None:
    root = make_root(
        tmp_path,
        """#!/usr/bin/env bash
set -eu

if [ "$1" = cryptofuzz ] && [ "$2" = run ]; then
  output_root="${PQCDF_WORKSPACE_ROOT}/cryptofuzz/targets-run/liboqs-0.14.0"
  mkdir -p "$output_root"
  printf '%s\\n' '{"status":"completed-with-findings","normalized_outcome":"invariant_violation","stop_reason":"runs-limit","semantic_finding_count":2,"operation_diagnostic_count":3,"sanitizer_crash_count":0,"hang_count":0,"worker_count":2,"jobs":2,"cpu_allocation":"two-cpus","wall_time_seconds":1.5,"cpu_time_seconds":0.5,"operations":["OQS_KEM_SelfTest"],"algorithm_list":["fake-kem"],"property_list":["fake-property"],"module_version":"fake-module"}' > "$output_root/summary.json"
fi
""",
    )
    make_tmux(
        tmp_path,
        """
case "$1" in
  has-session)
    exit 1
    ;;
  new-session)
    launcher="${@: -1}"
    "$launcher" >/dev/null 2>&1
    exit $?
    ;;
esac
exit 0
""",
    )

    result = run_eval(
        tmp_path,
        root,
        "--campaign",
        "cryptofuzz-0.14.0",
        "--result-save-mode",
        "all",
        "--fuzzing-time",
        "1s",
        "--progress-interval",
        "1",
    )

    assert result.returncode == 0, result.stderr
    status = load_status(root, "cryptofuzz-0.14.0")
    assert status["result"] == "completed-with-findings"
    assert status["final_status"] == 0

    summary = load_summary(root)
    campaign = summary["campaigns"][0]
    assert campaign["result"] == "completed-with-findings"
    assert campaign["aggregate_status"] == 0
    assert campaign["summary_outcome"] == "completed-with-findings"
    assert campaign["semantic_finding_count"] == 2
    assert campaign["operation_diagnostic_count"] == 3
    assert campaign["worker_count"] == 2
    assert campaign["cpu_allocation"] == "two-cpus"
    assert campaign["module_version"] == "fake-module"
    assert summary["totals"] == {
        "semantic_finding_count": 2,
        "operation_diagnostic_count": 3,
        "sanitizer_crash_count": 0,
        "hang_count": 0,
    }


def test_eval_reports_clfuzz_structured_findings_without_a_failure(tmp_path: Path) -> None:
    root = make_root(
        tmp_path,
        """#!/usr/bin/env bash
set -eu

if [ "$1" = CLFuzz ] && [ "$2" = run ]; then
  output_root="${PQCDF_WORKSPACE_ROOT}/CLFuzz/targets-run/liboqs-0.14.0/full"
  mkdir -p "$output_root"
  printf '%s\\n' '{"status":"completed-with-findings","normalized_outcome":"invariant_violation","stop_reason":"runs-limit","semantic_finding_count":2,"operation_diagnostic_count":3,"sanitizer_crash_count":0,"hang_count":0,"worker_count":2,"jobs":2,"cpu_allocation":"two-cpus","wall_time_seconds":1.5,"cpu_time_seconds":0.5,"operations":["OQS_SIG_SelfTest"],"algorithm_list":["fake-sig"],"property_list":["fake-property"],"module_version":"fake-clfuzz-module"}' > "$output_root/summary.json"
fi
""",
    )
    make_tmux(
        tmp_path,
        """
case "$1" in
  has-session)
    exit 1
    ;;
  new-session)
    launcher="${@: -1}"
    "$launcher" >/dev/null 2>&1
    exit $?
    ;;
esac
exit 0
""",
    )

    result = run_eval(
        tmp_path,
        root,
        "--campaign",
        "CLFuzz-0.14.0",
        "--result-save-mode",
        "all",
        "--fuzzing-time",
        "1s",
        "--progress-interval",
        "1",
    )

    assert result.returncode == 0, result.stderr
    status = load_status(root, "CLFuzz-0.14.0")
    assert status["result"] == "completed-with-findings"
    assert status["final_status"] == 0

    summary = load_summary(root)
    campaign = summary["campaigns"][0]
    assert campaign["result"] == "completed-with-findings"
    assert campaign["aggregate_status"] == 0
    assert campaign["summary_outcome"] == "completed-with-findings"
    assert campaign["semantic_finding_count"] == 2
    assert campaign["operation_diagnostic_count"] == 3
    assert campaign["worker_count"] == 2
    assert campaign["cpu_allocation"] == "two-cpus"
    assert campaign["module_version"] == "fake-clfuzz-module"
