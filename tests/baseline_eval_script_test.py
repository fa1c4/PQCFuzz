import json
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVAL_SCRIPT = ROOT / "scripts" / "eval_baselines_fuzzing.sh"


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


def run_eval(tmp_path: Path, root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(EVAL_SCRIPT), *args],
        cwd=ROOT,
        env=env_with_temp_root(tmp_path, root),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


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


def test_campaign_filter_rejects_unknown_campaign(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    result = run_eval(tmp_path, root, "--dry-run", "--campaign", "unknown-0.14.0")

    assert result.returncode == 2
    assert "unknown campaign 'unknown-0.14.0'" in result.stderr


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
