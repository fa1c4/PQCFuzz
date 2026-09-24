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
        metamorphic_text = metamorphic_launcher.read_text(encoding="utf-8")
        fips_text = fips_launcher.read_text(encoding="utf-8")
        assert "ORACLE_SUITE=metamorphic" in metamorphic_text
        assert "ORACLE_SUITE=fips" in fips_text
        # Hardening-only findings must not flip the campaign result.
        assert "results_have_serious_findings" in fips_text
        assert '"verdict": "NONCONFORMANT"' in fips_text
        assert "-name finding.json -print -quit" not in fips_text
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

def test_generated_compat_adapter_resolves_self_reference_right_side() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    start = script.index("pqcfuzz_get_liboqs_adapter(const char *implementation_id) {")
    end = script.index("pqcfuzz_get_pqclean_adapter(const char *implementation_id) {", start)
    kem_block = script[start:end]
    assert "kRightKem512" in kem_block
    assert "kRightKem1024" in kem_block

    start = script.index("pqcfuzz_get_liboqs_sig_adapter(const char *implementation_id) {")
    end = script.index("pqcfuzz_get_pqclean_sig_adapter(const char *implementation_id) {", start)
    sig_block = script[start:end]
    assert "kRightDsa44" in sig_block
    assert "kRightSlhDsaShake_128s" in sig_block

TMUX_STUB = """#!/usr/bin/env bash
state="${TMUX_STATE_DIR:?}"
get_val() {
  local key="$1"
  shift
  while [ "$#" -gt 0 ]; do
    if [ "$1" = "$key" ]; then
      shift
      echo "$1"
      return
    fi
    shift
  done
}
cmd="$1"
case "$cmd" in
  has-session)
    name="$(get_val -t "$@")"
    name="${name#=}"
    if [ -n "$name" ] && [ -f "$state/$name" ]; then exit 0; fi
    exit 1
    ;;
  new-session)
    name="$(get_val -s "$@")"
    if [ -n "$name" ]; then touch "$state/$name"; fi
    exit 0
    ;;
  kill-session)
    name="$(get_val -t "$@")"
    name="${name#=}"
    rm -f "$state/$name"
    echo "$name" >> "$state/kills.log"
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
"""


def test_ctrl_c_stops_started_campaign_sessions(tmp_path: Path) -> None:
    import signal
    import time

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    state_dir = tmp_path / "tmux-state"
    state_dir.mkdir()
    (bin_dir / "docker").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    (bin_dir / "tmux").write_text(TMUX_STUB, encoding="utf-8")
    (bin_dir / "docker").chmod(0o755)
    (bin_dir / "tmux").chmod(0o755)

    output_root = f"workspace/pqcfuzz_eval_sigint_test_{os.getpid()}"
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
    env["TMUX_STATE_DIR"] = str(state_dir)
    process = subprocess.Popen(
        [
            "bash",
            str(SCRIPT),
            "--full-test",
            "--versions",
            "0.14.0",
            "--output-root",
            output_root,
            "--session-prefix",
            "pqcfuzzsig",
            "--progress-interval",
            "3600",
        ],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.time() + 20
        expected = {"pqcfuzzsig-liboqs-0_14_0-metamorphic", "pqcfuzzsig-liboqs-0_14_0-fips"}
        while time.time() < deadline and not expected.issubset({p.name for p in state_dir.iterdir()}):
            time.sleep(0.1)
        assert expected.issubset({p.name for p in state_dir.iterdir()}), "sessions were not started"

        process.send_signal(signal.SIGINT)
        returncode = process.wait(timeout=20)
        assert returncode == 130

        kills = (state_dir / "kills.log").read_text(encoding="utf-8").splitlines()
        assert "pqcfuzzsig-liboqs-0_14_0-metamorphic" in kills
        assert "pqcfuzzsig-liboqs-0_14_0-fips" in kills
    finally:
        if process.poll() is None:
            process.kill()
        shutil.rmtree(REPO_ROOT / output_root, ignore_errors=True)

ARCHIVE_GUARD_TMUX_STUB = """#!/usr/bin/env bash
if [ "$1" = "has-session" ]; then
  for arg in "$@"; do
    if [ "$arg" = "=pqcfuzzguard-liboqs-0_14_0-metamorphic" ]; then exit 0; fi
  done
  exit 1
fi
exit 0
"""


def test_live_indexed_session_blocks_restart_and_archive(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    (bin_dir / "tmux").write_text(ARCHIVE_GUARD_TMUX_STUB, encoding="utf-8")
    (bin_dir / "docker").chmod(0o755)
    (bin_dir / "tmux").chmod(0o755)

    output_root = f"workspace/pqcfuzz_eval_guard_test_{os.getpid()}"
    root = REPO_ROOT / output_root
    status_dir = root / "status"
    status_dir.mkdir(parents=True)
    (status_dir / "campaigns.tsv").write_text(
        "campaign\tversion\tsession_name\tworkspace_root\tworkspace_root_abs\tlog_file\tlog_file_abs\tstatus_file\tstatus_file_abs\n"
        "liboqs-0.14.0-metamorphic\t0.14.0\tpqcfuzzguard-liboqs-0_14_0-metamorphic\t"
        f"{output_root}/campaigns/liboqs-0.14.0-metamorphic/workspace\t/abs/ws\tlog\t/abs/log\tstatus\t/abs/status.json\n",
        encoding="utf-8",
    )

    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
    result = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "--oracle-suite",
            "fips",
            "--versions",
            "0.14.0",
            "--output-root",
            output_root,
            "--session-prefix",
            "pqcfuzzguard",
        ],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
    )

    try:
        assert result.returncode == 2
        assert "has a live campaign session" in result.stderr
        assert "pqcfuzzguard-liboqs-0_14_0-metamorphic" in result.stderr
        assert root.is_dir()
        assert (status_dir / "campaigns.tsv").is_file()
    finally:
        shutil.rmtree(root, ignore_errors=True)
