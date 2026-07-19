from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_generated_launcher_template_closes_summary_python_before_shell_helpers() -> None:
    script = (REPO_ROOT / "scripts" / "pqcfuzz_eval.sh").read_text(encoding="utf-8")
    summary_start = script.index("write_run_summary() {")
    manifest_start = script.index("write_replay_manifest() {", summary_start)
    summary_body = script[summary_start:manifest_start]

    assert 'with open(path, "w", encoding="utf-8") as f:' in summary_body
    assert "\nPY\n}\n" in summary_body
    assert 'if ! bash -n "${LAUNCHER_FILE_BY_ID[$campaign]}"; then' in script


def test_launcher_collects_sanitizer_findings_and_honors_the_sanitizer_profile() -> None:
    script = (REPO_ROOT / "scripts" / "pqcfuzz_eval.sh").read_text(encoding="utf-8")

    assert "scripts/collect_sanitizer_findings.py" in script
    assert 'LIBOQS_SANITIZER_FLAGS="-fsanitize=fuzzer-no-link,${SANITIZERS}"' in script
    assert 'FUZZER_SANITIZER_FLAGS="-fsanitize=fuzzer,${SANITIZERS}"' in script
    assert "run_mldsa_empty_context_regression" in script
    assert "detect_leaks=1" in script
    assert 'finish_campaign "completed-with-findings" 0' in script
