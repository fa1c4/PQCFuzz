from __future__ import annotations

import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from triage.sanitizer_evidence import fingerprint_payload


def test_same_sanitizer_class_different_stable_frames_do_not_match() -> None:
    a = (REPO_ROOT / "tests/fixtures/asan_same_class_different_frames_a.txt").read_text(encoding="utf-8")
    b = (REPO_ROOT / "tests/fixtures/asan_same_class_different_frames_b.txt").read_text(encoding="utf-8")

    assert fingerprint_payload(a)["sanitizer"] == fingerprint_payload(b)["sanitizer"] == "address"
    assert fingerprint_payload(a)["subtype"] == fingerprint_payload(b)["subtype"] == "heap-use-after-free"
    assert fingerprint_payload(a)["fingerprint"] != fingerprint_payload(b)["fingerprint"]


def test_address_pid_and_temp_path_changes_do_not_change_fingerprint() -> None:
    original = (REPO_ROOT / "tests/fixtures/asan_same_class_different_frames_a.txt").read_text(encoding="utf-8")
    variant = (
        original.replace("==12345==", "==99999==")
        .replace("0x603000000040", "0xabcdef123456")
        .replace("/tmp/build-a/", "/tmp/other-random-build/")
        .replace(":42:7", ":100:2")
    )

    assert fingerprint_payload(original)["fingerprint"] == fingerprint_payload(variant)["fingerprint"]


def test_cli_prints_fingerprint_for_fixture() -> None:
    fixture = REPO_ROOT / "tests/fixtures/asan_same_class_different_frames_a.txt"
    completed = subprocess.run(
        [sys.executable, "src/triage/sanitizer_evidence.py", str(fixture), "--algorithm", "ML-KEM-768"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=True,
    )

    assert "sha256:" in completed.stdout
    assert "heap-use-after-free" in completed.stdout
