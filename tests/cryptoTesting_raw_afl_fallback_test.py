"""Tests for the raw AFL fallback path parser in cryptoTesting_paper_counts.

These tests verify that nested cryptoTesting raw AFL paths are correctly parsed
to recover paper property, paper test number, algorithm, and artifact kind.
No Docker or long fuzzing required.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "scripts" / "cryptoTesting_paper_counts.py"

SPEC = importlib.util.spec_from_file_location("cryptoTesting_paper_counts", MODULE_PATH)
assert SPEC and SPEC.loader
PC = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PC
SPEC.loader.exec_module(PC)


# --------------------------------------------------------------------------
# Helper to build synthetic raw AFL trees
# --------------------------------------------------------------------------

def make_afl_tree(base: Path) -> Path:
    """Create a synthetic raw AFL tree under ``base/afl`` and return ``base``."""
    afl = base / "afl"

    # KEM/Decaps/c/14/fuzzoutputs/default/crashes/id:000001
    crash_dir = afl / "KEM" / "Decaps" / "c" / "14" / "fuzzoutputs" / "default" / "crashes"
    crash_dir.mkdir(parents=True, exist_ok=True)
    (crash_dir / "id:000001,sig:06,src:000000").write_bytes(b"\x00")
    (afl / "KEM" / "Decaps" / "c" / "14" / "alg.txt").write_text("NTRU-HRSS-701\n")

    # SIGN/Verify/sig/Falcon-512/fuzzoutputs/default/hangs/id:000002
    hang_dir = afl / "SIGN" / "Verify" / "sig" / "Falcon-512" / "fuzzoutputs" / "default" / "hangs"
    hang_dir.mkdir(parents=True, exist_ok=True)
    (hang_dir / "id:000002,src:000000").write_bytes(b"\x00")
    (afl / "SIGN" / "Verify" / "sig" / "Falcon-512" / "alg.txt").write_text("Falcon-512\n")

    # KEM/Encaps/badrng/sntrup761/metadata/setup-timeout/GenInput.json
    # (Note: in the real tree this is under fuzzoutputs/default/setup-timeout/)
    setup_dir = afl / "KEM" / "Encaps" / "badrng" / "sntrup761" / "fuzzoutputs" / "default" / "setup-timeout"
    setup_dir.mkdir(parents=True, exist_ok=True)
    (setup_dir / "GenInput.json").write_text('{"category":"setup-timeout"}')
    (afl / "KEM" / "Encaps" / "badrng" / "sntrup761" / "alg.txt").write_text("sntrup761\n")

    # KEM/Decaps/sk/Kyber512/fuzzinputs/default/queue/id:000000
    queue_dir = afl / "KEM" / "Decaps" / "sk" / "Kyber512" / "fuzzinputs" / "default" / "queue"
    queue_dir.mkdir(parents=True, exist_ok=True)
    (queue_dir / "id:000000,orig:clean_input.bin").write_bytes(b"\x00")
    (afl / "KEM" / "Decaps" / "sk" / "Kyber512" / "alg.txt").write_text("Kyber512\n")

    # An unrecognized path: afl/other/random/file
    other_dir = afl / "other" / "random"
    other_dir.mkdir(parents=True, exist_ok=True)
    (other_dir / "file").write_bytes(b"\x00")

    # metadata for version inference
    meta_dir = base / "metadata"
    meta_dir.mkdir(parents=True, exist_ok=True)
    (meta_dir / "campaign.json").write_text(json.dumps({"version": "0.4.0"}))

    return base


# --------------------------------------------------------------------------
# Test 1: crash artifact under KEM/Decaps/c
# --------------------------------------------------------------------------

def test_parse_crash_kem_decaps_c():
    afl_root = Path("/tmp/test_afl/afl")
    path = afl_root / "KEM" / "Decaps" / "c" / "14" / "fuzzoutputs" / "default" / "crashes" / "id:000001"
    info = PC.parse_afl_artifact_path(path, afl_root)
    assert info is not None
    assert info.property == "KEM/Decaps/c"
    assert info.paper_test_number == 7
    assert info.algorithm == "14"
    assert info.artifact_kind == "crash"


# --------------------------------------------------------------------------
# Test 2: hang artifact under SIGN/Verify/sig
# --------------------------------------------------------------------------

def test_parse_hang_sign_verify_sig():
    afl_root = Path("/tmp/test_afl/afl")
    path = afl_root / "SIGN" / "Verify" / "sig" / "Falcon-512" / "fuzzoutputs" / "default" / "hangs" / "id:000002"
    info = PC.parse_afl_artifact_path(path, afl_root)
    assert info is not None
    assert info.property == "SIGN/Verify/sig"
    assert info.paper_test_number == 13
    assert info.algorithm == "Falcon-512"
    assert info.artifact_kind == "hang"


# --------------------------------------------------------------------------
# Test 3: setup-timeout artifact under KEM/Encaps/badrng
# --------------------------------------------------------------------------

def test_parse_setup_timeout_kem_encaps_badrng():
    afl_root = Path("/tmp/test_afl/afl")
    path = afl_root / "KEM" / "Encaps" / "badrng" / "sntrup761" / "fuzzoutputs" / "default" / "setup-timeout" / "GenInput.json"
    info = PC.parse_afl_artifact_path(path, afl_root)
    assert info is not None
    assert info.property == "KEM/Encaps/badrng"
    assert info.paper_test_number == 5
    assert info.artifact_kind == "setup_timeout"


# --------------------------------------------------------------------------
# Test 4: queue artifact under KEM/Decaps/sk (not a finding)
# --------------------------------------------------------------------------

def test_parse_queue_kem_decaps_sk():
    afl_root = Path("/tmp/test_afl/afl")
    path = afl_root / "KEM" / "Decaps" / "sk" / "Kyber512" / "fuzzinputs" / "default" / "queue" / "id:000000"
    info = PC.parse_afl_artifact_path(path, afl_root)
    assert info is not None
    assert info.property == "KEM/Decaps/sk"
    assert info.paper_test_number == 6
    assert info.artifact_kind == "queue"


# --------------------------------------------------------------------------
# Test 5: unrecognized path returns None
# --------------------------------------------------------------------------

def test_parse_unrecognized_path_returns_none():
    afl_root = Path("/tmp/test_afl/afl")
    path = afl_root / "other" / "random" / "file"
    info = PC.parse_afl_artifact_path(path, afl_root)
    assert info is None


def test_parse_path_outside_afl_root_returns_none():
    afl_root = Path("/tmp/test_afl/afl")
    path = Path("/tmp/elsewhere/file")
    info = PC.parse_afl_artifact_path(path, afl_root)
    assert info is None


# --------------------------------------------------------------------------
# Test 6: synthetic raw-only result root emits paper_count_key rows
# --------------------------------------------------------------------------

def test_raw_only_result_root_emits_paper_count(tmp_path):
    root = make_afl_tree(tmp_path / "raw_only")
    rows = PC.read_raw_manifest(root, diagnostics=False)
    # Should recover crash and hang rows (but not setup-timeout or queue).
    crash_hang_rows = [r for r in rows if r["error"] in ("hang", "other")]
    assert len(crash_hang_rows) >= 2
    tests = {r["test"] for r in crash_hang_rows}
    assert "KEM/Decaps/c" in tests
    assert "SIGN/Verify/sig" in tests

    # Setup-timeout must NOT be counted as a target hang.
    hang_rows = [r for r in rows if r["error"] == "hang"]
    for r in hang_rows:
        assert r["test"] != "KEM/Encaps/badrng" or r["name"] != "sntrup761"

    # Normalizing should produce paper_count_key rows.
    normalized = PC.normalize_rows(rows)
    assert len(normalized) >= 2
    keys = {(d["report_test_name"], d["outcome_bucket"]) for d in normalized}
    assert ("KEM/Decaps/c", "crash_hang") in keys
    assert ("SIGN/Verify/sig", "crash_hang") in keys


# --------------------------------------------------------------------------
# Test: setup-timeout is NOT counted as hang
# --------------------------------------------------------------------------

def test_setup_timeout_not_counted_as_hang(tmp_path):
    root = make_afl_tree(tmp_path / "setup_test")
    rows = PC.read_raw_manifest(root, diagnostics=True)
    diag = rows.raw_afl_diagnostics
    setup_diags = [d for d in diag if d["artifact_kind"] == "setup_timeout"]
    assert len(setup_diags) >= 1
    for d in setup_diags:
        assert d["counted"] == "no"


# --------------------------------------------------------------------------
# Test: diagnostics output has correct schema
# --------------------------------------------------------------------------

def test_diagnostics_schema(tmp_path):
    root = make_afl_tree(tmp_path / "diag_test")
    rows = PC.read_raw_manifest(root, diagnostics=True)
    diag = rows.raw_afl_diagnostics
    assert len(diag) > 0
    required_cols = {"path", "recognized", "property", "paper_test_number",
                     "algorithm", "artifact_kind", "counted", "reason"}
    for d in diag:
        assert required_cols.issubset(d.keys())


# --------------------------------------------------------------------------
# Test: algorithm names with hyphens/underscores/numbers are handled
# --------------------------------------------------------------------------

@pytest.mark.parametrize("alg_name", [
    "NTRU-HRSS-701",
    "ML-KEM-768",
    "Kyber512",
    "Falcon-512",
    "SPHINCS+-SHA256-192f-robust",
    "cross-rsdp-128-balanced",
])
def test_algorithm_name_tolerated(alg_name):
    afl_root = Path("/tmp/test_afl/afl")
    path = afl_root / "KEM" / "Decaps" / "c" / alg_name / "fuzzoutputs" / "default" / "crashes" / "id:000001"
    info = PC.parse_afl_artifact_path(path, afl_root)
    assert info is not None
    assert info.algorithm == alg_name


# --------------------------------------------------------------------------
# Test: PAPER_PROPERTY_MAP covers all Tests 2-13
# --------------------------------------------------------------------------

def test_paper_property_map_covers_all_tests():
    expected = {
        "KEM/Keygen/badrng", "KEM/Encaps/pk-0", "KEM/Encaps/pk",
        "KEM/Encaps/badrng", "KEM/Decaps/sk", "KEM/Decaps/c",
        "SIGN/Keygen/badrng", "SIGN/Sign/sk", "SIGN/Sign/m",
        "SIGN/Sign/badrng", "SIGN/Verify/pk", "SIGN/Verify/m",
        "SIGN/Verify/sig",
    }
    assert set(PC.PAPER_PROPERTY_MAP.keys()) == expected
