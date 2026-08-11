"""Mapping and classification tests for the cryptoTesting reproduction audit.

These tests verify that the vendored cryptoTesting harness schedules all paper
report-name tests, that the paper test mapping is faithful, and that the
classification rules match the paper.  No Docker or long fuzzing required.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "scripts" / "cryptoTesting_paper_counts.py"

SPEC = importlib.util.spec_from_file_location("cryptoTesting_paper_counts_mapping", MODULE_PATH)
assert SPEC and SPEC.loader
PC = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PC
SPEC.loader.exec_module(PC)

BASELINE_DIR = REPO_ROOT / "baselines" / "cryptoTesting"
FUZZ_LIBOQS = BASELINE_DIR / "fuzz_liboqs.py"


# --------------------------------------------------------------------------
# The 13 paper report-name tests that the harness must schedule
# --------------------------------------------------------------------------

REQUIRED_REPORT_NAMES = [
    "KEM/Keygen/badrng",
    "KEM/Encaps/pk-0",
    "KEM/Encaps/pk",
    "KEM/Encaps/badrng",
    "KEM/Decaps/sk",
    "KEM/Decaps/c",
    "SIGN/Keygen/badrng",
    "SIGN/Sign/sk",
    "SIGN/Sign/m",
    "SIGN/Sign/badrng",
    "SIGN/Verify/pk",
    "SIGN/Verify/m",
    "SIGN/Verify/sig",
]


def test_harness_schedules_all_paper_tests():
    text = FUZZ_LIBOQS.read_text(encoding="utf-8")
    testpaths = re.search(r"TESTPATHS\s*=\s*\(([^)]*)\)", text, re.DOTALL).group(1)
    scheduled = set()
    for m in re.finditer(r'"([^"]*liboqs/([^"]+))"', testpaths):
        scheduled.add(m.group(2))
    for name in REQUIRED_REPORT_NAMES:
        assert name in scheduled, f"harness missing paper test {name!r}"


def test_report_name_set_matches_paper_map():
    assert set(REQUIRED_REPORT_NAMES) == set(PC.REPORT_TO_PAPER.keys())


# --------------------------------------------------------------------------
# Paper test number mapping (Tests 2-13) from the README / plan
# --------------------------------------------------------------------------

@pytest.mark.parametrize("report_name,paper_num", [
    ("KEM/Keygen/badrng", 2),
    ("SIGN/Keygen/badrng", 2),
    ("KEM/Encaps/pk-0", 3),
    ("KEM/Encaps/pk", 4),
    ("KEM/Encaps/badrng", 5),
    ("KEM/Decaps/sk", 6),
    ("KEM/Decaps/c", 7),
    ("SIGN/Sign/sk", 8),
    ("SIGN/Sign/m", 9),
    ("SIGN/Sign/badrng", 10),
    ("SIGN/Verify/pk", 11),
    ("SIGN/Verify/m", 12),
    ("SIGN/Verify/sig", 13),
])
def test_report_to_paper_mapping(report_name, paper_num):
    assert PC.REPORT_TO_PAPER[report_name] == paper_num


# --------------------------------------------------------------------------
# Version target mapping from the README
# --------------------------------------------------------------------------

@pytest.mark.parametrize("version,target", [
    ("0.14.0", "ches_liboqs"),
    ("0.8.0", "cur_liboqs"),
    ("0.4.0", "mid_liboqs"),
    ("2018-11", "old_liboqs"),
])
def test_version_target_mapping(version, target):
    assert PC.VERSION_TARGET_MAP[version] == target
    assert PC.TARGET_TO_VERSION[target] == version


# --------------------------------------------------------------------------
# Maul.c / Match.c semantics are faithful to the paper (source audit)
# --------------------------------------------------------------------------

def test_maul_implements_single_bit_flip():
    maul = BASELINE_DIR / "tech" / "paper_fuzzing" / "liboqs" / "Maul.c"
    text = maul.read_text(encoding="utf-8")
    # Single-bit flip via XOR of (128 >> mask_bit) at mask_byte.
    assert "^" in text and "128 >> mask_bit" in text
    # Sigma stepping with one_more bound by 8 * BufBytelen.
    assert "8 * BufBytelen" in text or "8*BufBytelen" in text
    # Expected result derived from label equality.
    assert "EQ" in text and "DIFF" in text


def test_match_crashes_only_on_mismatch():
    match = BASELINE_DIR / "tech" / "paper_fuzzing" / "liboqs" / "Match.c"
    text = match.read_text(encoding="utf-8")
    assert "y_equals_yp != exp_res" in text
    assert "abort()" in text


def test_verify_sig_maul_includes_signature_length_field():
    maul = BASELINE_DIR / "tech" / "paper_fuzzing" / "liboqs" / "SIGN" / "Verify" / "sig" / "Maul.py"
    text = maul.read_text(encoding="utf-8")
    assert "signature_len" in text
    # The length field is mauled first (sigma < signature_len), then the buffer.
    assert "maul the signature length" in text
    assert "maul the signature buffer" in text


def test_badrng_maul_uses_fixed_rng_iteration():
    maul = BASELINE_DIR / "tech" / "paper_fuzzing" / "liboqs" / "KEM" / "Encaps" / "badrng" / "Maul.py"
    text = maul.read_text(encoding="utf-8")
    # Bad-randomness iterates sigma over RNG byte values with expected DIFF.
    assert "256**len(x)" in text
    assert "lbl = DIFF" in text


# --------------------------------------------------------------------------
# BLACKLIST status: full-run mode for paper-complete reproduction
# --------------------------------------------------------------------------

def test_blacklist_is_empty_for_full_run():
    info = PC.detect_blacklist(FUZZ_LIBOQS)
    assert info["is_full_run"], "BLACKLIST must be empty for paper-complete reproduction"
    assert info["blacklist"] == []


# --------------------------------------------------------------------------
# Paper Table 3 targets are internally consistent
# --------------------------------------------------------------------------

def test_table3_targets_are_deduplicated_counts():
    # Every Table 3 entry's expected count must be a positive integer (or 0 for
    # the non-malleability columns the paper reports as 0).
    for (ver, test, bucket, subtype, exp, note) in PC.PAPER_TABLE3:
        assert isinstance(exp, int) and exp >= 0
        assert ver in PC.VERSION_TARGET_MAP
        assert test in PC.REPORT_TO_PAPER
        assert bucket in ("malleability", "crash_hang", "non_malleability")
        assert subtype in PC.OUTCOME_SUBTYPES


def test_table3_covers_three_supported_versions():
    versions = {e[0] for e in PC.PAPER_TABLE3}
    assert {"0.14.0", "0.8.0", "0.4.0"}.issubset(versions)
    assert "2018-11" not in versions  # out of current wrapper scope


# --------------------------------------------------------------------------
# Counting rule: dedup by version + algorithm + test + outcome bucket + subtype
# --------------------------------------------------------------------------

def test_dedup_key_excludes_raw_bitflip_offset():
    rows = [
        {"name": "Kyber-512", "test": "KEM/Decaps/sk", "expected": "unequal",
         "x_xor_xp": f"{offset:064x}", "gotten": "equal"}
        for offset in range(64)
    ]
    norm = PC.normalize_rows(rows)
    assert len(norm) == 1
    assert norm[0]["raw_evidence_count"] == 64
    # The paper_count_key must not include the raw bit-flip offset.
    assert "x_xor_xp" not in norm[0]["paper_count_key"]
    counts = PC.paper_counts_by_key(norm)
    assert counts[("unknown", "KEM/Decaps/sk", "malleability", "maul")] == 1


def test_crash_subtypes_deduplicated_independently():
    rows = [
        {"name": "Picnic-L1-FS", "test": "SIGN/Sign/sk", "error": "heap-buffer-overflow"},
        {"name": "Picnic-L1-FS", "test": "SIGN/Sign/sk", "error": "heap-buffer-overflow"},
        {"name": "Picnic-L1-FS", "test": "SIGN/Sign/sk", "error": "hang"},
    ]
    norm = PC.normalize_rows(rows)
    # Two distinct (bucket, subtype) groups: heapoverflow and hang.
    assert len(norm) == 2
    subtypes = {d["outcome_subtype"] for d in norm}
    assert subtypes == {"heapoverflow", "hang"}
