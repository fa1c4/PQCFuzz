"""Tests for the cryptoTesting paper-level bug locator.

These tests verify the classification rules (A-I), source trace helpers, and
output generation. No Docker or long fuzzing required.
"""

from __future__ import annotations

import csv
import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "scripts" / "cryptoTesting_bug_locator.py"

SPEC = importlib.util.spec_from_file_location("cryptoTesting_bug_locator", MODULE_PATH)
assert SPEC and SPEC.loader
BL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BL
SPEC.loader.exec_module(BL)

SOURCE_ROOT = REPO_ROOT / "third_party"


# --------------------------------------------------------------------------
# Source trace helpers
# --------------------------------------------------------------------------

def test_source_root_for_version():
    p = BL.source_root_for_version(SOURCE_ROOT, "0.4.0")
    assert p.is_dir()
    assert p.name == "liboqs-0.4.0"


def test_find_source_path_ntru():
    p = BL.find_source_path(SOURCE_ROOT, "NTRU-HRSS-701", "0.4.0")
    assert p is not None and p.is_dir()
    assert "ntru" in str(p)


def test_find_source_path_falcon():
    for ver in ("0.4.0", "0.8.0", "0.14.0"):
        p = BL.find_source_path(SOURCE_ROOT, "Falcon-512", ver)
        assert p is not None and p.is_dir(), f"Falcon source missing for {ver}"


def test_find_source_path_missing_returns_none():
    p = BL.find_source_path(SOURCE_ROOT, "NonExistent-Alg", "0.4.0")
    assert p is None


def test_source_trace_status():
    assert BL.source_trace_status(None) == "missing_source_path"
    p = BL.find_source_path(SOURCE_ROOT, "NTRU-HRSS-701", "0.4.0")
    assert BL.source_trace_status(p) == "source_path_exists_but_lines_unverified"


# --------------------------------------------------------------------------
# Rule A: NTRU 0.4.0 IND-CCA
# --------------------------------------------------------------------------

@pytest.mark.parametrize("alg", ["NTRU-HRSS-701", "NTRU-HPS-2048-677", "NTRU-HPS-2048-509"])
def test_rule_a_ntru_ind_cca(alg):
    row = {"version": "0.4.0", "algorithm": alg, "test_id": "KEM/Decaps/c",
           "paper_test_number": 7, "outcome_bucket": "malleability", "outcome_subtype": "maul"}
    cls = BL.classify(row, SOURCE_ROOT)
    assert cls.paper_category == "CONFIRMED_SECURITY_NOTION_COUNTEREXAMPLE"
    assert "IND-CCA" in cls.paper_claim
    assert cls.confidence in ("HIGH", "MEDIUM")


def test_rule_a_does_not_match_pk_sk_mauling():
    """NTRU pk/sk mauling must NOT be classified by Rule A."""
    row = {"version": "0.4.0", "algorithm": "NTRU-HRSS-701", "test_id": "KEM/Decaps/sk",
           "paper_test_number": 6, "outcome_bucket": "malleability", "outcome_subtype": "maul"}
    cls = BL.classify(row, SOURCE_ROOT)
    assert cls.paper_category != "CONFIRMED_SECURITY_NOTION_COUNTEREXAMPLE" or "IND-CCA" not in cls.paper_claim


# --------------------------------------------------------------------------
# Rule B: Falcon sUF-CMA
# --------------------------------------------------------------------------

@pytest.mark.parametrize("alg", ["Falcon-512", "Falcon-1024", "Falcon-padded-1024"])
def test_rule_b_falcon_suf_cma(alg):
    row = {"version": "0.14.0", "algorithm": alg, "test_id": "SIGN/Verify/sig",
           "paper_test_number": 13, "outcome_bucket": "malleability", "outcome_subtype": "maul"}
    cls = BL.classify(row, SOURCE_ROOT)
    assert cls.paper_category == "CONFIRMED_SECURITY_NOTION_COUNTEREXAMPLE"
    assert "sUF-CMA" in cls.paper_claim or "non-canonical" in cls.paper_claim


def test_rule_b_distinguished_from_verify_pk():
    row = {"version": "0.14.0", "algorithm": "Falcon-512", "test_id": "SIGN/Verify/pk",
           "paper_test_number": 11, "outcome_bucket": "malleability", "outcome_subtype": "maul"}
    cls = BL.classify(row, SOURCE_ROOT)
    assert cls.paper_category != "CONFIRMED_SECURITY_NOTION_COUNTEREXAMPLE" or "sUF-CMA" not in cls.paper_claim


# --------------------------------------------------------------------------
# Rule C: CROSS / SNOVA
# --------------------------------------------------------------------------

def test_rule_c_cross():
    row = {"version": "0.14.0", "algorithm": "cross-rsdp-128-balanced", "test_id": "SIGN/Verify/sig",
           "paper_test_number": 13, "outcome_bucket": "malleability", "outcome_subtype": "maul"}
    cls = BL.classify(row, SOURCE_ROOT)
    assert cls.paper_category == "CONFIRMED_SECURITY_NOTION_COUNTEREXAMPLE"
    assert cls.source_trace_status == "needs_manual_review"


def test_rule_c_snova():
    row = {"version": "0.14.0", "algorithm": "SNOVA-128-25-4", "test_id": "SIGN/Verify/sig",
           "paper_test_number": 13, "outcome_bucket": "malleability", "outcome_subtype": "maul"}
    cls = BL.classify(row, SOURCE_ROOT)
    assert cls.paper_category == "CONFIRMED_SECURITY_NOTION_COUNTEREXAMPLE"


# --------------------------------------------------------------------------
# Rule D: Picnic crashes
# --------------------------------------------------------------------------

def test_rule_d_picnic_crash():
    row = {"version": "0.4.0", "algorithm": "Picnic-L1-FS", "test_id": "SIGN/Sign/sk",
           "paper_test_number": 8, "outcome_bucket": "crash_hang", "outcome_subtype": "heapoverflow"}
    cls = BL.classify(row, SOURCE_ROOT)
    assert cls.paper_category == "CONFIRMED_SOFTWARE_BUG"
    assert cls.confidence == "HIGH"


def test_rule_d_picnic_malleability_not_software_bug():
    """Malleability without crash evidence must not trigger Rule D."""
    row = {"version": "0.4.0", "algorithm": "Picnic-L1-FS", "test_id": "SIGN/Sign/sk",
           "paper_test_number": 8, "outcome_bucket": "malleability", "outcome_subtype": "maul"}
    cls = BL.classify(row, SOURCE_ROOT)
    assert cls.paper_category != "CONFIRMED_SOFTWARE_BUG"


# --------------------------------------------------------------------------
# Rule E: SIKE/SIDH segfaults
# --------------------------------------------------------------------------

def test_rule_e_sike_segfault():
    row = {"version": "0.4.0", "algorithm": "SIDH-p434-compressed", "test_id": "KEM/Encaps/pk",
           "paper_test_number": 4, "outcome_bucket": "crash_hang", "outcome_subtype": "segfault"}
    cls = BL.classify(row, SOURCE_ROOT)
    assert cls.paper_category == "CONFIRMED_SOFTWARE_BUG"


# --------------------------------------------------------------------------
# Rule F: Bad-RNG hangs
# --------------------------------------------------------------------------

@pytest.mark.parametrize("ptn,test_id", [(2, "KEM/Keygen/badrng"), (5, "KEM/Encaps/badrng"), (10, "SIGN/Sign/badrng")])
def test_rule_f_bad_rng_hang(ptn, test_id):
    row = {"version": "0.4.0", "algorithm": "SomeAlg", "test_id": test_id,
           "paper_test_number": ptn, "outcome_bucket": "crash_hang", "outcome_subtype": "hang"}
    cls = BL.classify(row, SOURCE_ROOT)
    assert cls.paper_category == "BAD_RNG_ROBUSTNESS_ISSUE"
    assert "robustness" in cls.paper_claim.lower() or "bad randomness" in cls.paper_claim.lower()


# --------------------------------------------------------------------------
# Rule G: FO transform secret-key features
# --------------------------------------------------------------------------

@pytest.mark.parametrize("alg", ["Kyber512", "ML-KEM-768", "NewHope-512-CCA", "FrodoKEM-640-AES",
                                  "BIKE1-L1-CPA", "Classic-McEliece-348864", "Saber-Light-SABER"])
def test_rule_g_fo_transform(alg):
    row = {"version": "0.4.0", "algorithm": alg, "test_id": "KEM/Decaps/sk",
           "paper_test_number": 6, "outcome_bucket": "malleability", "outcome_subtype": "maul"}
    cls = BL.classify(row, SOURCE_ROOT)
    assert cls.paper_category == "UNEXPECTED_BUT_ALLOWED_FEATURE"


# --------------------------------------------------------------------------
# Rule H: Dilithium
# --------------------------------------------------------------------------

def test_rule_h_dilithium_feature():
    row = {"version": "0.4.0", "algorithm": "Dilithium2", "test_id": "SIGN/Sign/sk",
           "paper_test_number": 8, "outcome_bucket": "malleability", "outcome_subtype": "maul"}
    cls = BL.classify(row, SOURCE_ROOT)
    assert cls.paper_category == "UNEXPECTED_BUT_ALLOWED_FEATURE"


def test_rule_h_ml_dsa_inconclusive():
    row = {"version": "0.14.0", "algorithm": "ML-DSA-44", "test_id": "SIGN/Sign/sk",
           "paper_test_number": 8, "outcome_bucket": "malleability", "outcome_subtype": "maul"}
    cls = BL.classify(row, SOURCE_ROOT)
    assert cls.paper_category == "INCONCLUSIVE"
    assert "multi-message" in cls.paper_claim.lower()


# --------------------------------------------------------------------------
# Rule I: Harness artifacts
# --------------------------------------------------------------------------

def test_rule_i_setup_timeout():
    row = {"version": "0.4.0", "algorithm": "SomeAlg", "test_id": "KEM/Keygen/badrng",
           "paper_test_number": 2, "outcome_bucket": "crash_hang", "outcome_subtype": "setup_timeout"}
    cls = BL.classify(row, SOURCE_ROOT)
    assert cls.paper_category == "HARNESS_ARTIFACT"


# --------------------------------------------------------------------------
# Default rule
# --------------------------------------------------------------------------

def test_default_rule_inconclusive():
    row = {"version": "0.8.0", "algorithm": "SomeUnknownAlg", "test_id": "SIGN/Verify/m",
           "paper_test_number": 12, "outcome_bucket": "malleability", "outcome_subtype": "maul"}
    cls = BL.classify(row, SOURCE_ROOT)
    assert cls.paper_category == "INCONCLUSIVE"
    assert cls.confidence == "LOW"


# --------------------------------------------------------------------------
# Integration: build_locator_rows + output generation
# --------------------------------------------------------------------------

def test_build_locator_rows(tmp_path):
    paper_rows = [
        {"liboqs_version": "0.4.0", "algorithm": "NTRU-HRSS-701", "report_test_name": "KEM/Decaps/c",
         "paper_test_number": "7", "outcome_bucket": "malleability", "outcome_subtype": "maul",
         "raw_evidence_count": "5", "library": "liboqs", "source_report_path": "/tmp/test.db",
         "representative_artifact": "/tmp/test.db", "representative_report_row": ""},
        {"liboqs_version": "0.14.0", "algorithm": "Falcon-512", "report_test_name": "SIGN/Verify/sig",
         "paper_test_number": "13", "outcome_bucket": "malleability", "outcome_subtype": "maul",
         "raw_evidence_count": "3", "library": "liboqs", "source_report_path": "/tmp/test.db",
         "representative_artifact": "/tmp/test.db", "representative_report_row": ""},
    ]
    rows = BL.build_locator_rows(paper_rows, SOURCE_ROOT)
    assert len(rows) == 2
    assert rows[0]["paper_category"] == "CONFIRMED_SECURITY_NOTION_COUNTEREXAMPLE"
    assert rows[1]["paper_category"] == "CONFIRMED_SECURITY_NOTION_COUNTEREXAMPLE"
    # Check required fields.
    for field in BL.BUG_LOCATOR_FIELDS:
        assert field in rows[0], f"missing field: {field}"


def test_full_output_generation(tmp_path):
    paper_rows = [
        {"liboqs_version": "0.4.0", "algorithm": "NTRU-HRSS-701", "report_test_name": "KEM/Decaps/c",
         "paper_test_number": "7", "outcome_bucket": "malleability", "outcome_subtype": "maul",
         "raw_evidence_count": "5", "library": "liboqs", "source_report_path": "/tmp/test.db",
         "representative_artifact": "/tmp/test.db", "representative_report_row": ""},
    ]
    rows = BL.build_locator_rows(paper_rows, SOURCE_ROOT)
    BL.write_tsv(tmp_path / "bug_locator.tsv", rows, BL.BUG_LOCATOR_FIELDS)
    BL.write_root_cause_review(tmp_path / "root_cause_review.md", rows)
    BL.write_confirmed_paper_bugs(tmp_path / "confirmed_paper_bugs.md", rows)
    BL.write_unexpected_features(tmp_path / "unexpected_features.md", rows)
    BL.write_harness_artifacts(tmp_path / "harness_artifacts.md", rows)
    BL.write_inconclusive(tmp_path / "inconclusive_or_needs_rerun.md", rows)
    BL.write_locator_summary(tmp_path / "locator_summary.json", rows)

    assert (tmp_path / "bug_locator.tsv").is_file()
    assert (tmp_path / "root_cause_review.md").is_file()
    assert (tmp_path / "confirmed_paper_bugs.md").is_file()
    assert (tmp_path / "unexpected_features.md").is_file()
    assert (tmp_path / "harness_artifacts.md").is_file()
    assert (tmp_path / "inconclusive_or_needs_rerun.md").is_file()
    assert (tmp_path / "locator_summary.json").is_file()

    summary = json.loads((tmp_path / "locator_summary.json").read_text())
    assert summary["total_rows"] == 1
    assert summary["category_counts"]["CONFIRMED_SECURITY_NOTION_COUNTEREXAMPLE"] == 1


def test_malleability_not_automatically_bug():
    """The guardrail: malleability observations are not automatically bugs."""
    # An unmapped algorithm with malleability should be INCONCLUSIVE, not a bug.
    row = {"version": "0.8.0", "algorithm": "UnknownScheme", "test_id": "SIGN/Verify/m",
           "paper_test_number": 12, "outcome_bucket": "malleability", "outcome_subtype": "maul"}
    cls = BL.classify(row, SOURCE_ROOT)
    assert cls.paper_category == "INCONCLUSIVE"
    assert cls.paper_category not in ("CONFIRMED_SOFTWARE_BUG", "CONFIRMED_SECURITY_NOTION_COUNTEREXAMPLE")


def test_bad_rng_hang_not_vulnerability():
    """The guardrail: bad-RNG hangs are robustness issues, not vulnerabilities."""
    row = {"version": "0.4.0", "algorithm": "SomeAlg", "test_id": "KEM/Keygen/badrng",
           "paper_test_number": 2, "outcome_bucket": "crash_hang", "outcome_subtype": "hang"}
    cls = BL.classify(row, SOURCE_ROOT)
    assert cls.paper_category == "BAD_RNG_ROBUSTNESS_ISSUE"
    assert cls.paper_category != "CONFIRMED_SOFTWARE_BUG"
